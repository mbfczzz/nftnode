package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// --- 内嵌前端文件 ---

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// --- 数据结构 ---

type ForwardRule struct {
	ID             string  `json:"id"`
	LocalPort      string  `json:"local_port"`
	RemoteAddr     string  `json:"remote_addr"`
	RemotePort     string  `json:"remote_port"`
	BackupAddr     string  `json:"backup_addr,omitempty"` // 备用落地地址（IPv4/IPv6/域名），可选
	BackupPort     string  `json:"backup_port,omitempty"` // 备用落地端口
	Note           string  `json:"note"`
	UsedBytes      uint64  `json:"used_bytes"`
	QuotaGB        float64 `json:"quota_gb"`
	Enabled        bool    `json:"enabled"`
	ResetDay       int     `json:"reset_day"`       // 每月几号重置 (1-31)，0 不自动重置
	LastResetTime  string  `json:"last_reset_time"` // 上次重置的月份 "2026-04"
	Reachable      *bool   `json:"reachable,omitempty"`             // 运行时：当前生效线路是否可达（不持久化）
	LastResolvedIP string  `json:"last_resolved_ip,omitempty"`      // 主线路：上次解析的 IP 缓存
	BackupLastResolvedIP string `json:"backup_last_resolved_ip,omitempty"` // 备用线路：上次解析的 IP 缓存
	UsingBackup    bool    `json:"using_backup"`           // 运行时：当前是否切到备用线路（不持久化）
	PrimaryUp      *bool   `json:"primary_up,omitempty"`   // 运行时：主线路是否可达
	BackupUp       *bool   `json:"backup_up,omitempty"`    // 运行时：备用线路是否可达
}

// activeTarget 返回当前生效线路的（地址, 端口, 已缓存解析IP）。
// 主优先：仅当切到备用且配置了备用时才用备用线路。
func (r *ForwardRule) activeTarget() (addr, port, cachedIP string) {
	if r.UsingBackup && r.BackupAddr != "" {
		return r.BackupAddr, r.BackupPort, r.BackupLastResolvedIP
	}
	return r.RemoteAddr, r.RemotePort, r.LastResolvedIP
}

type PanelConfig struct {
	Auth struct {
		Password     string `toml:"password"`
		PasswordHash string `toml:"password_hash"`
	} `toml:"auth"`
	Server struct {
		Port int `toml:"port"`
	} `toml:"server"`
	HTTPS struct {
		Enabled  bool   `toml:"enabled"`
		CertFile string `toml:"cert_file"`
		KeyFile  string `toml:"key_file"`
	} `toml:"https"`
	Nftables struct {
		ConfigPath string `toml:"config_path"`
		RulesPath  string `toml:"rules_path"`
	} `toml:"nftables"`
	Session struct {
		Secret string `toml:"secret"`
	} `toml:"session"`
}

// --- 全局变量 ---

var (
	mu          sync.Mutex
	rules       []ForwardRule
	panelConfig PanelConfig
	configPath  = "./config.toml"

	// 流量统计：记录上次 nft counter 读数，用于计算增量
	lastCounterSnap = make(map[string]uint64)

	// 登录限流：防暴力破解
	loginMu        sync.Mutex
	loginAttempts  = make(map[string]int)
	loginLockUntil = make(map[string]time.Time)
	maxAttempts    = 5
	lockDuration   = 15 * time.Minute
)

// --- 输入校验 ---

// 合法地址正则：IPv4、方括号包裹的 IPv6、域名
var (
	reIPv4   = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	reDomain = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
)

func validatePort(s string) bool {
	p, err := strconv.Atoi(s)
	return err == nil && p >= 1 && p <= 65535
}

func validateAddress(addr string) bool {
	if addr == "" {
		return false
	}
	// 方括号包裹的 IPv6
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		inner := addr[1 : len(addr)-1]
		return net.ParseIP(inner) != nil
	}
	// 纯 IPv4
	if reIPv4.MatchString(addr) {
		return net.ParseIP(addr) != nil
	}
	// 域名
	if reDomain.MatchString(addr) && len(addr) <= 253 {
		return true
	}
	return false
}

// validateBackup 校验备用线路：留空表示不启用（合法）；
// 一旦填写则地址与端口必须同时存在且合法。
func validateBackup(addr, port string) bool {
	if addr == "" && port == "" {
		return true // 不配置备用线路
	}
	return validateAddress(addr) && validatePort(port)
}

// 防止 nftables 配置注入：只允许安全字符
func sanitizeForNft(s string) string {
	safe := regexp.MustCompile(`[^a-zA-Z0-9\.\:\[\]\-\_]`)
	return safe.ReplaceAllString(s, "")
}

// resolveDomainIP 把域名解析成单个 IP，供内核 nftables DNAT 使用。
//   - 带 3 秒超时，避免 DNS 故障时阻塞调用方（generateNftConfLocked 在持锁中调用）
//   - 优先返回 IPv4（中转转发场景 v4 路由最普遍），无 A 记录才回退 IPv6
//   - 直接取解析返回的首个记录（不排序），CDN/轮询 DNS 多记录时以解析顺序为准
func resolveDomainIP(host string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	var v4, v6 []string
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			v4 = append(v4, ip.IP.String())
		} else {
			v6 = append(v6, ip.IP.String())
		}
	}
	if len(v4) > 0 {
		return v4[0], nil
	}
	if len(v6) > 0 {
		return v6[0], nil
	}
	return "", fmt.Errorf("域名 %s 无可用 A/AAAA 记录", host)
}

// resolveAndCache 解析 addr（若为域名）并把结果写入 *cache。
//   - addr 为纯 IP 时直接返回 false（无需解析）
//   - 解析成功且 IP 变化 → 更新缓存，返回 true（需要重载 nft）
//   - 解析失败 → 清空缓存（不再沿用旧 IP 兜底），缓存原本非空时返回 true
func resolveAndCache(addr string, cache *string, label string) bool {
	if addr == "" {
		return false
	}
	host := strings.Trim(addr, "[]")
	if net.ParseIP(host) != nil {
		return false // 是 IP，不需要解析
	}
	if resolved, err := resolveDomainIP(host); err == nil {
		if *cache != resolved {
			log.Printf("[DNS] %s域名 %s 目标 IP 变更: %s -> %s", label, addr, *cache, resolved)
			*cache = resolved
			return true
		}
		return false
	}
	// 解析失败：清空缓存，触发重载使该（线路）规则被跳过
	if *cache != "" {
		log.Printf("[DNS] %s域名 %s 解析失败，清空缓存 IP %s", label, addr, *cache)
		*cache = ""
		return true
	}
	log.Printf("[DNS] %s域名 %s 解析失败", label, addr)
	return false
}

// dialOK 做一次 TCP 拨测，3 秒超时，判断落地端口是否可连通。
// addr 可为 IP 或域名（域名由 DialTimeout 自行解析）。
func dialOK(addr, port string) bool {
	if addr == "" || port == "" {
		return false
	}
	cleanAddr := strings.Trim(addr, "[]")
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(cleanAddr, port), 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// --- 配置加载 ---

func LoadPanelConfig() error {
	// 如果 config.toml 不存在，尝试从 config.toml.example 自动生成
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		examplePath := configPath + ".example"
		if _, err := os.Stat(examplePath); err == nil {
			data, err := os.ReadFile(examplePath)
			if err != nil {
				return fmt.Errorf("读取 %s 失败: %v", examplePath, err)
			}
			if err := os.WriteFile(configPath, data, 0600); err != nil {
				return fmt.Errorf("生成 %s 失败: %v", configPath, err)
			}
			log.Printf("已从 %s 自动生成 %s，请及时修改默认密码！", examplePath, configPath)
		} else {
			return fmt.Errorf("配置文件 %s 不存在，也找不到 %s 模板", configPath, examplePath)
		}
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	if _, err := toml.Decode(string(data), &panelConfig); err != nil {
		return err
	}

	if panelConfig.Nftables.ConfigPath == "" {
		panelConfig.Nftables.ConfigPath = "/etc/nftables.conf"
	}
	if panelConfig.Nftables.RulesPath == "" {
		panelConfig.Nftables.RulesPath = "/root/.nft-forward/rules.json"
	}

	// 自动生成 Session Secret
	if panelConfig.Session.Secret == "" {
		secret, err := generateRandomSecret(32)
		if err != nil {
			return fmt.Errorf("生成 Session Secret 失败: %v", err)
		}
		panelConfig.Session.Secret = secret
		log.Println("已自动生成 Session Secret")
		if err := savePanelConfig(); err != nil {
			return fmt.Errorf("保存配置失败: %v", err)
		}
	}

	// 自动将明文密码迁移为 bcrypt 哈希
	if panelConfig.Auth.Password != "" && panelConfig.Auth.PasswordHash == "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(panelConfig.Auth.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("密码哈希化失败: %v", err)
		}
		panelConfig.Auth.PasswordHash = string(hash)
		panelConfig.Auth.Password = ""
		log.Println("已将明文密码迁移为 bcrypt 哈希")
		if err := savePanelConfig(); err != nil {
			return fmt.Errorf("保存配置失败: %v", err)
		}
	}

	// 没有任何密码配置 → 提示
	if panelConfig.Auth.PasswordHash == "" && panelConfig.Auth.Password == "" {
		log.Println("警告: 未配置任何密码，请在 config.toml 中设置 [auth] password")
	}

	return nil
}

func generateRandomSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func savePanelConfig() error {
	var buf bytes.Buffer
	buf.WriteString("# nftables 转发面板配置\n")
	buf.WriteString("# 警告: 请修改默认密码！首次运行后明文密码会自动迁移为 bcrypt 哈希\n\n")

	buf.WriteString("[auth]\n")
	if panelConfig.Auth.Password != "" {
		buf.WriteString(fmt.Sprintf("password = \"%s\"\n", panelConfig.Auth.Password))
	}
	if panelConfig.Auth.PasswordHash != "" {
		buf.WriteString(fmt.Sprintf("password_hash = \"%s\"\n", panelConfig.Auth.PasswordHash))
	}
	buf.WriteString("\n")

	buf.WriteString("[server]\n")
	buf.WriteString(fmt.Sprintf("port = %d\n\n", panelConfig.Server.Port))

	buf.WriteString("[https]\n")
	buf.WriteString(fmt.Sprintf("enabled = %t\n", panelConfig.HTTPS.Enabled))
	buf.WriteString(fmt.Sprintf("cert_file = \"%s\"\n", panelConfig.HTTPS.CertFile))
	buf.WriteString(fmt.Sprintf("key_file = \"%s\"\n\n", panelConfig.HTTPS.KeyFile))

	buf.WriteString("[nftables]\n")
	buf.WriteString(fmt.Sprintf("config_path = \"%s\"\n", panelConfig.Nftables.ConfigPath))
	buf.WriteString(fmt.Sprintf("rules_path = \"%s\"\n\n", panelConfig.Nftables.RulesPath))

	buf.WriteString("[session]\n")
	buf.WriteString(fmt.Sprintf("secret = \"%s\"\n\n", panelConfig.Session.Secret))

	return os.WriteFile(configPath, buf.Bytes(), 0600)
}

// --- 规则持久化 ---

// 调用方必须持有 mu 锁
func LoadRules() error {
	// 确保父目录存在
	dir := filepath.Dir(panelConfig.Nftables.RulesPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("创建规则目录失败 %s: %v", dir, err)
	}

	data, err := os.ReadFile(panelConfig.Nftables.RulesPath)
	if err != nil {
		rules = []ForwardRule{}
		return saveRulesLocked()
	}
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}
	
	// 旧数据向后兼容：将新加载配置中因零值而判定停用的项，如果在初始态，强制修正为开启
	changed := false
	for i := range rules {
		if !rules[i].Enabled && rules[i].UsedBytes == 0 && rules[i].QuotaGB == 0 {
			rules[i].Enabled = true
			changed = true
		}
	}
	if changed {
		_ = saveRulesLocked()
	}
	return nil
}

// 调用方必须持有 mu 锁
func saveRulesLocked() error {
	// 落盘前复制并清空运行时字段，避免重启后残留旧拨测/切换状态
	// （主优先：重启后默认回到主线路，由后台拨测在 60s 内重新决策）
	cp := make([]ForwardRule, len(rules))
	copy(cp, rules)
	for i := range cp {
		cp[i].Reachable = nil
		cp[i].PrimaryUp = nil
		cp[i].BackupUp = nil
		cp[i].UsingBackup = false
	}
	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(panelConfig.Nftables.RulesPath, data, 0600)
}

// --- nftables 配置生成 ---

func isIPv6(addr string) bool {
	clean := strings.Trim(addr, "[]")
	return strings.Contains(clean, ":")
}

// 调用方必须持有 mu 锁（读 rules）
func generateNftConfLocked() error {
	var buf bytes.Buffer

	buf.WriteString("#!/usr/sbin/nft -f\n\n")
	// 仅删除本项目创建的表，不影响其他防火墙规则
	buf.WriteString("table inet nft_forward\n")
	buf.WriteString("delete table inet nft_forward\n\n")
	buf.WriteString("table inet nft_forward {\n\n")

	// prerouting 链
	buf.WriteString("    chain prerouting {\n")
	buf.WriteString("        type nat hook prerouting priority -100; policy accept;\n\n")

	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled {
			continue // 超额封停或被禁用的规则跳过其 NAT，拦截网络
		}

		// 选取当前生效线路（主优先，主挂了才切备用）
		activeAddr, activePort, activeCachedIP := rule.activeTarget()

		targetIP := strings.Trim(activeAddr, "[]")
		if net.ParseIP(targetIP) == nil {
			// 目标是域名：内核只认 IP，这里替换为解析后的 IP
			if activeCachedIP != "" && net.ParseIP(activeCachedIP) != nil {
				targetIP = activeCachedIP // 优先用缓存（含后台定时刷新的结果）
			} else if ip, err := resolveDomainIP(targetIP); err == nil {
				targetIP = ip
				// 首次解析成功，写入对应线路的缓存
				if rule.UsingBackup && rule.BackupAddr != "" {
					rule.BackupLastResolvedIP = ip
				} else {
					rule.LastResolvedIP = ip
				}
			} else {
				log.Printf("[警告] 规则 %s 的目标域名 %s 解析失败，跳过此转发规则: %v", rule.ID, activeAddr, err)
				buf.WriteString(fmt.Sprintf("        # Rule %s (跳过: 域名 %s 解析失败)\n\n", rule.ID, activeAddr))
				continue
			}
		}

		// 安全: 经过校验的值再额外做一次 sanitize
		lport := sanitizeForNft(rule.LocalPort)
		rport := sanitizeForNft(activePort)
		addr := sanitizeForNft(targetIP)

		noteComment := ""
		if rule.Note != "" {
			// 注释里也做 sanitize 防止换行注入
			noteComment = fmt.Sprintf(" (%s)", sanitizeForNft(rule.Note))
		}

		// 内核级 comment：写入 nftables 规则元数据，nft list ruleset 时可直接看到规则用途
		// 格式: "nat_端口" 或 "nat_端口_备注"，截断到 80 字符防止超出 nftables 128 字符上限
		nftComment := fmt.Sprintf("nat_%s", lport)
		if rule.Note != "" {
			sanitizedNote := sanitizeForNft(rule.Note)
			if len(sanitizedNote) > 60 {
				sanitizedNote = sanitizedNote[:60]
			}
			nftComment = fmt.Sprintf("nat_%s_%s", lport, sanitizedNote)
		}

		if isIPv6(targetIP) {
			buf.WriteString(fmt.Sprintf("        # Rule %s%s\n", rule.ID, noteComment))
			buf.WriteString(fmt.Sprintf("        tcp dport %s dnat ip6 to [%s]:%s comment \"%s\"\n", lport, addr, rport, nftComment))
			buf.WriteString(fmt.Sprintf("        udp dport %s dnat ip6 to [%s]:%s comment \"%s\"\n", lport, addr, rport, nftComment))
		} else {
			buf.WriteString(fmt.Sprintf("        # Rule %s%s\n", rule.ID, noteComment))
			buf.WriteString(fmt.Sprintf("        tcp dport %s dnat ip to %s:%s comment \"%s\"\n", lport, addr, rport, nftComment))
			buf.WriteString(fmt.Sprintf("        udp dport %s dnat ip to %s:%s comment \"%s\"\n", lport, addr, rport, nftComment))
		}
		buf.WriteString("\n")
	}

	buf.WriteString("    }\n\n")

	// forward 链 — 流量统计（filter 类型可统计所有包，NAT 链只统计首包）
	// 用远端 IP+端口匹配（最大兼容性），comment 标记本机端口供解析器提取
	buf.WriteString("    chain forward {\n")
	buf.WriteString("        type filter hook forward priority 0; policy accept;\n\n")
	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled {
			continue
		}

		activeAddr, activePort, activeCachedIP := rule.activeTarget()
		targetIP := strings.Trim(activeAddr, "[]")
		if net.ParseIP(targetIP) == nil {
			// 域名规则：仅在已有有效缓存 IP 时才生成统计规则；尚未解析成功的跳过，防止 nft 报错
			if activeCachedIP != "" && net.ParseIP(activeCachedIP) != nil {
				targetIP = activeCachedIP
			} else {
				continue
			}
		}

		lport := sanitizeForNft(rule.LocalPort)
		rport := sanitizeForNft(activePort)
		addr := sanitizeForNft(targetIP)
		ipFamily := "ip"
		if isIPv6(targetIP) {
			ipFamily = "ip6"
		}
		// 去程：客户端 → 远端（匹配目标地址+端口）
		buf.WriteString(fmt.Sprintf("        %s daddr %s tcp dport %s counter comment \"fwd_%s\"\n", ipFamily, addr, rport, lport))
		buf.WriteString(fmt.Sprintf("        %s daddr %s udp dport %s counter comment \"fwd_%s\"\n", ipFamily, addr, rport, lport))
		// 回程：远端 → 客户端（匹配源地址+端口）
		buf.WriteString(fmt.Sprintf("        %s saddr %s tcp sport %s counter comment \"fwd_%s\"\n", ipFamily, addr, rport, lport))
		buf.WriteString(fmt.Sprintf("        %s saddr %s udp sport %s counter comment \"fwd_%s\"\n", ipFamily, addr, rport, lport))
	}
	buf.WriteString("    }\n\n")

	// postrouting 链 — 仅对 DNAT 过的包做 masquerade
	buf.WriteString("    chain postrouting {\n")
	buf.WriteString("        type nat hook postrouting priority 100; policy accept;\n")
	buf.WriteString("        ct status dnat masquerade\n")
	buf.WriteString("    }\n")
	buf.WriteString("}\n")

	return os.WriteFile(panelConfig.Nftables.ConfigPath, buf.Bytes(), 0644)
}

// 调用方必须持有 mu 锁
func applyNftRulesLocked() error {
	if err := generateNftConfLocked(); err != nil {
		return fmt.Errorf("生成配置失败: %v", err)
	}
	cmd := exec.Command("nft", "-f", panelConfig.Nftables.ConfigPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("应用规则失败: %s - %v", string(output), err)
	}
	return nil
}

// saveAndApplyLocked 保存规则并应用，失败时回滚内存状态
// 调用方必须持有 mu 锁，且在调用前将 backup 设为修改前的 rules 快照
func saveAndApplyLocked(backup []ForwardRule) error {
	if err := saveRulesLocked(); err != nil {
		rules = backup // 回滚内存
		return fmt.Errorf("保存规则失败: %v", err)
	}
	if err := applyNftRulesLocked(); err != nil {
		// 回滚: 恢复内存 + 磁盘 JSON + 磁盘 nftables.conf
		rules = backup
		_ = saveRulesLocked()
		_ = generateNftConfLocked()
		return err
	}
	return nil
}

// 深拷贝 rules 用于回滚
func snapshotRules() []ForwardRule {
	cp := make([]ForwardRule, len(rules))
	copy(cp, rules)
	return cp
}

// --- 密码校验 ---

func verifyPassword(inputPassword string) bool {
	if panelConfig.Auth.PasswordHash != "" {
		return bcrypt.CompareHashAndPassword([]byte(panelConfig.Auth.PasswordHash), []byte(inputPassword)) == nil
	}
	if panelConfig.Auth.Password != "" {
		log.Println("警告: 正在使用明文密码验证，请检查 bcrypt 哈希迁移是否成功")
		return panelConfig.Auth.Password == inputPassword
	}
	return false
}

// --- 流量提取 ---

func parseNftCounters(out []byte) map[string]uint64 {
	counterMap := make(map[string]uint64)
	var data map[string]interface{}
	if err := json.Unmarshal(out, &data); err != nil {
		return counterMap
	}
	nftables, ok := data["nftables"].([]interface{})
	if !ok {
		return counterMap
	}
	for _, item := range nftables {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		ruleObj, ok := obj["rule"].(map[string]interface{})
		if !ok {
			continue
		}
		// 只解析 forward 链的 counter（流量统计）
		chain, _ := ruleObj["chain"].(string)
		if chain != "forward" {
			continue
		}

		// 从 comment 字段提取本机端口（格式: "fwd_12142"）
		comment, _ := ruleObj["comment"].(string)
		if !strings.HasPrefix(comment, "fwd_") {
			continue
		}
		localPort := strings.TrimPrefix(comment, "fwd_")

		exprs, ok := ruleObj["expr"].([]interface{})
		if !ok {
			continue
		}

		var countBytes uint64
		for _, expr := range exprs {
			e, ok := expr.(map[string]interface{})
			if !ok {
				continue
			}
			if counter, ok := e["counter"].(map[string]interface{}); ok {
				if bytes, ok := counter["bytes"].(float64); ok {
					countBytes = uint64(bytes)
				}
			}
		}
		counterMap[localPort] += countBytes
	}
	return counterMap
}

// checkForwardBlocked 检测 iptables FORWARD 链是否为 DROP 且缺少 DNAT 放行规则
// 典型场景：Docker 将 FORWARD 策略设为 DROP，导致 nftables DNAT 转发流量被拦截
func checkForwardBlocked() bool {
	// 检查 FORWARD 默认策略
	out, err := exec.Command("iptables", "-L", "FORWARD", "-n").Output()
	if err != nil {
		return false // iptables 不可用，不阻断
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) == 0 {
		return false
	}
	// 首行格式: "Chain FORWARD (policy DROP)"
	if !strings.Contains(lines[0], "policy DROP") {
		return false // 策略不是 DROP，不阻断
	}
	// 策略是 DROP，检查是否有 DNAT 放行规则
	checkOut, err := exec.Command("iptables", "-C", "FORWARD", "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT").CombinedOutput()
	_ = checkOut
	if err == nil {
		return false // 有放行规则，不阻断
	}
	return true // FORWARD=DROP 且无 DNAT 放行 → 转发被阻断
}

// --- 登录限流 ---

// 检查 IP 是否被锁定
func isLoginLocked(ip string) (bool, time.Duration) {
	loginMu.Lock()
	defer loginMu.Unlock()

	if until, ok := loginLockUntil[ip]; ok {
		if time.Now().Before(until) {
			return true, time.Until(until)
		}
		// 锁定已过期，清理
		delete(loginLockUntil, ip)
		delete(loginAttempts, ip)
	}
	return false, 0
}

// 记录登录失败
func recordLoginFailure(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()

	loginAttempts[ip]++
	if loginAttempts[ip] >= maxAttempts {
		loginLockUntil[ip] = time.Now().Add(lockDuration)
		log.Printf("IP %s 连续登录失败 %d 次，已锁定 %v", ip, maxAttempts, lockDuration)
	}
}

// 登录成功后清除记录
func clearLoginAttempts(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()

	delete(loginAttempts, ip)
	delete(loginLockUntil, ip)
}

// --- 中间件 ---

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		if user == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

// --- 主函数 ---

func main() {
	if err := LoadPanelConfig(); err != nil {
		log.Fatalf("无法加载面板配置: %v", err)
	}

	mu.Lock()
	if err := LoadRules(); err != nil {
		log.Fatalf("无法加载转发规则: %v", err)
	}
	// 启动时自动重新生成并应用 nftables 配置（确保 forward 统计链等新功能生效）
	if err := applyNftRulesLocked(); err != nil {
		log.Printf("启动时应用规则失败（可能首次安装未配置）: %v", err)
	} else {
		log.Printf("启动时已重新应用 %d 条规则", len(rules))
	}
	mu.Unlock()

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	store := cookie.NewStore([]byte(panelConfig.Session.Secret))
	store.Options(sessions.Options{
		HttpOnly: true,
		MaxAge:   3600 * 4,
		Path:     "/",
	})
	r.Use(sessions.Sessions("nft_session", store))

	// --- 并发轮询控制 ---
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		// 启动后立即执行第一次检测，不等 60 秒
		firstRun := make(chan struct{}, 1)
		firstRun <- struct{}{}
		for {
			select {
			case <-firstRun:
			case <-ticker.C:
			}
			out, err := exec.Command("nft", "-j", "list", "table", "inet", "nft_forward").Output()
			if err != nil {
				continue
			}

			// 检测 iptables FORWARD DROP（Docker 冲突）
			forwardBlocked := checkForwardBlocked()

			// 并发拨测所有落地机连通性（每条规则一个 goroutine，3 秒超时）
			// 先拷贝需要拨测的信息，避免长时间持锁
			// 用 rule.ID 作为索引键，避免拨测期间增删规则导致下标错位
			mu.Lock()
			type probeTarget struct {
				id         string
				addr, port string
				backupAddr, backupPort string
			}
			targets := make([]probeTarget, len(rules))
			for i, rule := range rules {
				targets[i] = probeTarget{rule.ID, rule.RemoteAddr, rule.RemotePort, rule.BackupAddr, rule.BackupPort}
			}
			mu.Unlock()

			type probeResult struct {
				id        string
				primaryUp bool
				hasBackup bool
				backupUp  bool
			}
			results := make(chan probeResult, len(targets))
			for _, t := range targets {
				go func(t probeTarget) {
					primaryUp := dialOK(t.addr, t.port)
					hasBackup := t.backupAddr != ""
					backupUp := false
					if hasBackup {
						backupUp = dialOK(t.backupAddr, t.backupPort)
					}
					results <- probeResult{t.id, primaryUp, hasBackup, backupUp}
				}(t)
			}

			// 收集拨测结果（按规则 ID 索引）
			primaryReach := make(map[string]bool)
			backupReach := make(map[string]bool)
			hasBackupMap := make(map[string]bool)
			for j := 0; j < len(targets); j++ {
				r := <-results
				primaryReach[r.id] = r.primaryUp
				backupReach[r.id] = r.backupUp
				hasBackupMap[r.id] = r.hasBackup
			}

			counterMap := parseNftCounters(out)
			mu.Lock()
			changed := false
			backup := snapshotRules()
			now := time.Now()
			currentMonth := now.Format("2006-01")
			currentDay := now.Day()
			// 计算当月最后一天：下月1号往前推1天
			lastDayOfMonth := time.Date(now.Year(), now.Month()+1, 0, 0, 0, 0, 0, now.Location()).Day()

			for i := range rules {
				// 1. 动态域名解析与变更检测（DDNS/CDN 目标 IP 变化时自动热重载）
				// 主线路与备用线路的域名都做动态解析（DDNS/CDN 目标 IP 变化时自动热重载）
				if resolveAndCache(rules[i].RemoteAddr, &rules[i].LastResolvedIP, "主") {
					changed = true
				}
				if rules[i].BackupAddr != "" {
					if resolveAndCache(rules[i].BackupAddr, &rules[i].BackupLastResolvedIP, "备") {
						changed = true
					}
				}

				// 流量统计：增量累加，不直接覆盖
				// nft counter 在 delete table 后会清零，所以用“本次读数 - 上次读数”算增量
				var thisDelta uint64
				if currentCounter, ok := counterMap[rules[i].LocalPort]; ok {
					prevCounter := lastCounterSnap[rules[i].LocalPort]
					if currentCounter >= prevCounter {
						thisDelta = currentCounter - prevCounter
					} else {
						// counter 被重置了（delete table 或重启 nftables），直接加上新值
						thisDelta = currentCounter
					}
					rules[i].UsedBytes += thisDelta
				}

				// 主/备故障切换 + 连通性状态更新（按规则 ID 匹配，避免增删导致错位）
				if primaryUp, ok := primaryReach[rules[i].ID]; ok {
					hasBackup := hasBackupMap[rules[i].ID]
					backupUp := backupReach[rules[i].ID]

					// 主优先：主通用主；主断且备用通才切备用；都断则维持主（规则会因不可达而显示异常）
					newUsing := !primaryUp && hasBackup && backupUp
					if newUsing != rules[i].UsingBackup {
						if newUsing {
							log.Printf("[切换] 规则 %s (端口 %s) 主线路不可达，切换到备用线路 %s:%s", rules[i].ID, rules[i].LocalPort, rules[i].BackupAddr, rules[i].BackupPort)
						} else {
							log.Printf("[切换] 规则 %s (端口 %s) 主线路恢复，切回主线路 %s:%s", rules[i].ID, rules[i].LocalPort, rules[i].RemoteAddr, rules[i].RemotePort)
						}
						rules[i].UsingBackup = newUsing
						changed = true // 触发 nft 重载，使新线路生效
					}

					// 运行时状态：当前生效线路是否可达
					activeUp := primaryUp || (hasBackup && backupUp)
					r := activeUp && !forwardBlocked
					rules[i].Reachable = &r
					p := primaryUp
					rules[i].PrimaryUp = &p
					if hasBackup {
						b := backupUp
						rules[i].BackupUp = &b
					} else {
						rules[i].BackupUp = nil
					}
				}

				// 账期自动重置：当月未重置过 且 今天已到达重置日（或月末兜底）
				// 例：ResetDay=31 但2月只有28天 → 在28号（月末最后一天）自动触发
				if rules[i].ResetDay > 0 && rules[i].LastResetTime != currentMonth {
					effectiveDay := rules[i].ResetDay
					if effectiveDay > lastDayOfMonth {
						effectiveDay = lastDayOfMonth // 短月兜底：月末最后一天触发
					}
					if currentDay >= effectiveDay {
						rules[i].UsedBytes = 0
						rules[i].Enabled = true
						rules[i].LastResetTime = currentMonth
						changed = true
						log.Printf("规则 %s (端口 %s) 账期重置，流量已清零（重置日:%d，实际触发日:%d）", rules[i].ID, rules[i].LocalPort, rules[i].ResetDay, currentDay)
					}
				}

				// 判断封停
				if rules[i].QuotaGB > 0 && rules[i].Enabled {
					if float64(rules[i].UsedBytes) > rules[i].QuotaGB*1024*1024*1024 {
						rules[i].Enabled = false
						changed = true
						log.Printf("规则 %s (端口 %s) 流量超额，已封停", rules[i].ID, rules[i].LocalPort)
					}
				}
			}
			if changed {
				_ = saveAndApplyLocked(backup)
			} else {
				// 没封停也存一次总流量
				_ = saveRulesLocked()
			}
			// 更新 counter 快照，供下一轮增量计算
			lastCounterSnap = counterMap
			mu.Unlock()
		}
	}()

	staticSubFS, _ := fs.Sub(staticFS, "static")
	r.StaticFS("/static", http.FS(staticSubFS))

	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		log.Fatalf("无法加载模板: %v", err)
	}
	r.SetHTMLTemplate(tmpl)

	// --- 登录 ---
	r.GET("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("user") != nil {
			c.Redirect(http.StatusFound, "/")
			return
		}
		c.HTML(http.StatusOK, "login.html", nil)
	})

	r.POST("/login", func(c *gin.Context) {
		clientIP := c.ClientIP()

		// 检查是否被锁定
		if locked, remaining := isLoginLocked(clientIP); locked {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": fmt.Sprintf("登录失败次数过多，请 %d 分钟后重试", int(remaining.Minutes())+1),
			})
			return
		}

		var loginData struct {
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&loginData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
			return
		}
		if verifyPassword(loginData.Password) {
			clearLoginAttempts(clientIP)
			session := sessions.Default(c)
			session.Set("user", true)
			session.Options(sessions.Options{MaxAge: 3600 * 4, HttpOnly: true, Path: "/"})
			if err := session.Save(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Session 保存失败"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "登录成功"})
		} else {
			recordLoginFailure(clientIP)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
		}
	})

	// --- 认证路由组 ---
	api := r.Group("/")
	api.Use(AuthRequired())
	{
		api.GET("/", func(c *gin.Context) {
			c.HTML(http.StatusOK, "index.html", nil)
		})

		// 获取规则（分页）
		api.GET("/api/rules", func(c *gin.Context) {
			page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
			size, _ := strconv.Atoi(c.DefaultQuery("size", "10"))
			if page < 1 {
				page = 1
			}
			if size < 1 || size > 100 {
				size = 10
			}

			mu.Lock()
			defer mu.Unlock()

			total := len(rules)
			start := (page - 1) * size
			end := start + size
			if start >= total {
				start = total
			}
			if end > total {
				end = total
			}

			c.JSON(200, gin.H{"rules": rules[start:end], "total": total})
		})

		// 添加单条规则
		api.POST("/api/rules", func(c *gin.Context) {
			var input struct {
				LocalPort  string  `json:"local_port"`
				RemoteAddr string  `json:"remote_addr"`
				RemotePort string  `json:"remote_port"`
				BackupAddr string  `json:"backup_addr"`
				BackupPort string  `json:"backup_port"`
				Note       string  `json:"note"`
				QuotaGB    float64 `json:"quota_gb"`
				ResetDay   int     `json:"reset_day"`
			}
			if err := c.ShouldBindJSON(&input); err != nil {
				c.JSON(400, gin.H{"error": "无效输入"})
				return
			}

			// 校验所有字段
			if !validatePort(input.LocalPort) {
				c.JSON(400, gin.H{"error": "本机端口无效 (1-65535)"})
				return
			}
			if !validatePort(input.RemotePort) {
				c.JSON(400, gin.H{"error": "目标端口无效 (1-65535)"})
				return
			}
			if !validateAddress(input.RemoteAddr) {
				c.JSON(400, gin.H{"error": "目标地址无效，请输入合法的 IPv4/IPv6/域名"})
				return
			}
			// 备用线路可选：填了就必须地址+端口都合法
			if !validateBackup(input.BackupAddr, input.BackupPort) {
				c.JSON(400, gin.H{"error": "备用线路无效：地址和端口需同时填写且合法 (IPv4/IPv6/域名 + 1-65535)"})
				return
			}

			mu.Lock()
			defer mu.Unlock()

			// 检查端口重复
			for _, r := range rules {
				if r.LocalPort == input.LocalPort {
					c.JSON(409, gin.H{"error": fmt.Sprintf("端口 %s 已存在", input.LocalPort)})
					return
				}
			}

			// 先备份再修改
			backup := snapshotRules()

			newRule := ForwardRule{
				ID:         uuid.New().String()[:8],
				LocalPort:  input.LocalPort,
				RemoteAddr: input.RemoteAddr,
				RemotePort: input.RemotePort,
				BackupAddr: input.BackupAddr,
				BackupPort: input.BackupPort,
				Note:       input.Note,
				QuotaGB:    input.QuotaGB,
				ResetDay:   input.ResetDay,
				Enabled:    true,
			}
			rules = append(rules, newRule)

			if err := saveAndApplyLocked(backup); err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}

			c.JSON(201, newRule)
		})

		// 批量添加规则
		api.POST("/api/rules/batch", func(c *gin.Context) {
			var input struct {
				Rules []struct {
					LocalPort  string `json:"local_port"`
					RemoteAddr string `json:"remote_addr"`
					RemotePort string `json:"remote_port"`
					Note       string `json:"note"`
					// 此处批量未扩展quota_gb输入，可考虑支持，默认为0
				} `json:"rules"`
			}
			if err := c.ShouldBindJSON(&input); err != nil {
				c.JSON(400, gin.H{"error": "无效输入"})
				return
			}

			mu.Lock()
			defer mu.Unlock()

			backup := snapshotRules()
			added := 0
			failed := []string{}

			for _, item := range input.Rules {
				// 校验每条规则
				if !validatePort(item.LocalPort) {
					failed = append(failed, fmt.Sprintf("端口 %s 无效", item.LocalPort))
					continue
				}
				if !validatePort(item.RemotePort) {
					failed = append(failed, fmt.Sprintf("目标端口 %s 无效", item.RemotePort))
					continue
				}
				if !validateAddress(item.RemoteAddr) {
					failed = append(failed, fmt.Sprintf("地址 %s 无效", item.RemoteAddr))
					continue
				}

				exists := false
				for _, r := range rules {
					if r.LocalPort == item.LocalPort {
						exists = true
						break
					}
				}
				if exists {
					failed = append(failed, fmt.Sprintf("端口 %s 已存在", item.LocalPort))
					continue
				}

				rules = append(rules, ForwardRule{
					ID:         uuid.New().String()[:8],
					LocalPort:  item.LocalPort,
					RemoteAddr: item.RemoteAddr,
					RemotePort: item.RemotePort,
					Note:       item.Note,
					Enabled:    true,
				})
				added++
			}

			if added > 0 {
				if err := saveAndApplyLocked(backup); err != nil {
					c.JSON(500, gin.H{"error": err.Error()})
					return
				}
			}

			c.JSON(200, gin.H{
				"added":  added,
				"failed": failed,
			})
		})

		// 删除规则
		api.DELETE("/api/rules/:id", func(c *gin.Context) {
			id := c.Param("id")

			mu.Lock()
			defer mu.Unlock()

			backup := snapshotRules()
			found := false
			for i, r := range rules {
				if r.ID == id {
					rules = append(rules[:i], rules[i+1:]...)
					found = true
					break
				}
			}

			if !found {
				c.JSON(404, gin.H{"error": "规则不存在"})
				return
			}

			if err := saveAndApplyLocked(backup); err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}

			c.JSON(200, gin.H{"message": "规则已删除"})
		})

		// 重置用量
		api.POST("/api/rules/:id/reset", func(c *gin.Context) {
			id := c.Param("id")
			mu.Lock()
			defer mu.Unlock()
			backup := snapshotRules()
			found := false
			for i, r := range rules {
				if r.ID == id {
					rules[i].UsedBytes = 0
					rules[i].Enabled = true
					found = true
					break
				}
			}
			if !found {
				c.JSON(404, gin.H{"error": "规则不存在"})
				return
			}
			if err := saveAndApplyLocked(backup); err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			c.JSON(200, gin.H{"message": "流量已重置并恢复"})
		})

		// 设置配额
		api.PUT("/api/rules/:id/quota", func(c *gin.Context) {
			id := c.Param("id")
			var input struct {
				QuotaGB float64 `json:"quota_gb"`
			}
			if err := c.ShouldBindJSON(&input); err != nil {
				c.JSON(400, gin.H{"error": "无效输入"})
				return
			}
			mu.Lock()
			defer mu.Unlock()
			backup := snapshotRules()
			found := false
			for i, r := range rules {
				if r.ID == id {
					rules[i].QuotaGB = input.QuotaGB
					// 如果设置了配额，判断一下是不是可以解封
					if !rules[i].Enabled && (rules[i].QuotaGB == 0 || float64(rules[i].UsedBytes) <= rules[i].QuotaGB*1024*1024*1024) {
						rules[i].Enabled = true
					}
					found = true
					break
				}
			}
			if !found {
				c.JSON(404, gin.H{"error": "规则不存在"})
				return
			}
			if err := saveAndApplyLocked(backup); err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			c.JSON(200, gin.H{"message": "配额已更新"})
		})

		// 编辑规则（修改本机端口、目标地址、目标端口、备注、配额、重置日）
		api.PUT("/api/rules/:id", func(c *gin.Context) {
			id := c.Param("id")
			var input struct {
				LocalPort  string  `json:"local_port"`
				RemoteAddr string  `json:"remote_addr"`
				RemotePort string  `json:"remote_port"`
				BackupAddr string  `json:"backup_addr"`
				BackupPort string  `json:"backup_port"`
				Note       string  `json:"note"`
				QuotaGB    float64 `json:"quota_gb"`
				ResetDay   int     `json:"reset_day"`
			}
			if err := c.ShouldBindJSON(&input); err != nil {
				c.JSON(400, gin.H{"error": "无效输入"})
				return
			}

			// 校验字段（允许部分更新：只校验非空字段）
			if input.LocalPort != "" && !validatePort(input.LocalPort) {
				c.JSON(400, gin.H{"error": "本机端口无效 (1-65535)"})
				return
			}
			if input.RemotePort != "" && !validatePort(input.RemotePort) {
				c.JSON(400, gin.H{"error": "目标端口无效 (1-65535)"})
				return
			}
			if input.RemoteAddr != "" && !validateAddress(input.RemoteAddr) {
				c.JSON(400, gin.H{"error": "目标地址无效，请输入合法的 IPv4/IPv6/域名"})
				return
			}
			// 备用线路：允许清空（两者都空）；否则地址+端口都要合法
			if !validateBackup(input.BackupAddr, input.BackupPort) {
				c.JSON(400, gin.H{"error": "备用线路无效：地址和端口需同时填写且合法 (IPv4/IPv6/域名 + 1-65535)"})
				return
			}

			mu.Lock()
			defer mu.Unlock()

			// 如果要修改本机端口，需要检查是否与其他规则冲突
			if input.LocalPort != "" {
				for _, r := range rules {
					if r.ID != id && r.LocalPort == input.LocalPort {
						c.JSON(409, gin.H{"error": fmt.Sprintf("本机端口 %s 已被其他规则占用", input.LocalPort)})
						return
					}
				}
			}

			backup := snapshotRules()
			found := false
			for i, r := range rules {
				if r.ID == id {
					if input.LocalPort != "" {
						rules[i].LocalPort = input.LocalPort
					}
					if input.RemoteAddr != "" {
						rules[i].RemoteAddr = input.RemoteAddr
					}
					if input.RemotePort != "" {
						rules[i].RemotePort = input.RemotePort
					}
					// 备用线路允许清空，所以始终覆盖；清空时一并复位运行时切换状态与缓存
					rules[i].BackupAddr = input.BackupAddr
					rules[i].BackupPort = input.BackupPort
					if input.BackupAddr == "" {
						rules[i].UsingBackup = false
						rules[i].BackupLastResolvedIP = ""
						rules[i].BackupUp = nil
					}
					// 备注允许清空，所以始终更新
					rules[i].Note = input.Note
					// 配额和重置日始终更新
					rules[i].QuotaGB = input.QuotaGB
					rules[i].ResetDay = input.ResetDay
					// 如果配额增大或取消限额，自动解封
					if !rules[i].Enabled && (rules[i].QuotaGB == 0 || float64(rules[i].UsedBytes) <= rules[i].QuotaGB*1024*1024*1024) {
						rules[i].Enabled = true
					}
					found = true
					break
				}
			}

			if !found {
				c.JSON(404, gin.H{"error": "规则不存在"})
				return
			}

			if err := saveAndApplyLocked(backup); err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}

			c.JSON(200, gin.H{"message": "规则已更新"})
		})

		// 服务控制
		api.POST("/api/service/start", func(c *gin.Context) {
			mu.Lock()
			err := applyNftRulesLocked()
			mu.Unlock()
			if err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			cmd := exec.Command("systemctl", "start", "nftables")
			if err := cmd.Run(); err != nil {
				c.JSON(500, gin.H{"error": "启动失败"})
				return
			}
			c.JSON(200, gin.H{"message": "nftables 已启动"})
		})

		api.POST("/api/service/stop", func(c *gin.Context) {
			cmd := exec.Command("systemctl", "stop", "nftables")
			if err := cmd.Run(); err != nil {
				c.JSON(500, gin.H{"error": "停止失败"})
				return
			}
			c.JSON(200, gin.H{"message": "nftables 已停止"})
		})

		api.POST("/api/service/restart", func(c *gin.Context) {
			mu.Lock()
			err := applyNftRulesLocked()
			mu.Unlock()
			if err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			cmd := exec.Command("systemctl", "restart", "nftables")
			if err := cmd.Run(); err != nil {
				c.JSON(500, gin.H{"error": "重启失败"})
				return
			}
			c.JSON(200, gin.H{"message": "nftables 已重启"})
		})

		api.GET("/api/service/status", func(c *gin.Context) {
			cmd := exec.Command("systemctl", "is-active", "--quiet", "nftables")
			err := cmd.Run()
			status := "已停止"
			if err == nil {
				status = "运行中"
			}
			c.JSON(200, gin.H{"status": status})
		})

		// 登出
		api.POST("/logout", func(c *gin.Context) {
			session := sessions.Default(c)
			session.Clear()
			session.Save()
			c.JSON(http.StatusOK, gin.H{"message": "登出成功"})
		})

		// 修改密码
		api.PUT("/api/password", func(c *gin.Context) {
			var input struct {
				OldPassword string `json:"old_password"`
				NewPassword string `json:"new_password"`
			}
			if err := c.ShouldBindJSON(&input); err != nil {
				c.JSON(400, gin.H{"error": "无效请求"})
				return
			}

			if input.OldPassword == "" || input.NewPassword == "" {
				c.JSON(400, gin.H{"error": "旧密码和新密码不能为空"})
				return
			}
			if len(input.NewPassword) < 4 {
				c.JSON(400, gin.H{"error": "新密码至少 4 个字符"})
				return
			}

			// 验证旧密码
			if !verifyPassword(input.OldPassword) {
				c.JSON(401, gin.H{"error": "当前密码错误"})
				return
			}

			// 生成新密码的 bcrypt 哈希
			hash, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				c.JSON(500, gin.H{"error": "密码加密失败"})
				return
			}

			// 更新配置并持久化
			panelConfig.Auth.PasswordHash = string(hash)
			panelConfig.Auth.Password = ""
			if err := savePanelConfig(); err != nil {
				c.JSON(500, gin.H{"error": "保存配置失败: " + err.Error()})
				return
			}

			log.Printf("密码已修改 (来自 IP: %s)", c.ClientIP())
			c.JSON(200, gin.H{"message": "密码修改成功"})
		})
	}


	// --- 启动服务器 ---
	port := panelConfig.Server.Port
	if port == 0 {
		port = 3456
	}

	if panelConfig.HTTPS.Enabled && panelConfig.HTTPS.CertFile != "" && panelConfig.HTTPS.KeyFile != "" {
		log.Printf("面板运行在 HTTPS :%d\n", port)
		// HTTP → HTTPS 重定向 (监听 port+1，跳转到 port)
		go func() {
			httpPort := port + 1
			log.Printf("HTTP→HTTPS 重定向: :%d → :%d\n", httpPort, port)
			srv := &http.Server{
				Addr: fmt.Sprintf(":%d", httpPort),
				Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					host := req.Host
					// 去掉请求中的端口号
					if h, _, err := net.SplitHostPort(host); err == nil {
						host = h
					}
					target := fmt.Sprintf("https://%s:%d%s", host, port, req.URL.Path)
					if req.URL.RawQuery != "" {
						target += "?" + req.URL.RawQuery
					}
					http.Redirect(w, req, target, http.StatusMovedPermanently)
				}),
			}
			srv.ListenAndServe()
		}()
		if err := r.RunTLS(fmt.Sprintf(":%d", port), panelConfig.HTTPS.CertFile, panelConfig.HTTPS.KeyFile); err != nil {
			log.Fatalf("HTTPS 启动失败: %v", err)
		}
	} else {
		if panelConfig.HTTPS.Enabled {
			log.Println("警告: HTTPS 已启用但证书未配置，回退 HTTP")
		}
		log.Printf("面板运行在 HTTP :%d\n", port)
		r.Run(fmt.Sprintf(":%d", port))
	}
}
