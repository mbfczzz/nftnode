package main

import (
	"bytes"
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
	ID         string `json:"id"`
	LocalPort  string `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort string `json:"remote_port"`
	Note       string `json:"note"`
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

// 防止 nftables 配置注入：只允许安全字符
func sanitizeForNft(s string) string {
	safe := regexp.MustCompile(`[^a-zA-Z0-9\.\:\[\]\-\_]`)
	return safe.ReplaceAllString(s, "")
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
	buf.WriteString(fmt.Sprintf("secret = \"%s\"\n", panelConfig.Session.Secret))

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
	return json.Unmarshal(data, &rules)
}

// 调用方必须持有 mu 锁
func saveRulesLocked() error {
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(panelConfig.Nftables.RulesPath, data, 0644)
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

	for _, rule := range rules {
		// 安全: 经过校验的值再额外做一次 sanitize
		lport := sanitizeForNft(rule.LocalPort)
		rport := sanitizeForNft(rule.RemotePort)
		addr := sanitizeForNft(strings.Trim(rule.RemoteAddr, "[]"))

		noteComment := ""
		if rule.Note != "" {
			// 注释里也做 sanitize 防止换行注入
			noteComment = fmt.Sprintf(" (%s)", sanitizeForNft(rule.Note))
		}

		if isIPv6(rule.RemoteAddr) {
			buf.WriteString(fmt.Sprintf("        # Rule %s%s\n", rule.ID, noteComment))
			buf.WriteString(fmt.Sprintf("        tcp dport %s dnat to [%s]:%s\n", lport, addr, rport))
			buf.WriteString(fmt.Sprintf("        udp dport %s dnat to [%s]:%s\n", lport, addr, rport))
		} else {
			buf.WriteString(fmt.Sprintf("        # Rule %s%s\n", rule.ID, noteComment))
			buf.WriteString(fmt.Sprintf("        tcp dport %s dnat to %s:%s\n", lport, addr, rport))
			buf.WriteString(fmt.Sprintf("        udp dport %s dnat to %s:%s\n", lport, addr, rport))
		}
		buf.WriteString("\n")
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

			c.JSON(200, gin.H{
				"rules": rules[start:end],
				"total": total,
			})
		})

		// 添加单条规则
		api.POST("/api/rules", func(c *gin.Context) {
			var input struct {
				LocalPort  string `json:"local_port"`
				RemoteAddr string `json:"remote_addr"`
				RemotePort string `json:"remote_port"`
				Note       string `json:"note"`
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
				Note:       input.Note,
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

		// 编辑规则（修改目标地址、目标端口、备注，不允许修改本机端口）
		api.PUT("/api/rules/:id", func(c *gin.Context) {
			id := c.Param("id")
			var input struct {
				RemoteAddr string `json:"remote_addr"`
				RemotePort string `json:"remote_port"`
				Note       string `json:"note"`
			}
			if err := c.ShouldBindJSON(&input); err != nil {
				c.JSON(400, gin.H{"error": "无效输入"})
				return
			}

			// 校验字段（允许部分更新：只校验非空字段）
			if input.RemotePort != "" && !validatePort(input.RemotePort) {
				c.JSON(400, gin.H{"error": "目标端口无效 (1-65535)"})
				return
			}
			if input.RemoteAddr != "" && !validateAddress(input.RemoteAddr) {
				c.JSON(400, gin.H{"error": "目标地址无效，请输入合法的 IPv4/IPv6/域名"})
				return
			}

			mu.Lock()
			defer mu.Unlock()

			backup := snapshotRules()
			found := false
			for i, r := range rules {
				if r.ID == id {
					if input.RemoteAddr != "" {
						rules[i].RemoteAddr = input.RemoteAddr
					}
					if input.RemotePort != "" {
						rules[i].RemotePort = input.RemotePort
					}
					// 备注允许清空，所以始终更新
					rules[i].Note = input.Note
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
	}

	// --- 启动服务器 ---
	port := panelConfig.Server.Port
	if port == 0 {
		port = 8080
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
