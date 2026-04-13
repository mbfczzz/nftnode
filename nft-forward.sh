#!/bin/bash
# ============================================================
#  nftables 一键端口转发脚本
#  版本: 1.0.0
#  基于 nftables inet 表，支持 IPv4/IPv6 双栈转发
# ============================================================

# --- 基础配置 ---
sh_ver="1.0.0"
panel_ver="v1.2"

# GitHub 仓库（修改为你的用户名/仓库名）
GITHUB_REPO="wsuming97/nftnode"

# 颜色定义
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
PLAIN="\033[0m"

# 路径定义
NFT_DIR="/root/.nft-forward"
RULES_FILE="${NFT_DIR}/rules.json"
NFT_CONF="/etc/nftables.conf"
PANEL_DIR="/root/nft-forward/web"
PANEL_BIN="${PANEL_DIR}/nft_panel"
PANEL_SERVICE="/etc/systemd/system/nft-panel.service"

# --- 状态检测函数 ---
get_nft_status() {
    if systemctl is-active --quiet nftables; then
        echo -e "${GREEN}运行中${PLAIN}"
    else
        echo -e "${RED}未运行${PLAIN}"
    fi
}

get_panel_status() {
    if [ ! -f "$PANEL_BIN" ]; then
        echo -e "${RED}未安装${PLAIN}"
    elif systemctl is-active --quiet nft-panel; then
        echo -e "${GREEN}运行中${PLAIN}"
    else
        echo -e "${YELLOW}已安装但未启动${PLAIN}"
    fi
}

# --- 核心校验函数 ---
validate_port() {
    local port=$1
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        echo -e "${RED}错误: 端口必须是 1-65535 之间的数字。${PLAIN}"
        return 1
    fi
}

validate_address() {
    local addr=$1
    if [[ -z "$addr" ]]; then
        echo -e "${RED}错误: 地址不能为空。${PLAIN}"
        return 1
    fi
    # 允许 IPv4、IPv6、域名
    if [[ "$addr" =~ ^[a-zA-Z0-9\.\:\-\[\]]+$ ]]; then
        return 0
    else
        echo -e "${RED}错误: 无效的 IP 或域名格式。${PLAIN}"
        return 1
    fi
}

is_ipv6() {
    local addr=$1
    if [[ "$addr" == *":"* ]]; then
        return 0
    fi
    return 1
}

# --- 依赖检测 ---
check_dependencies() {
    local deps=("nft" "curl" "systemctl" "sed" "grep" "jq")
    local missing=()
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then missing+=("$dep"); fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}安装依赖: ${missing[*]} ...${PLAIN}"
        if [ -x "$(command -v apt-get)" ]; then
            apt-get update -y >/dev/null 2>&1
            apt-get install -y nftables jq curl >/dev/null 2>&1
        elif [ -x "$(command -v yum)" ]; then
            yum install -y nftables jq curl >/dev/null 2>&1
        else
            echo -e "${RED}请手动安装依赖: ${missing[*]}${PLAIN}"; exit 1
        fi
    fi
}

# --- 初始化环境 ---
init_env() {
    mkdir -p "$NFT_DIR"
    mkdir -p "/root/nft-forward"

    # 创建空规则文件
    if [ ! -f "$RULES_FILE" ]; then
        echo '[]' > "$RULES_FILE"
    fi

    # 开启内核转发（使用独立 sysctl 文件，不污染系统配置）
    cat > /etc/sysctl.d/99-nft-forward.conf <<SYSEOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
SYSEOF
    sysctl --system >/dev/null 2>&1

    # 启用 nftables
    systemctl enable nftables >/dev/null 2>&1
}

# --- nftables 配置生成 ---
generate_nft_conf() {
    local rules_json
    rules_json=$(cat "$RULES_FILE")

    cat > "$NFT_CONF" <<'HEADER'
#!/usr/sbin/nft -f

# 仅操作本项目创建的表，不影响其他防火墙规则
table inet nft_forward
delete table inet nft_forward

table inet nft_forward {

    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
HEADER

    # 一次性提取所有规则字段，避免循环内多次 fork jq
    echo "$rules_json" | jq -r '.[] | [.local_port, .remote_addr, .remote_port, .id, (.note // "")] | @tsv' |
    while IFS=$'\t' read -r lport raddr rport rid rnote; do
        local note_comment=""
        [ -n "$rnote" ] && note_comment=" ($rnote)"

        # 判断 IPv4 还是 IPv6
        if is_ipv6 "$raddr"; then
            local clean_addr
            clean_addr=$(echo "$raddr" | tr -d '[]')
            echo "        # Rule: ${rid}${note_comment}" >> "$NFT_CONF"
            echo "        tcp dport ${lport} dnat ip6 to [${clean_addr}]:${rport}" >> "$NFT_CONF"
            echo "        udp dport ${lport} dnat ip6 to [${clean_addr}]:${rport}" >> "$NFT_CONF"
        else
            echo "        # Rule: ${rid}${note_comment}" >> "$NFT_CONF"
            echo "        tcp dport ${lport} dnat ip to ${raddr}:${rport}" >> "$NFT_CONF"
            echo "        udp dport ${lport} dnat ip to ${raddr}:${rport}" >> "$NFT_CONF"
        fi
    done

    cat >> "$NFT_CONF" <<'FOOTER'
    }

    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        ct status dnat masquerade
    }
}
FOOTER

    echo -e "${GREEN}nftables 配置已生成${PLAIN}"
}

# 应用 nftables 规则
apply_rules() {
    generate_nft_conf
    if nft -f "$NFT_CONF" 2>/dev/null; then
        rm -f "${RULES_FILE}.bak"
    else
        echo -e "${RED}规则应用失败，正在回滚...${PLAIN}"
        if [ -f "${RULES_FILE}.bak" ]; then
            mv "${RULES_FILE}.bak" "$RULES_FILE"
            generate_nft_conf
            echo -e "${YELLOW}已还原转发规则配置${PLAIN}"
        fi
        return 1
    fi
}

# --- 安装 nftables ---
install_nftables() {
    echo -e "${GREEN}> 部署 nftables 转发环境...${PLAIN}"
    check_dependencies
    init_env
    apply_rules
    systemctl restart nftables
    echo -e "${GREEN}安装完成！nftables 端口转发环境已就绪。${PLAIN}"
}

# --- 卸载 ---
uninstall_nftables() {
    read -p "确定卸载 nftables 转发配置? [y/N]: " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return

    # 仅删除本项目创建的表
    nft delete table inet nft_forward 2>/dev/null

    # 备份原有 nftables 配置后再覆盖
    if [ -f "$NFT_CONF" ]; then
        cp "$NFT_CONF" "${NFT_CONF}.bak.$(date +%Y%m%d%H%M%S)"
        echo -e "${GREEN}已备份原配置: ${NFT_CONF}.bak.*${PLAIN}"
    fi
    cat > "$NFT_CONF" <<'EOF'
#!/usr/sbin/nft -f
# nft_forward 表已卸载
EOF

    # 清理 sysctl 配置
    rm -f /etc/sysctl.d/99-nft-forward.conf
    sysctl --system >/dev/null 2>&1

    read -p "删除转发规则配置? [y/N]: " del_conf
    [[ "$del_conf" == "y" || "$del_conf" == "Y" ]] && rm -rf "$NFT_DIR"
    echo -e "${GREEN}已卸载转发配置 (其他防火墙规则不受影响)${PLAIN}"
}

# --- 代理服务安装管理 ---

# 已知的代理服务列表（安装子脚本时保护这些服务不被意外停止）
PROXY_SERVICES=("xray" "shadowsocks")

run_proxy_script() {
    local script_name=$1
    local script_url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/${script_name}"

    # 记录当前正在运行的代理服务，用于子脚本结束后恢复
    local running_before=()
    for svc in "${PROXY_SERVICES[@]}"; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            running_before+=("$svc")
        fi
    done

    echo -e "${CYAN}正在下载并运行 ${script_name}...${PLAIN}"
    if curl -sL "$script_url" -o "/tmp/${script_name}"; then
        chmod +x "/tmp/${script_name}"
        bash "/tmp/${script_name}"
        rm -f "/tmp/${script_name}"
    else
        echo -e "${RED}下载 ${script_name} 失败，请检查网络或 GITHUB_REPO 配置。${PLAIN}"
        return
    fi

    # 恢复被意外停止的代理服务
    for svc in "${running_before[@]}"; do
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "${YELLOW}检测到 ${svc} 服务被意外停止，正在恢复...${PLAIN}"
            systemctl start "$svc" 2>/dev/null
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                echo -e "${GREEN}${svc} 服务已恢复${PLAIN}"
            else
                echo -e "${RED}${svc} 服务恢复失败，请手动检查: systemctl status ${svc}${PLAIN}"
            fi
        fi
    done
}

# --- 转发管理 ---
add_forward() {
    echo -e "${YELLOW}>>> 添加转发规则 (连续错误2次自动返回)${PLAIN}"

    # 1. 本机端口
    local attempt=0
    local lp
    while true; do
        read -e -p "本机端口: " lp
        if ! validate_port "$lp"; then
            ((attempt++)); [ $attempt -ge 2 ] && { echo -e "${RED}错误过多，返回主菜单${PLAIN}"; return; }
            continue
        fi
        # 检查端口是否已存在
        if jq -e ".[] | select(.local_port == \"$lp\")" "$RULES_FILE" >/dev/null 2>&1; then
            echo -e "${RED}错误: 端口 ${lp} 的规则已存在。${PLAIN}"
            ((attempt++)); [ $attempt -ge 2 ] && { echo -e "${RED}错误过多，返回主菜单${PLAIN}"; return; }
            continue
        fi
        break
    done

    # 2. 落地IP
    attempt=0
    local raddr
    while true; do
        read -e -p "落地IP/域名 (IPv6请用方括号如[::1]): " raddr
        if ! validate_address "$raddr"; then
            ((attempt++)); [ $attempt -ge 2 ] && { echo -e "${RED}错误过多，返回主菜单${PLAIN}"; return; }
            continue
        fi
        break
    done

    # 3. 落地端口
    attempt=0
    local rp
    while true; do
        read -e -p "落地端口: " rp
        if ! validate_port "$rp"; then
            ((attempt++)); [ $attempt -ge 2 ] && { echo -e "${RED}错误过多，返回主菜单${PLAIN}"; return; }
            continue
        fi
        break
    done

    # 备注
    local rnote
    read -e -p "备注 (可留空): " rnote

    # 生成唯一ID
    local rule_id
    rule_id=$(date +%s%N | md5sum | head -c 8)

    # 写入规则前备份
    cp "$RULES_FILE" "${RULES_FILE}.bak" 2>/dev/null
    local new_rule
    new_rule=$(jq -c ". + [{\"id\": \"${rule_id}\", \"local_port\": \"${lp}\", \"remote_addr\": \"${raddr}\", \"remote_port\": \"${rp}\", \"note\": \"${rnote}\"}]" "$RULES_FILE")
    echo "$new_rule" > "$RULES_FILE"

    if apply_rules; then
        echo -e "${GREEN}转发规则已添加: 0.0.0.0:${lp} -> ${raddr}:${rp} [${rnote:-无备注}]${PLAIN}"
    fi
}

add_range_forward() {
    echo -e "${YELLOW}>>> 端口段转发 (连续错误2次自动返回)${PLAIN}"
    local attempt=0

    local raddr sp ep rbp rnote
    while true; do read -e -p "落地IP/域名: " raddr; validate_address "$raddr" && break; ((attempt++)); [ $attempt -ge 2 ] && return; done
    attempt=0; while true; do read -e -p "起始端口: " sp; validate_port "$sp" && break; ((attempt++)); [ $attempt -ge 2 ] && return; done
    attempt=0; while true; do read -e -p "结束端口: " ep; validate_port "$ep" && break; ((attempt++)); [ $attempt -ge 2 ] && return; done
    attempt=0; while true; do read -e -p "落地基准端口: " rbp; validate_port "$rbp" && break; ((attempt++)); [ $attempt -ge 2 ] && return; done
    read -e -p "备注 (可留空): " rnote

    [ "$sp" -ge "$ep" ] && { echo -e "${RED}起始必须小于结束${PLAIN}"; return; }

    echo "生成规则中..."

    # 优化: 一次性读取已有规则的本机端口列表
    local existing_ports
    existing_ports=$(jq -r '.[].local_port' "$RULES_FILE" 2>/dev/null)

    # 优化: 在内存中构建所有新规则，最后一次性写入，避免每次都调用 jq
    local new_rules_json="["
    local rp=$rbp
    local skipped=0
    local first=1
    
    # 提前用 grep 加速检查
    for ((p=sp; p<=ep; p++)); do
        # 获取匹配当前端口的行
        if echo "$existing_ports" | grep -qx "$p"; then
            ((skipped++))
            ((rp++))
            continue
        fi
        
        local rule_id
        rule_id=$(echo "${p}${rp}${RANDOM}" | md5sum | head -c 8)
        
        # 组装 JSON 片段，不再循环内调用 jq
        if [ $first -eq 1 ]; then
            first=0
        else
            new_rules_json="${new_rules_json},"
        fi
        
        # 构建一条规则对象的 JSON 字符串
        new_rules_json="${new_rules_json}{\"id\": \"${rule_id}\", \"local_port\": \"${p}\", \"remote_addr\": \"${raddr}\", \"remote_port\": \"${rp}\", \"note\": \"${rnote}\"}"
        
        ((rp++))
    done
    new_rules_json="${new_rules_json}]"

    # 如果没有任何新规则被添加，则直接返回
    if [ "$new_rules_json" == "[]" ]; then
        echo -e "${YELLOW}所有指定的端口都已存在，未添加新规则。${PLAIN}"
        return
    fi

    # 合并新规则到现有规则（备份后写入）
    cp "$RULES_FILE" "${RULES_FILE}.bak" 2>/dev/null
    local merged
    merged=$(jq -s '.[0] + .[1]' "$RULES_FILE" <(echo "$new_rules_json"))
    echo "$merged" > "$RULES_FILE"

    if apply_rules; then
        local added=$(echo "$new_rules_json" | jq 'length')
        echo -e "${GREEN}端口段 ${sp}-${ep} 转发规则已添加 (${added} 条新增，${skipped} 条跳过)${PLAIN}"
    fi
}

delete_forward() {
    local rules_json
    rules_json=$(cat "$RULES_FILE")
    local count
    count=$(echo "$rules_json" | jq 'length')

    [ "$count" -eq 0 ] && { echo "无转发规则"; return; }

    echo "================================================================"
    printf "  ${CYAN}%-4s %-10s %-22s %-8s %-12s${PLAIN}\n" "序号" "本机端口" "目标地址" "目标端口" "备注"
    echo "----------------------------------------------------------------"
    local idx=0
    echo "$rules_json" | jq -r '.[] | [.local_port, .remote_addr, .remote_port, (.note // "-")] | @tsv' |
    while IFS=$'\t' read -r lp ra rp rn; do
        ((idx++))
        printf "  ${GREEN}%-4s${PLAIN} %-10s %-22s %-8s %-12s\n" "$idx" "$lp" "$ra" "$rp" "$rn"
    done
    echo "================================================================"

    read -p "删除序号 (0取消): " c
    [[ "$c" == "0" || -z "$c" ]] && return

    local del_idx=$((c-1))
    if [ "$del_idx" -ge 0 ] && [ "$del_idx" -lt "$count" ]; then
        cp "$RULES_FILE" "${RULES_FILE}.bak" 2>/dev/null
        local new_rules
        new_rules=$(echo "$rules_json" | jq "del(.[$del_idx])")
        echo "$new_rules" > "$RULES_FILE"
        if apply_rules; then
            echo -e "${GREEN}规则已删除${PLAIN}"
        fi
    else
        echo -e "${RED}无效的序号${PLAIN}"
    fi
}

view_rules() {
    local rules_json
    rules_json=$(cat "$RULES_FILE")
    local count
    count=$(echo "$rules_json" | jq 'length')

    if [ "$count" -eq 0 ]; then
        echo -e "${YELLOW}当前无转发规则${PLAIN}"
        return
    fi

    echo ""
    echo "================================================================"
    printf "  ${CYAN}%-4s %-10s %-22s %-8s %-12s${PLAIN}\n" "序号" "本机端口" "目标地址" "目标端口" "备注"
    echo "----------------------------------------------------------------"
    local idx=0
    echo "$rules_json" | jq -r '.[] | [.local_port, .remote_addr, .remote_port, (.note // "-")] | @tsv' |
    while IFS=$'\t' read -r lp ra rp rn; do
        ((idx++))
        printf "  ${GREEN}%-4s${PLAIN} %-10s %-22s %-8s %-12s\n" "$idx" "$lp" "$ra" "$rp" "$rn"
    done
    echo "================================================================"
    echo ""
    echo -e "${CYAN}当前 nftables 规则:${PLAIN}"
    nft list ruleset 2>/dev/null || echo -e "${RED}无法获取 nftables 规则${PLAIN}"
}

# --- 查看已部署节点 ---
view_nodes() {
    echo ""
    echo -e "${CYAN}================================================${PLAIN}"
    echo -e "${CYAN}          已部署节点信息${PLAIN}"
    echo -e "${CYAN}================================================${PLAIN}"
    echo ""

    local found=0

    # 检测 Xray Reality
    if [ -f "/usr/local/etc/xray/config.json" ]; then
        found=1
        local xray_status="${RED}未运行${PLAIN}"
        systemctl is-active --quiet xray 2>/dev/null && xray_status="${GREEN}运行中${PLAIN}"

        echo -e "  ${GREEN}[Xray Reality]${PLAIN}  状态: $xray_status"
        echo -e "  ────────────────────────────────────────"

        # 从服务端配置读取端口
        local port=$(jq -r '.inbounds[0].port // "N/A"' /usr/local/etc/xray/config.json 2>/dev/null)
        local uuid=$(jq -r '.inbounds[0].settings.clients[0].id // "N/A"' /usr/local/etc/xray/config.json 2>/dev/null)
        local sni=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0] // "N/A"' /usr/local/etc/xray/config.json 2>/dev/null)

        echo -e "  端口: ${YELLOW}${port}${PLAIN}"
        echo -e "  UUID: ${YELLOW}${uuid}${PLAIN}"
        echo -e "  SNI:  ${YELLOW}${sni}${PLAIN}"

        # 从客户端配置读取连接链接
        if [ -f "/usr/local/etc/xray/reclient.json" ]; then
            local link=$(jq -r '."连接链接" // empty' /usr/local/etc/xray/reclient.json 2>/dev/null)
            local pubkey=$(jq -r '."配置参数"."公钥" // empty' /usr/local/etc/xray/reclient.json 2>/dev/null)
            [ -n "$pubkey" ] && echo -e "  公钥: ${YELLOW}${pubkey}${PLAIN}"
            if [ -n "$link" ]; then
                echo ""
                echo -e "  ${GREEN}连接链接:${PLAIN}"
                echo -e "  ${YELLOW}${link}${PLAIN}"
            fi
        else
            echo -e "  ${RED}未找到客户端配置文件 (reclient.json)${PLAIN}"
        fi
        echo ""
    fi

    # 检测 Shadowsocks
    if [ -f "/etc/shadowsocks/config.json" ]; then
        found=1
        local ss_status="${RED}未运行${PLAIN}"
        systemctl is-active --quiet shadowsocks 2>/dev/null && ss_status="${GREEN}运行中${PLAIN}"

        echo -e "  ${GREEN}[Shadowsocks]${PLAIN}  状态: $ss_status"
        echo -e "  ────────────────────────────────────────"

        local ss_port=$(jq -r '.server_port // "N/A"' /etc/shadowsocks/config.json 2>/dev/null)
        local ss_pwd=$(jq -r '.password // "N/A"' /etc/shadowsocks/config.json 2>/dev/null)
        local ss_method=$(jq -r '.method // "N/A"' /etc/shadowsocks/config.json 2>/dev/null)

        echo -e "  端口:   ${YELLOW}${ss_port}${PLAIN}"
        echo -e "  密码:   ${YELLOW}${ss_pwd}${PLAIN}"
        echo -e "  加密:   ${YELLOW}${ss_method}${PLAIN}"

        # 获取服务器 IP 并生成 SS 链接
        local server_ip
        server_ip=$(curl -s --max-time 3 ip.sb 2>/dev/null)
        if [ -n "$server_ip" ]; then
            local ss_link="ss://$(echo -n "${ss_method}:${ss_pwd}@${server_ip}:${ss_port}" | base64 -w 0)"
            echo ""
            echo -e "  ${GREEN}连接链接:${PLAIN}"
            echo -e "  ${YELLOW}${ss_link}${PLAIN}"
        fi
        echo ""
    fi

    if [ $found -eq 0 ]; then
        echo -e "  ${YELLOW}暂无已部署节点（可通过菜单 4/5 安装 Xray Reality 或 Shadowsocks）${PLAIN}"
    fi

    echo -e "${CYAN}================================================${PLAIN}"
}

# --- 服务控制 ---
start_service() { systemctl start nftables && echo -e "${GREEN}nftables 已启动${PLAIN}" || echo -e "${RED}启动失败${PLAIN}"; }
stop_service() { systemctl stop nftables && echo -e "${GREEN}nftables 已停止${PLAIN}" || echo -e "${RED}停止失败${PLAIN}"; }
restart_service() {
    apply_rules
    systemctl restart nftables
    sleep 1
    if systemctl is-active --quiet nftables; then
        echo -e "${GREEN}nftables 重启成功${PLAIN}"
    else
        echo -e "${RED}nftables 重启失败${PLAIN}"
    fi
}

# --- 面板管理 ---
panel_management() {
    while true; do
        clear
        echo "=== nftables 面板管理 ($panel_ver) ==="
        echo -e "面板状态: $(get_panel_status)"
        echo "================================="
        echo "  1. 安装面板"
        echo "  2. 启动面板"
        echo "  3. 停止面板"
        echo "  4. 卸载面板"
        echo "  0. 返回上级"
        read -p "选择: " pc
        case $pc in
            1) install_panel ;;
            2) systemctl start nft-panel && echo "面板已启动" || echo "启动失败" ;;
            3) systemctl stop nft-panel && echo "面板已停止" ;;
            4) uninstall_panel ;;
            0) break ;;
            *) echo "无效选择" ;;
        esac
        read -p "按回车继续..."
    done
}

install_panel() {
    check_dependencies
    local arch=$(uname -m)
    local p_file=""
    case "$arch" in
        x86_64) p_file="nft-panel-linux-amd64.tar.gz" ;;
        aarch64|arm64) p_file="nft-panel-linux-arm64.tar.gz" ;;
        *) echo "不支持架构: $arch"; return ;;
    esac

    mkdir -p "$PANEL_DIR"

    # 注: 实际使用时需替换为你的 GitHub Releases 下载地址
    local url="https://github.com/${GITHUB_REPO}/releases/download/${panel_ver}/${p_file}"
    echo -e "${YELLOW}下载面板: ${url}${PLAIN}"
    if wget -O "/tmp/$p_file" "$url" 2>/dev/null || curl -L -o "/tmp/$p_file" "$url" 2>/dev/null; then
        tar -xzf "/tmp/$p_file" -C "$PANEL_DIR" && chmod +x "$PANEL_BIN" && rm -f "/tmp/$p_file"

        cat > "$PANEL_SERVICE" <<EOF
[Unit]
Description=nftables Forward Web Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${PANEL_DIR}
ExecStart=${PANEL_BIN}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable nft-panel
        systemctl start nft-panel
        echo -e "${GREEN}面板安装成功!${PLAIN}"
    else
        echo -e "${RED}下载失败，请检查网络或手动安装${PLAIN}"
    fi
}

uninstall_panel() {
    systemctl stop nft-panel 2>/dev/null
    systemctl disable nft-panel 2>/dev/null
    rm -f "$PANEL_SERVICE"
    systemctl daemon-reload
    rm -rf "$PANEL_DIR"
    echo -e "${GREEN}面板已卸载${PLAIN}"
}

# --- 脚本更新 ---
Update_Shell() {
    # 注: 实际使用时需替换为你的 GitHub raw 地址
    local url="https://raw.githubusercontent.com/${GITHUB_REPO}/main/nft-forward.sh"
    local new_ver
    new_ver=$(curl -sL "$url" | grep 'sh_ver="' | awk -F '=' '{print $NF}' | tr -d '"' | head -1)
    [[ -z "$new_ver" ]] && { echo -e "${RED}检测失败${PLAIN}"; return; }
    [[ "$new_ver" == "$sh_ver" ]] && { echo "已是最新版本 v${sh_ver}"; return; }
    read -p "更新到 v${new_ver}? [y/N]: " yn
    if [[ "$yn" =~ ^[Yy]$ ]]; then
        curl -sL "$url" -o nft-forward.sh && chmod +x nft-forward.sh
        echo -e "${GREEN}已更新到 v${new_ver}，请重新运行脚本${PLAIN}"
        exit 0
    fi
}

# --- 主菜单 ---
show_menu() {
    clear
    echo "################################################"
    echo "#    nftables 一键端口转发脚本 (v${sh_ver})      #"
    echo "################################################"
    echo -e " nftables 状态: $(get_nft_status)"
    echo -e " 面板 状态:     $(get_panel_status)"
    echo "------------------------------------------------"
    echo "  1. 安装 / 重置 nftables 转发"
    echo "  2. 卸载转发配置"
    echo "------------------------------------------------"
    echo "  3. 安装 Caddy HTTPS 代理"
    echo "  4. 安装 Xray Reality"
    echo "  5. 安装 Shadowsocks Rust"
    echo "  6. 查看当前转发配置"
    echo "  7. 查看已部署节点"
    echo "------------------------------------------------"
    echo "  8. 启动 nftables"
    echo "  9. 停止 nftables"
    echo "  10. 重启 nftables"
    echo "------------------------------------------------"
    echo "  11. 更新脚本"
    echo "  12. 面板管理"
    echo "  0. 退出脚本"
    echo "################################################"
}

main() {
    # 检查 root 权限
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误: 请以 root 用户运行此脚本${PLAIN}"
        exit 1
    fi

    check_dependencies
    init_env

    while true; do
        show_menu
        read -p "选择 [0-12]: " opt
        case $opt in
            1) install_nftables ;;
            2) uninstall_nftables ;;
            3) run_proxy_script "https.sh" ;;
            4) run_proxy_script "reality.sh" ;;
            5) run_proxy_script "ss-rust.sh" ;;
            6) view_rules ;;
            7) view_nodes ;;
            8) start_service ;;
            9) stop_service ;;
            10) restart_service ;;
            11) Update_Shell ;;
            12) panel_management ;;
            0) exit 0 ;;
            *) echo "无效选择" ;;
        esac
        [ "$opt" != "0" ] && read -p "按回车返回..."
    done
}

main
