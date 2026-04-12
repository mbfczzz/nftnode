#!/bin/bash
# ============================================================
#  nftables 端口转发诊断脚本
#  用法: bash diagnose.sh
#  在中转机上运行，自动检测转发链路各环节
# ============================================================

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
PLAIN="\033[0m"

pass() { echo -e "  ${GREEN}✔ $1${PLAIN}"; }
fail() { echo -e "  ${RED}✘ $1${PLAIN}"; }
warn() { echo -e "  ${YELLOW}⚠ $1${PLAIN}"; }
info() { echo -e "  ${CYAN}ℹ $1${PLAIN}"; }

RULES_FILE="/root/.nft-forward/rules.json"

echo ""
echo "================================================"
echo "   nftables 端口转发诊断工具"
echo "================================================"
echo ""

# ========== 1. 基础环境 ==========
echo -e "${CYAN}[1/7] 基础环境检测${PLAIN}"

# Root 权限
if [ "$(id -u)" == "0" ]; then
    pass "Root 权限"
else
    fail "未使用 Root 权限运行，部分检测可能不准确"
fi

# 系统版本
if [ -f /etc/os-release ]; then
    . /etc/os-release
    info "系统: $PRETTY_NAME"
fi

# ========== 2. 内核转发 ==========
echo ""
echo -e "${CYAN}[2/7] 内核转发检测${PLAIN}"

ipv4_fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
ipv6_fwd=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)

if [ "$ipv4_fwd" == "1" ]; then
    pass "IPv4 转发已开启 (net.ipv4.ip_forward = 1)"
else
    fail "IPv4 转发未开启 (net.ipv4.ip_forward = ${ipv4_fwd:-未知})"
    echo -e "    ${YELLOW}修复: echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-nft-forward.conf && sysctl --system${PLAIN}"
fi

if [ "$ipv6_fwd" == "1" ]; then
    pass "IPv6 转发已开启"
else
    warn "IPv6 转发未开启 (如无 IPv6 规则可忽略)"
fi

# ========== 3. nftables 服务状态 ==========
echo ""
echo -e "${CYAN}[3/7] nftables 服务状态${PLAIN}"

if systemctl is-active --quiet nftables 2>/dev/null; then
    pass "nftables 服务运行中"
else
    fail "nftables 服务未运行"
    echo -e "    ${YELLOW}修复: systemctl start nftables${PLAIN}"
fi

# 检查 nft_forward 表是否存在
if nft list table inet nft_forward &>/dev/null; then
    pass "nft_forward 表已加载"
    
    # 检查链是否存在
    if nft list chain inet nft_forward prerouting &>/dev/null; then
        pass "prerouting 链存在"
    else
        fail "prerouting 链不存在"
    fi
    
    if nft list chain inet nft_forward postrouting &>/dev/null; then
        pass "postrouting 链存在"
    else
        fail "postrouting 链不存在"
    fi
else
    fail "nft_forward 表未加载，规则可能未生效"
    echo -e "    ${YELLOW}修复: nft -f /etc/nftables.conf${PLAIN}"
fi

# ========== 4. 规则匹配检测 ==========
echo ""
echo -e "${CYAN}[4/7] 转发规则检测${PLAIN}"

if [ -f "$RULES_FILE" ]; then
    rule_count=$(jq 'length' "$RULES_FILE" 2>/dev/null)
    if [ "$rule_count" -gt 0 ] 2>/dev/null; then
        pass "规则文件存在，共 ${rule_count} 条规则"
    else
        warn "规则文件存在但无规则"
    fi
else
    fail "规则文件不存在: $RULES_FILE"
fi

# 显示 nftables 实际加载的 DNAT 规则数量
nft_rules=$(nft list chain inet nft_forward prerouting 2>/dev/null | grep -c "dnat")
info "nftables 中实际加载的 DNAT 规则: ${nft_rules} 条"

if [ "$rule_count" -gt 0 ] 2>/dev/null && [ "$nft_rules" -eq 0 ] 2>/dev/null; then
    fail "规则文件有规则但 nftables 未加载，需要重新应用"
    echo -e "    ${YELLOW}修复: nft -f /etc/nftables.conf${PLAIN}"
fi

# ========== 5. 本机端口监听/占用检测 ==========
echo ""
echo -e "${CYAN}[5/7] 端口占用检测${PLAIN}"

if [ -f "$RULES_FILE" ] && command -v jq &>/dev/null; then
    jq -r '.[].local_port' "$RULES_FILE" 2>/dev/null | while read -r lport; do
        # 检查是否有其他进程占用了这个端口（NAT转发不需要监听，但如果有进程监听了就会冲突）
        occupied=$(ss -tlnp 2>/dev/null | grep ":${lport} " | head -1)
        if [ -n "$occupied" ]; then
            proc_name=$(echo "$occupied" | grep -oP 'users:\(\("\K[^"]+')
            fail "端口 ${lport} 被进程 [${proc_name:-未知}] 占用，可能导致转发失败"
        else
            pass "端口 ${lport} 无进程占用 (正常，NAT 转发不需要监听)"
        fi
    done
fi

# ========== 6. 落地机连通性测试 ==========
echo ""
echo -e "${CYAN}[6/7] 落地机连通性测试${PLAIN}"

if [ -f "$RULES_FILE" ] && command -v jq &>/dev/null; then
    # 提取唯一的 远程地址:端口 组合
    jq -r '.[] | "\(.remote_addr)|\(.remote_port)|\(.local_port)"' "$RULES_FILE" 2>/dev/null | while IFS='|' read -r raddr rport lport; do
        # 清理 IPv6 方括号
        clean_addr=$(echo "$raddr" | tr -d '[]')
        
        echo -e "  ${CYAN}--- 规则: 本机:${lport} → ${raddr}:${rport} ---${PLAIN}"
        
        # Ping 测试
        if ping -c 1 -W 3 "$clean_addr" &>/dev/null; then
            pass "Ping ${clean_addr} 成功"
        else
            warn "Ping ${clean_addr} 失败 (可能禁 ping，不一定影响转发)"
        fi
        
        # TCP 端口测试（关键！）
        if command -v nc &>/dev/null; then
            if nc -z -w 5 "$clean_addr" "$rport" 2>/dev/null; then
                pass "TCP 连接 ${clean_addr}:${rport} 成功"
            else
                fail "TCP 连接 ${clean_addr}:${rport} 失败 ← 落地机端口可能未开放或被防火墙拦截"
            fi
        elif command -v bash &>/dev/null; then
            # 用 bash /dev/tcp 替代
            if timeout 5 bash -c "echo >/dev/tcp/${clean_addr}/${rport}" 2>/dev/null; then
                pass "TCP 连接 ${clean_addr}:${rport} 成功"
            else
                fail "TCP 连接 ${clean_addr}:${rport} 失败 ← 落地机端口可能未开放"
            fi
        else
            warn "无 nc 或 bash，跳过 TCP 端口测试"
        fi
        
        # MTR/Traceroute (简略，只显示跳数)
        if command -v traceroute &>/dev/null; then
            hops=$(traceroute -n -m 15 -w 2 "$clean_addr" 2>/dev/null | tail -1 | awk '{print $1}')
            info "到 ${clean_addr} 的路由跳数: ${hops:-未知}"
        fi
    done
else
    warn "无法读取规则文件，跳过连通性测试"
fi

# ========== 7. 防火墙 / 其他拦截检测 ==========
echo ""
echo -e "${CYAN}[7/7] 防火墙与其他拦截检测${PLAIN}"

# 检查是否有 iptables 规则可能冲突
ipt_rules=$(iptables -L -n 2>/dev/null | grep -c "DROP\|REJECT" || echo "0")
if [ "$ipt_rules" -gt 0 ]; then
    warn "iptables 中有 ${ipt_rules} 条 DROP/REJECT 规则，可能与 nftables 冲突"
    echo -e "    ${YELLOW}查看: iptables -L -n --line-numbers${PLAIN}"
else
    pass "iptables 无 DROP/REJECT 规则"
fi

# 检查是否有其他 nftables 表的拦截规则
other_drop=$(nft list ruleset 2>/dev/null | grep -v "nft_forward" | grep -c "drop\|reject" || echo "0")
if [ "$other_drop" -gt 0 ]; then
    warn "其他 nftables 表中有 ${other_drop} 条 drop/reject 规则，可能拦截转发流量"
    echo -e "    ${YELLOW}查看: nft list ruleset${PLAIN}"
else
    pass "其他 nftables 表无拦截规则"
fi

# 检查 firewalld
if systemctl is-active --quiet firewalld 2>/dev/null; then
    warn "firewalld 正在运行，可能与 nftables 规则冲突"
    echo -e "    ${YELLOW}建议: systemctl stop firewalld && systemctl disable firewalld${PLAIN}"
else
    pass "firewalld 未运行"
fi

# 检查 ufw
if systemctl is-active --quiet ufw 2>/dev/null; then
    warn "ufw 正在运行，可能与 nftables 规则冲突"
    echo -e "    ${YELLOW}建议: ufw disable${PLAIN}"
else
    pass "ufw 未运行"
fi

# ========== 汇总 ==========
echo ""
echo "================================================"
echo -e "${CYAN}诊断完成${PLAIN}"
echo "================================================"
echo ""
echo "常见问题排查优先级："
echo "  1. 内核转发是否开启 (ip_forward)"
echo "  2. 落地机端口是否开放 (TCP 连接测试)"
echo "  3. 中转机本机端口是否被其他进程占用"
echo "  4. 是否有 iptables / firewalld / ufw 拦截"
echo "  5. 落地机防火墙是否放行对应端口"
echo ""
