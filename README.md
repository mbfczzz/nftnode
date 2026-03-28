# nftables 一键端口转发脚本 & 可视化管理面板

基于 **nftables** 的一键端口转发解决方案，支持 IPv4/IPv6 双栈，适用于 Debian 12+ 等使用 nftables 的 Linux 发行版。

## ✨ 功能特点

- 🚀 **内核级转发** — 使用 nftables NAT，零额外进程，性能极佳
- 🌐 **IPv4/IPv6 双栈** — 使用 `inet` 表同时支持 IPv4 和 IPv6 转发
- 🖥️ **可视化面板** — 现代暗色主题 Web 管理界面，单二进制部署（go:embed）
- 📦 **批量操作** — 支持批量导入转发规则
- 🔒 **安全认证** — bcrypt 密码哈希 + 随机 Session Secret + HTTPS 支持
- 🛡️ **安全隔离** — 仅操作 `inet nft_forward` 表，不影响其他防火墙规则

## 📋 流量走向

```
客户端 --> A服务器(中转) --> B/C 服务器(落地) --> 目标网站 --> 返回客户端
```

## 🔧 一键安装

```bash
curl -L https://raw.githubusercontent.com/wsuming97/nftnode/main/nft-forward.sh -o nft-forward.sh && chmod +x nft-forward.sh && ./nft-forward.sh
```

## 📖 使用说明

### 脚本界面

```
################################################################
#    nftables 一键端口转发脚本 (v1.0.0)      #
################################################################
 nftables 状态: 运行中
 面板 状态:     未安装
----------------------------------------------------------------
  1. 安装 / 重置 nftables 转发
  2. 卸载转发配置
----------------------------------------------------------------
  3. 安装 Caddy HTTPS 代理
  4. 安装 Xray Reality
  5. 安装 Shadowsocks Rust
  6. 查看当前转发配置
----------------------------------------------------------------
  7. 启动 nftables
  8. 停止 nftables
  9. 重启 nftables
----------------------------------------------------------------
  10. 更新脚本
  11. 面板管理
  0. 退出脚本
################################################################
```

### 转发规则示例

| 中转端口 | 目标地址 | 目标端口 | 说明 |
|---|---|---|---|
| 2222 | 6.6.6.6 | 6666 | IPv4 转发 |
| 3333 | [2001:db8::1] | 7777 | IPv6 转发 |

### Web 面板

面板默认运行在 `http://服务器IP:8080`

配置文件路径：`/root/nft-forward/web/config.toml`

```toml
[auth]
# 首次运行后，明文 password 会自动加密为 bcrypt 哈希并清空 password 字段
password = "admin123"
password_hash = ""

[server]
port = 8080

[https]
enabled = false
cert_file = "./certificate/cert.pem"
key_file = "./certificate/private.key"

[session]
# 首次运行会自动生成 64 位随机安全密钥
secret = ""
```

## 🔐 安全建议

1. **修改默认密码** — 安装后立即修改面板密码
2. **启用 HTTPS** — 配置 SSL 证书后开启 HTTPS
3. **限制访问** — 建议通过防火墙限制面板端口的访问来源

## 📁 文件结构

```
nftables-forward/
├── nft-forward.sh              # 一键管理脚本
├── README.md                   # 项目说明
├── LICENSE                     # MIT 许可证
└── web/                        # Web 可视化面板
    ├── config.toml.example     # 面板配置模板（首次运行自动生成 config.toml）
    ├── go.mod                  # Go 依赖
    ├── main.go                 # Go 后端
    ├── templates/
    │   ├── index.html          # 管理页面
    │   └── login.html          # 登录页面
    └── static/
        └── app.js              # 前端逻辑
```

## 📝 生成的 nftables 配置

脚本会自动生成 `/etc/nftables.conf`（仅管理 `nft_forward` 表，不影响其他规则）：

```nft
#!/usr/sbin/nft -f

# 仅操作本项目创建的表
table inet nft_forward
delete table inet nft_forward

table inet nft_forward {
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        # Rule abc12345 (东京节点)
        tcp dport 2222 dnat ip to 6.6.6.6:6666
        udp dport 2222 dnat ip to 6.6.6.6:6666
    }

    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        ct status dnat masquerade
    }
}
```

## ⚙️ 系统要求

- Linux (Debian 12+ / Ubuntu 22.04+)
- root 权限
- nftables (`apt install nftables`)

## 📜 许可证

MIT License
