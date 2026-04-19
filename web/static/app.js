// ============================================================
//  nftables 转发管理面板 - 前端逻辑（含流量监控 + 节点总览）
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    // --- DOM 引用 ---
    const rulesBody = document.getElementById('rulesBody');
    const ruleCount = document.getElementById('ruleCount');
    const statusBadge = document.getElementById('statusBadge');
    const statusText = document.getElementById('statusText');
    const pageInfo = document.getElementById('pageInfo');
    const pageSizeSelect = document.getElementById('pageSizeSelect');
    const toggleV4 = document.getElementById('toggleV4');
    const toggleV6 = document.getElementById('toggleV6');
    const ipv6Notice = document.getElementById('ipv6Notice');
    const addrLabel = document.getElementById('addrLabel');
    const remoteAddrInput = document.getElementById('remoteAddr');
    const editModal = document.getElementById('editModal');
    const passwordModal = document.getElementById('passwordModal');

    let currentPage = 1;
    let pageSize = 10;
    let totalRules = 0;
    let allRules = [];
    let selectedProto = 'ipv4'; // 当前选中的协议

    // --- 工具函数 ---
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const k = 1024;
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + units[i];
    }

    // --- IPv4/IPv6 协议切换 ---
    function setProtocol(proto) {
        selectedProto = proto;
        if (proto === 'ipv4') {
            toggleV4.className = 'toggle-btn active-v4';
            toggleV6.className = 'toggle-btn';
            ipv6Notice.classList.remove('show');
            addrLabel.textContent = '目标 IPv4 地址';
            remoteAddrInput.placeholder = '如: 6.6.6.6 或 1.2.3.4';
        } else {
            toggleV4.className = 'toggle-btn';
            toggleV6.className = 'toggle-btn active-v6';
            ipv6Notice.classList.add('show');
            addrLabel.textContent = '目标 IPv6 地址';
            remoteAddrInput.placeholder = '如: 2001:db8::1 (自动添加方括号)';
        }
    }
    toggleV4.addEventListener('click', () => setProtocol('ipv4'));
    toggleV6.addEventListener('click', () => setProtocol('ipv6'));

    // --- Toast 通知 ---
    function showToast(message, type = 'info') {
        const existing = document.querySelector('.toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3500);
    }

    // --- 服务状态 ---
    async function updateStatus() {
        try {
            const res = await fetch('/api/service/status');
            if (!res.ok) throw new Error();
            const data = await res.json();

            if (data.status === '运行中') {
                statusBadge.className = 'status-badge running';
                statusText.textContent = '运行中';
            } else {
                statusBadge.className = 'status-badge stopped';
                statusText.textContent = '已停止';
            }
        } catch {
            statusBadge.className = 'status-badge stopped';
            statusText.textContent = '未知';
        }
    }

    // --- 规则列表 ---
    async function fetchRules() {
        try {
            const res = await fetch(`/api/rules?page=${currentPage}&size=${pageSize}`, {
                headers: { 'Cache-Control': 'no-cache' }
            });
            if (!res.ok) throw new Error('获取失败');
            const data = await res.json();

            totalRules = data.total || 0;
            allRules = Array.isArray(data.rules) ? data.rules : [];
            ruleCount.textContent = `共 ${totalRules} 条`;
            renderRules();
        } catch (e) {
            rulesBody.innerHTML = '<tr class="empty-row"><td colspan="10">获取规则失败</td></tr>';
        }
    }

    function isIPv6(addr) {
        return addr && addr.includes(':') && !addr.match(/^\d+\.\d+\.\d+\.\d+$/);
    }

    function renderRules() {
        if (allRules.length === 0) {
            rulesBody.innerHTML = '<tr class="empty-row"><td colspan="10">暂无转发规则</td></tr>';
            updatePagination();
            return;
        }

        rulesBody.innerHTML = allRules.map((rule, idx) => {
            const globalIdx = (currentPage - 1) * pageSize + idx + 1;
            const addr = rule.remote_addr || '';
            const v6 = isIPv6(addr);
            const tag = v6
                ? '<span class="ip-tag v6">IPv6</span>'
                : '<span class="ip-tag v4">IPv4</span>';
            const note = rule.note || '-';
            const suspended = rule.enabled === false;
            const rowClass = suspended ? 'rule-suspended' : '';

            // 流量进度条
            let trafficHtml = '';
            const usedBytes = rule.used_bytes || 0;
            const quotaGB = rule.quota_gb || 0;
            const resetDay = rule.reset_day || 0;
            const resetInfo = resetDay > 0 ? `每月${resetDay}号重置` : '';
            if (quotaGB > 0) {
                const quotaBytes = quotaGB * 1024 * 1024 * 1024;
                const pct = Math.min(100, (usedBytes / quotaBytes) * 100);
                const barColor = pct >= 100 ? 'red' : pct >= 80 ? 'yellow' : 'green';
                const textClass = pct >= 100 ? 'exceeded' : '';
                trafficHtml = `
                    <div class="traffic-cell">
                        <div class="traffic-text ${textClass}">${formatBytes(usedBytes)} / ${quotaGB} GB</div>
                        <div class="traffic-bar"><div class="traffic-bar-fill ${barColor}" style="width:${pct.toFixed(1)}%"></div></div>
                        ${resetInfo ? `<div style="font-size:11px;color:var(--text-muted);margin-top:2px">${resetInfo}</div>` : ''}
                    </div>`;
            } else {
                trafficHtml = `<div class="traffic-text">${formatBytes(usedBytes)} / 不限</div>`;
            }

            // 状态标签
            const statusTag = suspended
                ? '<span class="status-tag suspended">已封停</span>'
                : '<span class="status-tag active">正常</span>';

            // 操作按钮（增加重置按钮）
            let actionsHtml = `
                <button class="btn btn-outline btn-sm" data-action="edit" data-id="${rule.id}" data-addr="${addr}" data-port="${rule.remote_port}" data-note="${rule.note || ''}" data-quota="${quotaGB}">编辑</button>
                <button class="btn btn-danger btn-sm" data-action="delete" data-id="${rule.id}">删除</button>`;
            if (quotaGB > 0) {
                actionsHtml += `<button class="btn btn-warning btn-sm" data-action="reset" data-id="${rule.id}" title="清零流量并恢复转发">重置</button>`;
            }

            return `<tr class="${rowClass}">
                <td>${globalIdx}</td>
                <td><strong>${rule.local_port}</strong></td>
                <td>${tag}</td>
                <td>${addr}</td>
                <td>${rule.remote_port}</td>
                <td>TCP + UDP</td>
                <td>${trafficHtml}</td>
                <td>${statusTag}</td>
                <td style="color:var(--text-secondary);font-size:13px;max-width:120px;overflow:hidden;text-overflow:ellipsis" title="${note}">${note}</td>
                <td>${actionsHtml}</td>
            </tr>`;
        }).join('');

        updatePagination();
    }

    function updatePagination() {
        const totalPages = Math.max(1, Math.ceil(totalRules / pageSize));
        pageInfo.textContent = `第 ${currentPage} / ${totalPages} 页`;
        document.getElementById('prevPage').disabled = currentPage <= 1;
        document.getElementById('nextPage').disabled = currentPage >= totalPages;
    }

    // --- 事件委托：规则表格操作按钮 ---
    rulesBody.addEventListener('click', async (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;

        const action = btn.dataset.action;
        const id = btn.dataset.id;

        if (action === 'delete') {
            if (!confirm('确定删除此转发规则？')) return;
            try {
                const res = await fetch(`/api/rules/${id}`, { method: 'DELETE' });
                if (!res.ok) {
                    const d = await res.json();
                    throw new Error(d.error || '删除失败');
                }
                showToast('规则已删除', 'success');
                await fetchRules();
                await updateStatus();
            } catch (err) {
                showToast(err.message, 'error');
            }
        }

        if (action === 'edit') {
            // 打开编辑模态框，填充当前值
            document.getElementById('editRuleId').value = id;
            document.getElementById('editRemoteAddr').value = btn.dataset.addr || '';
            document.getElementById('editRemotePort').value = btn.dataset.port || '';
            document.getElementById('editRuleNote').value = btn.dataset.note || '';
            editModal.classList.add('show');
        }

        if (action === 'reset') {
            if (!confirm('确定清零该端口的已用流量并恢复转发？')) return;
            try {
                const res = await fetch(`/api/rules/${id}/reset`, { method: 'POST' });
                if (!res.ok) {
                    const d = await res.json();
                    throw new Error(d.error || '重置失败');
                }
                showToast('流量已重置', 'success');
                await fetchRules();
            } catch (err) {
                showToast(err.message, 'error');
            }
        }
    });

    // --- 编辑模态框：关闭 ---
    document.getElementById('editCancelBtn').addEventListener('click', () => {
        editModal.classList.remove('show');
    });
    editModal.addEventListener('click', (e) => {
        // 点击遮罩层关闭
        if (e.target === editModal) editModal.classList.remove('show');
    });

    // --- 编辑模态框：保存 ---
    document.getElementById('editSaveBtn').addEventListener('click', async () => {
        const id = document.getElementById('editRuleId').value;
        const remoteAddr = document.getElementById('editRemoteAddr').value.trim();
        const remotePort = document.getElementById('editRemotePort').value.trim();
        const note = document.getElementById('editRuleNote').value.trim();

        if (!remoteAddr || !remotePort) {
            showToast('目标地址和端口不能为空', 'error');
            return;
        }

        try {
            const res = await fetch(`/api/rules/${id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    remote_addr: remoteAddr,
                    remote_port: remotePort,
                    note: note
                })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || '更新失败');

            showToast('规则已更新', 'success');
            editModal.classList.remove('show');
            await fetchRules();
            await updateStatus();
        } catch (err) {
            showToast(err.message, 'error');
        }
    });

    // --- 添加单条规则 ---
    document.getElementById('addRuleBtn').addEventListener('click', async () => {
        const lp = document.getElementById('localPort').value.trim();
        let ra = document.getElementById('remoteAddr').value.trim();
        const rp = document.getElementById('remotePort').value.trim();
        const note = document.getElementById('ruleNote').value.trim();
        const quota = parseFloat(document.getElementById('ruleQuota').value) || 0;
        const resetDay = parseInt(document.getElementById('ruleResetDay').value) || 0;

        if (!lp || !ra || !rp) {
            showToast('请填写所有必填字段', 'error');
            return;
        }

        // IPv6 地址自动包裹方括号
        if (selectedProto === 'ipv6' && !ra.startsWith('[')) {
            ra = `[${ra}]`;
        }

        try {
            const res = await fetch('/api/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    local_port: lp,
                    remote_addr: ra,
                    remote_port: rp,
                    note: note,
                    quota_gb: quota,
                    reset_day: resetDay
                })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || '添加失败');

            showToast(`${selectedProto.toUpperCase()} 规则已添加`, 'success');
            document.getElementById('localPort').value = '';
            document.getElementById('remoteAddr').value = '';
            document.getElementById('remotePort').value = '';
            document.getElementById('ruleNote').value = '';
            document.getElementById('ruleQuota').value = '';
            document.getElementById('ruleResetDay').value = '';
            await fetchRules();
            await updateStatus();
        } catch (e) {
            showToast(e.message, 'error');
        }
    });

    // --- 批量添加 ---
    document.getElementById('batchAddBtn').addEventListener('click', async () => {
        const text = document.getElementById('batchRules').value.trim();
        if (!text) {
            showToast('请输入规则', 'error');
            return;
        }

        const lines = text.split('\n').filter(Boolean);
        const parsedRules = [];

        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;

            // 匹配: 端口:[IPv6]:端口 或 端口:IPv4:端口
            const ipv6Match = trimmed.match(/^(\d+):\[([^\]]+)\]:(\d+)$/);
            const ipv4Match = trimmed.match(/^(\d+):([^:\[\]]+):(\d+)$/);

            if (ipv6Match) {
                parsedRules.push({
                    local_port: ipv6Match[1],
                    remote_addr: `[${ipv6Match[2]}]`,
                    remote_port: ipv6Match[3]
                });
            } else if (ipv4Match) {
                parsedRules.push({
                    local_port: ipv4Match[1],
                    remote_addr: ipv4Match[2],
                    remote_port: ipv4Match[3]
                });
            } else {
                showToast(`格式错误: ${trimmed}`, 'error');
                return;
            }
        }

        if (parsedRules.length === 0) {
            showToast('未解析到有效规则', 'error');
            return;
        }

        try {
            const res = await fetch('/api/rules/batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rules: parsedRules })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || '批量添加失败');

            let msg = `成功添加 ${data.added} 条规则`;
            if (data.failed && data.failed.length > 0) {
                msg += `，${data.failed.length} 条失败`;
            }
            showToast(msg, data.added > 0 ? 'success' : 'error');
            document.getElementById('batchRules').value = '';
            await fetchRules();
            await updateStatus();
        } catch (e) {
            showToast(e.message, 'error');
        }
    });

    // --- 服务控制 ---
    async function serviceAction(action, label) {
        try {
            const res = await fetch(`/api/service/${action}`, { method: 'POST' });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || `${label}失败`);
            showToast(data.message || `${label}成功`, 'success');
            await updateStatus();
        } catch (e) {
            showToast(e.message, 'error');
        }
    }

    document.getElementById('startBtn').addEventListener('click', () => serviceAction('start', '启动'));
    document.getElementById('stopBtn').addEventListener('click', () => serviceAction('stop', '停止'));
    document.getElementById('restartBtn').addEventListener('click', () => serviceAction('restart', '重启'));

    // --- 登出 ---
    document.getElementById('logoutBtn').addEventListener('click', async () => {
        try {
            await fetch('/logout', { method: 'POST' });
            window.location.href = '/login';
        } catch {
            window.location.href = '/login';
        }
    });

    // --- 修改密码 ---
    const changePasswordBtn = document.getElementById('changePasswordBtn');
    const pwdCancelBtn = document.getElementById('pwdCancelBtn');
    const pwdSaveBtn = document.getElementById('pwdSaveBtn');

    // 打开修改密码弹窗
    changePasswordBtn.addEventListener('click', () => {
        document.getElementById('oldPassword').value = '';
        document.getElementById('newPassword').value = '';
        document.getElementById('confirmPassword').value = '';
        passwordModal.classList.add('show');
    });

    // 关闭修改密码弹窗
    pwdCancelBtn.addEventListener('click', () => {
        passwordModal.classList.remove('show');
    });
    passwordModal.addEventListener('click', (e) => {
        if (e.target === passwordModal) passwordModal.classList.remove('show');
    });

    // 提交修改密码
    pwdSaveBtn.addEventListener('click', async () => {
        const oldPwd = document.getElementById('oldPassword').value.trim();
        const newPwd = document.getElementById('newPassword').value.trim();
        const confirmPwd = document.getElementById('confirmPassword').value.trim();

        if (!oldPwd || !newPwd || !confirmPwd) {
            showToast('请填写所有密码字段', 'error');
            return;
        }
        if (newPwd !== confirmPwd) {
            showToast('两次输入的新密码不一致', 'error');
            return;
        }
        if (newPwd.length < 4) {
            showToast('新密码至少 4 个字符', 'error');
            return;
        }

        pwdSaveBtn.disabled = true;
        pwdSaveBtn.textContent = '修改中...';

        try {
            const res = await fetch('/api/password', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    old_password: oldPwd,
                    new_password: newPwd
                })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || '修改失败');

            showToast('密码修改成功', 'success');
            passwordModal.classList.remove('show');
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            pwdSaveBtn.disabled = false;
            pwdSaveBtn.textContent = '确认修改';
        }
    });

    // --- 分页 ---
    document.getElementById('prevPage').addEventListener('click', () => {
        if (currentPage > 1) { currentPage--; fetchRules(); }
    });
    document.getElementById('nextPage').addEventListener('click', () => {
        const totalPages = Math.ceil(totalRules / pageSize);
        if (currentPage < totalPages) { currentPage++; fetchRules(); }
    });
    pageSizeSelect.addEventListener('change', () => {
        pageSize = parseInt(pageSizeSelect.value, 10);
        currentPage = 1;
        fetchRules();
    });

    // --- 节点查看（本地代理） ---
    const nodesContainer = document.getElementById('nodesContainer');

    async function fetchNodes() {
        try {
            const res = await fetch('/api/nodes');
            if (!res.ok) throw new Error('获取失败');
            const data = await res.json();
            renderNodes(data.nodes || []);
        } catch (e) {
            nodesContainer.innerHTML = '<div class="nodes-empty">获取节点信息失败</div>';
        }
    }

    function renderNodes(nodes) {
        if (nodes.length === 0) {
            nodesContainer.innerHTML = '<div class="nodes-empty">暂无已部署节点（可通过脚本菜单安装 Xray Reality 或 Shadowsocks）</div>';
            return;
        }

        nodesContainer.innerHTML = nodes.map(node => {
            const statusClass = node.status === '运行中' ? 'running' : 'stopped';
            let infoRows = '';
            let icon = '';

            if (node.type === 'Xray Reality') {
                icon = '<svg class="icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>';
                infoRows = `
                    <span class="label">协议</span><span class="value">VLESS + Reality</span>
                    <span class="label">地址</span><span class="value">${node.address || '-'}</span>
                    <span class="label">端口</span><span class="value">${node.port || '-'}</span>
                    <span class="label">UUID</span><span class="value">${node.uuid || '-'}</span>
                    <span class="label">流控</span><span class="value">${node.flow || '-'}</span>
                    <span class="label">传输</span><span class="value">${node.network || '-'}</span>
                    <span class="label">安全</span><span class="value">${node.security || '-'}</span>
                    <span class="label">SNI</span><span class="value">${node.sni || '-'}</span>
                    <span class="label">公钥</span><span class="value">${node.public_key || '-'}</span>
                    <span class="label">Short ID</span><span class="value">${node.short_id || '-'}</span>
                `;
            } else if (node.type === 'Shadowsocks') {
                icon = '<svg class="icon-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path></svg>';
                infoRows = `
                    <span class="label">协议</span><span class="value">Shadowsocks</span>
                    <span class="label">地址</span><span class="value">${node.address || '-'}</span>
                    <span class="label">端口</span><span class="value">${node.port || '-'}</span>
                    <span class="label">密码</span><span class="value">${node.password || '-'}</span>
                    <span class="label">加密方式</span><span class="value">${node.method || '-'}</span>
                `;
            }

            const linkHtml = node.link
                ? `<div class="node-link" data-link="${encodeURIComponent(node.link)}" title="点击复制链接">
                       ${node.link}
                       <span class="copy-hint">点击复制</span>
                   </div>`
                : '';

            return `<div class="node-card">
                <div class="node-header">
                    <div class="node-type">${icon} ${node.type}</div>
                    <span class="node-status ${statusClass}">${node.status}</span>
                </div>
                <div class="node-info">${infoRows}</div>
                ${linkHtml}
            </div>`;
        }).join('');

        // 点击复制链接
        nodesContainer.querySelectorAll('.node-link').forEach(el => {
            el.addEventListener('click', () => {
                const link = decodeURIComponent(el.dataset.link);
                navigator.clipboard.writeText(link).then(() => {
                    showToast('连接链接已复制', 'success');
                }).catch(() => {
                    // fallback
                    const ta = document.createElement('textarea');
                    ta.value = link;
                    document.body.appendChild(ta);
                    ta.select();
                    document.execCommand('copy');
                    document.body.removeChild(ta);
                    showToast('连接链接已复制', 'success');
                });
            });
        });
    }

    document.getElementById('refreshNodesBtn').addEventListener('click', () => {
        nodesContainer.innerHTML = '<div class="nodes-empty">刷新中...</div>';
        fetchNodes();
    });

    // --- 节点总览（主控大盘） ---
    const overviewCard = document.getElementById('overviewCard');
    const overviewBody = document.getElementById('overviewBody');

    async function fetchOverview() {
        try {
            const res = await fetch('/api/nodes/overview');
            if (!res.ok) throw new Error('获取失败');
            const data = await res.json();
            const nodes = data.nodes || [];
            if (nodes.length === 0) {
                // 没有配置远程被控节点，则隐藏总览板块
                overviewCard.hidden = true;
                return;
            }
            overviewCard.hidden = false;
            renderOverview(nodes);
        } catch (e) {
            // 如果接口报错，静默隐藏
            overviewCard.hidden = true;
        }
    }

    function renderOverview(nodes) {
        overviewBody.innerHTML = nodes.map((node, idx) => {
            const onlineClass = node.online ? 'on' : 'off';
            const onlineText = node.online ? '在线' : '离线';
            const rulesCount = (node.rules || []).length;
            const totalUsed = (node.rules || []).reduce((s, r) => s + (r.used_bytes || 0), 0);
            const totalQuota = (node.rules || []).reduce((s, r) => s + (r.quota_gb || 0), 0);
            const quotaText = totalQuota > 0 ? `${totalQuota} GB` : '不限';
            const lastSeen = node.last_seen ? new Date(node.last_seen).toLocaleTimeString() : '-';
            const rowStyle = node.online ? '' : 'style="color:var(--danger); opacity:0.7"';

            return `<tr data-node-idx="${idx}" ${rowStyle}>
                <td><strong>${node.name || node.hostname || node.url}</strong></td>
                <td><span class="online-dot ${onlineClass}"></span>${onlineText}</td>
                <td>${rulesCount}</td>
                <td>${formatBytes(totalUsed)}</td>
                <td>${quotaText}</td>
                <td>${lastSeen}</td>
            </tr>`;
        }).join('');

        // 点击展开节点明细
        overviewBody.querySelectorAll('tr[data-node-idx]').forEach(tr => {
            tr.addEventListener('click', () => {
                const idx = parseInt(tr.dataset.nodeIdx);
                const existing = tr.nextElementSibling;
                if (existing && existing.classList.contains('node-detail-row')) {
                    existing.remove();
                    return;
                }
                const node = nodes[idx];
                const rules = node.rules || [];
                if (rules.length === 0) return;

                const detailHtml = `<tr class="node-detail-row"><td colspan="6">
                    <div class="node-detail-content">
                        <table>
                            <tr><th>端口</th><th>目标</th><th>已用</th><th>配额</th><th>状态</th></tr>
                            ${rules.map(r => {
                                const statusText = r.enabled === false ? '<span class="status-tag suspended">封停</span>' : '<span class="status-tag active">正常</span>';
                                const quota = r.quota_gb > 0 ? `${r.quota_gb} GB` : '不限';
                                return `<tr>
                                    <td>${r.local_port}</td>
                                    <td>${r.remote_addr}:${r.remote_port}</td>
                                    <td>${formatBytes(r.used_bytes || 0)}</td>
                                    <td>${quota}</td>
                                    <td>${statusText}</td>
                                </tr>`;
                            }).join('')}
                        </table>
                    </div>
                </td></tr>`;
                tr.insertAdjacentHTML('afterend', detailHtml);
            });
        });
    }

    const refreshOverviewBtn = document.getElementById('refreshOverviewBtn');
    if (refreshOverviewBtn) {
        refreshOverviewBtn.addEventListener('click', () => {
            overviewBody.innerHTML = '<tr><td colspan="6" class="overview-empty">刷新中...</td></tr>';
            fetchOverview();
        });
    }

    // --- 节点管理 CRUD ---
    const nodeManageList = document.getElementById('nodeManageList');

    async function fetchNodeManage() {
        try {
            const res = await fetch('/api/nodes/manage');
            if (!res.ok) throw new Error('获取失败');
            const data = await res.json();
            renderNodeManage(data.nodes || []);
            // 有节点就显示总览卡片
            if (data.nodes && data.nodes.length > 0) {
                overviewCard.hidden = false;
            }
        } catch (e) {
            nodeManageList.innerHTML = '<div style="color:var(--text-muted);font-size:13px">获取节点列表失败</div>';
        }
    }

    function renderNodeManage(nodes) {
        if (nodes.length === 0) {
            nodeManageList.innerHTML = '<div style="color:var(--text-muted);font-size:13px">未配置监控节点，在下方添加被控服务器</div>';
            return;
        }
        nodeManageList.innerHTML = nodes.map((n, idx) => {
            return `<div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--border)">
                <strong style="flex:1;font-size:13px">${n.name}</strong>
                <span style="flex:2;font-size:12px;color:var(--text-secondary);font-family:monospace">${n.url}</span>
                <span style="flex:1;font-size:12px;color:var(--text-muted);font-family:monospace;overflow:hidden;text-overflow:ellipsis" title="${n.token}">${n.token.substring(0,12)}...</span>
                <button class="btn btn-danger btn-sm" data-del-node="${idx}">删除</button>
            </div>`;
        }).join('');

        nodeManageList.querySelectorAll('[data-del-node]').forEach(btn => {
            btn.addEventListener('click', async () => {
                const idx = btn.dataset.delNode;
                if (!confirm('确定删除此监控节点？')) return;
                try {
                    const res = await fetch(`/api/nodes/manage/${idx}`, { method: 'DELETE' });
                    if (!res.ok) {
                        const d = await res.json();
                        throw new Error(d.error || '删除失败');
                    }
                    showToast('节点已删除', 'success');
                    fetchNodeManage();
                    fetchOverview();
                } catch (err) {
                    showToast(err.message, 'error');
                }
            });
        });
    }

    document.getElementById('addNodeBtn').addEventListener('click', async () => {
        const name = document.getElementById('nodeManageName').value.trim();
        const url = document.getElementById('nodeManageURL').value.trim();
        const token = document.getElementById('nodeManageToken').value.trim();
        if (!name || !url || !token) {
            showToast('节点名称、地址和 Token 不能为空', 'error');
            return;
        }
        try {
            const res = await fetch('/api/nodes/manage', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, url, token })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || '添加失败');
            showToast('节点已添加', 'success');
            document.getElementById('nodeManageName').value = '';
            document.getElementById('nodeManageURL').value = '';
            document.getElementById('nodeManageToken').value = '';
            fetchNodeManage();
            // 60秒后自动拉取总览
            setTimeout(fetchOverview, 2000);
        } catch (e) {
            showToast(e.message, 'error');
        }
    });

    // --- 初始化 ---
    fetchRules();
    updateStatus();
    fetchNodes();
    fetchOverview();
    fetchNodeManage();

    // 定时刷新状态与流量
    setInterval(updateStatus, 15000);
    setInterval(fetchRules, 60000);    // 每60秒刷新规则（含流量数据）
    setInterval(fetchOverview, 60000); // 每60秒刷新节点总览
});
