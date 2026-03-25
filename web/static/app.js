// ============================================================
//  nftables 转发管理面板 - 前端逻辑
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

    let currentPage = 1;
    let pageSize = 10;
    let totalRules = 0;
    let allRules = [];
    let selectedProto = 'ipv4'; // 当前选中的协议

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
            rulesBody.innerHTML = '<tr class="empty-row"><td colspan="8">获取规则失败</td></tr>';
        }
    }

    function isIPv6(addr) {
        return addr && addr.includes(':') && !addr.match(/^\d+\.\d+\.\d+\.\d+$/);
    }

    function renderRules() {
        if (allRules.length === 0) {
            rulesBody.innerHTML = '<tr class="empty-row"><td colspan="8">暂无转发规则</td></tr>';
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

            return `<tr>
                <td>${globalIdx}</td>
                <td><strong>${rule.local_port}</strong></td>
                <td>${tag}</td>
                <td>${addr}</td>
                <td>${rule.remote_port}</td>
                <td>TCP + UDP</td>
                <td style="color:var(--text-secondary);font-size:13px;max-width:120px;overflow:hidden;text-overflow:ellipsis" title="${note}">${note}</td>
                <td>
                    <button class="btn btn-outline btn-sm" data-action="edit" data-id="${rule.id}" data-addr="${addr}" data-port="${rule.remote_port}" data-note="${rule.note || ''}">编辑</button>
                    <button class="btn btn-danger btn-sm" data-action="delete" data-id="${rule.id}">删除</button>
                </td>
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
                    note: note
                })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || '添加失败');

            showToast(`${selectedProto.toUpperCase()} 规则已添加`, 'success');
            document.getElementById('localPort').value = '';
            document.getElementById('remoteAddr').value = '';
            document.getElementById('remotePort').value = '';
            document.getElementById('ruleNote').value = '';
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

    // --- 初始化 ---
    fetchRules();
    updateStatus();

    // 定时刷新状态
    setInterval(updateStatus, 15000);
});
