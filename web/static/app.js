// ============================================================
//  nftables 转发管理面板 - 前端逻辑（含流量监控 + 节点总览）
// ============================================================

document.addEventListener('DOMContentLoaded', () => {

    // ============================================================
    //  i18n 国际化系统 — 中英双语切换
    // ============================================================
    const I18N = {
        zh: {
            // Header
            'header.title': 'nftables 转发管理',
            'header.logout': '退出',
            // Service
            'svc.start': '启动', 'svc.stop': '停止', 'svc.restart': '重启',
            // Buttons
            'btn.cancel': '取消', 'btn.save': '保存',
            // Rules
            'rules.title': '转发规则列表',
            'rules.localPort': '本机端口', 'rules.ipType': 'IP类型',
            'rules.targetAddr': '目标地址', 'rules.targetPort': '目标端口',
            'rules.protocol': '协议', 'rules.traffic': '流量 / 配额',
            'rules.status': '状态', 'rules.note': '备注', 'rules.actions': '操作',
            // Pagination
            'page.prev': '上一页', 'page.next': '下一页',
            // Add rule
            'add.title': '添加转发规则',
            'add.localPort': '本机端口', 'add.targetPort': '目标端口',
            'add.note': '备注（可选）', 'add.quota': '月配额 GB（可选）',
            'add.resetDay': '重置日（可选）', 'add.submit': '添加规则',
            // 备用线路 / 多线路
            'backup.sectionLabel': '备用线路（可选，主线路不通时按顺序自动切换，恢复后自动切回）',
            'backup.add': '添加备用线路', 'backup.addrPh': '备用地址 IPv4/IPv6/域名', 'backup.portPh': '端口',
            'line.primary': '主', 'line.backupN': '备{n}',
            'test.btn': '测试', 'test.testing': '测试中…', 'test.fail': '不通', 'test.ok': '通',
            // Batch
            'batch.title': '批量添加转发规则', 'batch.submit': '批量添加',
            // Edit modal
            'edit.title': '编辑转发规则',
            // Password modal
            'pwd.title': '修改密码', 'pwd.confirm': '确认修改',
            // Status / dynamic
            'status.running': '运行中', 'status.stopped': '已停止', 'status.checking': '检测中...',
            'status.active': '正常', 'status.suspended': '已封停',
            'status.unreachable': '不通', 'status.checkingShort': '检测中',
            'status.exceeded': '已超额',
            'status.onBackupN': '备{n}线路', 'status.allDown': '全部不通',
            // Toast messages
            'toast.addOk': '{proto} 规则已添加', 'toast.editOk': '规则已更新',
            'toast.deleteOk': '规则已删除', 'toast.resetOk': '流量已重置',
            'toast.batchOk': '成功添加 {n} 条规则', 'toast.batchPartial': '成功添加 {n} 条规则，{f} 条失败',
            'toast.startOk': '服务已启动', 'toast.stopOk': '服务已停止',
            'toast.restartOk': '服务已重启',
            'toast.pwdOk': '密码修改成功',
            'toast.pwdMismatch': '两次输入的新密码不一致',
            'toast.pwdShort': '新密码至少 4 个字符',
            'toast.pwdEmpty': '请填写所有密码字段',
            'toast.editEmpty': '本机端口、目标地址和端口不能为空',
            'toast.addEmpty': '请填写所有必填字段',
            'toast.batchEmpty': '请输入规则',
            'toast.batchFormat': '格式错误: {line}',
            'toast.batchNone': '未解析到有效规则',
            'toast.confirmDelete': '确定删除此转发规则？',
            'toast.confirmReset': '确定清零该端口的已用流量并恢复转发？',
            // Table misc
            'rules.total': '共 {n} 条',
            'rules.empty': '暂无转发规则',
            'rules.fetchFail': '获取规则失败',
            'rules.edit': '编辑', 'rules.delete': '删除', 'rules.reset': '重置',
            'page.info': '第 {cur} / {total} 页',
            'traffic.unlimited': '不限', 'traffic.unlimitedQuota': '不限额',
            // Status text
            'status.unknown': '未知',
            'pwd.changing': '修改中...',
            // IPv4/IPv6 切换
            'proto.v4Label': '目标 IPv4 地址', 'proto.v4Ph': '如: 6.6.6.6 或 1.2.3.4',
            'proto.v6Label': '目标 IPv6 地址', 'proto.v6Ph': '如: 2001:db8::1 (自动添加方括号)',
        },
        en: {
            'header.title': 'nftables Forward Manager',
            'header.logout': 'Logout',
            'svc.start': 'Start', 'svc.stop': 'Stop', 'svc.restart': 'Restart',
            'btn.cancel': 'Cancel', 'btn.save': 'Save',
            'rules.title': 'Forward Rules',
            'rules.localPort': 'Local Port', 'rules.ipType': 'IP Type',
            'rules.targetAddr': 'Target Addr', 'rules.targetPort': 'Target Port',
            'rules.protocol': 'Protocol', 'rules.traffic': 'Traffic / Quota',
            'rules.status': 'Status', 'rules.note': 'Note', 'rules.actions': 'Actions',
            'page.prev': 'Prev', 'page.next': 'Next',
            'add.title': 'Add Forward Rule',
            'add.localPort': 'Local Port', 'add.targetPort': 'Target Port',
            'add.note': 'Note (optional)', 'add.quota': 'Monthly Quota GB (optional)',
            'add.resetDay': 'Reset Day (optional)', 'add.submit': 'Add Rule',
            'backup.sectionLabel': 'Backup lines (optional, auto-failover in order, auto switch back on recovery)',
            'backup.add': 'Add Backup Line', 'backup.addrPh': 'Backup addr IPv4/IPv6/domain', 'backup.portPh': 'Port',
            'line.primary': 'Primary', 'line.backupN': 'Backup{n}',
            'test.btn': 'Test', 'test.testing': 'Testing…', 'test.fail': 'Failed', 'test.ok': 'OK',
            'batch.title': 'Batch Add Rules', 'batch.submit': 'Batch Add',
            'edit.title': 'Edit Forward Rule',
            'pwd.title': 'Change Password', 'pwd.confirm': 'Confirm',
            'status.running': 'Running', 'status.stopped': 'Stopped', 'status.checking': 'Checking...',
            'status.active': 'Active', 'status.suspended': 'Suspended',
            'status.unreachable': 'Unreachable', 'status.checkingShort': 'Checking',
            'status.exceeded': 'Exceeded',
            'status.onBackupN': 'Backup{n}', 'status.allDown': 'All down',
            'toast.addOk': '{proto} rule added', 'toast.editOk': 'Rule updated',
            'toast.deleteOk': 'Rule deleted', 'toast.resetOk': 'Traffic reset',
            'toast.batchOk': '{n} rules added', 'toast.batchPartial': '{n} added, {f} failed',
            'toast.startOk': 'Service started', 'toast.stopOk': 'Service stopped',
            'toast.restartOk': 'Service restarted',
            'toast.pwdOk': 'Password changed',
            'toast.pwdMismatch': 'New passwords do not match',
            'toast.pwdShort': 'New password must be at least 4 characters',
            'toast.pwdEmpty': 'Please fill in all password fields',
            'toast.editEmpty': 'Local port, target address and port are required',
            'toast.addEmpty': 'Please fill in all required fields',
            'toast.batchEmpty': 'Please enter rules',
            'toast.batchFormat': 'Format error: {line}',
            'toast.batchNone': 'No valid rules parsed',
            'toast.confirmDelete': 'Delete this forward rule?',
            'toast.confirmReset': 'Reset traffic and resume forwarding?',
            'rules.total': '{n} rules',
            'rules.empty': 'No forward rules',
            'rules.fetchFail': 'Failed to load rules',
            'rules.edit': 'Edit', 'rules.delete': 'Delete', 'rules.reset': 'Reset',
            'page.info': 'Page {cur} / {total}',
            'traffic.unlimited': 'Unlimited', 'traffic.unlimitedQuota': 'Unlimited',
            'status.unknown': 'Unknown',
            'pwd.changing': 'Saving...',
            'proto.v4Label': 'Target IPv4 Address', 'proto.v4Ph': 'e.g. 6.6.6.6 or 1.2.3.4',
            'proto.v6Label': 'Target IPv6 Address', 'proto.v6Ph': 'e.g. 2001:db8::1 (brackets added automatically)',
        }
    };

    // 当前语言，从 localStorage 读取，默认中文
    let currentLang = localStorage.getItem('nft_lang') || 'zh';

    // 翻译函数：按 key 获取当前语言文字，支持 {var} 占位符
    function t(key, vars) {
        let text = (I18N[currentLang] && I18N[currentLang][key]) || (I18N.zh[key]) || key;
        if (vars) {
            Object.keys(vars).forEach(k => {
                text = text.replace('{' + k + '}', vars[k]);
            });
        }
        return text;
    }

    // 应用翻译到所有 data-i18n 元素
    function applyI18n() {
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            const translated = t(key);
            if (translated !== key) {
                el.textContent = translated;
            }
        });
        // 更新语言切换按钮文字
        const langBtn = document.getElementById('langToggleBtn');
        if (langBtn) {
            langBtn.textContent = currentLang === 'zh' ? 'EN' : '中文';
        }
    }

    // 切换语言
    function toggleLang() {
        currentLang = currentLang === 'zh' ? 'en' : 'zh';
        localStorage.setItem('nft_lang', currentLang);
        applyI18n();
        // 刷新动态内容
        renderRules();
        updateStatus();
        ruleCount.textContent = t('rules.total', {n: totalRules});
        setProtocol(selectedProto);
    }

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
            addrLabel.textContent = t('proto.v4Label');
            remoteAddrInput.placeholder = t('proto.v4Ph');
        } else {
            toggleV4.className = 'toggle-btn';
            toggleV6.className = 'toggle-btn active-v6';
            ipv6Notice.classList.add('show');
            addrLabel.textContent = t('proto.v6Label');
            remoteAddrInput.placeholder = t('proto.v6Ph');
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
                statusText.textContent = t('status.running');
            } else {
                statusBadge.className = 'status-badge stopped';
                statusText.textContent = t('status.stopped');
            }

        } catch {
            statusBadge.className = 'status-badge stopped';
            statusText.textContent = t('status.unknown');
        }
    }

    // --- 规则列表 ---
    async function fetchRules() {
        try {
            const res = await fetch(`/api/rules?page=${currentPage}&size=${pageSize}`, {
                headers: { 'Cache-Control': 'no-cache' }
            });
            if (!res.ok) throw new Error('fetch failed');
            const data = await res.json();

            totalRules = data.total || 0;
            allRules = Array.isArray(data.rules) ? data.rules : [];
            ruleCount.textContent = t('rules.total', {n: totalRules});
            renderRules();
        } catch (e) {
            rulesBody.innerHTML = `<tr class="empty-row"><td colspan="10">${t('rules.fetchFail')}</td></tr>`;
        }
    }

    function isIPv6(addr) {
        return addr && addr.includes(':') && !addr.match(/^\d+\.\d+\.\d+\.\d+$/);
    }

    // ---- 备用线路：动态行管理 ----
    function escAttr(s) {
        return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
    }
    // 重新编号容器内所有备用行的序号标签（备1、备2…）
    function renumberBackups(containerId) {
        const rows = document.querySelectorAll(`#${containerId} .backup-row`);
        rows.forEach((r, i) => {
            const idx = r.querySelector('.backup-idx');
            if (idx) idx.textContent = t('line.backupN', {n: i + 1});
        });
    }
    function addBackupRow(containerId, addr = '', port = '') {
        const container = document.getElementById(containerId);
        if (!container) return;
        const row = document.createElement('div');
        row.className = 'backup-row';
        row.innerHTML =
            `<span class="backup-idx"></span>` +
            `<input type="text" class="backup-addr" placeholder="${escAttr(t('backup.addrPh'))}" value="${escAttr(addr)}">` +
            `<input type="number" class="backup-port" placeholder="${escAttr(t('backup.portPh'))}" min="1" max="65535" value="${escAttr(port)}">` +
            `<button type="button" class="btn-test backup-test">${escAttr(t('test.btn'))}</button>` +
            `<button type="button" class="btn btn-danger btn-sm backup-remove" title="删除">✕</button>` +
            `<span class="test-result backup-test-result"></span>`;
        const addrI = row.querySelector('.backup-addr');
        const portI = row.querySelector('.backup-port');
        const resEl = row.querySelector('.backup-test-result');
        row.querySelector('.backup-test').addEventListener('click', (e) => {
            let a = addrI.value.trim();
            if (a.includes(':') && !a.startsWith('[')) a = `[${a}]`;
            doTest(a, portI.value, resEl, e.currentTarget);
        });
        row.querySelector('.backup-remove').addEventListener('click', () => {
            row.remove();
            renumberBackups(containerId);
        });
        container.appendChild(row);
        renumberBackups(containerId);
    }
    // 收集容器内的备用线路为数组 [{addr, port}]，跳过完全空行，IPv6 自动加方括号
    function collectBackups(containerId) {
        const out = [];
        document.querySelectorAll(`#${containerId} .backup-row`).forEach(r => {
            let addr = r.querySelector('.backup-addr').value.trim();
            const port = r.querySelector('.backup-port').value.trim();
            if (!addr && !port) return;
            if (addr.includes(':') && !addr.startsWith('[')) addr = `[${addr}]`;
            out.push({addr, port});
        });
        return out;
    }

    const addBackupBtn = document.getElementById('addBackupBtn');
    if (addBackupBtn) addBackupBtn.addEventListener('click', () => addBackupRow('backupList'));
    const editAddBackupBtn = document.getElementById('editAddBackupBtn');
    if (editAddBackupBtn) editAddBackupBtn.addEventListener('click', () => addBackupRow('editBackupList'));

    // ---- 即时测试落地连通性 ----
    async function doTest(addr, port, resultEl, btnEl) {
        if (!resultEl) return;
        addr = (addr || '').trim();
        port = (port || '').trim();
        if (!addr || !port) {
            resultEl.className = 'test-result fail';
            resultEl.textContent = '✗ ' + (currentLang === 'zh' ? '请填地址和端口' : 'addr & port required');
            return;
        }
        resultEl.className = 'test-result testing';
        resultEl.textContent = t('test.testing');
        resultEl.title = '';
        if (btnEl) btnEl.disabled = true;
        try {
            const res = await fetch('/api/test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({addr, port})
            });
            const d = await res.json();
            if (!res.ok) throw new Error(d.error || 'test failed');
            if (d.ok) {
                resultEl.className = 'test-result ok';
                resultEl.textContent = `✓ ${d.latency_ms}ms` + (d.resolved_ip ? ` · ${d.resolved_ip}` : '');
                resultEl.title = '';
            } else {
                resultEl.className = 'test-result fail';
                resultEl.textContent = '✗ ' + t('test.fail');
                resultEl.title = d.error || '';
            }
        } catch (e) {
            resultEl.className = 'test-result fail';
            resultEl.textContent = '✗ ' + t('test.fail');
            resultEl.title = e.message;
        } finally {
            if (btnEl) btnEl.disabled = false;
        }
    }

    // 主目标地址的测试按钮（添加表单 / 编辑模态框）
    function wireMainTest(btnId, addrId, portId, resultId) {
        const btn = document.getElementById(btnId);
        if (!btn) return;
        btn.addEventListener('click', (e) => {
            let a = document.getElementById(addrId).value.trim();
            if (a.includes(':') && !a.startsWith('[')) a = `[${a}]`;
            doTest(a, document.getElementById(portId).value, document.getElementById(resultId), e.currentTarget);
        });
    }
    wireMainTest('testMainBtn', 'remoteAddr', 'remotePort', 'testMainResult');
    wireMainTest('editTestMainBtn', 'editRemoteAddr', 'editRemotePort', 'editTestMainResult');

    function renderRules() {
        if (allRules.length === 0) {
            rulesBody.innerHTML = `<tr class="empty-row"><td colspan="10">${t('rules.empty')}</td></tr>`;
            updatePagination();
            return;
        }

        rulesBody.innerHTML = allRules.map((rule, idx) => {
            const globalIdx = (currentPage - 1) * pageSize + idx + 1;
            const addr = rule.remote_addr || '';
            const backups = Array.isArray(rule.backups) ? rule.backups : [];
            const activeLine = rule.active_line || 0;
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
            const resetInfo = resetDay > 0 ? (currentLang === 'zh' ? `每月${resetDay}号重置` : `Resets on day ${resetDay}`) : '';
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
                trafficHtml = `<div class="traffic-text">${formatBytes(usedBytes)} / ${t('traffic.unlimited')}</div>`;
            }

            // 状态标签（三态：已封停/不通/正常）
            let statusTag;
            if (suspended) {
                statusTag = `<span class="status-tag suspended">${t('status.suspended')}</span>`;
            } else if (rule.reachable === false) {
                statusTag = `<span class="status-tag unreachable">${t('status.unreachable')}</span>`;
            } else if (rule.reachable === true) {
                statusTag = `<span class="status-tag active">${t('status.active')}</span>`;
            } else {
                statusTag = `<span class="status-tag checking">${t('status.checkingShort')}</span>`;
            }
            // 已切到备用线路时追加醒目徽标
            if (!suspended && activeLine > 0) {
                statusTag += `<span class="status-tag" style="background:#fef3c7;color:#92400e;margin-left:4px">${t('status.onBackupN', {n: activeLine})}</span>`;
            }

            // 线路列表：主 + 各备用，每条带状态点（🟢通/🔴断/⚪检测中）、标签、测试按钮，当前生效线路高亮 ◀
            const lines = [{label: t('line.primary'), a: addr, p: rule.remote_port, up: rule.primary_up}]
                .concat(backups.map((b, i) => ({label: t('line.backupN', {n: i + 1}), a: b.addr, p: b.port, up: b.up})));
            const dotOf = (up) => up === true ? '🟢' : up === false ? '🔴' : '⚪';
            const addrCell = `<div class="line-list">` + lines.map((ln, i) => {
                const active = i === activeLine;
                return `<div class="line-item ${active ? 'active' : 'inactive'}">` +
                    `<span class="line-dot">${dotOf(ln.up)}</span>` +
                    `<span class="line-tag">${ln.label}</span>` +
                    `<span class="line-addr">${ln.a}:${ln.p}</span>` +
                    (active ? `<span class="line-active-mark">◀</span>` : '') +
                    `<button class="btn-test" data-action="test-line" data-addr="${escAttr(ln.a)}" data-port="${escAttr(ln.p)}">${t('test.btn')}</button>` +
                    `<span class="test-result"></span>` +
                `</div>`;
            }).join('') + `</div>`;
            // 目标端口列：显示当前生效线路的端口
            const activePort = (lines[activeLine] || lines[0]).p;

            // 操作按钮（增加重置按钮）；备用线路通过 allRules 查找填充，无需 data 属性
            let actionsHtml = `
                <button class="btn btn-outline btn-sm" data-action="edit" data-id="${rule.id}" data-localport="${rule.local_port}" data-addr="${addr}" data-port="${rule.remote_port}" data-note="${rule.note || ''}" data-quota="${quotaGB}" data-resetday="${resetDay}">${t('rules.edit')}</button>
                <button class="btn btn-danger btn-sm" data-action="delete" data-id="${rule.id}">${t('rules.delete')}</button>`;
            if (quotaGB > 0) {
                actionsHtml += `<button class="btn btn-warning btn-sm" data-action="reset" data-id="${rule.id}">${t('rules.reset')}</button>`;
            }

            return `<tr class="${rowClass}">
                <td>${globalIdx}</td>
                <td><strong>${rule.local_port}</strong></td>
                <td>${tag}</td>
                <td>${addrCell}</td>
                <td>${activePort}</td>
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
        pageInfo.textContent = t('page.info', {cur: currentPage, total: totalPages});
        document.getElementById('prevPage').disabled = currentPage <= 1;
        document.getElementById('nextPage').disabled = currentPage >= totalPages;
    }

    // --- 事件委托：规则表格操作按钮 ---
    rulesBody.addEventListener('click', async (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;

        const action = btn.dataset.action;
        const id = btn.dataset.id;

        if (action === 'test-line') {
            const li = btn.closest('.line-item');
            const resultEl = li ? li.querySelector('.test-result') : null;
            doTest(btn.dataset.addr, btn.dataset.port, resultEl, btn);
            return;
        }

        if (action === 'delete') {
            if (!confirm(t('toast.confirmDelete'))) return;
            try {
                const res = await fetch(`/api/rules/${id}`, { method: 'DELETE' });
                if (!res.ok) {
                    const d = await res.json();
                    throw new Error(d.error || 'Delete failed');
                }
                showToast(t('toast.deleteOk'), 'success');
                await fetchRules();
                await updateStatus();
            } catch (err) {
                showToast(err.message, 'error');
            }
        }

        if (action === 'edit') {
            // 打开编辑模态框，填充当前值
            document.getElementById('editRuleId').value = id;
            document.getElementById('editLocalPort').value = btn.dataset.localport || '';
            document.getElementById('editRemoteAddr').value = btn.dataset.addr || '';
            document.getElementById('editRemotePort').value = btn.dataset.port || '';
            document.getElementById('editRuleNote').value = btn.dataset.note || '';
            document.getElementById('editQuotaGB').value = btn.dataset.quota || '0';
            document.getElementById('editResetDay').value = btn.dataset.resetday || '0';
            // 备用线路：从内存规则填充（去掉 IPv6 方括号便于编辑）
            const editList = document.getElementById('editBackupList');
            editList.innerHTML = '';
            const ruleObj = allRules.find(r => r.id === id);
            const bks = (ruleObj && Array.isArray(ruleObj.backups)) ? ruleObj.backups : [];
            bks.forEach(b => addBackupRow('editBackupList', (b.addr || '').replace(/^\[|\]$/g, ''), b.port || ''));
            editModal.classList.add('show');
        }

        if (action === 'reset') {
            if (!confirm(t('toast.confirmReset'))) return;
            try {
                const res = await fetch(`/api/rules/${id}/reset`, { method: 'POST' });
                if (!res.ok) {
                    const d = await res.json();
                    throw new Error(d.error || 'Reset failed');
                }
                showToast(t('toast.resetOk'), 'success');
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
        const localPort = document.getElementById('editLocalPort').value.trim();
        const remoteAddr = document.getElementById('editRemoteAddr').value.trim();
        const remotePort = document.getElementById('editRemotePort').value.trim();
        const note = document.getElementById('editRuleNote').value.trim();
        const quotaGB = parseFloat(document.getElementById('editQuotaGB').value) || 0;
        const resetDay = parseInt(document.getElementById('editResetDay').value) || 0;
        const backups = collectBackups('editBackupList');

        if (!localPort || !remoteAddr || !remotePort) {
            showToast(t('toast.editEmpty'), 'error');
            return;
        }

        try {
            const res = await fetch(`/api/rules/${id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    local_port: localPort,
                    remote_addr: remoteAddr,
                    remote_port: remotePort,
                    backups: backups,
                    note: note,
                    quota_gb: quotaGB,
                    reset_day: resetDay
                })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Update failed');

            showToast(t('toast.editOk'), 'success');
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
        const backups = collectBackups('backupList');

        if (!lp || !ra || !rp) {
            showToast(t('toast.addEmpty'), 'error');
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
                    backups: backups,
                    note: note,
                    quota_gb: quota,
                    reset_day: resetDay
                })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Add failed');

            showToast(t('toast.addOk', {proto: selectedProto.toUpperCase()}), 'success');
            document.getElementById('localPort').value = '';
            document.getElementById('remoteAddr').value = '';
            document.getElementById('remotePort').value = '';
            document.getElementById('backupList').innerHTML = '';
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
            showToast(t('toast.batchEmpty'), 'error');
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
                showToast(t('toast.batchFormat', {line: trimmed}), 'error');
                return;
            }
        }

        if (parsedRules.length === 0) {
            showToast(t('toast.batchNone'), 'error');
            return;
        }

        try {
            const res = await fetch('/api/rules/batch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rules: parsedRules })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Batch add failed');

            const failedCount = (data.failed && data.failed.length) || 0;
            const msg = failedCount > 0
                ? t('toast.batchPartial', {n: data.added, f: failedCount})
                : t('toast.batchOk', {n: data.added});
            showToast(msg, data.added > 0 ? 'success' : 'error');
            document.getElementById('batchRules').value = '';
            await fetchRules();
            await updateStatus();
        } catch (e) {
            showToast(e.message, 'error');
        }
    });

    // --- 服务控制 ---
    async function serviceAction(action, okKey) {
        try {
            const res = await fetch(`/api/service/${action}`, { method: 'POST' });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || action + ' failed');
            showToast(data.message || t(okKey), 'success');
            await updateStatus();
        } catch (e) {
            showToast(e.message, 'error');
        }
    }

    document.getElementById('startBtn').addEventListener('click', () => serviceAction('start', 'toast.startOk'));
    document.getElementById('stopBtn').addEventListener('click', () => serviceAction('stop', 'toast.stopOk'));
    document.getElementById('restartBtn').addEventListener('click', () => serviceAction('restart', 'toast.restartOk'));

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
            showToast(t('toast.pwdEmpty'), 'error');
            return;
        }
        if (newPwd !== confirmPwd) {
            showToast(t('toast.pwdMismatch'), 'error');
            return;
        }
        if (newPwd.length < 4) {
            showToast(t('toast.pwdShort'), 'error');
            return;
        }

        pwdSaveBtn.disabled = true;
        pwdSaveBtn.textContent = t('pwd.changing');

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
            if (!res.ok) throw new Error(data.error || 'Change failed');

            showToast(t('toast.pwdOk'), 'success');
            passwordModal.classList.remove('show');
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            pwdSaveBtn.disabled = false;
            pwdSaveBtn.textContent = t('pwd.confirm');
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
    // i18n: 绑定语言切换按钮并应用当前语言
    const langToggleBtn = document.getElementById('langToggleBtn');
    if (langToggleBtn) langToggleBtn.addEventListener('click', toggleLang);
    applyI18n();

    fetchRules();
    updateStatus();

    // 定时刷新状态与流量
    setInterval(updateStatus, 15000);
    setInterval(fetchRules, 60000);    // 每60秒刷新规则（含流量数据）
});
