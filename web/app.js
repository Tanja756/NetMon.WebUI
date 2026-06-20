'use strict';

const API_BASE = '/api';

// State
let allServers = [];
let selectedServer = null; // key string
let autoUpdate = true;
let updateInterval = null;
let currentSort = { col: null, asc: true };
let searchFilter = '';
let clientVisible = false;
let activeTab = 'disk';

// Cached data for monitors (fetched separately)
let cachedData = {
    disk: null,
    network: null,
    portscan: null,
    firewall: null,
    webserver: null,
    dns: null,
};

// DOM refs
const topbarText = document.getElementById('topbar-text');
const topbarUpdated = document.getElementById('topbar-updated');
const serversTbody = document.getElementById('servers-tbody');
const searchInput = document.getElementById('search-input');
const pauseBtn = document.getElementById('pause-btn');
const statusMsg = document.getElementById('status-message');
const detailPre = document.getElementById('detail-pre');
const serverDetailHeader = document.getElementById('server-detail');
const clientTableContainer = document.getElementById('client-table-container');
const clientTbody = document.getElementById('client-tbody');
const clientHeaderRow = document.getElementById('client-header-row');
const infoTbody = document.getElementById('info-tbody');
const loginTbody = document.getElementById('login-tbody');

// Monitor DOM refs
const monitorTabs = document.querySelectorAll('.monitor-tab');
const diskContent = document.getElementById('disk-content');
const networkContent = document.getElementById('network-content');
const portscanContent = document.getElementById('portscan-content');
const firewallContent = document.getElementById('firewall-content');
const webserverContent = document.getElementById('webserver-content');
const dnsContent = document.getElementById('dns-content');

// Helpers
function fmtBytes(b) {
    if (b < 1000) return b + 'b';
    if (b < 1000 ** 2) return Math.floor(b / 1000) + 'kb';
    if (b < 1000 ** 3) return Math.floor(b / (1000 ** 2)) + 'mb';
    if (b < 1000 ** 4) return Math.floor(b / (1000 ** 3)) + 'gb';
    return Math.floor(b / (1000 ** 4)) + 'tb';
}

function trafficClass(rate) {
    if (rate > 50 * 1024 * 1024) return 'traffic-high';
    if (rate > 5 * 1024 * 1024) return 'traffic-mid';
    return 'traffic-low';
}

function stateClass(state) {
    const s = (state || '').toLowerCase();
    if (s === 'established') return 'state-established';
    if (s.includes('time_wait') || s.includes('close')) return 'state-time-wait';
    return 'state-default';
}

function getServerKey(srv) {
    return `${srv.pid}|${srv.proto}|${srv.local_ip}|${srv.port}`;
}

function escHtml(str) {
    if (str == null) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

function getToken() {
    return localStorage.getItem('netmon_token') || '';
}

// Fetch data with auth token
async function fetchJSON(url) {
    const headers = {};
    const token = getToken();
    if (token) {
        headers['Authorization'] = 'Bearer ' + token;
    }
    const resp = await fetch(url, { headers });
    if (resp.status === 401) {
        // Token expired/invalid — перенаправляем на логин
        localStorage.removeItem('netmon_token');
        window.location.href = '/login.html';
        throw new Error('Unauthorized');
    }
    if (!resp.ok) throw new Error(await resp.text());
    return resp.json();
}

async function refreshAll() {
    try {
        const [serverData, loginData] = await Promise.all([
            fetchJSON(`${API_BASE}/servers`),
            fetchJSON(`${API_BASE}/login-info`),
        ]);

        allServers = serverData.servers || [];
        const summary = serverData.summary || {};
        renderServers();
        renderTopbar(summary);
        renderLoginInfo(loginData);
        updateStatus('Updated at ' + new Date().toLocaleTimeString());

        // Если выбран сервер, обновляем детали
        if (selectedServer) {
            const srv = allServers.find(s => getServerKey(s) === selectedServer);
            if (srv) {
                showServerDetail(srv, !!clientVisible);
            } else {
                selectedServer = null;
                clearDetail();
                hideClients();
            }
        }

        // Фоновое обновление данных мониторов
        refreshMonitors();
    } catch (err) {
        updateStatus('Error: ' + err.message);
    }
}

// Render servers table
function renderServers() {
    let list = [...allServers];

    // Filter
    if (searchFilter) {
        const flt = searchFilter.toLowerCase();
        list = list.filter(s =>
            String(s.pid).includes(flt) ||
            s.name.toLowerCase().includes(flt) ||
            String(s.port).includes(flt)
        );
    }

    // Sort
    if (currentSort.col) {
        list.sort((a, b) => {
            let va = a[currentSort.col];
            let vb = b[currentSort.col];
            if (typeof va === 'string') va = va.toLowerCase();
            if (typeof vb === 'string') vb = vb.toLowerCase();
            if (va < vb) return currentSort.asc ? -1 : 1;
            if (va > vb) return currentSort.asc ? 1 : -1;
            return 0;
        });
    }

    // Deduplicate
    const seen = new Set();
    const unique = [];
    for (const s of list) {
        const key = getServerKey(s);
        if (!seen.has(key)) {
            seen.add(key);
            unique.push(s);
        }
    }

    serversTbody.innerHTML = '';
    for (const srv of unique) {
        const key = getServerKey(srv);
        const rate = Math.max(srv.rx_rate, srv.tx_rate);
        const tclass = trafficClass(rate);
        const rx = fmtBytes(Math.round(srv.rx_rate)) + '/s';
        const tx = fmtBytes(Math.round(srv.tx_rate)) + '/s';

        const tr = document.createElement('tr');
        tr.dataset.key = key;
        if (key === selectedServer) tr.classList.add('selected');

        tr.innerHTML = `
            <td>${srv.pid}</td>
            <td>${escHtml(srv.name)}</td>
            <td>${srv.proto}</td>
            <td>${srv.local_ip}</td>
            <td>${srv.port}</td>
            <td>${srv.client_count}</td>
            <td class="${tclass}">${rx}</td>
            <td class="${tclass}">${tx}</td>
        `;

        tr.addEventListener('click', () => selectServer(srv));
        serversTbody.appendChild(tr);
    }
}

function renderTopbar(summary) {
    topbarText.textContent =
        `Servers: ${summary.server_count} | Clients: ${summary.client_count} | ` +
        `⬇ ${summary.total_rx_rate_formatted}  ⬆ ${summary.total_tx_rate_formatted} | ` +
        `Σ⬇ ${summary.total_rx_bytes_formatted}  Σ⬆ ${summary.total_tx_bytes_formatted}`;
    topbarUpdated.textContent = new Date().toLocaleTimeString();
}

function renderLoginInfo(data) {
    // Info table
    infoTbody.innerHTML = `<tr>
        <td>${data.active_users}</td>
        <td>${data.active_sessions}</td>
        <td>${data.failed_last_hour}</td>
        <td>${data.uptime}</td>
    </tr>`;

    // Login table
    loginTbody.innerHTML = '';
    const logins = data.recent_logins || [];
    for (const l of logins) {
        const tr = document.createElement('tr');
        const statusClass = l.status === 'Accepted' ? 'login-ok' : 'login-fail';
        tr.innerHTML = `
            <td>${l.time}</td>
            <td>${escHtml(l.ip)}</td>
            <td>${escHtml(l.username)}</td>
            <td class="${statusClass}">${escHtml(l.status)}</td>
        `;
        loginTbody.appendChild(tr);
    }
}

// Server selection
function selectServer(srv) {
    selectedServer = getServerKey(srv);
    document.querySelectorAll('#servers-tbody tr').forEach(tr => {
        tr.classList.toggle('selected', tr.dataset.key === selectedServer);
    });
    showServerDetail(srv, true);
}

function showServerDetail(srv, showClients) {
    const p = srv.process || {};
    const killBtnHtml = srv.pid
        ? `<button class="kill-btn" onclick="killProcess(${srv.pid}, '${escHtml(srv.name)}')">✕ Kill</button>`
        : '';
    const detail = [
        `PID:       ${srv.pid}`,
        `USER:      ${p.username || '?'}`,
        `PROTO:     ${srv.proto}`,
        `PORT:      ${srv.port}`,
        `LOCAL:     ${srv.local_ip}`,
        ``,
        `CPU:       ${p.cpu_percent != null ? p.cpu_percent + '%' : '?'}`,
        `MEM:       ${p.memory_bytes != null ? fmtBytes(p.memory_bytes) : '?'}`,
        `THREADS:   ${p.threads != null ? p.threads : '?'}`,
        ``,
        `RX rate:   ${srv.rx_rate_formatted}`,
        `TX rate:   ${srv.tx_rate_formatted}`,
        ``,
        `EXE:`,
        `  ${p.exe || '?'}`,
        ``,
        `CMD:`,
        `  ${p.cmdline || '?'}`,
    ].join('\n');
    detailPre.textContent = detail;
    serverDetailHeader.innerHTML = `${srv.name} (PID ${srv.pid}) ${killBtnHtml}`;

    if (showClients && srv.client_count > 0) {
        showClientsTable(srv);
    } else if (showClients) {
        hideClients();
    }
}

function clearDetail() {
    detailPre.textContent = 'Select a server to view details';
    serverDetailHeader.innerHTML = 'Select a server';
}

// Kill process
async function killProcess(pid, name) {
    if (!confirm(`Kill process ${pid} (${name})?`)) return;
    const force = confirm(
        `Send SIGTERM first?\n\n` +
        `OK = SIGTERM (graceful)\n` +
        `Cancel = SIGKILL (force)`
    );
    try {
        const headers = {};
        const token = getToken();
        if (token) headers['Authorization'] = 'Bearer ' + token;
        const resp = await fetch(`${API_BASE}/kill/${pid}?force=${!force}`, { method: 'POST', headers });
        const data = await resp.json();
        if (data.success) {
            updateStatus(`✓ ${data.message}`);
        } else {
            updateStatus(`✗ ${data.message}`);
        }
    } catch (err) {
        updateStatus(`✗ Kill error: ${err.message}`);
    }
}

// Clients table
function showClientsTable(srv) {
    clientTableContainer.style.display = 'block';
    clientVisible = true;
    clientTbody.innerHTML = '';

    const clients = srv.clients || [];
    const isOvpn = clients.length > 0 && clients[0].hasOwnProperty('common_name');

    if (isOvpn) {
        clientHeaderRow.innerHTML = `
            <th>Common Name</th>
            <th>Remote Address</th>
            <th>RX</th>
            <th>TX</th>
            <th>Connected Since</th>
        `;
        for (const c of clients) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${escHtml(c.common_name || '')}</td>
                <td>${escHtml(c.address || c.real_address || '')}</td>
                <td>${fmtBytes(parseInt(c.bytes_received) || 0)}</td>
                <td>${fmtBytes(parseInt(c.bytes_sent) || 0)}</td>
                <td>${escHtml(c.connected_since || '')}</td>
            `;
            clientTbody.appendChild(tr);
        }
    } else {
        clientHeaderRow.innerHTML = `
            <th>Remote Addr</th>
            <th>State</th>
            <th>Client PID</th>
        `;
        for (const c of clients) {
            const tr = document.createElement('tr');
            const sc = stateClass(c.state);
            tr.innerHTML = `
                <td>${escHtml(c.address || '')}</td>
                <td class="${sc}">${escHtml(c.state || '')}</td>
                <td>${c.pid != null ? c.pid : '-'}</td>
            `;
            clientTbody.appendChild(tr);
        }
    }
}

function hideClients() {
    clientTableContainer.style.display = 'none';
    clientVisible = false;
}

function toggleClients() {
    if (clientVisible) {
        hideClients();
    } else if (selectedServer) {
        const srv = allServers.find(s => getServerKey(s) === selectedServer);
        if (srv) {
            showClientsTable(srv);
        }
    }
    updateStatus();
}

// Search
searchInput.addEventListener('input', () => {
    searchFilter = searchInput.value.trim();
    renderServers();
});

document.addEventListener('keydown', (e) => {
    if (e.key === '/' && document.activeElement !== searchInput) {
        e.preventDefault();
        searchInput.focus();
    }
    if (e.key === 'Escape') {
        searchInput.value = '';
        searchFilter = '';
        searchInput.blur();
        renderServers();
    }
    if (e.key === ' ' || e.key === 'Space') {
        e.preventDefault();
        togglePause();
    }
    if (e.key.toLowerCase() === 's' && document.activeElement !== searchInput) {
        toggleClients();
    }
    if (e.key.toLowerCase() === 'k' && selectedServer && document.activeElement !== searchInput) {
        const srv = allServers.find(s => getServerKey(s) === selectedServer);
        if (srv && srv.pid) {
            killProcess(srv.pid, srv.name);
        }
    }
    // Tab switching with 1-6 keys
    const tabIndex = parseInt(e.key);
    if (tabIndex >= 1 && tabIndex <= 6) {
        const tabs = ['disk', 'network', 'portscan', 'firewall', 'webserver', 'dns'];
        switchTab(tabs[tabIndex - 1]);
    }
});

// Pause
function togglePause() {
    autoUpdate = !autoUpdate;
    pauseBtn.classList.toggle('paused', !autoUpdate);
    pauseBtn.title = autoUpdate ? 'Pause auto-update' : 'Resume auto-update';
    if (autoUpdate) {
        startAutoUpdate();
    } else {
        stopAutoUpdate();
    }
    updateStatus();
}

pauseBtn.addEventListener('click', togglePause);

function startAutoUpdate() {
    stopAutoUpdate();
    updateInterval = setInterval(refreshAll, 2000);
}

function stopAutoUpdate() {
    if (updateInterval) {
        clearInterval(updateInterval);
        updateInterval = null;
    }
}

function updateStatus(msg) {
    if (msg) {
        statusMsg.textContent = msg;
    } else {
        statusMsg.textContent = `Auto-update: ${autoUpdate ? 'ON' : 'OFF'} | Clients: ${clientVisible ? 'visible' : 'hidden'}`;
    }
}

// Sort by column header
document.querySelectorAll('#servers-table thead th').forEach(th => {
    th.addEventListener('click', () => {
        const col = th.dataset.sort;
        if (!col) return;
        if (currentSort.col === col) {
            currentSort.asc = !currentSort.asc;
        } else {
            currentSort.col = col;
            currentSort.asc = true;
        }
        document.querySelectorAll('#servers-table thead th').forEach(t => {
            t.classList.remove('sorted-asc', 'sorted-desc');
        });
        th.classList.add(currentSort.asc ? 'sorted-asc' : 'sorted-desc');
        renderServers();
    });
});

// ==================================================================
// Monitor panels — tab switching
// ==================================================================

function switchTab(tabName) {
    activeTab = tabName;
    monitorTabs.forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabName);
    });
    document.querySelectorAll('.monitor-pane').forEach(pane => {
        pane.classList.toggle('active', pane.id === `pane-${tabName}`);
    });
    // Render active tab content if we have cached data
    renderMonitorTab(tabName);
}

monitorTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        switchTab(tab.dataset.tab);
    });
});

function renderMonitorTab(tabName) {
    const data = cachedData[tabName];
    if (!data) return;

    switch (tabName) {
        case 'disk': renderDisk(data); break;
        case 'network': renderNetwork(data); break;
        case 'portscan': renderPortScan(data); break;
        case 'firewall': renderFirewall(data); break;
        case 'webserver': renderWebServer(data); break;
        case 'dns': renderDNS(data); break;
    }
}

// ==================================================================
// Monitor data fetching
// ==================================================================

async function refreshMonitors() {
    try {
        const [disk, network, portscan, firewall, webserver, dns] = await Promise.all([
            fetchJSON(`${API_BASE}/disk`).catch(() => null),
            fetchJSON(`${API_BASE}/network`).catch(() => null),
            fetchJSON(`${API_BASE}/port-scans`).catch(() => null),
            fetchJSON(`${API_BASE}/firewall`).catch(() => null),
            fetchJSON(`${API_BASE}/webserver`).catch(() => null),
            fetchJSON(`${API_BASE}/dns`).catch(() => null),
        ]);

        if (disk) cachedData.disk = disk;
        if (network) cachedData.network = network;
        if (portscan) cachedData.portscan = portscan;
        if (firewall) cachedData.firewall = firewall;
        if (webserver) cachedData.webserver = webserver;
        if (dns) cachedData.dns = dns;

        renderMonitorTab(activeTab);
    } catch (err) {
        // Silent fail for background refresh
    }
}

// ==================================================================
// Monitor renderers
// ==================================================================

function renderDisk(data) {
    const disks = data.disks || [];
    if (!disks.length) {
        diskContent.innerHTML = '<div class="dns-info">No disk data available</div>';
        return;
    }

    let html = '';
    for (const d of disks) {
        const pct = d.percent || 0;
        const barClass = pct > 90 ? 'critical' : pct > 75 ? 'warning' : '';
        const totalStr = fmtBytes(d.total_bytes);
        const usedStr = fmtBytes(d.used_bytes);
        const freeStr = fmtBytes(d.free_bytes);
        const forecast = d.forecast_hours != null
            ? `<span class="disk-forecast">⏳ ~${d.forecast_hours}h to full</span>`
            : '';
        html += `<div class="disk-item">
            <div><strong>${escHtml(d.device)}</strong> on <em>${escHtml(d.mount)}</em> [${d.fstype}]</div>
            <div class="disk-bar">
                <span class="disk-label">${totalStr} total</span>
                <div style="flex:1; background:#222; border-radius:2px;">
                    <div class="disk-bar-fill ${barClass}" style="width:${pct}%"></div>
                </div>
                <span class="disk-pct">${pct}%</span>
            </div>
            <div style="color:#888;font-size:10px;">Used: ${usedStr} | Free: ${freeStr} ${forecast}</div>
        </div>`;
    }

    // I/O stats
    const io = data.io || {};
    if (Object.keys(io).length) {
        html += '<div style="margin-top:8px;border-top:1px solid #222;padding-top:4px;"><strong>Disk I/O:</strong></div>';
        for (const [name, stats] of Object.entries(io)) {
            html += `<div class="iface-item">
                <span class="iface-name">${escHtml(name)}</span>
                <span style="color:#888;font-size:10px;margin-left:8px;">
                    R: ${fmtBytes(stats.read_bytes)} | W: ${fmtBytes(stats.write_bytes)} |
                    IOPS R: ${stats.read_count} W: ${stats.write_count}
                </span>
            </div>`;
        }
    }

    diskContent.innerHTML = html;
}

function renderNetwork(data) {
    const ifaces = data.interfaces || [];
    if (!ifaces.length) {
        networkContent.innerHTML = '<div class="dns-info">No network interface data</div>';
        return;
    }

    let html = '';
    for (const iface of ifaces) {
        const errClass = (iface.err_rate_in > 0 || iface.err_rate_out > 0) ? 'error-count' : '';
        const dropClass = (iface.drop_rate_in > 0 || iface.drop_rate_out > 0) ? 'drop-count' : '';
        html += `<div class="iface-item">
            <div class="iface-name">${escHtml(iface.name)}</div>
            <div style="font-size:10px;color:#888;">
                RX: ${fmtBytes(Math.round(iface.rx_rate))}/s |
                TX: ${fmtBytes(Math.round(iface.tx_rate))}/s
            </div>
            <div style="font-size:10px;">
                <span class="${errClass}">⚠ Errors IN: ${iface.err_in} (${iface.err_rate_in}/s) OUT: ${iface.err_out} (${iface.err_rate_out}/s)</span><br>
                <span class="${dropClass}">⬇ Drops IN: ${iface.drop_in} (${iface.drop_rate_in}/s) OUT: ${iface.drop_out} (${iface.drop_rate_out}/s)</span>
                ${iface.collisions ? `<br><span class="collision-count">⚡ Collisions: ${iface.collisions}</span>` : ''}
            </div>
        </div>`;
    }
    networkContent.innerHTML = html;
}

function renderPortScan(data) {
    const suspicious = data.suspicious || [];
    const stats = data.stats || {};

    let html = `<div class="dns-info">
        <span class="dns-key">Tracked IPs:</span> <span class="dns-val">${stats.total_ips_tracked || 0}</span>
        <span class="dns-key" style="margin-left:16px;">Tracked Ports:</span> <span class="dns-val">${stats.total_ports_tracked || 0}</span>
        <span class="dns-key" style="margin-left:16px;">Suspicious:</span> <span class="dns-val">${stats.suspicious_count || 0}</span>
    </div>`;

    if (!suspicious.length) {
        html += '<div style="color:#4a4;padding:8px 0;">✓ No port scans detected</div>';
    } else {
        for (const s of suspicious) {
            const firstSeen = new Date(s.first_seen * 1000).toLocaleTimeString();
            const lastSeen = new Date(s.last_seen * 1000).toLocaleTimeString();
            html += `<div class="scan-item">
                <span class="scan-ip">${escHtml(s.ip)}</span>
                <span style="color:#a44;font-weight:bold;"> — ${s.ports_count} ports</span>
                <span style="color:#888;font-size:10px;margin-left:8px;">
                    (${firstSeen} – ${lastSeen})
                </span>
                <div style="color:#888;font-size:10px;">Ports: ${s.ports.join(', ')}</div>
            </div>`;
        }
    }

    portscanContent.innerHTML = html;
}

function renderFirewall(data) {
    const rules = data.rules || [];
    if (!rules.length) {
        firewallContent.innerHTML = '<div class="dns-info">No iptables rules or permission denied</div>';
        return;
    }

    let html = `<div class="dns-info">
        <span class="dns-key">Total rules:</span> <span class="dns-val">${data.rules_count || 0}</span>
    </div>`;

    // Group by chain
    const chains = {};
    for (const r of rules) {
        if (!chains[r.chain]) chains[r.chain] = [];
        chains[r.chain].push(r);
    }

    for (const [chain, chainRules] of Object.entries(chains)) {
        html += `<div style="margin-top:4px;"><strong style="color:#8af;">${chain}:</strong> (${chainRules.length} rules)</div>`;
        for (const r of chainRules) {
            const targetClass = ['DROP', 'REJECT'].includes(r.target.toUpperCase()) ? 'fw-target drop' : 'fw-target';
            const inStr = r.in && r.in !== '*' ? ` in:${r.in}` : '';
            const outStr = r.out && r.out !== '*' ? ` out:${r.out}` : '';
            const dportStr = r.dport ? ` <span style="color:#aa4;">→ :${r.dport}</span>` : '';
            html += `<div class="fw-rule">
                <span style="color:#666;font-size:9px;">#${r.num}</span>
                <span class="${targetClass}">${escHtml(r.target)}</span>
                <span style="color:#888;">${escHtml(r.prot)}${inStr}${outStr}</span>
                <span style="color:#666;">${escHtml(r.source)}→${escHtml(r.destination)}</span>
                ${dportStr}
            </div>`;
        }
    }

    firewallContent.innerHTML = html;
}

function renderWebServer(data) {
    if (data.error) {
        webserverContent.innerHTML = `<div class="dns-info">${escHtml(data.error)}</div>`;
        return;
    }

    let html = `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:6px;">
        <div class="ws-stat">Requests: <span class="ws-stat-value">${data.total_requests || 0}</span></div>
        <div class="ws-stat">RPS: <span class="ws-stat-value">${(data.requests_per_second || 0).toFixed(1)}</span></div>
        <div class="ws-stat">Log: <span class="ws-stat-value" style="font-size:10px;">${data.log_path || '?'}</span></div>
    </div>`;

    // Status codes
    if (data.status_codes && Object.keys(data.status_codes).length) {
        html += '<div style="margin-bottom:4px;"><strong>Status codes:</strong> ';
        for (const [code, count] of Object.entries(data.status_codes)) {
            const codeClass = code.startsWith('2') ? 'ws-status-2xx'
                : code.startsWith('3') ? 'ws-status-3xx'
                : code.startsWith('4') ? 'ws-status-4xx'
                : code.startsWith('5') ? 'ws-status-5xx'
                : '';
            html += `<span class="ws-status ${codeClass}">${code}: ${count}</span> `;
        }
        html += '</div>';
    }

    // Top IPs
    if (data.top_ips && data.top_ips.length) {
        html += '<div style="margin-bottom:4px;"><strong>Top IPs:</strong></div>';
        for (const ip of data.top_ips.slice(0, 10)) {
            html += `<div class="ws-row"><span class="ws-ip">${escHtml(ip.ip)}</span> <span style="color:#888;">${ip.count} req</span></div>`;
        }
    }

    // Top paths
    if (data.top_paths && data.top_paths.length) {
        html += '<div style="margin-top:4px;margin-bottom:4px;"><strong>Top paths:</strong></div>';
        for (const p of data.top_paths.slice(0, 40)) {
            html += `<div class="ws-row"><span class="ws-path">${escHtml(p.path)}</span> <span style="color:#888;">${p.count}</span></div>`;
        }
    }

    // Recent entries (последние запросы)
    if (data.recent_entries && data.recent_entries.length) {
        html += '<div style="margin-top:8px;border-top:1px solid #222;padding-top:4px;"><strong>Recent requests:</strong></div>';
        for (const e of data.recent_entries.slice(0, 40)) {
            const sc = e.status >= 400 ? 'ws-status-4xx' : e.status >= 500 ? 'ws-status-5xx' : '';
            html += `<div class="ws-row" style="font-size:9px;">
                <span style="color:#888;">${escHtml(e.time)}</span>
                <span style="color:#cdd6f4;">${escHtml(e.ip)}</span>
                <span style="color:#6c7086;">${escHtml(e.method)}</span>
                <span class="ws-path">${escHtml(e.path)}</span>
                <span class="${sc}">${e.status}</span>
            </div>`;
        }
    }

    webserverContent.innerHTML = html;
}

function renderDNS(data) {
    if (data.error) {
        dnsContent.innerHTML = `<div class="dns-info">${escHtml(data.error)}</div>`;
        return;
    }

    let html = `<div class="dns-info">
        <span class="dns-key">Type:</span> <span class="dns-val">${data.dns_type || '?'}</span>
    </div>`;

    if (data.dns_type === 'systemd-resolved' && data.statistics) {
        for (const [key, val] of Object.entries(data.statistics)) {
            html += `<div class="dns-info">
                <span class="dns-key">${escHtml(key.replace(/_/g, ' '))}:</span>
                <span class="dns-val">${escHtml(val)}</span>
            </div>`;
        }
    }

    if (data.queries_per_minute != null) {
        html += `<div class="dns-info">
            <span class="dns-key">Queries/min:</span>
            <span class="dns-val">${data.queries_per_minute.toFixed(1)}</span>
        </div>`;
    }

    if (data.recent_queries != null) {
        html += `<div class="dns-info">
            <span class="dns-key">Recent queries:</span>
            <span class="dns-val">${data.recent_queries}</span>
        </div>`;
    }

    if (data.captured_packets != null) {
        html += `<div class="dns-info">
            <span class="dns-key">Captured packets:</span>
            <span class="dns-val">${data.captured_packets}</span>
        </div>`;
    }

    if (data.note) {
        html += `<div style="color:#888;font-size:10px;margin-top:4px;">${escHtml(data.note)}</div>`;
    }

    if (data.raw_lines && data.raw_lines.length) {
        html += '<div style="margin-top:8px;border-top:1px solid #222;padding-top:4px;"><strong>Raw log lines:</strong></div>';
        for (const line of data.raw_lines) {
            html += `<div style="font-size:9px;color:#666;padding:1px 0;word-break:break-all;">${escHtml(line)}</div>`;
        }
    }

    dnsContent.innerHTML = html;
}

// Init
function init() {
    startAutoUpdate();
    refreshAll();

    // Initial tab render
    renderMonitorTab('disk');
}

init();