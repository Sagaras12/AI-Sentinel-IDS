/* SentinelPulse AI — local Flask + Groq frontend. No Supabase or login. */
'use strict';

let threatData = [];
let lineChart = null;
let doughnutChart = null;
let analyticsLine = null;
let analyticsDonut = null;
let pendingMitigationId = null;
let refreshTimer = null;
let settings = {};
let currentSearchQuery = '';
let moduleThreatTableUpdate = null;

const $ = id => document.getElementById(id);

const palette = () => {
    const s = getComputedStyle(document.documentElement);
    return {
        text: s.getPropertyValue('--muted').trim(),
        grid: s.getPropertyValue('--border').trim(),
        cyan: s.getPropertyValue('--cyan').trim(),
        red: s.getPropertyValue('--red').trim(),
        orange: s.getPropertyValue('--orange').trim(),
        violet: s.getPropertyValue('--violet').trim(),
        green: s.getPropertyValue('--green').trim()
    };
};

async function api(url, options = {}) {
    const r = await fetch(url, {
        ...options,
        headers: {
            ...(options.headers || {}),
            ...(options.body ? { 'Content-Type': 'application/json' } : {})
        }
    });

    const data = (r.headers.get('content-type') || '').includes('application/json')
        ? await r.json()
        : null;

    if (!r.ok) {
        throw new Error(data?.error || `Request failed (${r.status})`);
    }

    return data;
}

function toast(message, type = 'success') {
    const n = document.createElement('div');
    n.className = `toast ${type === 'error' ? 'error' : type === 'info' ? 'info' : ''}`;
    n.textContent = message;
    $('toastRegion').appendChild(n);
    setTimeout(() => n.remove(), 3800);
}

function loading(el, on) {
    if (el) el.disabled = on;
}

function make(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
}

function dateLabel() {
    const d = new Date();

    $('currentDate').textContent = new Intl.DateTimeFormat('en-IN', {
        weekday: 'short',
        day: '2-digit',
        month: 'short',
        year: 'numeric'
    }).format(d);

    $('lastUpdated').textContent =
        `Updated ${d.toLocaleTimeString('en-IN', {
            hour: '2-digit',
            minute: '2-digit'
        })}`;
}

function updateKpis() {
    const rows = threatData;
    const active = rows.filter(x => x.status === 'Active');

    const score = Math.max(
        0,
        100 - active.reduce((s, x) =>
            s + ({ Critical: 5, High: 3, Medium: 1, Low: 0 }[x.severity] || 0),
            0
        )
    );

    $('kpi-total-logs').textContent = rows.length;
    $('kpi-active-critical').textContent =
        active.filter(x => x.severity === 'Critical').length;

    $('kpi-mitigated').textContent =
        rows.filter(x => x.status === 'Mitigated').length;

    $('kpi-health-score').replaceChildren(
        document.createTextNode(score),
        Object.assign(document.createElement('small'), { textContent: '%' })
    );

    $('healthBar').style.width = `${score}%`;
    $('nav-threat-count').textContent = active.length;

    dateLabel();
}

function severityBadge(v) {
    return make('span', `severity-badge sev-${String(v).toLowerCase()}`, v);
}

function statusBadge(v) {
    return make(
        'span',
        `status-badge ${v === 'Active' ? 'status-active' : 'status-mitigated'}`,
        v
    );
}

function fillThreatTable(tbody, rows, allowMitigate = true) {
    tbody.replaceChildren();

    if (!rows.length) {
        const tr = make('tr');
        const td = make(
            'td',
            'empty-cell',
            'No incidents match your search or filters.'
        );

        td.colSpan = allowMitigate ? 7 : 5;
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
    }

    rows.forEach(log => {
        const tr = make('tr');

        const vals = [
            log.timestamp,
            log.source_ip,
            log.attack_type,
            log.mitre_id
        ];

        vals.forEach(v => {
            tr.appendChild(make('td', '', String(v ?? '—')));
        });

        let td = make('td');
        td.appendChild(severityBadge(log.severity));
        tr.appendChild(td);

        td = make('td');
        td.appendChild(statusBadge(log.status));
        tr.appendChild(td);

        if (allowMitigate) {
            td = make('td');

            if (log.status === 'Active') {
                const b = make('button', 'mitigate-btn', 'Mitigate');
                b.type = 'button';
                b.addEventListener('click', () =>
                    confirmMitigationDialog(log.id)
                );
                td.appendChild(b);
            } else {
                td.textContent = '—';
            }

            tr.appendChild(td);
        }

        tbody.appendChild(tr);
    });
}

/* SEARCH SYSTEM */

function filteredRows(query = '', severity = 'All', status = 'All') {
    query = String(query).trim().toLowerCase();

    return threatData.filter(x =>
        (severity === 'All' || x.severity === severity) &&
        (status === 'All' || x.status === status) &&
        (
            !query ||
            [
                x.timestamp,
                x.source_ip,
                x.attack_type,
                x.mitre_id,
                x.severity,
                x.status,
                x.description
            ].some(v =>
                String(v ?? '').toLowerCase().includes(query)
            )
        )
    );
}

function syncSearchInputs(value) {
    currentSearchQuery = String(value ?? '');

    renderThreatTable();

    if (moduleThreatTableUpdate) {
        moduleThreatTableUpdate();
    }
}

function renderThreatTable() {
    const rows = filteredRows(
        currentSearchQuery,
        $('severityFilter').value
    );

    fillThreatTable($('threatTableBody'), rows, true);

    $('recordCount').textContent =
        `${rows.length} ${rows.length === 1 ? 'record' : 'records'}`;

    $('tableSummary').textContent =
        `${threatData.filter(x => x.status === 'Active').length} active · ` +
        `${threatData.filter(x => x.status === 'Mitigated').length} mitigated`;
}

/* CHARTS */

function initCharts() {
    if (!window.Chart) {
        toast('Chart.js failed to load.', 'error');
        return;
    }

    const p = palette();

    lineChart = new Chart($('lineChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: []
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: p.text, maxTicksLimit: 6 }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: p.grid },
                    ticks: { color: p.text }
                }
            }
        }
    });

    doughnutChart = new Chart($('doughnutChart'), {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    p.red,
                    p.orange,
                    p.violet,
                    p.green,
                    p.cyan
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '76%',
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function chartData() {
    const labels = [];
    const traffic = [];
    const threats = [];

    for (let i = 11; i >= 0; i--) {
        labels.push(
            new Date(Date.now() - i * 60000).toLocaleTimeString('en-IN', {
                hour: '2-digit',
                minute: '2-digit'
            })
        );

        traffic.push(100 + Math.floor(Math.random() * 145));
        threats.push(Math.floor(Math.random() * 3));
    }

    return { labels, traffic, threats };
}

function updateCharts() {
    if (!lineChart || !doughnutChart) return;

    const p = palette();
    const d = chartData();
    const counts = {};

    threatData
        .filter(x => x.status === 'Active')
        .forEach(x => {
            counts[x.attack_type] = (counts[x.attack_type] || 0) + 1;
        });

    lineChart.data = {
        labels: d.labels,
        datasets: [
            {
                label: 'Simulated traffic (demo)',
                data: d.traffic,
                borderColor: p.cyan,
                backgroundColor: p.cyan + '22',
                fill: true,
                tension: 0.38,
                pointRadius: 0,
                borderWidth: 2
            },
            {
                label: 'Active threat events (illustrative)',
                data: d.threats,
                borderColor: p.red,
                tension: 0.35,
                pointRadius: 2,
                borderWidth: 2
            }
        ]
    };

    lineChart.update('none');

    const entries = Object.entries(counts);
    const colors = [p.red, p.orange, p.violet, p.green, p.cyan];

    doughnutChart.data.labels = entries.map(x => x[0]);
    doughnutChart.data.datasets[0].data = entries.map(x => x[1]);
    doughnutChart.data.datasets[0].backgroundColor = colors;
    doughnutChart.update();

    $('donutTotal').textContent =
        entries.reduce((s, x) => s + x[1], 0);

    const legend = $('chartLegend');
    legend.replaceChildren();

    entries.forEach(([name, count], i) => {
        const item = make('span');
        const dot = make('i');

        dot.style.background = colors[i];

        item.append(
            dot,
            document.createTextNode(`${name} · ${count}`)
        );

        legend.appendChild(item);
    });
}

/* DATA REFRESH */

async function refreshAll(show = false) {
    try {
        threatData = await api('/api/threats');

        updateKpis();
        renderThreatTable();

        if (moduleThreatTableUpdate) {
            moduleThreatTableUpdate();
        }

        updateCharts();

        if (show) {
            toast('Incident data refreshed.');
        }

        if (!$('reportsPage').hidden) loadReports();
        if (!$('analyticsPage').hidden) loadAnalytics();

    } catch (e) {
        toast(`Could not load local incident data: ${e.message}`, 'error');
    }
}

/* SIMULATION */

async function simulate(type, button) {
    loading(button, true);

    try {
        await api('/api/simulate', {
            method: 'POST',
            body: JSON.stringify({ type })
        });

        await refreshAll();

        if (settings.notifications !== false) {
            toast(`${type} simulation added to the incident feed.`);
        }

    } catch (e) {
        toast(e.message, 'error');

    } finally {
        loading(button, false);
    }
}

/* MITIGATION */

function confirmMitigationDialog(id) {
    pendingMitigationId = id;
    $('confirmModal').hidden = false;
    $('confirmMitigate').focus();
}

function closeMitigation() {
    pendingMitigationId = null;
    $('confirmModal').hidden = true;
}

async function mitigate() {
    if (pendingMitigationId === null) return;

    const id = pendingMitigationId;
    loading($('confirmMitigate'), true);

    try {
        await api('/api/mitigate', {
            method: 'POST',
            body: JSON.stringify({ id })
        });

        closeMitigation();
        await refreshAll();

        if (settings.notifications !== false) {
            toast('Incident record marked as mitigated. No network traffic was blocked.');
        }

    } catch (e) {
        toast(e.message, 'error');

    } finally {
        loading($('confirmMitigate'), false);
    }
}

/* GROQ COPILOT */

async function copilotRequest(message, log, sendButton) {
    const typing = make(
        'div',
        'typing',
        'Groq Copilot is analyzing the local incident dataset...'
    );

    log.appendChild(typing);
    log.scrollTop = log.scrollHeight;

    loading(sendButton, true);

    try {
        const result = await api('/api/copilot/chat', {
            method: 'POST',
            body: JSON.stringify({ message })
        });

        typing.remove();
        addChat(log, 'Copilot', result.answer);

    } catch (e) {
        typing.remove();

        addChat(
            log,
            'Copilot',
            `I couldn't complete that request: ${e.message}`
        );

        toast(e.message, 'error');

    } finally {
        loading(sendButton, false);
    }
}

function addChat(log, who, message) {
    const wrap = make(
        'div',
        `chat-message ${who === 'You' ? 'user' : 'assistant'}`
    );

    const avatar = make('span', 'chat-avatar');
    const content = make('div', 'bubble-wrap');

    const meta = make(
        'span',
        'sender',
        who === 'You' ? 'YOU' : 'SENTINELPULSE · GROQ'
    );

    const time = make(
        'time',
        '',
        new Date().toLocaleTimeString('en-IN', {
            hour: '2-digit',
            minute: '2-digit'
        })
    );

    const bubble = make('div', 'chat-bubble', message);

    meta.append(' ', time);

    avatar.textContent = who === 'You' ? 'U' : 'AI';

    content.append(meta, bubble);
    wrap.append(avatar, content);

    log.appendChild(wrap);
    log.scrollTop = log.scrollHeight;
}

function sendChatFrom(input, log, button) {
    const msg = input.value.trim();

    if (!msg) return;

    addChat(log, 'You', msg);
    input.value = '';

    copilotRequest(msg, log, button);
}

/* NAVIGATION */

function setPage(page) {
    moduleThreatTableUpdate = null;

    const names = [
        'Overview',
        'Threat Intelligence',
        'Security Analytics',
        'Attack Simulator',
        'SOC Copilot',
        'Incident Reports',
        'Settings'
    ];

    if (!names.includes(page)) page = 'Overview';

    document.querySelectorAll('.nav-item[data-page]').forEach(b => {
        b.classList.toggle('active', b.dataset.page === page);
    });

    $('page-title').textContent = page;

    $('welcome-title').textContent =
        page === 'Overview' ? 'Security overview' : page;

    const overview = page === 'Overview';

    $('overviewKpis').hidden = !overview;
    $('overviewAnalytics').hidden = !overview;
    $('overviewLower').hidden = !overview;
    $('moduleWorkspace').hidden = overview;

    [
        'reportsPage',
        'settingsPage',
        'analyticsPage',
        'simulatorPage',
        'copilotPage',
        'threatsPage'
    ].forEach(id => {
        $(id).hidden = true;
    });

    if (!overview) {
        const map = {
            'Threat Intelligence': 'threatsPage',
            'Security Analytics': 'analyticsPage',
            'Attack Simulator': 'simulatorPage',
            'SOC Copilot': 'copilotPage',
            'Incident Reports': 'reportsPage',
            'Settings': 'settingsPage'
        };

        $(map[page]).hidden = false;
        renderModule(page);
    }

    $('sidebar').classList.remove('open');
}

function moduleCard(label, value, detail) {
    const card = make('article', 'kpi-card');

    card.append(
        make('div', 'kpi-top', label),
        make('div', 'kpi-value', String(value)),
        make('div', 'kpi-foot', detail)
    );

    return card;
}

/* MODULE RENDERING */

function renderModule(page) {

    if (page === 'Threat Intelligence') {
        const mount = $('threatsMount');
        mount.replaceChildren();

        const toolbar = make('div', 'table-toolbar');

        const search = make('input');
        search.id = 'threatModuleSearch';
        search.type = 'search';
        search.placeholder = 'Search IP, attack type, MITRE ID...';
        search.className = 'module-search';
        search.value = currentSearchQuery;

        search.setAttribute(
            'aria-label',
            'Search threat intelligence records'
        );

        const sev = make('select');

        ['All', 'Critical', 'High', 'Medium', 'Low'].forEach(x => {
            const o = make(
                'option',
                '',
                x === 'All' ? 'All severities' : x
            );

            o.value = x;
            sev.appendChild(o);
        });

        const status = make('select');

        ['All', 'Active', 'Mitigated'].forEach(x => {
            const o = make(
                'option',
                '',
                x === 'All' ? 'All statuses' : x
            );

            o.value = x;
            status.appendChild(o);
        });

        const count = make('span', 'record-count');

        toolbar.append(search, sev, status, count);

        const scroll = make('div', 'table-scroll');
        const table = make('table');
        const thead = make('thead');
        const tr = make('tr');

        [
            'Timestamp',
            'Source IP',
            'Attack type',
            'MITRE ATT&CK',
            'Severity',
            'Status',
            'Action'
        ].forEach(x => {
            tr.appendChild(make('th', '', x));
        });

        thead.appendChild(tr);

        const tbody = make('tbody');

        table.append(thead, tbody);
        scroll.appendChild(table);

        mount.append(toolbar, scroll);

        const update = () => {
            const rows = filteredRows(
                currentSearchQuery,
                sev.value,
                status.value
            );

            fillThreatTable(tbody, rows, true);
            count.textContent = `${rows.length} records`;
        };

        moduleThreatTableUpdate = update;

        search.addEventListener('input', () => {
            syncSearchInputs(search.value);
        });

        sev.addEventListener('change', update);
        status.addEventListener('change', update);

        update();
    }

    if (page === 'Attack Simulator') {
        const mount = $('simulatorMount');
        mount.replaceChildren();

        mount.append(
            make(
                'div',
                'sim-warning',
                'Simulation only. This creates sample incident records and does not execute real attacks or generate network traffic.'
            )
        );

        const grid = make('div', 'module-sim-grid');

        [
            ['Brute Force', 'Credential attack', 'key-round'],
            ['SQL Injection', 'Application exploit', 'database-zap'],
            ['DDoS', 'Service disruption', 'network']
        ].forEach(([type, desc, icon]) => {
            const b = make('button', 'sim-btn');
            b.type = 'button';

            b.append(
                make(
                    'span',
                    'sim-type-icon',
                    icon === 'key-round' ? '⌑' :
                    icon === 'network' ? '⌁' : '▤'
                ),
                make('span', '', `${type} — ${desc}`),
                make('span', '', '＋')
            );

            b.addEventListener('click', () => simulate(type, b));
            grid.appendChild(b);
        });

        mount.appendChild(grid);

        const recent = make('div', 'panel-title', 'Recent simulated incidents');
        mount.appendChild(recent);

        const list = make('div', 'module-list');

        threatData
            .filter(x => x.simulated)
            .slice(-8)
            .reverse()
            .forEach(x => {
                list.appendChild(
                    make(
                        'div',
                        'setting-row',
                        `${x.timestamp} · ${x.attack_type} · ${x.severity} · ${x.status}`
                    )
                );
            });

        mount.appendChild(list);
    }

    if (page === 'SOC Copilot') {
        const mount = $('copilotMount');
        mount.replaceChildren();

        const note = make(
            'p',
            'copilot-note',
            'Powered by Groq. Answers use your locally stored incident records as context; validate recommendations before acting.'
        );

        const log = make('div', 'chat-log');

        addChat(
            log,
            'Copilot',
            'Hello, analyst. I can investigate your incident records, summarize alert patterns and suggest defensive next steps.'
        );

        const form = make('form', 'chat-compose');
        const input = make('input');

        input.placeholder = 'Ask SentinelPulse about your security data...';
        input.setAttribute('aria-label', 'Ask Groq SOC Copilot');

        const btn = make('button', '', '➤');
        btn.type = 'submit';

        form.append(input, btn);

        form.addEventListener('submit', e => {
            e.preventDefault();
            sendChatFrom(input, log, btn);
        });

        const prompts = make('div', 'quick-prompts');

        [
            'Summarize active critical alerts',
            'Which source IP appears most often?',
            'Recommend investigation steps for the highest severity incidents'
        ].forEach(text => {
            const b = make('button', 'quick-btn', text);
            b.type = 'button';

            b.addEventListener('click', () => {
                input.value = text;
                sendChatFrom(input, log, btn);
            });

            prompts.appendChild(b);
        });

        mount.append(note, prompts, log, form);
    }

    if (page === 'Incident Reports') loadReports();
    if (page === 'Security Analytics') loadAnalytics();
    if (page === 'Settings') loadSettingsForm();
}

/* REPORTS */

async function loadReports() {
    try {
        const r = await api('/api/reports');
        const k = $('reportKpis');

        k.replaceChildren(
            moduleCard('Total incidents', r.total, 'All locally stored records'),
            moduleCard('Active incidents', r.active, 'Require analyst review'),
            moduleCard('Mitigated', r.mitigated, 'Record status updated'),
            moduleCard('Critical active', r.critical, 'Highest severity active')
        );

        const body = $('reportsTableBody');
        body.replaceChildren();

        r.recent.forEach(x => {
            const tr = make('tr');

            [x.timestamp, x.source_ip, x.attack_type, x.severity, x.status]
                .forEach((v, i) => {
                    const td = make('td');

                    if (i === 3) {
                        td.appendChild(severityBadge(v));
                    } else if (i === 4) {
                        td.appendChild(statusBadge(v));
                    } else {
                        td.textContent = v;
                    }

                    tr.appendChild(td);
                });

            body.appendChild(tr);
        });

    } catch (e) {
        toast(e.message, 'error');
    }
}

/* ANALYTICS */

async function loadAnalytics() {
    try {
        const r = await api('/api/analytics');
        const k = $('analyticsKpis');

        k.replaceChildren(
            moduleCard('Total incidents', r.total, 'Recorded locally'),
            moduleCard('Active', r.active, 'Current open records'),
            moduleCard('Mitigated', r.mitigated, 'Closed records')
        );

        const p = palette();

        if (!analyticsLine) {
            analyticsLine = new Chart($('analyticsLineChart'), {
                type: 'line',
                data: {
                    labels: [],
                    datasets: []
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: true }
                    },
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: p.text }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: p.grid },
                            ticks: { color: p.text }
                        }
                    }
                }
            });
        }

        if (!analyticsDonut) {
            analyticsDonut = new Chart($('analyticsDoughnutChart'), {
                type: 'doughnut',
                data: {
                    labels: [],
                    datasets: [{
                        data: [],
                        backgroundColor: [
                            p.red,
                            p.orange,
                            p.violet,
                            p.green,
                            p.cyan
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
        }

        const demo = chartData();

        analyticsLine.data = {
            labels: demo.labels,
            datasets: [
                {
                    label: 'Simulated traffic (demo)',
                    data: demo.traffic,
                    borderColor: p.cyan,
                    tension: 0.35,
                    pointRadius: 0
                },
                {
                    label: 'Illustrative threat events',
                    data: demo.threats,
                    borderColor: p.red,
                    tension: 0.35,
                    pointRadius: 2
                }
            ]
        };

        analyticsLine.update();

        analyticsDonut.data.labels = Object.keys(r.attack_types);
        analyticsDonut.data.datasets[0].data =
            Object.values(r.attack_types);

        analyticsDonut.update();

    } catch (e) {
        toast(e.message, 'error');
    }
}

/* SETTINGS */

async function loadSettingsForm() {
    try {
        settings = await api('/api/settings');

        $('settingTheme').value = settings.theme;
        $('settingCompact').checked = settings.compact_mode;
        $('settingRefresh').value = String(settings.refresh_interval);
        $('settingNotifications').checked = settings.notifications;
        $('settingAnalyst').value = settings.analyst_name;

        $('sidebarUserName').textContent =
            settings.analyst_name || 'Security Analyst';

    } catch (e) {
        toast(e.message, 'error');
    }
}

async function saveSettings(e) {
    e.preventDefault();

    const payload = {
        theme: $('settingTheme').value,
        compact_mode: $('settingCompact').checked,
        refresh_interval: Number($('settingRefresh').value),
        notifications: $('settingNotifications').checked,
        analyst_name: $('settingAnalyst').value.trim() || 'Security Analyst'
    };

    try {
        settings = await api('/api/settings', {
            method: 'POST',
            body: JSON.stringify(payload)
        });

        applySettings();
        toast('Workspace preferences saved locally.');

    } catch (e) {
        toast(e.message, 'error');
    }
}

function applySettings() {
    document.documentElement.dataset.theme = settings.theme || 'dark';

    document.body.classList.toggle(
        'compact-mode',
        !!settings.compact_mode
    );

    $('sidebarUserName').textContent =
        settings.analyst_name || 'Security Analyst';

    if (refreshTimer) clearInterval(refreshTimer);

    if (Number(settings.refresh_interval) > 0) {
        refreshTimer = setInterval(
            () => refreshAll(),
            Number(settings.refresh_interval) * 1000
        );
    }

    updateCharts();
}

async function loadSettings() {
    try {
        settings = await api('/api/settings');
        applySettings();

    } catch (e) {
        toast(e.message, 'error');
    }
}

/* CSV EXPORT */

async function exportCsv() {
    const b = $('exportBtn');
    loading(b, true);

    try {
        const r = await fetch('/api/export');

        if (!r.ok) {
            throw new Error('CSV export failed.');
        }

        const blob = await r.blob();
        const url = URL.createObjectURL(blob);
        const a = make('a');

        a.href = url;
        a.download = 'sentinelpulse_incidents.csv';
        a.click();

        URL.revokeObjectURL(url);

        toast('Incident CSV downloaded.');

    } catch (e) {
        toast(e.message, 'error');

    } finally {
        loading(b, false);
    }
}

/* NOTIFICATIONS */

async function showNotifications() {
    if (settings.notifications === false) {
        toast('In-app notifications are disabled in Settings.', 'info');
        return;
    }

    try {
        const items = await api('/api/notifications');

        if (!items.length) {
            toast('No active incident notifications.', 'info');
            return;
        }

        toast(
            `${items.length} active incident notification(s). Open Threat Intelligence to review.`,
            'info'
        );

    } catch (e) {
        toast(e.message, 'error');
    }
}

/* INITIALIZATION */

function initTheme() {
    document.documentElement.dataset.theme = 'dark';
}

document.addEventListener('DOMContentLoaded', async () => {
    initTheme();
    initCharts();

    if (window.lucide) lucide.createIcons();

    await loadSettings();
    await refreshAll();

    document.querySelectorAll('.nav-item[data-page]').forEach(b => {
        b.addEventListener('click', () => setPage(b.dataset.page));
    });

    /* Connect both existing search bars */
    $('searchBox').addEventListener('input', e => {
        syncSearchInputs(e.target.value);
    });

    $('globalSearch').addEventListener('input', e => {
        syncSearchInputs(e.target.value);
    });

    /* Press Enter to open Threat Intelligence */
    $('globalSearch').addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            e.preventDefault();
            setPage('Threat Intelligence');
            $('threatModuleSearch')?.focus();
        }
    });

    $('searchBox').addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            e.preventDefault();
            setPage('Threat Intelligence');
            $('threatModuleSearch')?.focus();
        }
    });

    /* Keyboard shortcuts */
    document.addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            $('globalSearch').focus();
        }

        if (e.key === 'Escape') {
            closeMitigation();
            $('sidebar').classList.remove('open');
        }
    });

    $('severityFilter').addEventListener('change', renderThreatTable);

    $('refreshBtn').addEventListener('click', () => refreshAll(true));

    $('exportBtn').addEventListener('click', exportCsv);
    $('reportsExportBtn').addEventListener('click', exportCsv);

    document.querySelectorAll('.sim-btn').forEach(b => {
        b.addEventListener('click', () => simulate(b.dataset.type, b));
    });

    $('confirmMitigate').addEventListener('click', mitigate);
    $('cancelMitigate').addEventListener('click', closeMitigation);

    $('confirmModal').addEventListener('click', e => {
        if (e.target === $('confirmModal')) {
            closeMitigation();
        }
    });

    $('chatForm').addEventListener('submit', e => {
        e.preventDefault();
        sendChatFrom($('chatInput'), $('chatLog'), $('sendChat'));
    });

    document.querySelectorAll('.quick-btn').forEach(b => {
        b.addEventListener('click', () => {
            const map = {
                critical: 'Summarize active critical alerts',
                dangerous_ip: 'Which source IP appears most often?',
                suggestion: 'Recommend defensive investigation steps'
            };

            $('chatInput').value = map[b.dataset.q] || b.textContent;

            sendChatFrom(
                $('chatInput'),
                $('chatLog'),
                $('sendChat')
            );
        });
    });

    $('themeToggle').addEventListener('click', async () => {
        settings.theme =
            document.documentElement.dataset.theme === 'dark'
                ? 'light'
                : 'dark';

        document.documentElement.dataset.theme = settings.theme;

        try {
            await api('/api/settings', {
                method: 'POST',
                body: JSON.stringify({ theme: settings.theme })
            });
        } catch (e) {}

        updateCharts();
    });

    $('menuToggle').addEventListener('click', () => {
        $('sidebar').classList.toggle('open');
    });

    $('notificationBtn').addEventListener('click', showNotifications);

    $('settingsForm').addEventListener('submit', saveSettings);

    $('resetSettings').addEventListener('click', async () => {
        try {
            settings = await api('/api/settings', {
                method: 'POST',
                body: JSON.stringify({
                    theme: 'dark',
                    compact_mode: false,
                    refresh_interval: 30,
                    notifications: true,
                    analyst_name: 'Security Analyst'
                })
            });

            await loadSettingsForm();
            applySettings();

            toast('Settings reset to defaults.');

        } catch (e) {
            toast(e.message, 'error');
        }
    });
});