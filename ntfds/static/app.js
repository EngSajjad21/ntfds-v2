'use strict';
/* NTFDS dashboard — vanilla JS, no build step, no CDN (works fully offline except map tiles). */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const store = {
  get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
};
let lang = store.get('ntfds.lang', (navigator.language || '').startsWith('ar') ? 'ar' : 'en');
const t = k => (I18N[lang] && I18N[lang][k]) || I18N.en[k] || k;

const STATUS_COLOR = { Online: '--ok', Warning: '--warn', Offline: '--bad', Unreachable: '--unr', Maintenance: '--maint', Unknown: '--unk' };
const cssv = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

/* ───────── state ───────── */
const S = { devices: new Map(), sel: null, range: '1h', summary: null, filters: { q: '', status: '', group: '' }, tab: 'overview', openInc: 0 };
let map, markers = new Map(), chart, socket, discTimer, rafId = 0;

/* ───────── helpers ───────── */
function fmtDur(s) {
  s = Math.max(0, Math.round(s)); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : m ? `${m}m ${s % 60}s` : `${s}s`;
}
const ago = iso => iso ? fmtDur((Date.now() - new Date(iso)) / 1000) : '—';
const LTR = x => `\u2066${x}\u2069`;   // keep numbers left-to-right inside RTL text
const ms = v => v == null ? '—' : LTR(`${Math.round(v * 10) / 10} ms`);
const pct = v => v == null ? '—' : LTR(`${v}%`);
const when = iso => iso ? new Date(iso).toLocaleString(lang === 'ar' ? 'ar-IQ' : undefined, { dateStyle: 'short', timeStyle: 'medium' }) : '—';
const pill = s => `<span class="pill s-${s}">${esc(t('s_' + s))}</span>`;

function toast(title, body = '', kind = '') {
  const el = document.createElement('div'); el.className = 'toast ' + kind;
  el.innerHTML = `<b>${esc(title)}</b>${body ? esc(body) : ''}`;
  $('#toasts').append(el); setTimeout(() => el.remove(), kind === 'bad' ? 9000 : 5000);
}

async function api(path, opt = {}, retry = true) {
  const headers = { ...(opt.headers || {}) };
  if (opt.json !== undefined) { headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(opt.json); }
  const tok = store.get('ntfds.token', '');
  if (tok) headers.Authorization = 'Bearer ' + tok;
  const res = await fetch(path, { ...opt, headers });
  if (res.status === 401 && retry) { await askToken(); return api(path, opt, false); }
  if (opt.raw) return res;
  let data = null; try { data = await res.json(); } catch { /* empty */ }
  if (!res.ok) throw new Error((data && (data.error || data.message)) || res.statusText);
  return data;
}
function askToken() {
  return new Promise(r => { const d = $('#tokDlg'); d.addEventListener('close', () => { store.set('ntfds.token', $('#tokInput').value.trim()); if (socket) { socket.auth = { token: store.get('ntfds.token', '') }; socket.connect(); } r(); }, { once: true }); d.showModal(); });
}
async function download(url, name) {
  const res = await api(url, { raw: true }); const blob = await res.blob();
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: name }); a.click(); URL.revokeObjectURL(a.href);
}

/* ───────── i18n / theme ───────── */
function applyI18n() {
  document.documentElement.lang = lang; document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  $$('[data-i18n]').forEach(el => {
    const txt = t(el.dataset.i18n), tn = [...el.childNodes].find(n => n.nodeType === 3 && n.textContent.trim());
    if (tn) tn.textContent = txt + ' '; else if (!el.children.length) el.textContent = txt; else el.prepend(txt);
  });
  $$('[data-i18n-ph]').forEach(el => el.placeholder = t(el.dataset.i18nPh));
  $('#langBtn').textContent = lang === 'ar' ? 'EN' : 'عربي';
  fillStatusFilter();
  $('#connTxt').textContent = $('#conn').classList.contains('on') ? t('live') : t('offline');
}
function setTheme(th) { document.documentElement.dataset.theme = th; store.set('ntfds.theme', th); if (chart) loadMetrics(); }
setTheme(store.get('ntfds.theme', matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));

/* ───────── map ───────── */
const BLANK_TILE = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
function initMap() {
  map = L.map('map', { zoomControl: true }).setView([33.3152, 44.3661], 5);
  const url = $('#map').dataset.tile;
  if (!url) return;                                   // tiles disabled → grid background only
  let ok = 0, bad = 0;
  const tiles = L.tileLayer(url, {
    attribution: '© OpenStreetMap contributors', maxZoom: 19,
    referrerPolicy: 'strict-origin-when-cross-origin',  // tile servers reject requests without a Referer
    errorTileUrl: BLANK_TILE,                           // never show a provider's error image
  }).addTo(map);
  tiles.on('tileload', () => ok++);
  tiles.on('tileerror', () => { bad++; if (bad >= 4 && ok === 0) { map.removeLayer(tiles); $('#map').classList.add('no-tiles'); } });
}
function updateMarker(d) {
  const ok = d.latitude != null && d.longitude != null;
  if (!ok) { if (markers.has(d.id)) { map.removeLayer(markers.get(d.id)); markers.delete(d.id); } return; }
  const color = cssv(STATUS_COLOR[d.last_status] || '--unk');
  let m = markers.get(d.id);
  if (!m) {
    m = L.circleMarker([d.latitude, d.longitude], { radius: 9, weight: 3, fillOpacity: .85 }).addTo(map);
    m.on('click', () => selectDevice(d.id)); markers.set(d.id, m);
  } else m.setLatLng([d.latitude, d.longitude]);
  m.setStyle({ color, fillColor: color });
  m.bindTooltip(`<b>${esc(d.name)}</b><br>${esc(d.host)} · ${esc(t('s_' + d.last_status))}<br>${ms(d.last_response_time)}`);
}
function syncMarkers(fit = false) {
  const ids = new Set(S.devices.keys());
  for (const id of [...markers.keys()]) if (!ids.has(id)) { map.removeLayer(markers.get(id)); markers.delete(id); }
  S.devices.forEach(updateMarker);
  $('#mapHint').classList.toggle('hide', markers.size > 0);
  if (fit && markers.size) map.fitBounds(L.featureGroup([...markers.values()]).getBounds().pad(.3), { maxZoom: 14 });
}

/* ───────── overview ───────── */
function counts() {
  const c = { Online: 0, Warning: 0, Offline: 0, Unreachable: 0, Maintenance: 0, Unknown: 0 };
  S.devices.forEach(d => c[d.last_status] = (c[d.last_status] || 0) + 1); return c;
}
function renderKpis() {
  const c = counts(), s = S.summary || {};
  const k = (label, val, color, unit = '') => `<div class="kpi" style="--c:var(${color})"><small>${esc(label)}</small><b>${val}</b>${unit ? `<em>${unit}</em>` : ''}</div>`;
  $('#kpis').innerHTML =
    k(t('kpi_total'), S.devices.size, '--accent') + k(t('kpi_online'), c.Online, '--ok') + k(t('kpi_warning'), c.Warning, '--warn') +
    k(t('kpi_offline'), c.Offline + c.Unreachable, '--bad') +
    k(t('kpi_latency'), s.avg_latency ?? '—', '--accent', s.avg_latency != null ? 'ms' : '') +
    k(t('kpi_uptime'), s.uptime_24h ?? '—', '--ok', s.uptime_24h != null ? '%' : '') + k(t('kpi_incidents'), s.open_incidents ?? 0, '--bad');
}
function fillStatusFilter() {
  const sel = $('#fStatus'), cur = sel.value;
  sel.innerHTML = `<option value="">${esc(t('all_status'))}</option>` + Object.keys(STATUS_COLOR).map(s => `<option value="${s}">${esc(t('s_' + s))}</option>`).join('');
  sel.value = cur;
  const g = $('#fGroup'), gc = g.value, groups = [...new Set([...S.devices.values()].map(d => d.group).filter(Boolean))].sort();
  g.innerHTML = `<option value="">${esc(t('all_groups'))}</option>` + groups.map(x => `<option>${esc(x)}</option>`).join(''); g.value = groups.includes(gc) ? gc : '';
}
function filtered() {
  const { q, status, group } = S.filters, ql = q.toLowerCase();
  const order = { Offline: 0, Unreachable: 1, Warning: 2, Unknown: 3, Maintenance: 4, Online: 5 };
  return [...S.devices.values()].filter(d => (!status || d.last_status === status) && (!group || d.group === group) &&
    (!ql || (d.name + d.host + (d.group || '')).toLowerCase().includes(ql)))
    .sort((a, b) => (order[a.last_status] - order[b.last_status]) || a.name.localeCompare(b.name));
}
function renderList() {
  const list = filtered();
  $('#devList').innerHTML = list.length ? list.map(d => `
    <div class="dev s-${d.last_status} ${S.sel === d.id ? 'sel' : ''}" data-id="${d.id}" tabindex="0" role="button">
      <span class="dot"></span><span class="n">${esc(d.name)}</span>
      <span class="m"><b>${d.last_status === 'Offline' || d.last_status === 'Unreachable' ? esc(t('s_' + d.last_status)) : ms(d.last_response_time)}</b>${d.last_checked ? ago(d.last_checked) : '—'}</span>
      <span class="h">${esc(d.host)}${d.check_type !== 'icmp' ? ` · ${esc(d.check_type)}${d.port ? ':' + d.port : ''}` : ''}${d.group ? ' · ' + esc(d.group) : ''}</span>
    </div>`).join('') : `<div class="empty">${esc(t('none'))}</div>`;
}
const scheduleRender = () => { if (!rafId) rafId = requestAnimationFrame(() => { rafId = 0; renderKpis(); renderList(); syncMarkers(); if (S.tab === 'topology') renderTopology(); }); };

$('#devList').addEventListener('click', e => { const r = e.target.closest('.dev'); if (r) selectDevice(+r.dataset.id); });
$('#devList').addEventListener('keydown', e => { if (e.key === 'Enter') e.target.click(); });
['q', 'fStatus', 'fGroup'].forEach(id => $('#' + id).addEventListener('input', e => { S.filters[{ q: 'q', fStatus: 'status', fGroup: 'group' }[id]] = e.target.value; renderList(); }));

/* ───────── device detail ───────── */
async function selectDevice(id) {
  S.sel = id; switchTab('overview'); renderList();
  const d = S.devices.get(id); if (!d) return;
  const box = $('#detail'); box.classList.remove('hide');
  box.innerHTML = `<div id="dHead"></div><div id="dStats" class="stats"></div>
    <div class="inline" style="justify-content:space-between;margin-bottom:6px"><h3>${esc(t('latency'))}</h3>
      <div class="seg" id="rangeSeg">${['1h', '6h', '24h', '7d', '30d'].map(r => `<button data-r="${r}" class="${r === S.range ? 'on' : ''}">${r}</button>`).join('')}</div></div>
    <div class="chart-box"><canvas id="chart"></canvas></div><div id="dDiag"></div><div id="dInc"></div>`;
  chart = null; renderHead(); await loadMetrics(); loadDeviceIncidents();
  if (d.latitude != null && markers.has(id)) map.panTo([d.latitude, d.longitude]);
  box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}
function renderHead() {
  const d = S.devices.get(S.sel); if (!d) return;
  const parent = d.parent_id && S.devices.get(d.parent_id);
  $('#dHead').innerHTML = `<div class="d-head"><div><h2>${esc(d.name)} ${pill(d.last_status)}</h2>
      <div class="muted mono">${esc(d.host)} · ${esc(d.kind)}${d.group ? ' · ' + esc(d.group) : ''} · ${esc(d.check_type)}${d.port ? ':' + d.port : ''}${parent ? ` · ↑ ${esc(parent.name)}` : ''}</div>
      <div class="muted">${esc(d.last_detail || '')} · ${esc(t('since'))} ${ago(d.last_change)}</div></div>
    <div class="d-actions"><button class="primary" id="bCheck">${esc(t('check_now'))}</button><button id="bDiag">${esc(t('diagnose'))}</button>
      <button id="bMaint">${esc(d.maintenance ? t('maint_off') : t('maint_on'))}</button><button id="bEdit">${esc(t('edit'))}</button><button class="danger" id="bDel">${esc(t('delete'))}</button></div></div>`;
  $('#bCheck').onclick = async e => { e.target.disabled = true; try { await api(`/api/devices/${d.id}/check`, { method: 'POST' }); } catch (x) { toast('Error', x.message, 'bad'); } e.target.disabled = false; };
  $('#bDiag').onclick = async e => { e.target.disabled = true; $('#dDiag').innerHTML = `<div class="empty">…</div>`; try { $('#dDiag').innerHTML = renderDiagnosis(await api(`/api/devices/${d.id}/diagnose`, { method: 'POST' })); } catch (x) { $('#dDiag').innerHTML = ''; toast('Error', x.message, 'bad'); } e.target.disabled = false; };
  $('#bMaint').onclick = () => api(`/api/devices/${d.id}`, { method: 'PUT', json: { maintenance: !d.maintenance } }).catch(x => toast('Error', x.message, 'bad'));
  $('#bEdit').onclick = () => openDeviceDialog(d);
  $('#bDel').onclick = async () => { if (confirm(t('confirm_del'))) { await api(`/api/devices/${d.id}`, { method: 'DELETE' }); $('#detail').classList.add('hide'); S.sel = null; } };
}
async function loadMetrics() {
  if (!S.sel) return;
  const m = await api(`/api/devices/${S.sel}/metrics?range=${S.range}`);
  const s = m.stats, u = m.uptime;
  $('#dStats').innerHTML = [[t('uptime') + ' 24h', pct(u['24h'])], [t('uptime') + ' 7d', pct(u['7d'])], [t('uptime') + ' 30d', pct(u['30d'])],
    ['Avg', ms(s.avg)], ['Min / Max', `${s.min == null ? '—' : Math.round(s.min)} / ${s.max == null ? '—' : Math.round(s.max)}`], ['P95', ms(s.p95)], [t('jitter'), ms(s.avg_jitter)], [t('loss'), pct(s.avg_loss)]]
    .map(([a, b]) => `<div class="stat"><small>${esc(a)}</small><b>${b}</b></div>`).join('');
  const fmt = iso => { const d = new Date(iso); return ['7d', '30d'].includes(S.range) ? d.toLocaleDateString(undefined, { day: '2-digit', month: 'short' }) + ' ' + d.getHours() + 'h' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); };
  const pts = m.series, text = cssv('--muted'), grid = cssv('--line');
  const cfg = {
    data: {
      labels: pts.map(p => fmt(p.t)), datasets: [
        { type: 'line', label: t('latency') + ' (ms)', data: pts.map(p => p.latency), borderColor: cssv('--accent'), backgroundColor: cssv('--accent') + '22', fill: true, tension: .25, pointRadius: 0, borderWidth: 2, yAxisID: 'y' },
        { type: 'line', label: 'Max', data: pts.map(p => p.max), borderColor: cssv('--warn'), borderDash: [4, 4], pointRadius: 0, borderWidth: 1, yAxisID: 'y' },
        { type: 'bar', label: t('loss') + ' %', data: pts.map(p => p.down ? 100 : p.loss), backgroundColor: cssv('--bad') + 'aa', yAxisID: 'y1', barPercentage: 1, categoryPercentage: 1 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false, interaction: { mode: 'index', intersect: false },
      plugins: { legend: { labels: { color: text, boxWidth: 12 } } },
      scales: {
        x: { ticks: { color: text, maxTicksLimit: 8 }, grid: { display: false } },
        y: { beginAtZero: true, ticks: { color: text }, grid: { color: grid }, title: { display: true, text: 'ms', color: text } },
        y1: { position: 'right', min: 0, max: 100, display: false },
      },
    },
  };
  if (chart) chart.destroy();
  chart = new Chart($('#chart'), cfg);
}
$('#detail').addEventListener('click', e => { const b = e.target.closest('#rangeSeg button'); if (!b) return; S.range = b.dataset.r; $$('#rangeSeg button').forEach(x => x.classList.toggle('on', x === b)); loadMetrics(); });
async function loadDeviceIncidents() {
  if (!S.sel) return;
  const rows = await api(`/api/incidents?device_id=${S.sel}&limit=8`);
  $('#dInc').innerHTML = rows.length ? `<h3 style="margin:16px 0 6px">${esc(t('nav_incidents'))}</h3><div class="table-wrap"><table><tbody>${rows.map(i => `<tr><td>${incSev(i)}</td><td>${esc(i.kind.replace('_', ' '))}</td><td>${esc(i.message)}</td><td class="num">${when(i.started_at)}</td><td class="num">${fmtDur(i.duration)}${i.open ? ' ⏳' : ''}</td></tr>`).join('')}</tbody></table></div>` : '';
}
function renderDiagnosis(r) {
  const vk = 'verdict_' + r.verdict, vt = I18N.en[vk] ? t(vk) : r.verdict;
  return `<div class="diag"><div class="verdict">${esc(vt)}</div>
    ${r.findings.map(f => `<div class="finding ${esc(f.severity)}">${esc(f.text)}${f.fix ? `<small>→ ${esc(f.fix)}</small>` : ''}</div>`).join('')}
    ${r.steps.map(s => `<div class="step"><i>${s.ok ? '✅' : '❌'}</i><span>${esc(s.name)}</span><code>${esc(s.detail)}</code></div>`).join('')}</div>`;
}

/* ───────── device dialog ───────── */
function openDeviceDialog(d = null) {
  const dlg = $('#devDlg'), f = $('#devForm'), v = k => d && d[k] != null ? esc(d[k]) : '';
  const opt = (arr, cur) => arr.map(x => `<option ${x === cur ? 'selected' : ''}>${x}</option>`).join('');
  const kinds = S.summary?.kinds || ['other'], cts = S.summary?.check_types || ['icmp'];
  const parents = [...S.devices.values()].filter(x => !d || x.id !== d.id);
  f.innerHTML = `<h3 class="span2">${esc(t('f_title'))}</h3>
    <label>${t('f_name')}<input name="name" required maxlength="100" value="${v('name')}"></label>
    <label>${t('f_host')}<input name="host" required value="${v('host')}" placeholder="192.168.1.1"></label>
    <label>${t('f_kind')}<select name="kind">${opt(kinds, d?.kind || 'other')}</select></label>
    <label>${t('f_group')}<input name="group" value="${v('group')}" list="groupsDl"></label>
    <label>${t('f_check')}<select name="check_type">${opt(cts, d?.check_type || 'icmp')}</select></label>
    <label data-f="port">${t('f_port')}<input name="port" type="number" min="1" max="65535" value="${v('port')}"></label>
    <label data-f="arg" class="span2">${t('f_arg')}<input name="check_arg" value="${v('check_arg')}" placeholder="https://… / example.com"></label>
    <label>${t('f_parent')}<select name="parent_id"><option value="">${esc(t('none_parent'))}</option>${parents.map(p => `<option value="${p.id}" ${d?.parent_id === p.id ? 'selected' : ''}>${esc(p.name)}</option>`).join('')}</select></label>
    <label>${t('f_interval')}<input name="interval" type="number" min="2" value="${v('interval')}" placeholder="default"></label>
    <label>${t('f_wl')}<input name="warn_latency" type="number" min="1" value="${v('warn_latency')}" placeholder="default"></label>
    <label>${t('f_wloss')}<input name="warn_loss" type="number" min="1" max="100" value="${v('warn_loss')}" placeholder="default"></label>
    <label>${t('f_lat')}<input name="latitude" type="number" step="any" value="${v('latitude')}"></label>
    <label>${t('f_lng')}<input name="longitude" type="number" step="any" value="${v('longitude')}"></label>
    <label class="span2">${t('f_notes')}<textarea name="notes" rows="2">${v('notes')}</textarea></label>
    <label class="chk"><input type="checkbox" name="enabled" ${d?.enabled === false ? '' : 'checked'}> ${t('f_enabled')}</label>
    <div class="span2 row-end"><button type="button" id="dlgCancel">${esc(t('cancel'))}</button><button class="primary">${esc(t('save'))}</button></div>
    <datalist id="groupsDl">${[...new Set([...S.devices.values()].map(x => x.group).filter(Boolean))].map(g => `<option>${esc(g)}</option>`).join('')}</datalist>`;
  const sync = () => { const c = f.check_type.value; f.querySelector('[data-f=port]').classList.toggle('hide', !['tcp', 'http'].includes(c)); f.querySelector('[data-f=arg]').classList.toggle('hide', !['http', 'dns'].includes(c)); };
  f.check_type.onchange = sync; sync();
  $('#dlgCancel').onclick = () => dlg.close();
  f.onsubmit = async e => {
    e.preventDefault();
    const o = {}; new FormData(f).forEach((val, k) => { o[k] = val; }); o.enabled = f.enabled.checked;
    ['port', 'interval', 'warn_latency', 'warn_loss', 'latitude', 'longitude', 'parent_id'].forEach(k => { o[k] = o[k] === '' ? null : Number(o[k]); });
    try { const res = await api(d ? `/api/devices/${d.id}` : '/api/devices', { method: d ? 'PUT' : 'POST', json: o }); dlg.close(); if (!d) toast(res.name, '✔', 'ok'); }
    catch (x) { toast('Error', x.message, 'bad'); }
  };
  dlg.showModal();
}
$('#addBtn').onclick = () => openDeviceDialog();

/* ───────── topology ───────── */
function renderTopology() {
  const devs = [...S.devices.values()], by = new Map(devs.map(d => [d.id, d])), kids = new Map();
  devs.forEach(d => { const p = d.parent_id && by.has(d.parent_id) ? d.parent_id : 0; (kids.get(p) || kids.set(p, []).get(p)).push(d); });
  const roots = kids.get(0) || [], trees = roots.filter(r => kids.has(r.id)), solo = roots.filter(r => !kids.has(r.id));
  const W = 158, H = 48, GX = 22, GY = 74; let leaf = 0, maxDepth = 0; const pos = new Map();
  const place = (n, depth) => {
    maxDepth = Math.max(maxDepth, depth); const ch = (kids.get(n.id) || []).slice().sort((a, b) => a.name.localeCompare(b.name));
    if (!ch.length) { pos.set(n.id, { x: leaf++ * (W + GX), y: depth * (H + GY) }); return; }
    ch.forEach(c => place(c, depth + 1));
    pos.set(n.id, { x: (pos.get(ch[0].id).x + pos.get(ch[ch.length - 1].id).x) / 2, y: depth * (H + GY) });
  };
  trees.forEach(r => place(r, 0));
  const treeW = Math.max(leaf, 1) * (W + GX), soloY = trees.length ? (maxDepth + 1) * (H + GY) + 20 : 0, perRow = Math.max(Math.floor(Math.max(treeW, 900) / (W + GX)), 1);
  solo.forEach((d, i) => pos.set(d.id, { x: (i % perRow) * (W + GX), y: soloY + Math.floor(i / perRow) * (H + 22) }));
  const width = Math.max(treeW, Math.min(solo.length, perRow) * (W + GX)), height = soloY + Math.ceil(solo.length / perRow) * (H + 22) + (trees.length ? 0 : 0) + 20;
  if (!devs.length) { $('#topo').innerHTML = `<div class="empty">${esc(t('none'))}</div>`; return; }
  const edges = devs.filter(d => d.parent_id && pos.has(d.parent_id) && pos.has(d.id)).map(d => {
    const a = pos.get(d.parent_id), b = pos.get(d.id), x1 = a.x + W / 2, y1 = a.y + H, x2 = b.x + W / 2, y2 = b.y, my = (y1 + y2) / 2;
    const bad = ['Offline', 'Unreachable'].includes(d.last_status);
    return `<path class="edge ${bad ? 'bad' : ''}" d="M${x1} ${y1} C${x1} ${my},${x2} ${my},${x2} ${y2}"/>`;
  }).join('');
  const nodes = devs.map(d => { const p = pos.get(d.id), n = (kids.get(d.id) || []).length;
    return `<g class="node s-${d.last_status}" data-id="${d.id}" transform="translate(${p.x} ${p.y})" style="--c:var(${STATUS_COLOR[d.last_status]})"><title>${esc(d.name)} — ${esc(d.last_status)}</title>
      <rect width="${W}" height="${H}" rx="9"/><circle cx="14" cy="${H / 2}" r="5" fill="var(--c)"/>
      <text x="26" y="20" font-weight="600">${esc(d.name.length > 18 ? d.name.slice(0, 17) + '…' : d.name)}</text>
      <text x="26" y="35" class="sub">${esc(d.host.length > 20 ? d.host.slice(0, 19) + '…' : d.host)}${n ? ` · ${n}↓` : ''}</text></g>`; }).join('');
  $('#topo').innerHTML = `<svg width="${width + 4}" height="${height + 4}" viewBox="-2 -2 ${width + 4} ${height + 4}">${edges}${nodes}</svg>`;
}
$('#topo').addEventListener('click', e => { const n = e.target.closest('.node'); if (n) selectDevice(+n.dataset.id); });

/* ───────── incidents ───────── */
const incSev = i => `<span class="pill s-${i.severity === 'critical' ? 'Offline' : 'Warning'}">${esc(i.severity)}</span>`;
async function loadIncidents() {
  const f = $('#incFilter').value, rows = await api('/api/incidents?limit=200' + (f ? '&status=' + f : ''));
  $('#incTable tbody').innerHTML = rows.length ? rows.map(i => `<tr><td>${incSev(i)}</td><td><a href="#" data-dev="${i.device_id}">${esc(i.device_name)}</a></td><td>${esc(i.kind.replace('_', ' '))}${i.suppressed ? ' 🔕' : ''}</td><td>${esc(i.message)}</td><td class="num">${when(i.started_at)}</td><td class="num">${fmtDur(i.duration)}${i.open ? ' ⏳' : ''}</td>
    <td>${i.open && !i.acknowledged ? `<button data-ack="${i.id}">${esc(t('ack'))}</button>` : i.acknowledged ? `<span class="muted">✓ ${esc(t('acked'))}</span>` : ''}</td></tr>`).join('') : `<tr><td colspan="7" class="empty">${esc(t('none'))}</td></tr>`;
}
$('#incFilter').onchange = loadIncidents;
$('#incTable').addEventListener('click', async e => {
  const a = e.target.closest('[data-ack]'), l = e.target.closest('[data-dev]');
  if (a) { await api(`/api/incidents/${a.dataset.ack}/ack`, { method: 'POST' }); loadIncidents(); }
  if (l) { e.preventDefault(); selectDevice(+l.dataset.dev); }
});
async function refreshSummary() { try { S.summary = await api('/api/summary'); S.openInc = S.summary.open_incidents; const b = $('#incBadge'); b.textContent = S.openInc; b.classList.toggle('hide', !S.openInc); document.title = (S.openInc ? `(${S.openInc}) ` : '') + 'NTFDS — Network Operations'; renderKpis(); } catch { /* ignore */ } }

/* ───────── tools ───────── */
const TOOL_HINT = { ports: ['22,80,443,8000-8010 (empty = common ports)', true], dns: ['DNS server (optional, e.g. 1.1.1.1)', true], ping: ['', false], traceroute: ['', false], http: ['', false], diagnose: ['', false] };
$('#toolSel').onchange = e => { const [ph, show] = TOOL_HINT[e.target.value]; const x = $('#toolExtra'); x.placeholder = ph; x.classList.toggle('hide', !show); $('#toolTarget').placeholder = e.target.value === 'http' ? 'https://example.com' : 'host / IP'; };
$('#toolForm').onsubmit = async e => {
  e.preventDefault(); const tool = $('#toolSel').value, target = $('#toolTarget').value.trim(), extra = $('#toolExtra').value.trim(), out = $('#toolOut');
  const body = { target }; if (tool === 'ports' && extra) body.ports = extra; if (tool === 'dns' && extra) body.server = extra;
  $('#toolGo').disabled = true; out.className = 'tool-out muted'; out.textContent = '…';
  try { const r = await api('/api/tools/' + tool, { method: 'POST', json: body }); out.className = 'tool-out'; out.innerHTML = renderTool(tool, r); }
  catch (x) { out.className = 'tool-out'; out.innerHTML = `<div class="finding critical">${esc(x.message)}</div>`; }
  $('#toolGo').disabled = false;
};
function renderTool(tool, r) {
  if (tool === 'diagnose') return renderDiagnosis(r);
  if (tool === 'ping') return `${pill(r.ok ? 'Online' : 'Offline')} <span class="chip">avg ${ms(r.latency)}</span><span class="chip">loss ${pct(r.loss)}</span><span class="chip">jitter ${ms(r.jitter)}</span><span class="chip">${esc(r.detail)}</span>`;
  if (tool === 'traceroute') return !r.available ? `<div class="finding warning">${esc(r.error)}</div>` : `<div class="diag">${r.hops.map(h => `<div class="hop"><span>${h.hop}</span><span>${esc(h.ip || '*')}</span><span>${ms(h.rtt)}</span></div>`).join('') || esc(r.error || '')}</div>`;
  if (tool === 'dns') return r.ok ? `${r.records.map(x => `<span class="chip">${x.type} ${esc(x.value)}</span>`).join('')}<span class="chip">${ms(r.latency)}</span>${r.reverse ? `<span class="chip">PTR ${esc(r.reverse)}</span>` : ''}${r.rcode != null ? `<span class="chip">rcode ${r.rcode} · ${r.answers} answers</span>` : ''}` : `<div class="finding critical">${esc(r.error || 'rcode ' + r.rcode)}</div>`;
  if (tool === 'ports') return `<p>${r.scanned} scanned · <b>${r.open.length}</b> open · ${r.closed} closed · ${r.filtered} filtered</p>` + (r.open.length ? `<div class="diag">${r.open.map(p => `<div class="step"><i>🟢</i><b>${p.port}</b><span>${esc(p.service || '')}</span><code>${esc(p.banner || '')} ${ms(p.ms)}</code></div>`).join('')}</div>` : '');
  if (tool === 'http') return `${pill(r.ok ? 'Online' : 'Offline')} <span class="chip">${esc(r.detail)}</span><span class="chip">${ms(r.latency)}</span>${r.server ? `<span class="chip">Server: ${esc(r.server)}</span>` : ''}${r.ssl_days != null ? `<span class="chip">TLS ${r.ssl_days} d left</span>` : ''}`;
  return `<pre>${esc(JSON.stringify(r, null, 2))}</pre>`;
}

/* ───────── discovery ───────── */
$('#discForm').onsubmit = async e => {
  e.preventDefault(); clearInterval(discTimer);
  try {
    const job = await api('/api/discovery', { method: 'POST', json: { cidr: $('#discCidr').value.trim() || undefined } });
    $('#discProg').classList.remove('hide'); $('#discTable').classList.add('hide'); $('#discAdd').classList.add('hide');
    const poll = async () => {
      const j = await api('/api/discovery/' + job.id); $('#discProg div').style.width = Math.round(100 * j.done / j.total) + '%';
      if (j.state === 'done') { clearInterval(discTimer); $('#discProg').classList.add('hide'); renderDiscovery(j); }
    };
    discTimer = setInterval(() => poll().catch(x => { clearInterval(discTimer); toast('Error', x.message, 'bad'); }), 800);
  } catch (x) { toast('Error', x.message, 'bad'); }
};
function renderDiscovery(j) {
  $('#discTable tbody').innerHTML = j.found.map(h => `<tr><td><input type="checkbox" data-ip="${esc(h.ip)}" data-name="${esc(h.hostname || '')}" ${h.known ? 'disabled' : 'checked'}></td><td class="mono">${esc(h.ip)}</td><td>${esc(h.hostname || '—')}</td><td class="mono">${esc(h.mac || '—')}</td><td class="num">${ms(h.latency)}</td><td>${h.known ? '✓ monitored' : ''}</td></tr>`).join('') || `<tr><td colspan="6" class="empty">${esc(t('none'))}</td></tr>`;
  $('#discTable').classList.remove('hide'); $('#discAdd').classList.toggle('hide', !j.found.some(h => !h.known));
}
$('#discAll').onchange = e => $$('#discTable tbody input:not(:disabled)').forEach(c => c.checked = e.target.checked);
$('#discAdd').onclick = async () => {
  const sel = $$('#discTable tbody input:checked'); let n = 0;
  for (const c of sel) { try { await api('/api/devices', { method: 'POST', json: { name: c.dataset.name || c.dataset.ip, host: c.dataset.ip } }); n++; c.disabled = true; } catch { /* dup */ } }
  toast(`${n} / ${sel.length}`, '✔', 'ok');
};

/* ───────── reports ───────── */
async function loadSla() {
  const days = $('#slaDays').value, r = await api('/api/reports/sla?days=' + days);
  const col = u => u == null ? '' : u >= 99.9 ? 'var(--ok)' : u >= 99 ? 'var(--warn)' : 'var(--bad)';
  $('#slaTable tbody').innerHTML = r.rows.map(x => `<tr><td><b>${esc(x.name)}</b><div class="muted mono">${esc(x.host)}</div></td><td class="num" style="color:${col(x.uptime)};font-weight:700">${x.uptime == null ? '—' : x.uptime + '%'}</td><td class="num">${x.incidents}</td><td class="num">${x.mttr == null ? '—' : fmtDur(x.mttr)}</td><td class="num">${fmtDur(x.downtime)}</td><td class="num">${ms(x.avg_latency)}</td><td class="num">${ms(x.p95)}</td><td class="num">${pct(x.avg_loss)}</td></tr>`).join('') || `<tr><td colspan="8" class="empty">${esc(t('none'))}</td></tr>`;
}
$('#slaDays').onchange = loadSla;
document.addEventListener('click', e => {
  const b = e.target.closest('[data-dl]'); if (!b) return;
  const url = b.id === 'slaCsv' ? b.dataset.dl + '&days=' + $('#slaDays').value : b.dataset.dl;
  download(url, url.includes('sla') ? 'sla.csv' : 'devices.csv').catch(x => toast('Error', x.message, 'bad'));
});
$('#importFile').onchange = async e => {
  const f = e.target.files[0]; if (!f) return; const txt = await f.text();
  try { const r = await api('/api/devices/import', f.name.endsWith('.json') ? { method: 'POST', json: JSON.parse(txt) } : { method: 'POST', headers: { 'Content-Type': 'text/csv' }, body: txt });
    toast(`+${r.added}`, r.skipped.length ? `${r.skipped.length} skipped` : '', r.skipped.length ? 'warn' : 'ok'); } catch (x) { toast('Error', x.message, 'bad'); }
  e.target.value = '';
};

/* ───────── settings & channels ───────── */
async function loadSettings() {
  const s = await api('/api/settings'), f = $('#setForm');
  f.innerHTML = Object.entries(s).map(([k, v]) => typeof v === 'boolean'
    ? `<label class="chk span2"><input type="checkbox" name="${k}" ${v ? 'checked' : ''}> ${esc(t('s_' + k))}</label>`
    : `<label>${esc(t('s_' + k))}<input name="${k}" type="number" step="any" min="0.1" value="${v}"></label>`).join('') + `<div class="span2"><button class="primary">${esc(t('save'))}</button></div>`;
  f.onsubmit = async e => { e.preventDefault(); const o = {}; new FormData(f).forEach((v, k) => o[k] = Number(v)); $$('input[type=checkbox]', f).forEach(c => o[c.name] = c.checked);
    try { await api('/api/settings', { method: 'PUT', json: o }); toast(t('saved'), '', 'ok'); } catch (x) { toast('Error', x.message, 'bad'); } };
  loadChannels();
}
async function loadChannels() {
  const rows = await api('/api/channels');
  $('#chList').innerHTML = rows.map(c => `<div class="ch"><b>${esc(c.name)} <span class="muted">· ${esc(c.type)} · ≥${esc(c.min_severity)}</span></b>
    <button data-test="${c.id}">Test</button><button data-tog="${c.id}">${c.enabled ? 'On' : 'Off'}</button><button class="danger" data-delch="${c.id}">✕</button></div>`).join('') || `<p class="muted">${esc(t('none'))}</p>`;
}
$('#chList').addEventListener('click', async e => {
  const b = e.target.closest('button'); if (!b) return;
  try {
    if (b.dataset.test) { const r = await api(`/api/channels/${b.dataset.test}/test`, { method: 'POST' }).catch(x => ({ ok: false, error: x.message })); toast(r.ok ? 'OK' : 'Failed', r.error || '', r.ok ? 'ok' : 'bad'); }
    if (b.dataset.tog) { const cur = b.textContent === 'On'; await api(`/api/channels/${b.dataset.tog}`, { method: 'PUT', json: { enabled: !cur } }); loadChannels(); }
    if (b.dataset.delch) { await api(`/api/channels/${b.dataset.delch}`, { method: 'DELETE' }); loadChannels(); }
  } catch (x) { toast('Error', x.message, 'bad'); }
});
const CH_FIELDS = { webhook: ['url'], slack: ['url'], discord: ['url'], telegram: ['bot_token', 'chat_id'], email: ['to'] };
$('#chForm').elements.type.onchange = e => $$('#chForm [data-f]').forEach(l => l.classList.toggle('hide', !CH_FIELDS[e.target.value].includes(l.dataset.f)));
$('#chForm').onsubmit = async e => {
  e.preventDefault(); const f = e.target, type = f.type.value, config = {}; CH_FIELDS[type].forEach(k => config[k] = f[k].value.trim());
  try { await api('/api/channels', { method: 'POST', json: { name: f.name.value, type, config, min_severity: f.min_severity.value } }); f.reset(); loadChannels(); } catch (x) { toast('Error', x.message, 'bad'); }
};

/* ───────── tabs ───────── */
function switchTab(name) {
  S.tab = name; $$('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === name)); $$('.tab').forEach(s => s.classList.toggle('on', s.id === 'tab-' + name));
  if (name === 'overview' && map) setTimeout(() => map.invalidateSize(), 50);
  if (name === 'topology') renderTopology(); if (name === 'incidents') loadIncidents(); if (name === 'reports') loadSla(); if (name === 'settings') loadSettings();
  if (name === 'tools') $('#toolTarget').focus();
}
$('#tabs').addEventListener('click', e => { const b = e.target.closest('button'); if (b) switchTab(b.dataset.tab); });
$('#langBtn').onclick = () => { lang = lang === 'ar' ? 'en' : 'ar'; store.set('ntfds.lang', lang); applyI18n(); renderKpis(); renderList(); if (S.sel) { renderHead(); loadMetrics(); } if (S.tab === 'settings') loadSettings(); };
$('#themeBtn').onclick = () => { setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'); scheduleRender(); };
$('#tokenBtn').onclick = askToken;

/* ───────── realtime ───────── */
function connect() {
  socket = io({ auth: { token: store.get('ntfds.token', '') }, reconnectionDelay: 1000, reconnectionDelayMax: 8000 });
  const state = on => { $('#conn').classList.toggle('on', on); $('#connTxt').textContent = on ? t('live') : t('offline'); };
  socket.on('connect', () => { state(true); fetchDevices(); refreshSummary(); });
  socket.on('disconnect', () => state(false));
  socket.on('connect_error', async () => { state(false); if (document.body.dataset.auth === 'on' && !store.get('ntfds.token')) await askToken(); });
  socket.on('device_update', ({ device }) => {
    const was = S.devices.get(device.id); S.devices.set(device.id, device); scheduleRender();
    if (S.sel === device.id) { renderHead(); if (S.range === '1h' && chart && !(was && was.last_checked === device.last_checked)) { /* keep chart fresh cheaply */ if (Date.now() - (chart._lastReload || 0) > 15000) { chart._lastReload = Date.now(); loadMetrics().then(() => chart && (chart._lastReload = Date.now())); } } }
  });
  ['device_added', 'device_updated', 'device_removed'].forEach(ev => socket.on(ev, async () => { await fetchDevices(); refreshSummary(); if (S.sel && !S.devices.has(S.sel)) { $('#detail').classList.add('hide'); S.sel = null; } else if (S.sel) renderHead(); }));
  socket.on('incident_opened', ev => { if (!ev.incident.suppressed) toast(`${t('inc_opened')}: ${ev.device.name}`, ev.incident.message, ev.incident.severity === 'critical' ? 'bad' : 'warn'); afterIncident(ev); });
  socket.on('incident_resolved', ev => { if (!ev.incident.suppressed) toast(`${t('inc_resolved')}: ${ev.device.name}`, '', 'ok'); afterIncident(ev); });
  socket.on('incident_ack', () => { if (S.tab === 'incidents') loadIncidents(); });
}
function afterIncident(ev) {
  refreshSummary(); if (S.tab === 'incidents') loadIncidents(); if (S.sel === ev.device.id) loadDeviceIncidents();
  if (ev.type === 'opened' && !ev.incident.suppressed && 'Notification' in window && Notification.permission === 'granted') new Notification(`${ev.device.name}: ${ev.incident.kind}`, { body: ev.incident.message });
}
async function fetchDevices() {
  const list = await api('/api/devices'), first = S.devices.size === 0;
  S.devices = new Map(list.map(d => [d.id, d])); fillStatusFilter(); renderKpis(); renderList(); syncMarkers(first); if (S.tab === 'topology') renderTopology();
}

/* ───────── boot ───────── */
(async function boot() {
  applyI18n(); initMap(); if (document.body.dataset.auth === 'on') $('#tokenBtn').classList.remove('hide');
  try { await fetchDevices(); await refreshSummary(); } catch (x) { toast('Error', x.message, 'bad'); }
  connect();
  setInterval(() => { renderList(); }, 15000);          // refresh "x ago" labels
  setInterval(refreshSummary, 30000);
  if ('Notification' in window && Notification.permission === 'default') $('#conn').addEventListener('click', () => Notification.requestPermission(), { once: true });
})();
