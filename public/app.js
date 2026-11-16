'use strict';
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const state = {
  step: 1, maxStep: 1,
  file: null,          // { name, size, text, items }
  session: null, host: '', policies: [],
  policy: null,        // selected policy object
  vulns: [], selected: new Set(),
};

/* ---------------------------------------------------------------- helpers */
function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v; else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(c));
  return e;
}
const sevBadge = t => el('span', { class: `sev ${t || 'info'}`, text: t || 'n/a' });
const sevRank = t => { const i = SEV_ORDER.indexOf(t); return i < 0 ? 99 : i; };

function toast(msg, kind = '') {
  const t = $('#toast'); t.textContent = msg; t.className = `toast ${kind}`;
  clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.add('hidden'), kind === 'err' ? 8000 : 3500);
}
function log(msg, kind = '') {
  $('#log').classList.remove('hidden');
  $('#logList').prepend(el('li', { class: kind }, el('time', { text: new Date().toLocaleTimeString() }), msg));
}
async function busy(text, fn) {
  $('#busyText').textContent = text; $('#busy').classList.remove('hidden');
  try { return await fn(); } finally { $('#busy').classList.add('hidden'); }
}
async function api(method, url, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.session) headers['X-Session'] = state.session;
  let r;
  try { r = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined }); }
  catch (e) { throw new Error('Cannot reach the local app server'); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    if (r.status === 401 && state.session && /session expired/i.test(j.error || '')) { resetSession(); goto(2); }
    throw new Error(j.error || `HTTP ${r.status}`);
  }
  return j;
}

/* ------------------------------------------------------------- navigation */
function goto(n) {
  state.step = n; state.maxStep = Math.max(state.maxStep, n);
  $$('[data-panel]').forEach(p => p.classList.toggle('hidden', Number(p.dataset.panel) !== n));
  $$('#steps li').forEach(li => {
    const k = Number(li.dataset.step);
    li.classList.toggle('active', k === n);
    li.classList.toggle('done', k < n || (k <= state.maxStep && k !== n && reachable(k)));
  });
}
function reachable(k) {
  if (k === 1) return true;
  if (k === 2) return !!state.file;
  if (k === 3) return !!state.session;
  if (k === 4) return state.vulns.length > 0;
  return false;
}
$$('#steps li').forEach(li => li.addEventListener('click', () => { const k = Number(li.dataset.step); if (k !== state.step && reachable(k)) goto(k); }));
$$('[data-go]').forEach(b => b.addEventListener('click', () => goto(Number(b.dataset.go))));

/* ---------------------------------------------------------- 1. scan file */
// Parse the generic scanner XML locally for a preview (BIG-IP does the real parsing).
function parseScan(text) {
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  if (doc.querySelector('parsererror')) throw new Error('Not a well-formed XML file');
  const nodes = [...doc.getElementsByTagName('vulnerability')];
  if (!nodes.length) throw new Error('No <vulnerability> elements found — is this a scanner export?');
  const g = (n, tag) => { const c = [...n.children].find(x => x.localName === tag); return c ? c.textContent.trim() : ''; };
  return nodes.map(n => ({
    name: g(n, 'name'), url: g(n, 'url'), parameter: g(n, 'parameter') || g(n, 'cookie'),
    attackType: g(n, 'attack_type'), threat: g(n, 'threat').toLowerCase(), score: g(n, 'score'),
  }));
}

function loadFile(f) {
  if (!f) return;
  const rd = new FileReader();
  rd.onload = () => {
    try {
      const items = parseScan(rd.result);
      state.file = { name: f.name, size: f.size, text: rd.result, items };
      renderFile();
    } catch (e) { state.file = null; renderFile(); toast(e.message, 'err'); }
  };
  rd.readAsText(f);
}
function renderFile() {
  const f = state.file;
  $('#filePreview').classList.toggle('hidden', !f);
  $('#to2').disabled = !f;
  if (!f) return;
  $('#fileName').textContent = f.name;
  $('#fileInfo').textContent = `${(f.size / 1024).toFixed(1)} KB · ${f.items.length} findings`;
  const counts = {}; f.items.forEach(i => counts[i.threat || 'n/a'] = (counts[i.threat || 'n/a'] || 0) + 1);
  $('#sevSummary').replaceChildren(...Object.entries(counts).sort((a, b) => sevRank(a[0]) - sevRank(b[0]))
    .map(([k, v]) => el('span', { class: `chip c-${k}`, text: `${v} ${k}` })));
  const body = $('#previewTable tbody');
  body.replaceChildren(...[...f.items].sort((a, b) => sevRank(a.threat) - sevRank(b.threat)).map(i =>
    el('tr', {}, el('td', {}, sevBadge(i.threat)), el('td', { text: i.name }), el('td', { class: 'url', text: i.url }), el('td', { text: i.parameter }), el('td', { text: i.attackType }))));
}
const drop = $('#drop'), fileInput = $('#file');
drop.addEventListener('click', () => fileInput.click());
drop.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
fileInput.addEventListener('change', () => loadFile(fileInput.files[0]));
['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', e => loadFile(e.dataTransfer.files[0]));
$('#btnClearFile').addEventListener('click', () => { state.file = null; fileInput.value = ''; renderFile(); });
$('#to2').addEventListener('click', () => { if (!domains.list.length || state.file.name !== domains.forFile) { initDomains(); domains.forFile = state.file.name; } goto(2); });

/* ------------------------------------------------------- 2. connect BIG-IP */
function resetSession() {
  state.session = null; state.policies = []; state.policy = null; state.vulns = []; state.selected.clear();
  $('#conn').classList.add('hidden'); renderPolicies(); renderVulns();
}
$('#connForm').addEventListener('submit', async e => {
  e.preventDefault();
  try {
    const r = await busy('Connecting to BIG-IP…', () => api('POST', '/api/connect', {
      host: $('#host').value, username: $('#username').value, password: $('#password').value, verifyTls: $('#verifyTls').checked,
    }));
    $('#password').value = '';
    Object.assign(state, { session: r.session, host: r.host, policies: r.policies, policy: null });
    $('#connText').textContent = `${r.host}${r.version ? ' · v' + r.version : ''}`;
    $('#conn').classList.remove('hidden');
    log(`Connected to ${r.host} — ${r.policies.length} policies found`, 'ok');
    renderPolicies(); goto(3);
  } catch (err) { toast(err.message, 'err'); log(err.message, 'err'); }
});
$('#btnDisconnect').addEventListener('click', async () => {
  try { await api('POST', '/api/disconnect'); } catch { /* ignore */ }
  resetSession(); log('Disconnected'); goto(2);
});

/* ---------------------------------------------------- 3. policy + import */
function renderPolicies() {
  const q = $('#polFilter').value.toLowerCase();
  const rows = state.policies.filter(p => `${p.name} ${p.fullPath} ${p.id}`.toLowerCase().includes(q));
  const body = $('#polTable tbody');
  if (!rows.length) { body.replaceChildren(el('tr', {}, el('td', { colspan: 6, class: 'empty', text: state.policies.length ? 'No match' : 'No WAF policies on this device' }))); }
  else body.replaceChildren(...rows.map(p => {
    const sel = state.policy && state.policy.id === p.id;
    const tr = el('tr', { class: 'clickable' + (sel ? ' sel' : '') },
      el('td', {}, el('input', { type: 'radio', name: 'pol', ...(sel ? { checked: '' } : {}) })),
      el('td', { text: p.fullPath || p.name }), el('td', { class: 'url', text: p.id }),
      el('td', { text: p.enforcementMode || '' }), el('td', { text: p.type || '' }),
      el('td', { text: p.virtualServers.join(', ') || '—' }));
    tr.addEventListener('click', () => { state.policy = p; renderPolicies(); });
    return tr;
  }));
  updateImportBtn();
}
// Domains: default = host names found in the scan URLs; BIG-IP can also be asked.
const domains = { list: [], checked: new Set() };
function hostOf(u) { try { return new URL(u).hostname; } catch { return ''; } }
function initDomains() {
  const hosts = [...new Set((state.file ? state.file.items : []).map(i => hostOf(i.url)).filter(Boolean))];
  domains.list = hosts; domains.checked = new Set(hosts); renderDomains();
}
function addDomain(d, checked = true) {
  d = d.trim(); if (!d) return;
  if (!domains.list.includes(d)) domains.list.push(d);
  if (checked) domains.checked.add(d);
}
function renderDomains() {
  const all = $('#domAll').checked;
  const box = $('#domList'); box.classList.toggle('off', all);
  box.replaceChildren(...(domains.list.length ? domains.list.map(d => el('label', { class: 'check' },
    el('input', { type: 'checkbox', ...(domains.checked.has(d) ? { checked: '' } : {}), onchange: e => { e.target.checked ? domains.checked.add(d) : domains.checked.delete(d); updateImportBtn(); } }), d))
    : [el('span', { class: 'note', text: 'No domain found in the scan — add one manually or ask BIG-IP.' })]));
  updateImportBtn();
}
function updateImportBtn() {
  $('#btnImport').disabled = !(state.policy && state.file && ($('#domAll').checked || domains.checked.size));
}
$$('input[name=domMode]').forEach(r => r.addEventListener('change', renderDomains));
$('#btnAddDom').addEventListener('click', () => { addDomain($('#domCustom').value); $('#domCustom').value = ''; renderDomains(); });
$('#domCustom').addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); $('#btnAddDom').click(); } });
$('#btnAskDom').addEventListener('click', async () => {
  if (!state.policy) return toast('Select a policy first', 'err');
  try {
    const r = await busy('Asking BIG-IP for the domain names in the scan…', () =>
      api('POST', `/api/policies/${encodeURIComponent(state.policy.id)}/domains`, { filename: state.file.name, content: state.file.text }));
    r.domains.forEach(d => addDomain(d)); renderDomains();
    log(`BIG-IP found ${r.domains.length} domain(s): ${r.domains.join(', ') || '—'}`, r.domains.length ? 'ok' : '');
    if (!r.domains.length) toast('BIG-IP returned no domain names — add them manually', 'err');
  } catch (e) { toast(e.message, 'err'); log(e.message, 'err'); }
});
$('#polFilter').addEventListener('input', renderPolicies);
$('#btnRefreshPol').addEventListener('click', async () => {
  try {
    const r = await busy('Scanning policies…', () => api('GET', '/api/policies'));
    state.policies = r.policies;
    if (state.policy && !r.policies.some(p => p.id === state.policy.id)) state.policy = null;
    renderPolicies(); log(`Policy list refreshed (${r.policies.length})`);
  } catch (e) { toast(e.message, 'err'); }
});
$('#btnImport').addEventListener('click', async () => {
  const p = state.policy;
  try {
    const r = await busy(`Uploading scan and importing into “${p.name}”… (this can take a minute)`, () =>
      api('POST', `/api/policies/${encodeURIComponent(p.id)}/import`, { filename: state.file.name, content: state.file.text, importAllDomainNames: $('#domAll').checked, domainNames: [...domains.checked] }));
    log(`Uploaded as ${r.uploadedAs}; import task ${r.task.id || ''} ${r.task.status || 'done'}`, 'ok');
    setVulns(r.vulnerabilities);
    log(`BIG-IP selected ${r.vulnerabilities.length} vulnerabilities in “${p.name}”`, 'ok');
    toast(`Imported — ${r.vulnerabilities.length} vulnerabilities in policy`, 'ok');
    goto(4);
  } catch (e) { toast(e.message, 'err'); log(e.message, 'err'); }
});

/* ------------------------------------------------------ 4. vulnerabilities */
const canSelect = v => !isDone(v) && v.resolvable !== false;
const isDone = v => {
  const s = String(v.status || '').toLowerCase();
  return /resolved|fixed|mitigated|closed/.test(s) || v.resolution === true;
};
function setVulns(list) {
  state.vulns = list; state.selected = new Set([...state.selected].filter(id => list.some(v => v.id === id && canSelect(v))));
  const statuses = [...new Set(list.map(v => v.status).filter(Boolean))];
  $('#vStatus').replaceChildren(el('option', { value: '', text: 'All statuses' }), ...statuses.map(s => el('option', { value: s, text: s })));
  renderVulns();
}
function visibleVulns() {
  const q = $('#vFilter').value.toLowerCase(), sev = $('#vSev').value, st = $('#vStatus').value;
  return state.vulns.filter(v =>
    (!sev || v.threat === sev) && (!st || v.status === st) && (!$('#vResOnly').checked || canSelect(v)) &&
    (!q || `${v.name} ${v.url} ${v.parameter} ${v.attackType}`.toLowerCase().includes(q)))
    .sort((a, b) => sevRank(a.threat) - sevRank(b.threat) || String(a.name).localeCompare(String(b.name)));
}
function renderVulns() {
  $('#polLabel').textContent = state.policy ? `· ${state.policy.fullPath || state.policy.name}` : '';
  const rows = visibleVulns();
  const body = $('#vTable tbody');
  if (!rows.length) body.replaceChildren(el('tr', {}, el('td', { colspan: 8, class: 'empty', text: state.vulns.length ? 'No match for the filters' : 'BIG-IP reported no vulnerabilities for this policy' })));
  else body.replaceChildren(...rows.map(v => {
    const done = !canSelect(v);
    const cb = el('input', { type: 'checkbox', ...(state.selected.has(v.id) ? { checked: '' } : {}), ...(done ? { disabled: '' } : {}) });
    const tr = el('tr', { class: (state.selected.has(v.id) ? 'sel ' : '') + (done ? 'resolved' : ''), title: isDone(v) ? 'Already resolved' : v.resolvable === false ? 'BIG-IP cannot resolve this vulnerability' : '' },
      el('td', {}, cb), el('td', {}, sevBadge(v.threat)),
      el('td', {}, v.name, v.score != null ? el('small', { class: 'note', text: `  (score ${v.score})` }) : null),
      el('td', { class: 'url', text: v.url || '' }), el('td', { text: v.parameter || '' }), el('td', { text: v.attackType || '' }), el('td', { text: v.status || '' }),
      el('td', {}, isDone(v) ? el('span', { class: 'note', text: 'resolved' }) : v.resolvable === false ? el('span', { class: 'tag no', text: 'not resolvable' }) : el('span', { class: 'tag yes', text: 'resolvable' })));
    const toggle = () => { state.selected.has(v.id) ? state.selected.delete(v.id) : state.selected.add(v.id); renderVulns(); };
    if (!done) { cb.addEventListener('click', e => { e.stopPropagation(); toggle(); }); tr.addEventListener('click', toggle); }
    return tr;
  }));
  const n = state.selected.size;
  $('#selCount').textContent = `${n} selected · ${rows.length}/${state.vulns.length} shown`;
  $('#btnResolve').disabled = n === 0;
  const sel = rows.filter(canSelect);
  $('#chkAll').checked = sel.length > 0 && sel.every(v => state.selected.has(v.id));
}
['#vFilter', '#vSev', '#vStatus', '#vResOnly'].forEach(s => $(s).addEventListener('input', renderVulns));
$('#btnSelAll').addEventListener('click', () => { visibleVulns().filter(canSelect).forEach(v => state.selected.add(v.id)); renderVulns(); });
$('#btnSelNone').addEventListener('click', () => { state.selected.clear(); renderVulns(); });
$('#chkAll').addEventListener('change', e => { visibleVulns().filter(canSelect).forEach(v => e.target.checked ? state.selected.add(v.id) : state.selected.delete(v.id)); renderVulns(); });
$('#btnReload').addEventListener('click', async () => {
  try {
    const r = await busy('Reloading…', () => api('GET', `/api/policies/${encodeURIComponent(state.policy.id)}/vulnerabilities`));
    setVulns(r.vulnerabilities); log('Vulnerabilities reloaded');
  } catch (e) { toast(e.message, 'err'); }
});
$('#btnResolve').addEventListener('click', async () => {
  const ids = [...state.selected];
  const apply = $('#optApply').checked;
  if (!confirm(`Resolve ${ids.length} vulnerabilities in policy “${state.policy.name}”?\n\nThis modifies the WAF policy on ${state.host}` + (apply ? ' and applies it (live traffic is affected).' : '. The policy will NOT be applied yet.'))) return;
  try {
    const r = await busy('Applying fixes to policy…', () => api('POST', `/api/policies/${encodeURIComponent(state.policy.id)}/resolve`,
      { vulnerabilityIds: ids, stage: $('#optStage').checked, applyPolicy: apply }));
    log(`Resolved ${ids.length} vulnerabilities (task ${r.task.id || ''} ${r.task.status || 'done'})${r.applied ? '; policy applied' : '; policy not applied'}`, 'ok');
    state.selected.clear(); setVulns(r.vulnerabilities);
    toast(`${ids.length} vulnerabilities resolved${r.applied ? ' and policy applied' : ''}`, 'ok');
  } catch (e) { toast(e.message, 'err'); log(e.message, 'err'); }
});
$('#btnRaw').addEventListener('click', () => {
  $('#rawPre').textContent = JSON.stringify(state.vulns.map(v => v.raw), null, 2);
  $('#rawDlg').showModal();
});
$('#btnCloseRaw').addEventListener('click', () => $('#rawDlg').close());
$('#btnCopyRaw').addEventListener('click', () => navigator.clipboard.writeText($('#rawPre').textContent).then(() => toast('Copied', 'ok')));
$('#btnClearLog').addEventListener('click', () => { $('#logList').replaceChildren(); $('#log').classList.add('hidden'); });

goto(1);
