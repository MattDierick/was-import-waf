'use strict';
/**
 * Scan → BIG-IP Advanced WAF importer — backend.
 * Zero dependencies. Serves the UI and proxies a small, purpose-built API to
 * the BIG-IP iControl REST interface (the browser can't call BIG-IP directly:
 * self-signed certs + CORS).
 *
 * BIG-IP endpoints used (ASM / Advanced WAF):
 *   POST /mgmt/shared/authn/login                          token auth
 *   GET  /mgmt/tm/asm/policies                             list policies
 *   POST /mgmt/tm/asm/file-transfer/uploads/<file>         upload scan file (chunked)
 *   POST /mgmt/tm/asm/tasks/import-vulnerabilities         import scan into policy
 *   GET  /mgmt/tm/asm/policies/<id>/vulnerabilities        list vulnerabilities
 *   POST /mgmt/tm/asm/tasks/resolve-vulnerabilities        resolve selected ones
 *   POST /mgmt/tm/asm/tasks/apply-policy                   (optional) apply policy
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1'; // local-only: this app handles device credentials
const MAX_BODY = 100 * 1024 * 1024;
const CHUNK = 512 * 1024;
const PUBLIC = path.join(__dirname, 'public');

const sessions = new Map(); // sid -> { host, port, verifyTls, username, password, token, agent }

/* ------------------------------------------------------------------ BIG-IP */

class BigIpError extends Error {
  constructor(status, message, body) { super(message); this.status = status; this.body = body; }
}

function rawRequest(s, method, urlPath, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: s.host, port: s.port, method, path: urlPath, agent: s.agent, timeout: 60000,
      headers: { Accept: 'application/json', ...headers },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
        resolve({ status: res.statusCode, json, text });
      });
    });
    req.on('timeout', () => req.destroy(new Error('Timeout talking to BIG-IP')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function login(s) {
  const r = await rawRequest(s, 'POST', '/mgmt/shared/authn/login', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: s.username, password: s.password, loginProviderName: 'tmos' }),
  });
  if (r.status === 200 && r.json && r.json.token && r.json.token.token) {
    s.token = r.json.token.token;
    return;
  }
  if (r.status === 401 || r.status === 403) throw new BigIpError(401, 'Authentication failed: bad username or password');
  throw new BigIpError(r.status || 502, `Login failed (HTTP ${r.status}): ${(r.json && r.json.message) || r.text.slice(0, 200)}`);
}

/** Authenticated call; re-logs in once if the token expired. Throws on non-2xx. */
async function bigip(s, method, urlPath, { json, raw, headers = {} } = {}) {
  const attempt = async () => {
    const h = { 'X-F5-Auth-Token': s.token, ...headers };
    let body;
    if (json !== undefined) { body = JSON.stringify(json); h['Content-Type'] = 'application/json'; }
    if (raw) body = raw;
    return rawRequest(s, method, urlPath, { headers: h, body });
  };
  let r = await attempt();
  if (r.status === 401) { await login(s); r = await attempt(); }
  if (r.status < 200 || r.status >= 300) {
    const msg = (r.json && (r.json.message || r.json.errorStack)) || r.text.slice(0, 300) || `HTTP ${r.status}`;
    throw new BigIpError(r.status, `BIG-IP ${method} ${urlPath.split('?')[0]} → ${r.status}: ${typeof msg === 'string' ? msg : JSON.stringify(msg)}`, r.json);
  }
  return r.json;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

/** Poll an ASM async task until it finishes. */
async function waitTask(s, kind, id, timeoutMs = 120000) {
  const t0 = Date.now();
  for (;;) {
    const t = await bigip(s, 'GET', `/mgmt/tm/asm/tasks/${kind}/${id}`);
    const st = String(t.status || '').toUpperCase();
    if (st === 'COMPLETED') return t;
    if (st === 'FAILURE' || st === 'FAILED') {
      const why = (t.result && (t.result.message || JSON.stringify(t.result))) || 'task failed';
      throw new BigIpError(422, `BIG-IP task ${kind} failed: ${why}`, t);
    }
    if (Date.now() - t0 > timeoutMs) throw new BigIpError(504, `Timed out waiting for task ${kind}/${id}`);
    await sleep(700);
  }
}

async function runTask(s, kind, payload) {
  const t = await bigip(s, 'POST', `/mgmt/tm/asm/tasks/${kind}`, { json: payload });
  return t.id ? waitTask(s, kind, t.id) : t;
}

const cleanDomains = a => [...new Set((Array.isArray(a) ? a : []).map(d => String(d).trim()).filter(Boolean))];

/** Find the domain list in a task result, whatever the exact shape/version. */
function extractDomains(task) {
  const found = [];
  const walk = (v, key) => {
    if (Array.isArray(v)) {
      if (/domain/i.test(key || '')) v.forEach(x => found.push(typeof x === 'string' ? x : (x && (x.name || x.domainName || x.domain))));
      else v.forEach(x => walk(x, key));
    } else if (v && typeof v === 'object') Object.entries(v).forEach(([k, x]) => walk(x, k));
    else if (typeof v === 'string' && /domain/i.test(key || '') && v) v.split(/[,\s]+/).forEach(x => found.push(x));
  };
  walk(task.result); walk(task.domainNames, 'domainNames');
  return cleanDomains(found.filter(Boolean));
}

const policyLink = id => ({ link: `https://localhost/mgmt/tm/asm/policies/${id}` });

/** Upload content to /var/config/rest/downloads/<name> using chunked Content-Range. */
async function uploadFile(s, name, buf) {
  const total = buf.length;
  for (let start = 0; start < total || (total === 0 && start === 0); start += CHUNK) {
    const end = Math.min(start + CHUNK, total) - 1;
    await bigip(s, 'POST', `/mgmt/tm/asm/file-transfer/uploads/${encodeURIComponent(name)}`, {
      raw: buf.subarray(start, end + 1),
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Range': `${start}-${end}/${total}`,
        'Content-Length': end - start + 1,
      },
    });
    if (total === 0) break;
  }
}

/* --------------------------------------------------------------- Normalising
 * The shape of ASM vulnerability objects varies a little by version, so we
 * flatten defensively and keep the raw object for the "details" view. */

function pick(o, ...keys) {
  for (const k of keys) {
    const v = k.split('.').reduce((a, p) => (a == null ? a : a[p]), o);
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}

/** id → name map of ASM attack types (BIG-IP often returns only a reference link). */
async function attackTypeMap(s) {
  if (s.attackTypes) return s.attackTypes;
  const map = {};
  try {
    for (let skip = 0; ; skip += 500) {
      const r = await bigip(s, 'GET', `/mgmt/tm/asm/attack-types?$top=500&$skip=${skip}`);
      const items = r.items || [];
      items.forEach(a => { if (a.id != null && a.name) map[String(a.id)] = a.name; });
      if (items.length < 500) break;
    }
  } catch { /* optional: fall back to whatever the vulnerability object carries */ }
  return (s.attackTypes = map);
}

function attackTypeNames(v, atMap) {
  const names = [];
  const add = x => {
    if (x == null || x === '') return;
    if (typeof x === 'string') {
      const m = x.match(/attack-types\/([^/?#]+)/);          // a link
      names.push(m ? (atMap[m[1]] || null) : x);
    } else if (Array.isArray(x)) x.forEach(add);
    else if (typeof x === 'object') {
      if (x.name) names.push(x.name);
      else if (x.attackTypeName) names.push(x.attackTypeName);
      else if (x.link) add(x.link);
      else if (x.id != null) names.push(atMap[String(x.id)] || null);
    }
  };
  ['attackType', 'attackTypes', 'attackTypeReference', 'attackTypeReferences', 'attack_type', 'attackTypeName']
    .forEach(k => add(v[k]));
  return [...new Set(names.filter(Boolean))];
}

/** BIG-IP flags vulnerabilities it cannot fix with resolveType 'not-resolvable'. */
const isNotResolvable = rt => /not[\s_-]*resolvable|unresolvable/i.test(String(rt || ''));

function normalizeVuln(v, atMap = {}) {
  const resolveType = pick(v, 'resolveType', 'resolutionType');
  const attack = attackTypeNames(v, atMap).join(', ') || undefined;
  return {
    id: pick(v, 'id', 'vulnerabilityId'),
    name: pick(v, 'name', 'vulnerabilityName', 'description') || attack || '(unnamed)',
    attackType: attack,
    url: pick(v, 'url', 'uri', 'path', 'detectionUrl'),
    parameter: pick(v, 'parameter.name', 'parameter', 'parameterName', 'cookie', 'cookieName'),
    threat: String(pick(v, 'threat', 'severity', 'riskLevel') || '').toLowerCase() || undefined,
    score: pick(v, 'score', 'cvss'),
    status: pick(v, 'status', 'state'),
    scanner: pick(v, 'scanner', 'scannerName', 'source'),
    resolution: pick(v, 'resolution', 'resolved', 'isResolved', 'mitigation'),
    resolveType,
    resolvable: !isNotResolvable(resolveType),
    raw: v,
  };
}

/* ------------------------------------------------------------------ HTTP API */

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(new BigIpError(413, 'Payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new BigIpError(400, 'Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}

function getSession(req) {
  const s = sessions.get(req.headers['x-session']);
  if (!s) throw new BigIpError(401, 'Not connected to a BIG-IP (session expired). Please reconnect.');
  s.lastUsed = Date.now();
  return s;
}

async function listPolicies(s) {
  const r = await bigip(s, 'GET', '/mgmt/tm/asm/policies?$top=500');
  return (r.items || []).map(p => ({
    id: p.id,
    name: p.name,
    fullPath: p.fullPath,
    type: p.type,
    enforcementMode: p.enforcementMode,
    active: p.active,
    template: p.templateReference ? p.templateReference.name : undefined,
    virtualServers: (p.virtualServers || []).map(v => v.split('/').pop()),
  })).sort((a, b) => String(a.fullPath || a.name).localeCompare(String(b.fullPath || b.name)));
}

async function listVulns(s, policyId) {
  const items = [];
  const page = 200;
  for (let skip = 0; ; skip += page) {
    const r = await bigip(s, 'GET', `/mgmt/tm/asm/policies/${encodeURIComponent(policyId)}/vulnerabilities?$top=${page}&$skip=${skip}`);
    const got = r.items || [];
    items.push(...got);
    if (got.length < page) break;
  }
  const atMap = await attackTypeMap(s);
  return items.map(v => normalizeVuln(v, atMap));
}

const routes = [
  // Connect: validate credentials, open session, return the policy list
  ['POST', /^\/api\/connect$/, async (req, res) => {
    const b = await readBody(req);
    const host = String(b.host || '').trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!host || !b.username || !b.password) throw new BigIpError(400, 'Address, username and password are required');
    const [h, p] = host.split(':');
    const s = {
      host: h, port: Number(b.port || p || 443), username: b.username, password: b.password,
      verifyTls: !!b.verifyTls, lastUsed: Date.now(),
    };
    s.agent = new https.Agent({ rejectUnauthorized: s.verifyTls, keepAlive: true });
    try { await login(s); }
    catch (e) {
      if (e instanceof BigIpError) throw e;
      throw new BigIpError(502, `Cannot reach ${s.host}:${s.port} — ${e.code || e.message}`);
    }
    const policies = await listPolicies(s);
    let version;
    try { version = (await bigip(s, 'GET', '/mgmt/shared/identified-devices/config/device-info')).version; } catch { /* optional */ }
    const sid = crypto.randomBytes(24).toString('hex');
    sessions.set(sid, s);
    send(res, 200, { session: sid, host: `${s.host}:${s.port}`, version, policies });
  }],

  ['POST', /^\/api\/disconnect$/, async (req, res) => {
    const sid = req.headers['x-session']; const s = sessions.get(sid);
    if (s) { s.agent.destroy(); sessions.delete(sid); }
    send(res, 200, { ok: true });
  }],

  ['GET', /^\/api\/policies$/, async (req, res) => send(res, 200, { policies: await listPolicies(getSession(req)) })],

  // Upload the scan file + import it into the chosen policy
  ['POST', /^\/api\/policies\/([^/]+)\/import$/, async (req, res, m) => {
    const s = getSession(req);
    const policyId = decodeURIComponent(m[1]);
    const b = await readBody(req);
    if (typeof b.content !== 'string' || !b.content.length) throw new BigIpError(400, 'Scan file content is empty');
    const safe = String(b.filename || 'scan.xml').replace(/[^\w.\-]/g, '_');
    const name = `scanimport_${Date.now()}_${safe}`;
    await uploadFile(s, name, Buffer.from(b.content, 'utf8'));
    // BIG-IP requires one of: importAllDomainNames, domainNames, onlyGetDomainNames
    const domains = cleanDomains(b.domainNames);
    if (!b.importAllDomainNames && !domains.length) throw new BigIpError(400, 'Select at least one domain (or choose "all domains")');
    const payload = { filename: name, policyReference: policyLink(policyId) };
    if (b.importAllDomainNames) payload.importAllDomainNames = true; else payload.domainNames = domains;
    const task = await runTask(s, 'import-vulnerabilities', payload);
    const vulnerabilities = await listVulns(s, policyId);
    send(res, 200, { uploadedAs: name, task: { id: task.id, status: task.status, result: task.result }, vulnerabilities });
  }],

  // Ask BIG-IP which domain names it finds in the scan (onlyGetDomainNames)
  ['POST', /^\/api\/policies\/([^/]+)\/domains$/, async (req, res, m) => {
    const s = getSession(req);
    const policyId = decodeURIComponent(m[1]);
    const b = await readBody(req);
    if (typeof b.content !== 'string' || !b.content.length) throw new BigIpError(400, 'Scan file content is empty');
    const name = `scandomains_${Date.now()}_${String(b.filename || 'scan.xml').replace(/[^\w.\-]/g, '_')}`;
    await uploadFile(s, name, Buffer.from(b.content, 'utf8'));
    const task = await runTask(s, 'import-vulnerabilities', {
      filename: name, policyReference: policyLink(policyId), onlyGetDomainNames: true,
    });
    send(res, 200, { domains: extractDomains(task), raw: task.result });
  }],

  ['GET', /^\/api\/policies\/([^/]+)\/vulnerabilities$/, async (req, res, m) =>
    send(res, 200, { vulnerabilities: await listVulns(getSession(req), decodeURIComponent(m[1])) })],

  // Resolve selected vulnerabilities (+ optionally apply the policy)
  ['POST', /^\/api\/policies\/([^/]+)\/resolve$/, async (req, res, m) => {
    const s = getSession(req);
    const policyId = decodeURIComponent(m[1]);
    const b = await readBody(req);
    const ids = Array.isArray(b.vulnerabilityIds) ? b.vulnerabilityIds : [];
    if (!ids.length) throw new BigIpError(400, 'No vulnerabilities selected');
    // Refuse anything BIG-IP cannot resolve (it would fail the whole task with a 500)
    const current = await listVulns(s, policyId);
    const byId = new Map(current.map(v => [String(v.id), v]));
    const unknown = ids.filter(id => !byId.has(String(id)));
    if (unknown.length) throw new BigIpError(409, `${unknown.length} selected vulnerabilit${unknown.length > 1 ? 'ies are' : 'y is'} no longer in the policy — reload and retry`);
    const blocked = ids.map(id => byId.get(String(id))).filter(v => !v.resolvable);
    if (blocked.length) throw new BigIpError(400, `Not resolvable by BIG-IP: ${blocked.map(v => v.name).join(', ')}`);
    const payload = {
      policyReference: policyLink(policyId),
      vulnerabilityReferences: ids.map(id => ({ link: `https://localhost/mgmt/tm/asm/policies/${policyId}/vulnerabilities/${id}` })),
    };
    if (b.stage) payload.stage = true; // resolve & put new entities in staging
    const task = await runTask(s, 'resolve-vulnerabilities', payload);
    let applied = null;
    if (b.applyPolicy) {
      const a = await runTask(s, 'apply-policy', { policyReference: policyLink(policyId) });
      applied = { id: a.id, status: a.status };
    }
    const vulnerabilities = await listVulns(s, policyId);
    send(res, 200, { task: { id: task.id, status: task.status, result: task.result }, applied, vulnerabilities });
  }],

  ['POST', /^\/api\/policies\/([^/]+)\/apply$/, async (req, res, m) => {
    const s = getSession(req);
    const a = await runTask(s, 'apply-policy', { policyReference: policyLink(decodeURIComponent(m[1])) });
    send(res, 200, { id: a.id, status: a.status });
  }],
];

/* ------------------------------------------------------------------- static */

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
function serveStatic(req, res) {
  const u = new URL(req.url, 'http://x');
  const rel = u.pathname === '/' ? '/index.html' : decodeURIComponent(u.pathname);
  const file = path.normalize(path.join(PUBLIC, rel));
  if (!file.startsWith(PUBLIC + path.sep)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://x').pathname;
  if (!pathname.startsWith('/api/')) return serveStatic(req, res);
  // CSRF guard: only same-origin browser calls (they must send our custom header or JSON type)
  const origin = req.headers.origin;
  if (origin && new URL(origin).host !== req.headers.host) return send(res, 403, { error: 'Cross-origin request refused' });
  for (const [method, re, fn] of routes) {
    const m = pathname.match(re);
    if (m && req.method === method) {
      try { await fn(req, res, m); }
      catch (e) {
        const status = e instanceof BigIpError ? e.status : 500;
        if (!(e instanceof BigIpError)) console.error(e);
        send(res, status >= 400 && status < 600 ? status : 502, { error: e.message, details: e.body });
      }
      return;
    }
  }
  send(res, 404, { error: 'Unknown API route' });
});

// Drop idle sessions (credentials live only in memory)
setInterval(() => {
  for (const [sid, s] of sessions) if (Date.now() - s.lastUsed > 30 * 60 * 1000) { s.agent.destroy(); sessions.delete(sid); }
}, 60000).unref();

if (require.main === module) {
  server.listen(PORT, HOST, () => console.log(`Scan→WAF importer on http://${HOST}:${PORT}`));
}
module.exports = server;
