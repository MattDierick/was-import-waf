'use strict';
/**
 * Minimal mock of the BIG-IP ASM REST endpoints this app uses, for offline
 * demos/tests. Self-signed TLS via `openssl` if available, else falls back to
 * failing with a clear message.
 *   node test/mock-bigip.js            → https://127.0.0.1:8443  (admin / admin)
 */
const https = require('https');
const { execFileSync } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path');

function makeCert() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mockbigip-'));
  const key = path.join(dir, 'k.pem'), crt = path.join(dir, 'c.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', crt, '-days', '2', '-subj', '/CN=mock-bigip'], { stdio: 'ignore' });
  return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
}

const ATTACK = { 'SQL-Injection': 1, 'Information Leakage': 2 };
const ATTACK_BY_SCAN = { 'SQL-Injection': 'SQL-Injection', 'Set-Cookie does not use Secure keyword': 'Information Leakage' };

function create() {
  const TOKEN = 'mock-token';
  const policies = [
    { id: 'pol-aaa', name: 'arcadia_policy', fullPath: '/Common/arcadia_policy', type: 'security', enforcementMode: 'blocking', active: true, virtualServers: ['/Common/vs_arcadia'] },
    { id: 'pol-bbb', name: 'legacy_policy', fullPath: '/Common/legacy_policy', type: 'security', enforcementMode: 'transparent', active: false, virtualServers: [] },
  ];
  const uploads = {}, tasks = {}, vulns = {};
  let seq = 1;

  const parseScan = xml => [...xml.matchAll(/<vulnerability>([\s\S]*?)<\/vulnerability>/g)].map(m => {
    const g = t => (m[1].match(new RegExp(`<${t}>([^<]*)</${t}>`)) || [])[1];
    return { name: g('name'), url: g('url'), parameter: g('parameter') || g('cookie'), attackType: g('attack_type'), threat: g('threat'), score: Number(g('score')), status: 'open' };
  });

  const server = https.createServer(makeCert(), (req, res) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const url = new URL(req.url, 'https://x');
      const out = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
      const p = url.pathname;
      if (p === '/mgmt/shared/authn/login') {
        const b = JSON.parse(body);
        return b.username === 'admin' && b.password === 'admin' ? out(200, { token: { token: TOKEN } }) : out(401, { message: 'Authentication failed.' });
      }
      if (req.method === 'DELETE' && p === `/mgmt/shared/authz/tokens/${TOKEN}`) return out(200, {});
      if (req.headers['x-f5-auth-token'] !== TOKEN) return out(401, { message: 'Authorization failed' });
      if (p === '/mgmt/shared/identified-devices/config/device-info') return out(200, { version: '17.1.1 (mock)' });
      if (p === '/mgmt/tm/asm/policies') return out(200, { items: policies });
      if (p === '/mgmt/tm/asm/attack-types') return out(200, { items: Object.entries(ATTACK).map(([name, id]) => ({ id, name })) });
      let m;
      if ((m = p.match(/^\/mgmt\/tm\/asm\/file-transfer\/uploads\/(.+)$/))) {
        const name = decodeURIComponent(m[1]);
        (uploads[name] = uploads[name] || []).push(body);
        return out(200, { remainingByteCount: 0 });
      }
      if (p === '/mgmt/tm/asm/tasks/import-vulnerabilities' && req.method === 'POST') {
        const b = JSON.parse(body);
        const file = uploads[b.filename];
        if (!file) return out(400, { message: 'file not found' });
        if (!b.onlyGetDomainNames && !b.importAllDomainNames && !(b.domainNames && b.domainNames.length))
          return out(400, { message: "Could not add the Import Vulnerabilities Task 'Import Vulnerabilities Task (UNNAMED)'. Failed Required Fields: Must have at least 1 of (onlyGetDomainNames, importAllDomainNames, domainNames)" });
        const pid = b.policyReference.link.split('/').pop();
        const scan = parseScan(Buffer.concat(file).toString());
        if (b.onlyGetDomainNames) {
          const id = `t${seq++}`;
          tasks[id] = { id, status: 'COMPLETED', polls: 0, result: { domainNames: [...new Set(scan.map(v => new URL(v.url).hostname))] } };
          return out(201, { id, status: 'NEW' });
        }
        const only = b.importAllDomainNames ? null : b.domainNames;
        const keep = scan.filter(v => !only || only.includes(new URL(v.url).hostname));
        vulns[pid] = keep.map(v => ({ ...v, id: `v${seq++}` }));
        const id2 = `t${seq++}`; tasks[id2] = { id: id2, status: 'COMPLETED', result: { message: 'imported' }, polls: 0 };
        return out(201, { id: id2, status: 'NEW' });
      }
      if ((m = p.match(/^\/mgmt\/tm\/asm\/policies\/([^/]+)\/vulnerabilities$/))) {
        const all = (vulns[m[1]] || []).map(v => {
          const { attackType, ...rest } = v;
          const n = ATTACK_BY_SCAN[attackType];
          const resolveType = n ? 'resolvable' : 'not-resolvable';
          return n ? { ...rest, resolveType, attackTypeReference: { link: `https://localhost/mgmt/tm/asm/attack-types/${ATTACK[n]}?ver=17.1.1` } } : { ...rest, resolveType };
        });
        const top = Number(url.searchParams.get('$top') || 100), skip = Number(url.searchParams.get('$skip') || 0);
        return out(200, { items: all.slice(skip, skip + top) });
      }
      if (p === '/mgmt/tm/asm/tasks/resolve-vulnerabilities' && req.method === 'POST') {
        const b = JSON.parse(body);
        const pid = b.policyReference.link.split('/').pop();
        const mapped = (vulns[pid] || []).filter(v => b.vulnerabilityReferences.some(r => r.link.split('/').pop() === v.id));
        if (mapped.some(v => !ATTACK_BY_SCAN[v.attackType]))
          return out(500, { message: "Could not add the Resolve Vulnerabilities Task 'Resolve Vulnerabilities (UNNAMED)'. Can not resolve Vulnerabilities with resolveType 'not-resolvable'" });
        for (const r of b.vulnerabilityReferences) { const v = (vulns[pid] || []).find(x => x.id === r.link.split('/').pop()); if (v) v.status = 'resolved'; }
        const id = `t${seq++}`; tasks[id] = { id, status: 'COMPLETED', polls: 0 };
        return out(201, { id, status: 'NEW' });
      }
      if (p === '/mgmt/tm/asm/tasks/apply-policy' && req.method === 'POST') {
        const id = `t${seq++}`; tasks[id] = { id, status: 'COMPLETED', polls: 0 };
        return out(201, { id, status: 'NEW' });
      }
      if ((m = p.match(/^\/mgmt\/tm\/asm\/tasks\/[^/]+\/(.+)$/))) {
        const t = tasks[m[1]]; if (!t) return out(404, { message: 'no such task' });
        return out(200, t.polls++ < 1 ? { id: t.id, status: 'STARTED' } : t);
      }
      out(404, { message: `mock: ${req.method} ${p} not implemented` });
    });
  });
  return server;
}

module.exports = create;
if (require.main === module) {
  const port = Number(process.env.MOCK_PORT || 8443);
  create().listen(port, '127.0.0.1', () => console.log(`Mock BIG-IP on https://127.0.0.1:${port} (admin/admin)`));
}
