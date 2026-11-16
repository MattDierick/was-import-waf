'use strict';
// End-to-end test: app server ↔ mock BIG-IP, using the sample scan.
const assert = require('assert');
const fs = require('fs'), path = require('path');
const mock = require('./mock-bigip.js')();
const app = require('../server.js');

const call = async (base, method, url, body, sid) => {
  const r = await fetch(base + url, { method, headers: { 'Content-Type': 'application/json', ...(sid ? { 'X-Session': sid } : {}) }, body: body && JSON.stringify(body) });
  return { status: r.status, json: await r.json() };
};

(async () => {
  await new Promise(r => mock.listen(0, '127.0.0.1', r));
  await new Promise(r => app.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${app.address().port}`;
  const host = `127.0.0.1:${mock.address().port}`;

  let r = await call(base, 'POST', '/api/connect', { host, username: 'admin', password: 'bad' });
  assert.strictEqual(r.status, 401, 'bad password rejected');

  r = await call(base, 'POST', '/api/connect', { host, username: 'admin', password: 'admin' });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.json.policies.length, 2);
  const sid = r.json.session;

  const xml = fs.readFileSync(path.join(__dirname, '..', 'vulnerabilities.xml'), 'utf8');
  const expected = (xml.match(/<vulnerability>/g) || []).length;
  // no domain selection → refused before reaching BIG-IP
  r = await call(base, 'POST', '/api/policies/pol-aaa/import', { filename: 'v.xml', content: xml }, sid);
  assert.strictEqual(r.status, 400);

  // ask BIG-IP for domains
  r = await call(base, 'POST', '/api/policies/pol-aaa/domains', { filename: 'v.xml', content: xml }, sid);
  assert.strictEqual(r.status, 200, JSON.stringify(r.json));
  assert.deepStrictEqual(r.json.domains, ['arcadia-mybank.emea.f5se.com']);

  // unknown domain selected → nothing imported
  r = await call(base, 'POST', '/api/policies/pol-bbb/import', { filename: 'v.xml', content: xml, domainNames: ['other.example'] }, sid);
  assert.strictEqual(r.json.vulnerabilities.length, 0);

  r = await call(base, 'POST', '/api/policies/pol-aaa/import', { filename: 'vulnerabilities.xml', content: xml, domainNames: ['arcadia-mybank.emea.f5se.com'] }, sid);
  assert.strictEqual(r.status, 200, JSON.stringify(r.json));
  assert.strictEqual(r.json.vulnerabilities.length, expected);
  const sql = r.json.vulnerabilities.find(v => v.name === 'SQL Injection');
  assert.strictEqual(sql.attackType, 'SQL-Injection', 'SQL injection attack type');
  const ck = r.json.vulnerabilities.find(v => v.name === 'Cookie without Secure Flag');
  assert.ok(ck.attackType, 'cookie attack type shown');
  assert.strictEqual(ck.parameter, 'session');
  assert.strictEqual(r.json.vulnerabilities.filter(v => v.attackType).length, 2, 'exactly 2 attack types');
  assert.strictEqual(sql.threat, 'critical'); assert.strictEqual(sql.parameter, 'account');

  assert.strictEqual(r.json.vulnerabilities.filter(v => v.resolvable).length, 2, 'only 2 resolvable');
  const bad = r.json.vulnerabilities.find(v => !v.resolvable);
  r = await call(base, 'POST', '/api/policies/pol-aaa/resolve', { vulnerabilityIds: [sql.id, bad.id] }, sid);
  assert.strictEqual(r.status, 400, 'non-resolvable refused'); assert.match(r.json.error, /Not resolvable/);
  r = await call(base, 'POST', '/api/policies/pol-aaa/resolve', { vulnerabilityIds: [sql.id], applyPolicy: true }, sid);
  assert.strictEqual(r.status, 200, JSON.stringify(r.json));
  assert.ok(r.json.applied);
  assert.strictEqual(r.json.vulnerabilities.find(v => v.id === sql.id).status, 'resolved');

  r = await call(base, 'POST', '/api/policies/pol-aaa/resolve', { vulnerabilityIds: [] }, sid);
  assert.strictEqual(r.status, 400);
  r = await call(base, 'GET', '/api/policies', null, 'nope');
  assert.strictEqual(r.status, 401);

  // cross-origin guard
  const x = await fetch(base + '/api/policies', { headers: { Origin: 'http://evil.example' } });
  assert.strictEqual(x.status, 403);

  // static
  const idx = await fetch(base + '/'); assert.strictEqual(idx.status, 200);
  const trav = await fetch(base + '/..%2fserver.js'); assert.notStrictEqual(trav.status, 200);

  console.log('All e2e checks passed');
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
