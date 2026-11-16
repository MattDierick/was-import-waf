const fs = require('fs');
const xml = fs.readFileSync(__dirname + '/../vulnerabilities.xml', 'utf8');
const L = s => s.trim().split('\n').map(x => x.replace(/^ {6}/, ''));

const POLL = (kind, label) => L(`
      const t = pm.response.json();
      const st = String(t.status || '').toUpperCase();
      pm.test('${label}: task status is ' + st, () => pm.expect(['NEW','STARTED','COMPLETED']).to.include(st));
      if (st === 'FAILURE' || st === 'FAILED') { throw new Error('${label} task failed: ' + JSON.stringify(t.result || t)); }
      if (st !== 'COMPLETED') {
        const n = Number(pm.collectionVariables.get('poll_count') || 0) + 1;
        pm.collectionVariables.set('poll_count', n);
        if (n > 60) throw new Error('Timed out waiting for the task');
        // Collection Runner / Newman: re-run this request until the task completes
        // (the 1 s pause is in the pre-request script of each polling request).
        postman.setNextRequest(pm.info.requestName);
      } else {
        pm.collectionVariables.set('poll_count', 0);
        console.log('${label} COMPLETED', JSON.stringify(t.result || {}));
      }`);

const WAIT = L(`
      setTimeout(() => {}, 1000); // pause 1 s between polls`);
const jsonH = [{ key: 'Content-Type', value: 'application/json' }];
const url = (path, query) => {
  const full = 'https://{{bigip_host}}' + path;
  return { raw: full + (query ? '?' + query.map(q => q.join('=')).join('&') : ''), protocol: 'https', host: ['{{bigip_host}}'],
    path: path.split('/').filter(Boolean), ...(query ? { query: query.map(([key, value]) => ({ key, value })) } : {}) };
};
const req = (name, method, path, { query, body, headers = [], pre, test, desc, noauth } = {}) => ({
  name,
  event: [
    ...(pre ? [{ listen: 'prerequest', script: { type: 'text/javascript', exec: pre } }] : []),
    ...(test ? [{ listen: 'test', script: { type: 'text/javascript', exec: test } }] : []),
  ],
  request: { method, header: headers, ...(noauth ? { auth: { type: 'noauth' } } : {}),
    ...(body ? { body } : {}), url: url(path, query), ...(desc ? { description: desc } : {}) },
});
const jsonBody = obj => ({ mode: 'raw', raw: obj, options: { raw: { language: 'json' } } });
const policyRef = '{"link": "https://localhost/mgmt/tm/asm/policies/{{policy_id}}"}';

const listVulnTest = L(`
      const items = pm.response.json().items || [];
      const notResolvable = i => /not[\\s_-]*resolvable|unresolvable/i.test(String(i.resolveType || ''));
      const done = i => /resolved|fixed|mitigated|closed/i.test(String(i.status || ''));
      pm.test('Status 200', () => pm.response.to.have.status(200));
      console.log('Vulnerabilities in policy: ' + items.length);
      items.forEach(i => console.log([i.id, (i.threat||i.severity||'').toString().padEnd(8), i.resolveType || '?', i.status || '', i.name || '', i.url || ''].join(' | ')));
      const ok = items.filter(i => !notResolvable(i) && !done(i));
      pm.collectionVariables.set('auto_resolve_ids', ok.map(i => i.id).join(','));
      pm.collectionVariables.set('nonresolvable_ids', items.filter(notResolvable).map(i => i.id).join(','));
      pm.collectionVariables.set('resolved_ids', items.filter(done).map(i => i.id).join(','));
      console.log('Resolvable & open: ' + ok.length + ' | not resolvable: ' + items.filter(notResolvable).length + ' | already resolved: ' + items.filter(done).length);`);

const item = [
  { name: '0 · Authentication', item: [
    req('0.1 Login (get token)', 'POST', '/mgmt/shared/authn/login', { noauth: true, headers: jsonH,
      body: jsonBody('{\n  "username": "{{bigip_username}}",\n  "password": "{{bigip_password}}",\n  "loginProviderName": "tmos"\n}'),
      test: L(`
      pm.test('Login OK (200)', () => pm.response.to.have.status(200));
      const tok = pm.response.json().token.token;
      pm.collectionVariables.set('token', tok);
      console.log('Token stored');`),
      desc: 'Token-based auth. The token is stored in the collection variable {{token}} and sent as X-F5-Auth-Token by every other request.' }),
  ] },
  { name: '1 · Policies', item: [
    req('1.1 List WAF policies / select by name', 'GET', '/mgmt/tm/asm/policies', { query: [['$top', '500'], ['$select', 'id,name,fullPath,type,enforcementMode,active']],
      test: L(`
      pm.test('Status 200', () => pm.response.to.have.status(200));
      const items = pm.response.json().items || [];
      items.forEach(p => console.log(p.id + ' | ' + (p.fullPath || p.name) + ' | ' + (p.enforcementMode || '')));
      const want = pm.variables.get('policy_name');
      const p = items.find(x => x.name === want || x.fullPath === want || x.id === want);
      pm.test('Policy "' + want + '" found', () => pm.expect(p, 'set the environment variable policy_name to one of the names in the console').to.exist);
      if (p) { pm.collectionVariables.set('policy_id', p.id); console.log('Selected policy ' + p.fullPath + ' → id ' + p.id); }`),
      desc: 'Lists all ASM policies (see the Postman Console) and selects the one named in the environment variable policy_name (name, full path or id).' }),
  ] },
  { name: '2 · Import scan', item: [
    req('2.1 Upload scan file', 'POST', '/mgmt/tm/asm/file-transfer/uploads/{{uploaded_name}}', {
      headers: [{ key: 'Content-Type', value: 'application/octet-stream' }, { key: 'Content-Range', value: '0-0/1' }],
      body: { mode: 'raw', raw: xml, options: { raw: { language: 'text' } } },
      pre: L(`
      // unique file name on the BIG-IP + Content-Range computed from the body size
      const name = 'scanimport_' + Date.now() + '_' + pm.variables.get('scan_filename').replace(/[^\\w.\\-]/g, '_');
      pm.collectionVariables.set('uploaded_name', name);
      const body = pm.request.body.raw || '';
      const len = unescape(encodeURIComponent(body)).length;
      pm.request.headers.upsert({ key: 'Content-Range', value: '0-' + (len - 1) + '/' + len });`),
      test: L(`
      pm.test('Upload OK (200)', () => pm.response.to.have.status(200));
      console.log('Uploaded as ' + pm.collectionVariables.get('uploaded_name'));`),
      desc: 'The body contains the sample scan (vulnerabilities.xml). Replace it with your own scan XML. For files > 1 MB, upload in several chunks with successive Content-Range values (e.g. 0-1048575/3000000, 1048576-2097151/3000000, …).' }),
    req('2.2 (optional) Ask BIG-IP for the domain names in the scan', 'POST', '/mgmt/tm/asm/tasks/import-vulnerabilities', { headers: jsonH,
      body: jsonBody('{\n  "filename": "{{uploaded_name}}",\n  "policyReference": ' + policyRef + ',\n  "onlyGetDomainNames": true\n}'),
      test: L(`
      pm.test('Task created', () => pm.expect(pm.response.code).to.be.oneOf([200, 201, 202]));
      pm.collectionVariables.set('task_id', pm.response.json().id);`),
      desc: 'BIG-IP requires one of onlyGetDomainNames, importAllDomainNames or domainNames. This call only lists the domains; read the result in 2.3, then put them in the environment variable domain_names.' }),
    req('2.3 Poll task (domain names)', 'GET', '/mgmt/tm/asm/tasks/import-vulnerabilities/{{task_id}}', { pre: WAIT, test: [...POLL('', 'Domain discovery'), ...L(`
      if (st === 'COMPLETED') console.log('Domains found by BIG-IP: ' + JSON.stringify(t.result));`)] }),
    req('2.4 Import vulnerabilities into the policy', 'POST', '/mgmt/tm/asm/tasks/import-vulnerabilities', { headers: jsonH,
      body: jsonBody('{\n  "filename": "{{uploaded_name}}",\n  "policyReference": ' + policyRef + ',\n  {{domain_fragment}}\n}'),
      pre: L(`
      // import_all_domains=true → importAllDomainNames, otherwise the comma-separated domain_names
      if (String(pm.variables.get('import_all_domains')).toLowerCase() === 'true') {
        pm.collectionVariables.set('domain_fragment', '"importAllDomainNames": true');
      } else {
        const d = String(pm.variables.get('domain_names') || '').split(',').map(x => x.trim()).filter(Boolean);
        if (!d.length) throw new Error('Set domain_names (comma separated) or import_all_domains=true in the environment');
        pm.collectionVariables.set('domain_fragment', '"domainNames": ' + JSON.stringify(d));
      }`),
      test: L(`
      pm.test('Task created', () => pm.expect(pm.response.code).to.be.oneOf([200, 201, 202]));
      pm.collectionVariables.set('task_id', pm.response.json().id);`) }),
    req('2.5 Poll task (import)', 'GET', '/mgmt/tm/asm/tasks/import-vulnerabilities/{{task_id}}', { pre: WAIT, test: POLL('', 'Import') }),
  ] },
  { name: '3 · Vulnerabilities', item: [
    req('3.1 List vulnerabilities selected by BIG-IP', 'GET', '/mgmt/tm/asm/policies/{{policy_id}}/vulnerabilities', { query: [['$top', '500']], test: listVulnTest,
      desc: 'Prints id | severity | resolveType | status | name | url in the Console and stores which ids are resolvable. Items with resolveType "not-resolvable" can never be resolved.' }),
  ] },
  { name: '4 · Resolve & apply', item: [
    req('4.1 Resolve selected vulnerabilities', 'POST', '/mgmt/tm/asm/tasks/resolve-vulnerabilities', { headers: jsonH,
      body: jsonBody('{\n  "policyReference": ' + policyRef + ',\n  "vulnerabilityReferences": {{resolve_refs}}\n}'),
      pre: L(`
      // vulnerability_ids (comma separated) chooses what to fix; blank = every resolvable, still-open one
      const manual = String(pm.variables.get('vulnerability_ids') || '').split(',').map(x => x.trim()).filter(Boolean);
      const ids = manual.length ? manual : String(pm.collectionVariables.get('auto_resolve_ids') || '').split(',').filter(Boolean);
      const bad = String(pm.collectionVariables.get('nonresolvable_ids') || '').split(',').filter(Boolean);
      const blocked = ids.filter(i => bad.includes(i));
      if (blocked.length) throw new Error('Not resolvable by BIG-IP, remove from vulnerability_ids: ' + blocked.join(', '));
      if (!ids.length) throw new Error('Nothing to resolve (run 3.1 first; none resolvable/open)');
      const pid = pm.collectionVariables.get('policy_id');
      pm.collectionVariables.set('resolve_refs', JSON.stringify(ids.map(i => ({ link: 'https://localhost/mgmt/tm/asm/policies/' + pid + '/vulnerabilities/' + i }))));
      console.log('Resolving ' + ids.length + ' vulnerabilities: ' + ids.join(', '));`),
      test: L(`
      pm.test('Task created', () => pm.expect(pm.response.code).to.be.oneOf([200, 201, 202]));
      pm.collectionVariables.set('task_id', pm.response.json().id);`) }),
    req('4.2 Poll task (resolve)', 'GET', '/mgmt/tm/asm/tasks/resolve-vulnerabilities/{{task_id}}', { pre: WAIT, test: POLL('', 'Resolve') }),
    req('4.3 Apply policy', 'POST', '/mgmt/tm/asm/tasks/apply-policy', { headers: jsonH,
      body: jsonBody('{\n  "policyReference": ' + policyRef + '\n}'),
      test: L(`
      pm.test('Task created', () => pm.expect(pm.response.code).to.be.oneOf([200, 201, 202]));
      pm.collectionVariables.set('task_id', pm.response.json().id);`),
      desc: 'Pushes the policy changes live. Skip it if you want to review the policy first.' }),
    req('4.4 Poll task (apply policy)', 'GET', '/mgmt/tm/asm/tasks/apply-policy/{{task_id}}', { pre: WAIT, test: POLL('', 'Apply policy') }),
    req('4.5 Verify: list vulnerabilities again', 'GET', '/mgmt/tm/asm/policies/{{policy_id}}/vulnerabilities', { query: [['$top', '500']], test: listVulnTest }),
  ] },
  { name: '5 · Cleanup', item: [
    req('5.1 Logout (delete token)', 'DELETE', '/mgmt/shared/authz/tokens/{{token}}', { test: L(`
      pm.test('Token deleted', () => pm.expect(pm.response.code).to.be.oneOf([200, 204]));`) }),
  ] },
];

const collection = {
  info: { name: 'BIG-IP Advanced WAF – Import scan & resolve vulnerabilities',
    schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
    description: 'Run the folders in order (or use the Collection Runner with the environment "BIG-IP WAF scan import").\n\nFlow: login → pick policy → upload scan → (optional) discover domains → import → list vulnerabilities → resolve → apply policy → verify.\n\nSet in the environment: bigip_host, bigip_username, bigip_password, policy_name, domain_names (or import_all_domains=true), optionally vulnerability_ids.\nDisable "SSL certificate verification" in Postman settings (or the request) if the BIG-IP management cert is self-signed.\nPolling requests re-run themselves via setNextRequest — this only works in the Collection Runner / Newman; with a single Send, press Send again until the status is COMPLETED.' },
  auth: { type: 'apikey', apikey: [{ key: 'key', value: 'X-F5-Auth-Token' }, { key: 'value', value: '{{token}}' }, { key: 'in', value: 'header' }] },
  variable: ['token', 'policy_id', 'task_id', 'uploaded_name', 'domain_fragment', 'resolve_refs', 'auto_resolve_ids', 'nonresolvable_ids', 'resolved_ids', 'poll_count'].map(key => ({ key, value: '' })),
  item,
};
const env = {
  id: 'bigip-waf-scan-import', name: 'BIG-IP WAF scan import', _postman_variable_scope: 'environment',
  values: [
    ['bigip_host', '192.0.2.10', 'default', 'BIG-IP management address (add :port if not 443)'],
    ['bigip_username', 'admin', 'default'], ['bigip_password', '', 'secret'],
    ['scan_filename', 'vulnerabilities.xml', 'default'], ['policy_name', 'arcadia_policy', 'default', 'name, full path or id'],
    ['domain_names', 'arcadia-mybank.emea.f5se.com', 'default', 'comma separated'], ['import_all_domains', 'false', 'default'],
    ['vulnerability_ids', '', 'default', 'blank = all resolvable open ones; or comma separated ids'],
  ].map(([key, value, type, description]) => ({ key, value, type, enabled: true, ...(description ? { description } : {}) })),
};
fs.writeFileSync(__dirname + '/BIG-IP-WAF-scan-import.postman_collection.json', JSON.stringify(collection, null, 2));
fs.writeFileSync(__dirname + '/BIG-IP-WAF-scan-import.postman_environment.json', JSON.stringify(env, null, 2));
