# Scan → BIG-IP Advanced WAF importer

Zero-dependency Node (>=18) app. Import a scanner XML, pick a BIG-IP + WAF policy,
see what BIG-IP derived from the scan, select vulnerabilities and resolve them.

![Vulnerabilities detected by BIG-IP, with resolvable items selected](docs/screenshot.png)

*Step 4: BIG-IP lists the vulnerabilities derived from the scan; only the ones it can resolve are selectable.*

    npm start            # http://127.0.0.1:3000
    npm run mock         # optional fake BIG-IP on https://127.0.0.1:8443 (admin/admin)
    npm test             # end-to-end test against the mock

Flow: file (local preview) → BIG-IP login (token auth) → policy list → upload + `import-vulnerabilities`
→ list `/policies/<id>/vulnerabilities` → `resolve-vulnerabilities` → optional `apply-policy`.

Security: binds to 127.0.0.1, credentials held in memory only (30 min idle), cross-origin API calls refused.
Set HOST/PORT env vars to change; do not expose it on a network without adding TLS + auth.

Tested only against the included mock. Task payload field names (import/resolve) are in server.js
(`routes`) — check them against your BIG-IP version's iControl REST docs (`/mgmt/tm/asm/tasks/...`).

## Postman collection (same flow, no UI)

`postman/` contains a collection + environment that call the BIG-IP REST API directly:
login → pick policy by name → upload scan → (discover domains) → import → list vulnerabilities →
resolve → apply policy → verify → logout. Import both files, fill in `bigip_host`, `bigip_password`,
`policy_name`, `domain_names` (or `import_all_domains=true`), then run it with the Collection Runner
(polling requests re-run themselves until the task is COMPLETED). Leave `vulnerability_ids` empty to
resolve every resolvable open item, or list ids. Not-resolvable items are never sent.
The scan XML is embedded in request 2.1 (regenerate with `node postman/generate.js`, which reads `vulnerabilities.xml`).
Verified with Newman against the mock: `npx newman run postman/*collection.json -e postman/*environment.json --env-var bigip_host=127.0.0.1:8443 --env-var bigip_password=admin --insecure`
