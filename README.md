# jsanalyze-mcp

An MCP server that turns **JavaScript you captured** (a Burp Suite XML export, a folder of
`.js`/`.map`, or a HAR) into a **triaged, de-noised analysis**: endpoints, DOM-XSS sinks,
secrets, vulnerable libraries, postMessage handlers, feature flags, SPA routes, storage writes,
GraphQL operations, a webpack chunk map, recovered sourcemap sources — and a prioritized
`leads.json` where each candidate is tagged with the `hunt-*` skill that would prove it.

The tool does the mechanical work **and** the first-pass triage (clustering, party split,
taint-gating, normalization) so that when you drive it with a model, the model *triages* the
artifacts instead of re-reading 30k-line bundles.

> **It never touches the target.** It only processes artifacts you supply. Anything that would
> reach the network (fetching an external `.map`, verifying a secret, GraphQL introspection) is
> behind an Operator Gate (`allow_network`, off by default).

A ready-to-read demo lives in [`workspace/example/`](workspace/example/) (generated from the
synthetic fixture — no real-target data).

---

## 1. Requirements

- **Python ≥ 3.10**
- **Go** — only if `setup` has to build jsluice from source (the fork ships no binary). If
  `jsluice` is already on `$PATH`/`~/go/bin`, `setup` just verifies it.
- **Node/npm** — for `retire.js` (vulnerable-library scan). Optional.
- Optional enricher tools on `$PATH` (auto-detected, skipped if absent): `js-beautify`,
  `linkfinder`, `trufflehog`, `gitleaks`, `retire`, `sourcemapper`, `unwebpack-sourcemap`.

## 2. Install

```bash
cd jsanalyze-mcp
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[brotli]'      # brotli recommended — CDN JS is often brotli-encoded
```

Register with your MCP client (Claude Desktop / Claude Code), e.g. `mcp.json`:

```json
{
  "mcpServers": {
    "jsanalyze": {
      "command": "/home/kali/jsanalyze-mcp/.venv/bin/jsanalyze-mcp"
    }
  }
}
```

Verify the engine once:

```text
setup      # installs/verifies jsluice (0xshdax fork); idempotent
status     # jsluice + fork modes, Go, config, which enricher tools are present
```

## 3. Prepare input (you do this — the tool never crawls)

`analyze` accepts three **local** sources:

| Source | How to produce it |
|---|---|
| **Burp XML** | In Burp, select the JS (and HTML) items → right-click → **Save selected items** → `foo.xml`. Responses are stored base64; the tool decodes, de-chunks and de-compresses (gzip/deflate/brotli) them. HTML items also contribute their inline `<script>` and `<script src>` list. |
| **Directory** | A folder of already-saved `*.js` (and `*.map`) files. |
| **HAR** | A `.har` capture; JS and HTML responses are used. |

## 4. Use it

### A. The easy way — the `js_analyze` prompt
The server ships a prompt (`prompts/js-analyze.md`). In your client pick **js_analyze**
(optionally set `input_path`); it seeds the model with the doctrine: run `analyze`, pull the
queue with `leads`, drill in with `query`/`read_span`, finish the reachability/body-shape
judgment, and present a fixed, tidy report.

### B. Direct tool calls

```text
# 1) analyze a source → writes artifacts into workspace/<run>/ and returns a summary + issues[]
analyze(input_path="input/foo.xml", label="acme", scope_hosts=["acme.com"])
analyze(input_path="~/dumps/js-dir/")         # a directory of .js/.map
analyze(input_path="~/dumps/session.har")     # a HAR

# 2) list runs
runs()

# 3) pull the filtered lead queue (NOT report.md) — your worklist
leads("2026-… _acme", min_confidence="medium")
leads("2026-…_acme", cls="xss-sink")          # filter by class
leads("2026-…_acme", party="first")           # first-party only

# 4) drill into a lead without opening a huge bundle
read_span("2026-…_acme", "app.js__<hash>.js", 1850, radius=40)
query("2026-…_acme", "app.js__<hash>.js",
      "(call_expression function: (identifier) @f (#match? @f \"fetch\"))")
```

`scope_hosts` matters: it drives `party` (a URL on an out-of-scope host → `third`) and each
endpoint's `in_scope` flag. A base domain matches its subdomains (`acme.com` ⊇ `api.acme.com`).

### Worked example (the bundled demo)
`workspace/example/` was produced by:

```bash
analyze(input_path="tests/fixtures/example.xml", label="example", scope_hosts=["target.tld"])
```

Open `workspace/example/report.md` for the rendered report, or `leads.json` for the queue
(sink tainted by `location.hash`, a no-origin-check postMessage listener, BFLA/auth endpoints,
masked secrets, a vulnerable jQuery). `sinks.json` shows the audit side: clusters that were
**not** promoted to leads (vendor/constant/non-tainted) with their occurrence counts.

## 5. Tools

| Tool | Purpose |
|---|---|
| `setup()` | Install & verify jsluice (idempotent). |
| `status()` | Read-only: jsluice + fork modes, Go, config, enricher-tool availability. |
| `analyze(input_path, label?, scope_hosts?, modes?, keep_js?)` | Full pipeline → triage → write artifacts; returns summary + `issues[]`. |
| `runs(limit?)` | List existing runs with lead counts. |
| `leads(run, cls?, party?, tainted?, min_confidence?)` | The filtered lead queue. |
| `query(run, file, q)` | Run a jsluice tree-sitter query against one JS file of a run. |
| `read_span(run, file, line, radius?)` | A slice of a bundle around a line. |

## 6. Artifacts — `workspace/<YYYY-MM-DD>_<label>/`

| File | Contents |
|---|---|
| `leads.json` | **Distilled, gated candidate queue** — distinct leads, secrets masked, each with `suggested_skill`. |
| `report.md` | Human-readable report (masked) — the base for a model's triage. |
| `endpoints.json` / `.txt` | Normalized endpoints (`method,path,host,query,body_keys,call_type,party,in_scope,dynamic,fetchable`) / clean fetchable feed for ffuf/httpx. |
| `sinks.json` | Clustered DOM sinks: `sink_class, party, real_taint, lead, count, occurrences` (audit; only `lead=true` become leads). |
| `postmessage.json` | `postmessage-listener` / `-sender`(`"*"`) / `-origin-bypass` / `onmessage`. |
| `secrets.json` | Full secret values (jsluice+gitleaks+trufflehog, deduped) — **sensitive, gitignored**. |
| `libs.json` | Vulnerable libraries (retire.js): component, version, CVE, CWE, severity. |
| `flags.json` `routes.json` `storage.json` `graphql.json` `chunks.json` `framework.json` | The judgment layer the tool computes: SDK/UI feature flags, SPA routes, localStorage/cookie writes, GraphQL operations, webpack chunk map (present/missing), detected framework. |
| `sourcemaps.json` + `sources/` | `.map` references + sources reconstructed from inline/local maps (re-scanned for leads). |
| `issues.json` | Enricher/jsluice failures (surfaced, not swallowed). |
| `js/*.js` | Decoded + beautified bodies (line numbers in leads refer here). |

## 7. Lead taxonomy → proving skill

| `class` | From | `suggested_skill` |
|---|---|---|
| `idor-candidate` | endpoint `resource/{id}` or id-ish param | `hunt-idor` |
| `bfla-candidate` | endpoint `/admin`·`/internal` path **segment** | `hunt-api` |
| `auth-endpoint` | endpoint `/auth`·`/login`·`/token`… segment | `hunt-auth-bypass` |
| `graphql-candidate` | endpoint `/graphql` | `hunt-graphql` |
| `api-version` | endpoint `/v0`·`/beta`·`/legacy` | `hunt-api` |
| `secret-location` | secret (cloud key → `hunt-cloud`) | `hunt-secrets-disclosure` |
| `xss-sink` | sink — **gated**: real attacker-taint only, clustered | `hunt-xss` |
| `postmessage-listener` / `-sender` / `-origin-bypass` | postMessage families | `hunt-xss` (/ `hunt-auth-bypass` if token) |
| `feature-gate` | `ui-gate` flag (isAdmin / plan===) | `hunt-api` |
| `vulnerable-library` | retire.js (CWE-driven) | `hunt-xss`(79)/`hunt-injection`(89)/`hunt-server-side`(77/78/94/502)/`hunt-js-analysis` |

> **Leads = candidates, not findings.** `severity_hint`/`confidence` are potential only. Proof =
> an observed cross-boundary effect via the relevant `hunt-*` skill.

## 8. Operator Gate & safety

- `config.json → allow_network` (default `false`): external `.map` fetch, secret verification and
  GraphQL introspection stay **off**. Turn on only when the engagement authorizes it.
- Secrets are masked everywhere human-readable; full values live only in the gitignored
  `secrets.json`.
- Input (XML/JS/HAR) is treated as **untrusted data** — parsed, never executed.

## 9. Development

Core pipeline (parsers/analyzers/leads/formatters) is stdlib-only and testable without the MCP
runtime; the full server integration needs the venv (mcp + tools):

```bash
PYTHONPATH=src python3 -P tests/test_pipeline.py     # noise-gate core
./.venv/bin/python tests/test_enrichers.py           # full server.analyze integration
```
