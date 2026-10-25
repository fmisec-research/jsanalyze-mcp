# jsanalyze-mcp

MCP server for offline analysis of JavaScript you already captured. Give it a Burp Suite XML export, a HAR file, or a directory of `.js` and `.map` files. It returns a scored queue of leads, with the evidence needed to decide what to test next.

The server reads local artifacts only. It does not crawl, and it does not send requests to the target. Fetching an external source map, verifying a secret, or running GraphQL introspection stays behind `allow_network`, which is off by default.

A synthetic demo run is in [`workspace/example/`](workspace/example/). It contains no data from a real target.

## What you get

Each run writes `workspace/<YYYY-MM-DD>_<label>/`. Start with `leads.json` and `report.md`.

A lead is a candidate, not a finding. `severity_hint` and `confidence` describe potential. The queue is ordered by `score`. Proof is an observed effect across a trust boundary, done later with the `hunt-*` skill named on the lead. `caller_chain`, `body_keys`, `negative_control`, and `experiment` say what to try, so the model does not have to re-read the bundle.

The pipeline extracts and then judges:

- Endpoints, with method, body keys, and whether the same request appears in the capture
- DOM sinks, kept only when attacker-controlled data reaches them
- `postMessage` listeners, wildcard senders, and weak origin checks
- Secrets, split into public-by-design and private
- Vulnerable libraries, and calls whose output reaches an HTML sink
- SPA routes, feature flags, storage writes, GraphQL operations
- Webpack and Vite chunks, including chunks missing from the capture
- CSP hosts, response fields, and notes recovered from source maps

## Requirements

- Python 3.10 or newer
- [jsluice](https://github.com/0xshdax/jsluice), the upgraded fork. Extraction uses this binary, not upstream BishopFox. The fork keeps the original `urls` and `secrets` modes and adds `sinks`, `postmessage`, and `sourcemaps`, plus template-literal URLs and a larger secret-matcher set. `setup` installs `github.com/0xshdax/jsluice/cmd/jsluice@latest`. Go is required only when that install has to compile it. A binary already on `PATH` or in `~/go/bin` is used as-is after `setup` checks that the fork modes run.
- Node.js, optional, for `retire`
- Optional tools, detected on `PATH` and skipped when absent: `js-beautify`, `linkfinder`, `trufflehog`, `gitleaks`, `retire`, `sourcemapper`, `unwebpack-sourcemap`

Without `retire`, `trufflehog`, and `gitleaks`, a count of zero secrets or zero vulnerable libraries means those scanners did not run. It is not evidence that the bundle is clean.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[brotli]'
```

The `brotli` extra is recommended. CDN JavaScript is often Brotli-compressed, and Burp stores that body as-is. The extra requires `brotli>=1.2.1` (CVE-2026-111497 is an out-of-bounds write in older decoders). gzip and deflate need no extra package.

Confirm the engine:

```text
setup
status
```

`setup` installs or verifies the [0xshdax/jsluice](https://github.com/0xshdax/jsluice) fork and is safe to run again. It rejects an upstream binary that does not implement `sinks` and `sourcemaps`. `status` reports the resolved binary, whether those fork modes pass, Go, config, and which optional tools are present.

## Connect a client

The server speaks MCP over stdio. Point the client at the `jsanalyze-mcp` executable inside the virtualenv.

OpenCode 2:

```bash
opencode mcp add jsanalyze -- /absolute/path/to/.venv/bin/jsanalyze-mcp
```

OpenCode 1, in `~/.config/opencode/opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "jsanalyze": {
      "type": "local",
      "command": ["/absolute/path/to/.venv/bin/jsanalyze-mcp"],
      "enabled": true
    }
  }
}
```

Any other MCP client uses the same command:

```json
{
  "mcpServers": {
    "jsanalyze": {
      "command": "/absolute/path/to/.venv/bin/jsanalyze-mcp"
    }
  }
}
```

Restart the client after changing the config so it loads the new process.

## Prepare a capture

`analyze` accepts three local inputs.

| Input | How to produce it |
|---|---|
| Burp XML | Select the JavaScript and HTML items, then **Save selected items**. The tool base64-decodes each body, removes chunked encoding, and decompresses gzip, deflate, and Brotli. HTML contributes inline scripts, `script src`, CSP, and JSON responses. |
| Directory | A folder of `*.js` and `*.map` files. There is no request history, so the tool will not claim that an endpoint is untested. |
| HAR | A `.har` file. JavaScript and HTML responses are used, and `postData` is read for the traffic delta. |

Put captures in `input/`. That directory is gitignored. Do not paste an export into chat.

## Run an analysis

The server registers one prompt, `js_analyze` (`prompts/js-analyze.md`). Select it in the client, or send this:

```text
Use the jsanalyze MCP and follow the js_analyze prompt.
analyze(input_path="/absolute/path/to/input/capture.xml", label="app", scope_hosts=["app.example"])
Read issues[]. Triage with leads(), highest score first.
Do not open secrets.json and do not print a full secret.
Do not fetch the target. Leave allow_network off.
Write the report described in section 4 of the prompt.
```

`scope_hosts` is a list of hostnames, without a port or scheme. `app.example` also matches `api.app.example`. `localhost:3000` does not match host `localhost`, so a local app captured on port 3000 is scoped as `localhost`.

Direct tool calls:

```text
analyze(input_path="input/capture.xml", label="app", scope_hosts=["app.example"])
analyze(input_path="~/dumps/js/")
analyze(input_path="~/dumps/session.har")

runs()
leads("2026-01-01_app", min_confidence="medium")
leads("2026-01-01_app", cls="xss-sink")
leads("2026-01-01_app", party="first")

read_span("2026-01-01_app", "app.js__<hash>.js", 1850, radius=40)
query("2026-01-01_app", "app.js__<hash>.js",
      "(call_expression function: (identifier) @f (#match? @f \"fetch\"))")
```

The bundled demo was produced with:

```text
analyze(input_path="tests/fixtures/example.xml", label="example", scope_hosts=["target.tld"])
```

Read `workspace/example/report.md` for the rendered report and `leads.json` for the queue.

## Tools

| Tool | Purpose |
|---|---|
| `setup()` | Install and verify jsluice. Safe to repeat. |
| `status()` | jsluice, Go, config, and which optional tools are installed. |
| `analyze(input_path, label?, scope_hosts?, modes?, keep_js?)` | Run the pipeline and write the workspace. Returns a summary and `issues[]`. |
| `runs(limit?)` | List runs and their lead counts. |
| `leads(run, cls?, party?, tainted?, min_confidence?)` | Filtered lead queue, highest score first. |
| `query(run, file, q)` | One jsluice tree-sitter query against one file in a run. |
| `read_span(run, file, line, radius?)` | A slice of a bundle around a line. |

## Artifacts

All paths are under `workspace/<YYYY-MM-DD>_<label>/`.

| File | Contents |
|---|---|
| `leads.json` | Scored candidate queue. Secrets are masked. Each lead has `suggested_skill`, `score`, `score_factors`, `caller_chain`, `body_keys`, `seen_in_history`, `negative_control`, and `experiment`. |
| `report.md` | Rendered report. A model should refine this, not replace the evidence. |
| `endpoints.json`, `endpoints.txt` | Normalized endpoints. The text file lists fetchable paths for a later, authorized pass. |
| `sinks.json` | Clustered DOM sinks, including clusters that were not promoted. |
| `postmessage.json` | Listeners, wildcard senders, weak origin checks, and WebSocket `onmessage` (audit only). |
| `secrets.json` | Full secret values. Gitignored. Do not print it. |
| `libs.json` | retire.js results: component, version, CVE, severity. |
| `flags.json`, `routes.json`, `storage.json`, `graphql.json`, `chunks.json`, `framework.json` | Feature flags, SPA routes, storage writes, GraphQL operations, chunk map, framework and gadgets. |
| `csp.json` | Hosts from CSP `connect-src` and `frame-src` in the captured HTML. |
| `history.json` | Requests in the capture: method, URL, body keys, query keys, GraphQL operation names, and auth header or cookie names. Values are not stored. |
| `responses.json` | Sensitive keys in captured JSON responses, and inline handlers in captured HTML. |
| `source_notes.json` | Comments, mock paths, internal hosts, and credential-shaped strings mined from recovered source. |
| `sourcemaps.json`, `sources/` | Inline or local source maps, reconstructed and scanned again. An external `.map` that was not fetched is a `sourcemap` lead, not a download. |
| `issues.json` | Failed enrichers. An empty list means the steps that ran did not fail. It does not mean every optional tool was installed. |
| `js/` | Decoded and beautified bodies. Line numbers in leads refer to these files. |

`seen_in_history: false` is meaningful only when the capture contains real API traffic. A directory of JavaScript files, or a Burp export that is only script URLs, does not support that claim.

GET and POST of the same path are separate rows. A method that never appears in the capture stays untested even if another method of that path was sent. `ClientApi.post(url, { ... })` and a multi-line `JSON.stringify({ ... })` contribute body keys. A string that is only the tail of a concatenation, such as `'/note'` at the end of `'/api/' + id + '/note'`, is not its own endpoint.

## Lead classes

| Class | When it is raised | Skill |
|---|---|---|
| `idor-candidate` | `resource/{id}` or an id-shaped parameter | `hunt-idor` |
| `bfla-candidate` | Path segment `/admin`, `/internal`, or similar | `hunt-api` |
| `auth-endpoint` | Path segment `/auth`, `/login`, `/token`, or similar | `hunt-auth-bypass` |
| `graphql-candidate` | Path `/graphql` | `hunt-graphql` |
| `api-version` | Path segment `/v0`, `/beta`, `/legacy` | `hunt-api` |
| `endpoint-unverified` | In-scope API present in the bundle and absent from traffic | `hunt-api` |
| `endpoint-hidden` | First-party SPA route with no matching fetch, absent from traffic | `hunt-api` |
| `body-field-unsent` | An authorization or money field the bundle can send and this capture never sent | `hunt-api` |
| `client-controlled-value` | The client sends `price`, `total`, `amount`, or `quantity` | `hunt-business-logic` |
| `xss-sink` | Attacker-controlled data reaches an HTML or script sink | `hunt-xss` |
| `open-redirect` | A tainted navigation target with no `javascript:` or `data:` scheme | `hunt-open-redirect` |
| `html-sink` | Inline `on*=` handler or `javascript:` URL in captured HTML | `hunt-xss` |
| `sink-untraced` | First-party HTML or script sink the single-file tracer could not tie to a source. Capped, low. | `hunt-xss` |
| `postmessage-listener` | `message` listener with no verifiable origin check | `hunt-xss` |
| `postmessage-origin-bypass` | Origin check is a prefix or substring test | `hunt-xss` |
| `postmessage-sender` | `postMessage` to `"*"` | `hunt-xss`, or `hunt-auth-bypass` when the payload looks like a token |
| `secret-location` | A private secret. Public keys (`pk_`, analytics, Sentry DSN) stay informational. | `hunt-secrets-disclosure` |
| `cloud-config` | Firebase web config, or `createClient(url, anonKey)`, as one object | `hunt-cloud` |
| `vulnerable-library` | retire.js version match. Low until the vulnerable function is called. | Class depends on the CWE |
| `vulnerable-call` | Output of a vulnerable library call reaches an HTML sink | `hunt-xss` |
| `token-storage` | A token-like value written to a cookie or `localStorage` | `hunt-auth-bypass` |
| `graphql-operation` | A parsed query or mutation | `hunt-graphql` |
| `graphql-unsent` | An operation in the bundle that no sent request named | `hunt-graphql` |
| `websocket` | `ws://`, `wss://`, or a socket.io path | `hunt-websocket` |
| `csp-endpoint` | An internal or framed host in CSP that is absent from traffic | `hunt-api` |
| `framework-gadget` | `bypassSecurityTrust*`, `v-html`, a dynamic `javascript:` URL, or a deep merge | `hunt-xss` or `hunt-server-side` |
| `oauth-implicit`, `oauth-redirect` | `response_type=token`, or a `redirect_uri` built from input | `hunt-auth-bypass` |
| `mock-data-path` | A mock, dummy, or fixture path in recovered source | `hunt-js-analysis` |
| `sourcemap` | An external `.map` URL that was not fetched | `hunt-js-analysis` |
| `feature-gate` | A UI flag such as `isAdmin` or a plan check | `hunt-api` |

## Safety

- `allow_network` in `config/config.json` defaults to `false`.
- Human-readable output masks secrets. Full values exist only in gitignored `secrets.json`.
- XML, JavaScript, and HAR input is untrusted data. It is parsed and never executed.
- `read_span` and `query` can only read files inside the workspace for that run.

## Development

Parsers, analyzers, leads, and formatters use the Python standard library and do not need the MCP package. The server integration test needs the virtualenv.

```bash
PYTHONPATH=src python3 tests/test_units.py
PYTHONPATH=src python3 tests/test_pipeline.py
PYTHONPATH=src python3 tests/test_regression.py
./.venv/bin/python tests/test_enrichers.py
```

`test_regression.py` builds an anonymized Burp XML. It locks the cases that used to poison the queue: multi-hop taint, a webpack 4 chunk map, a SPA route misread as an API, a `postMessage` listener with and without a sink, a duplicated secret, and a CSP host.
