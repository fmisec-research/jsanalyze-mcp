"""jsanalyze-mcp — MCP entrypoint (tools + the js_analyze prompt).

Tools:
  setup / status                 — install & verify jsluice; report deps.
  analyze(input_path, ...)       — load a Burp XML / dir / HAR, run jsluice + enrichers,
                                   TRIAGE into de-noised artifacts, write them, return a
                                   summary + issues[].
  runs()                         — list existing analysis runs.
  leads(run, ...)                — the filtered lead queue (not report.md).
  query(run, file, q)            — run a jsluice tree-sitter query against a run's JS.
  read_span(run, file, line, r)  — a slice of a bundle around a line (so the model need
                                   not open a 68k-line file).

Prompt: js_analyze (prompts/js-analyze.md) — the doctrine for triaging the artifacts.

Only this file imports `mcp`; everything it calls is stdlib + the project's own modules.
"""

from __future__ import annotations

import json
from pathlib import Path

try:  # mcp >= 2.x
    from mcp.server.mcpserver import MCPServer as _Server
except ModuleNotFoundError:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP as _Server

from jsanalyze import setup as _setup
from jsanalyze.analyzers.chunks import map_chunks
from jsanalyze.analyzers.comment_miner import mine_comments
from jsanalyze.analyzers.endpoints import decode_atob_endpoints, normalize_endpoints
from jsanalyze.analyzers.flags import scan_flags
from jsanalyze.analyzers.framework import detect_framework
from jsanalyze.analyzers.graphql import extract_graphql
from jsanalyze.analyzers.jsluice_wrapper import resolve_jsluice, run_jsluice
from jsanalyze.analyzers.postmessage import classify_postmessage
from jsanalyze.analyzers.routes import extract_routes
from jsanalyze.analyzers.sinks import triage_sinks
from jsanalyze.analyzers.storage import scan_storage
from jsanalyze.enrichers import tools as _tools
from jsanalyze.enrichers.beautify import beautify_dir
from jsanalyze.enrichers.endpoints import linkfinder_endpoints
from jsanalyze.enrichers.secret_classify import classify_secrets
from jsanalyze.enrichers.secrets import scan_secrets
from jsanalyze.enrichers.sourcemaps import recover_sources
from jsanalyze.enrichers.vulnlibs import scan_libs
from jsanalyze.formatters.report_builder import build_report, report_summary
from jsanalyze.leads.lead_engine import build_leads
from jsanalyze.models import Item, Triaged
from jsanalyze.parsers.csp import collect_csp
from jsanalyze.parsers.history import collect_history
from jsanalyze.parsers.inputs import load_input
from jsanalyze.utils import workspace as W

mcp = _Server("jsanalyze-mcp")

# artifact filename for each Triaged list field
_ARTIFACTS = {
    "endpoints": "endpoints.json", "sinks": "sinks.json", "postmessage": "postmessage.json",
    "secrets": "secrets.json", "libs": "libs.json", "graphql": "graphql.json",
    "flags": "flags.json", "routes": "routes.json", "storage": "storage.json",
    "chunks": "chunks.json", "sourcemaps": "sourcemaps.json", "csp": "csp.json",
    "notes": "source_notes.json",
}


def _safe(label, fn, issues, default):
    """Run an enricher/analyzer; on failure record it in issues (never swallow silently)."""
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 — a bad enricher must not sink the run, but it IS reported
        issues.append(f"{label}: {type(e).__name__}: {e}")
        return default


# --- tools --------------------------------------------------------------------
@mcp.tool()
def setup() -> str:
    """Install & verify the jsluice analysis engine (0xshdax fork). Idempotent."""
    return _setup.ensure_jsluice()


@mcp.tool()
def status() -> str:
    """Read-only dependency check: jsluice + fork modes, Go, config, enricher tools."""
    return _setup.status()


@mcp.tool()
def analyze(
    input_path: str,
    label: str | None = None,
    scope_hosts: list[str] | None = None,
    modes: list[str] | None = None,
    keep_js: bool = True,
) -> str:
    """Analyze JavaScript from a LOCAL source and write triaged artifacts.

    Args:
        input_path:  a Burp Suite XML export, a directory of .js/.map files, or a .har file.
        label:       run-folder label (default: the input stem).
        scope_hosts: in-scope hosts; drives party (third) and endpoint in_scope.
        modes:       jsluice modes (default: all).
        keep_js:     keep decoded/beautified js/ in the workspace (default True).

    Writes endpoints/sinks/postmessage/secrets/libs/graphql/flags/routes/storage/chunks/
    sourcemaps .json, leads.json, report.md and (if any) sources/ into a per-run folder.
    Returns a compact Markdown summary + the workspace path + issues[].
    """
    p = Path(input_path).expanduser()
    if not p.exists():
        return f"Error: input tidak ditemukan: {input_path}"

    cfg = W.load_config()
    run = W.new_run(label or p.stem)
    issues: list[str] = []

    try:
        js_items, map_items, chunk_refs = load_input(p, scope_hosts, run.js_dir, cfg, issues)
    except ValueError as e:
        W.cleanup_js(run.js_dir)
        return f"Error: gagal memuat input — {e}"
    if not js_items:
        return (f"Tidak ada JavaScript ditemukan di {input_path}.\n"
                f"Workspace: {run.dir}\nissues: {issues}")

    beaut = _safe("beautify", lambda: beautify_dir(run.js_dir, cfg=cfg), issues,
                  {"beautified": 0, "tool": None})

    sm = _safe("sourcemaps",
               lambda: recover_sources(js_items, run.dir / "sources", cfg, map_items, scope_hosts),
               issues, {"recovered": 0, "refs": [], "files": []})
    # url has an empty authority (sources:///…) so recovered files don't pollute host lists
    src_items = [Item(url=f"sources:///{Path(f).name}", saved_path=f, is_javascript=True,
                      mimetype="script") for f in sm.get("files", [])]
    all_items = js_items + src_items
    issues += sm.get("issues", [])

    a = _safe("jsluice", lambda: run_jsluice(all_items, modes=modes, cfg=cfg), issues, None)
    if a is None:
        return (f"Error: jsluice gagal. Jalankan `setup` dulu.\nWorkspace: {run.dir}\n"
                f"issues: {issues}")
    issues += a.issues

    src_dir = run.dir / "sources"
    extra_urls = _safe("linkfinder", lambda: linkfinder_endpoints(all_items, cfg=cfg), issues, [])
    extra_urls += _safe("atob", lambda: decode_atob_endpoints(all_items), issues, [])
    tool_secrets = _safe("secrets", lambda: scan_secrets(run.js_dir, all_items, cfg=cfg), issues, [])
    if src_items:
        tool_secrets += _safe("secrets(sources)", lambda: scan_secrets(src_dir, src_items, cfg=cfg), issues, [])
    libs = _safe("retire", lambda: scan_libs(run.js_dir, all_items, cfg=cfg), issues, [])

    # request history already in the capture (point 2) and SPA routes are computed
    # FIRST so the endpoint normalizer can (a) flag untested surface and (b) tell a
    # client route apart from an API call.
    history = _safe("history", lambda: collect_history(p, scope_hosts), issues,
                    {"known": False, "keys": set(), "entries": [], "count": 0})
    csp = _safe("csp", lambda: collect_csp(p, scope_hosts), issues,
                {"known": False, "policies": [], "directives": []})
    routes = _safe("routes", lambda: extract_routes(all_items, cfg=cfg), issues, [])
    route_paths = [r.get("path") for r in routes if r.get("path")]

    tri = Triaged(
        endpoints=_safe("endpoints", lambda: normalize_endpoints(
            list(a.urls) + extra_urls, all_items, cfg, scope_hosts,
            route_paths=route_paths, history=history), issues, []),
        sinks=_safe("sinks", lambda: triage_sinks(a.sinks, all_items, cfg, scope_hosts), issues, []),
        postmessage=_safe("postmessage", lambda: classify_postmessage(a.postmessage, all_items, cfg, scope_hosts), issues, []),
        secrets=classify_secrets(list(a.secrets) + tool_secrets),
        libs=libs,
        graphql=_safe("graphql", lambda: extract_graphql(all_items, cfg=cfg), issues, []),
        flags=_safe("flags", lambda: scan_flags(all_items, cfg=cfg), issues, []),
        routes=routes,
        storage=_safe("storage", lambda: scan_storage(all_items, cfg=cfg), issues, []),
        chunks=(_safe("chunks", lambda: map_chunks(all_items, cfg=cfg), issues, [])
                + [{"src": r["src"], "from": r.get("from"), "present": r.get("present"), "kind": "html-ref"}
                   for r in (chunk_refs or [])]),
        framework=_safe("framework", lambda: detect_framework(all_items, cfg=cfg), issues, {}),
        sourcemaps=sm.get("refs", []),
        csp=csp.get("directives", []),
        notes=_safe("source_notes", lambda: mine_comments(src_items), issues, []),
        issues=issues,
    )

    leads = build_leads(tri, cfg=cfg, history=history, scope_hosts=scope_hosts)

    # write artifacts
    for field, fname in _ARTIFACTS.items():
        W.write_json(run.dir / fname, getattr(tri, field))
    W.write_json(run.dir / "framework.json", tri.framework)
    W.write_json(run.dir / "leads.json", leads)
    W.write_json(run.dir / "issues.json", issues)
    W.write_json(run.dir / "history.json", {
        "known": history.get("known", False), "count": history.get("count", 0),
        "hosts": history.get("hosts", []), "entries": history.get("entries", []),
    })
    fetchable = sorted({n["path"] if not n.get("host") else n["url"]
                        for n in tri.endpoints if n.get("fetchable")})
    W.write_text(run.dir / "endpoints.txt", "\n".join(fetchable) + ("\n" if fetchable else ""))

    enrichment = {"beautified": beaut, "sources": sm, "tools": _tools.available(cfg), "issues": issues}
    W.write_text(run.dir / "report.md", build_report(all_items, tri, leads, run, enrichment))

    if not keep_js:
        W.cleanup_js(run.js_dir)
    return report_summary(run, all_items, tri, leads, issues)


# --- interactive query surface (so the model can ask the data, not just get a batch) ---
def _run_dir(run: str) -> "Path | None":
    d = (W.DEFAULT_WORKSPACE / run).resolve()
    try:
        d.relative_to(W.DEFAULT_WORKSPACE.resolve())
    except ValueError:
        return None
    return d if d.is_dir() else None


def _resolve_file(run_dir: Path, file: str) -> "Path | None":
    """Resolve `file` to a JS under the run's js/ or sources/ (no path traversal)."""
    for sub in ("js", "sources", ""):
        cand = (run_dir / sub / file).resolve()
        try:
            cand.relative_to(run_dir.resolve())
        except ValueError:
            continue
        if cand.is_file():
            return cand
    # last resort: match by basename
    for base in (run_dir / "js", run_dir / "sources"):
        if base.is_dir():
            for f in base.rglob("*"):
                if f.is_file() and f.name == Path(file).name:
                    return f
    return None


@mcp.tool()
def runs(limit: int = 25) -> str:
    """List existing analysis runs (newest first) with their lead counts."""
    base = W.DEFAULT_WORKSPACE
    if not base.is_dir():
        return "No runs yet."
    rows = []
    for d in sorted((x for x in base.iterdir() if x.is_dir()),
                    key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
        n = "?"
        try:
            n = str(len(json.loads((d / "leads.json").read_text())))
        except (OSError, ValueError):
            pass
        rows.append(f"- `{d.name}` — {n} leads")
    return "## Runs\n" + ("\n".join(rows) if rows else "none")


@mcp.tool()
def leads(run: str, cls: str | None = None, party: str | None = None,
          tainted: bool | None = None, min_confidence: str | None = None) -> str:
    """Return the filtered lead queue for a run (not report.md).

    Filter by class (`cls`), `party`, `tainted`, and `min_confidence` (low|medium|high)."""
    d = _run_dir(run)
    if not d:
        return f"Error: run not found: {run}"
    try:
        items = json.loads((d / "leads.json").read_text())
    except (OSError, ValueError) as e:
        return f"Error: cannot read leads.json ({e})"
    rank = {"low": 0, "medium": 1, "high": 2}
    floor = rank.get((min_confidence or "").lower(), -1)
    out = []
    for ld in items:
        if cls and ld.get("class") != cls:
            continue
        if party and (ld.get("notes", "").find(f"party={party}") < 0):
            continue
        if tainted is not None and bool(ld.get("tainted")) != tainted:
            continue
        if floor >= 0 and rank.get(ld.get("confidence", "low"), 0) < floor:
            continue
        out.append(ld)
    if not out:
        return f"No leads match (run={run})."
    lines = [f"## Leads — {run} ({len(out)}/{len(items)})"]
    for ld in out:
        loc = f" @ {ld.get('source_file')}:{ld.get('line')}" if ld.get("source_file") else ""
        hist = " ⚠not-in-traffic" if ld.get("seen_in_history") is False else ""
        lines.append(f"- [{ld['id']}] score={ld.get('score')} **{ld['class']}** "
                     f"({ld.get('confidence')}/{ld.get('severity_hint')}) "
                     f"→ {ld.get('suggested_skill')} — `{(ld.get('evidence') or '')[:80]}`{loc}{hist}")
    return "\n".join(lines)


@mcp.tool()
def query(run: str, file: str, q: str) -> str:
    """Run a jsluice tree-sitter query (`jsluice query -q <q>`) against one JS file of a
    run (js/ or sources/). Returns the matched rows (JSON per line)."""
    d = _run_dir(run)
    if not d:
        return f"Error: run not found: {run}"
    target = _resolve_file(d, file)
    if not target:
        return f"Error: file not found in run: {file}"
    js = resolve_jsluice()
    if not js:
        return "Error: jsluice not found — run setup."
    proc = _tools.run([js, "query", "-q", q, "-f", str(target)], timeout=60)
    if proc is None:
        return "Error: jsluice query failed to run."
    out = (proc.stdout or "").strip()
    if not out:
        err = (proc.stderr or "").strip()
        return f"(no matches){chr(10) + err if err else ''}"
    lines = out.splitlines()
    head = "\n".join(lines[:200])
    return head + (f"\n… (+{len(lines) - 200} more rows)" if len(lines) > 200 else "")


@mcp.tool()
def read_span(run: str, file: str, line: int, radius: int = 40) -> str:
    """Return the lines of a run's JS file around `line` (± `radius`) so you can judge a
    lead without opening a huge bundle."""
    d = _run_dir(run)
    if not d:
        return f"Error: run not found: {run}"
    target = _resolve_file(d, file)
    if not target:
        return f"Error: file not found in run: {file}"
    try:
        text = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return f"Error: cannot read {file} ({e})"
    lo = max(0, int(line) - int(radius) - 1)
    hi = min(len(text), int(line) + int(radius))
    numbered = [f"{i + 1:>7}  {text[i]}" for i in range(lo, hi)]
    return f"```\n# {target.name} lines {lo + 1}-{hi} (of {len(text)})\n" + "\n".join(numbered) + "\n```"


# --- prompts ------------------------------------------------------------------
_PROMPTS_DIR = W.REPO_ROOT / "prompts"


def _load_prompt(name: str) -> str:
    try:
        return (_PROMPTS_DIR / name).read_text(encoding="utf-8")
    except OSError:
        return f"(prompt '{name}' not found under {_PROMPTS_DIR})"


@mcp.prompt(
    title="JS analysis (jsanalyze doctrine)",
    description="Drive the jsanalyze MCP on a Burp XML / dir / HAR and triage its artifacts "
    "into a neat, prioritized JavaScript analysis.",
)
def js_analyze(input_path: str = "") -> str:
    """Doctrine for a model using this MCP: run `analyze`, then TRIAGE the artifacts with
    `leads`/`query`/`read_span` — the tool already computed sinks/endpoints/flags/etc."""
    doctrine = _load_prompt("js-analyze.md")
    if input_path:
        return (f"Analyze `{input_path}` with the jsanalyze MCP (`analyze` tool), then "
                f"follow this doctrine.\n\n{doctrine}")
    return doctrine


def main() -> None:
    """Console-script / `python -m jsanalyze.server` entrypoint (stdio transport)."""
    mcp.run()


if __name__ == "__main__":
    main()
