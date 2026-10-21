"""Shared data contract for the whole pipeline (stdlib-only dataclasses).

Every component in jsanalyze-mcp agrees on these shapes:

    burp_parser   ->  list[Item]
    jsluice_wrapper(Item.saved_path ...)  ->  AnalysisResult
    lead_engine(AnalysisResult, items)    ->  list[Lead]
    report_builder(items, AnalysisResult, leads)  ->  str (markdown)

The per-mode records inside AnalysisResult are kept as plain dicts that mirror
jsluice's own JSON output *verbatim*, with two fields injected by the wrapper:

    "origin_url" : the Burp URL the .js file was served from (or None)
    "filename"   : already present in jsluice output (absolute path to the .js)

Ground-truth jsluice field shapes (fork github.com/0xshdax/jsluice), one JSON
object per output line, NO `-j` flag:

    urls        : {url, queryParams[], bodyParams[], method, type, filename}
    secrets     : {kind, data{...varies...}, filename, severity, context}
    sinks       : {kind, severity, tainted, taint?, line, source, filename}
    postmessage : {kind, originChecked, severity, sinks[], line, source, filename}
    sourcemaps  : {kind, url, inline, line, source, filename}
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# --- controlled vocabularies (documentation; not enforced) --------------------
CONFIDENCE = ("low", "medium", "high")
SEVERITY_HINT = ("info", "low", "medium", "high", "critical")
MODES = ("urls", "secrets", "sinks", "postmessage", "sourcemaps")


@dataclass
class Item:
    """One JavaScript response extracted from a Burp XML <item>."""

    url: str
    host: str = ""
    method: str = ""
    status: int | None = None
    mimetype: str | None = None
    is_javascript: bool = False
    js_body: str | None = None          # decoded body, HTTP headers already stripped
    saved_path: str | None = None       # workspace/<run>/js/<name>.js once written
    sha1: str = ""                      # short hash of js_body (dedupe + filename)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("js_body", None)          # never dump full bodies into metadata json
        return d


@dataclass
class AnalysisResult:
    """jsluice output (deduped, per mode) plus enricher output.

    Enrichers (optional external tools) extend these lists with extra records that
    keep the SAME shape as the jsluice ones, plus a ``detector`` field naming the
    source so the report/leads can attribute them:

      * urls    += linkfinder endpoints  -> {url, method:"", type:"linkfinder",
                   filename, source_file, origin_url, fetchable, detector:"linkfinder"}
      * secrets := normalized across detectors ->
                   {detector:"jsluice"|"gitleaks"|"trufflehog"|"secretfinder",
                    kind, severity, data:{...}, context, source_file, origin_url, line}
      * libs    := retire.js vulnerable libraries (NEW) ->
                   {component, version, severity, cves:[...], cwe:[...], summary,
                    below, detection, source_file, origin_url, detector:"retire"}
    """

    urls: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    sinks: list[dict] = field(default_factory=list)
    postmessage: list[dict] = field(default_factory=list)
    sourcemaps: list[dict] = field(default_factory=list)
    libs: list[dict] = field(default_factory=list)   # retire.js vulnerable libraries
    issues: list[str] = field(default_factory=list)  # jsluice run failures (surfaced, not dropped)

    def counts(self) -> dict[str, int]:
        c = {m: len(getattr(self, m)) for m in MODES}
        c["libs"] = len(self.libs)
        return c

    def total(self) -> int:
        return sum(len(getattr(self, m)) for m in MODES)


@dataclass
class Triaged:
    """Everything `analyze` computes for the model to TRIAGE (not re-derive). Each list
    is also written to its own artifact file; `issues` surfaces enricher/tool failures."""

    endpoints: list[dict] = field(default_factory=list)     # normalized (endpoints.json)
    sinks: list[dict] = field(default_factory=list)         # clustered (sinks.json)
    postmessage: list[dict] = field(default_factory=list)   # classified (postmessage.json)
    secrets: list[dict] = field(default_factory=list)       # normalized (secrets.json)
    libs: list[dict] = field(default_factory=list)          # retire.js (libs.json)
    graphql: list[dict] = field(default_factory=list)       # operations (graphql.json)
    flags: list[dict] = field(default_factory=list)         # feature flags (flags.json)
    routes: list[dict] = field(default_factory=list)        # SPA routes (routes.json)
    storage: list[dict] = field(default_factory=list)       # storage/cookie writes (storage.json)
    chunks: list[dict] = field(default_factory=list)        # webpack chunk map (chunks.json)
    framework: dict = field(default_factory=dict)           # framework.json
    sourcemaps: list[dict] = field(default_factory=list)    # real .map refs + recovered
    csp: list[dict] = field(default_factory=list)           # CSP directive hosts (csp.json)
    notes: list[dict] = field(default_factory=list)         # mined source comments (source_notes.json)
    responses: dict = field(default_factory=dict)           # response over-fetch + HTML sinks (responses.json)
    issues: list[str] = field(default_factory=list)         # enricher/jsluice failures (surfaced)


@dataclass
class Lead:
    """A vulnerability *candidate* (NOT a finding). Seeded deterministically from
    jsluice output, then tagged with a heuristic class + the hunt-* skill that
    would PROVE it. severity_hint/confidence are potential only.

    v2 (critique point 10): every retained lead also carries the fields a model
    needs to act WITHOUT re-reading a 30k-line bundle — a composite ``score`` (the
    real queue order, with explainable ``score_factors``), the short ``caller_chain``
    (taint/data-flow hops), the request ``body_keys``, a crisp ``negative_control``
    and the single ``experiment`` to run. ``seen_in_history`` records whether the
    endpoint was actually exercised in the captured traffic (False = untested surface)."""

    id: str
    cls: str                            # taxonomy, e.g. "idor-candidate", "xss-sink"
    title: str
    suggested_skill: str                # which hunt-* skill proves it
    source_file: str = ""               # workspace-relative .js path
    origin_url: str | None = None       # Burp URL the .js came from
    line: int | None = None
    evidence: str = ""                  # short code snippet / URL
    detector: str = ""                  # provenance, e.g. "jsluice:sinks"
    tainted: bool | None = None
    confidence: str = "low"             # low|medium|high (heuristic)
    severity_hint: str = "info"         # POTENTIAL impact, never proven
    next_step: str = ""
    notes: str = ""
    # --- v2 fields (point 10) -------------------------------------------------
    score: float = 0.0                  # composite priority (primary sort key, desc)
    score_factors: list[str] = field(default_factory=list)  # explainable +/- terms
    seen_in_history: bool | None = None  # True/False/None(unknown): exercised in traffic?
    caller_chain: list[str] = field(default_factory=list)   # taint/data-flow hops
    body_keys: list[str] = field(default_factory=list)      # request body field names
    method: str = ""                    # HTTP method (endpoints)
    negative_control: str = ""          # the control that MUST fail for the bug to hold
    experiment: str = ""                # the ONE specific test to run

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["class"] = d.pop("cls")       # emit as "class" in JSON (reserved word in py)
        return d
