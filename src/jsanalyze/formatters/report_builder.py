"""Render a :class:`Triaged` bundle + leads into a tidy Markdown report and a compact
tool-return summary. Secrets are always masked; nothing here re-derives analysis."""

from __future__ import annotations

import json
from collections import Counter
from urllib.parse import urlsplit

from jsanalyze.utils.workspace import mask_data

_SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONF = {"high": 0, "medium": 1, "low": 2}
_REMINDER = ("Leads = kandidat, bukan temuan. Bukti = efek lintas-batas yang teramati "
             "via skill hunt-*.")


def _one(v):
    return ("" if v is None else str(v)).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()


def _cell(v, default="-"):
    s = _one(v) or default
    return s.replace("|", "\\|")


def _inline(v):
    return " ".join(_one(v).split()).replace("`", "'")


def _hosts(items, tri):
    seen, hosts = set(), []
    for it in items or []:
        h = getattr(it, "host", "") or urlsplit(getattr(it, "url", "") or "").netloc
        if h and h not in seen:
            seen.add(h); hosts.append(h)
    for n in tri.endpoints:
        h = n.get("host")
        if h and h not in seen:
            seen.add(h); hosts.append(h)
    return ", ".join(hosts[:5]) + (f" +{len(hosts) - 5}" if len(hosts) > 5 else "") if hosts else "unknown"


def _counts(items, tri, leads):
    ep_f = sum(1 for n in tri.endpoints if n.get("fetchable"))
    sink_l = sum(1 for c in tri.sinks if c.get("lead"))
    pm_l = sum(1 for r in tri.postmessage if r.get("lead"))
    return (f"JS: {len(items or [])} | Endpoints: {ep_f} fetchable/{len(tri.endpoints)} | "
            f"Sinks: {sink_l} lead/{len(tri.sinks)} | Secrets: {len(tri.secrets)} | "
            f"Vuln libs: {len(tri.libs)} | postMessage: {pm_l} lead/{len(tri.postmessage)} | "
            f"Flags: {len(tri.flags)} | Routes: {len(tri.routes)} | Storage: {len(tri.storage)} | "
            f"GraphQL: {len(tri.graphql)} | Leads: {len(leads or [])}")


def _lead_rank(ld):
    return (_SEV.get(ld.get("severity_hint"), 9), _CONF.get(ld.get("confidence"), 9))


def _leads_section(leads):
    if not leads:
        return "_none_"
    groups, order = {}, []
    for ld in sorted(leads, key=_lead_rank):
        s = ld.get("suggested_skill") or "map-app"
        if s not in groups:
            groups[s] = []; order.append(s)
        groups[s].append(ld)
    out = []
    for s in sorted(order, key=lambda k: (-len(groups[k]), k)):
        out.append(f"### {s}")
        for ld in groups[s]:
            loc = f" — {ld.get('source_file')}:{ld.get('line')}" if ld.get("source_file") else ""
            out.append(f"- [{ld['id']}] **{ld['class']}** ({ld.get('confidence')}/{ld.get('severity_hint')}) "
                       f"— `{_inline(ld.get('evidence'))[:90]}`{loc} → {_inline(ld.get('next_step'))}")
    return "\n".join(out)


def _endpoints_section(tri):
    fetch = [n for n in tri.endpoints if n.get("fetchable")]
    if not tri.endpoints:
        return "_none_"
    rows = ["| Method | Path/URL | Party | In-scope | Type |", "| --- | --- | --- | --- | --- |"]
    for n in fetch[:60]:
        loc = n.get("url") if n.get("host") else n.get("path")
        rows.append(f"| {_cell(n.get('method'))} | {_cell(loc)} | {_cell(n.get('party'))} | "
                    f"{_cell(n.get('in_scope'))} | {_cell(n.get('call_type'))} |")
    tail = []
    if len(fetch) > 60:
        tail.append(f"… +{len(fetch) - 60} more fetchable (endpoints.txt)")
    non = len(tri.endpoints) - len(fetch)
    if non:
        tail.append(f"_{non} non-fetchable/dynamic kept in endpoints.json_")
    return "\n".join(rows) + ("\n\n" + "  ·  ".join(tail) if tail else "")


def _sinks_section(tri):
    if not tri.sinks:
        return "_none_"
    rows = ["| Lead | Class | Kind | Party | Real-taint | Count | Sample |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
    for c in tri.sinks[:40]:
        occ = (c.get("occurrences") or [{}])[0]
        rows.append(f"| {'✅' if c.get('lead') else ''} | {_cell(c.get('sink_class'))} | "
                    f"{_cell(c.get('kind'))} | {_cell(c.get('party'))} | {_cell(c.get('real_taint'))} | "
                    f"{_cell(c.get('count'))} | {_cell(_inline(occ.get('source'))[:48])} |")
    extra = f"\n\n… +{len(tri.sinks) - 40} more clusters (sinks.json)" if len(tri.sinks) > 40 else ""
    return "\n".join(rows) + extra


def _secrets_section(tri):
    if not tri.secrets:
        return "_none_"
    rows = ["| Detector | Kind | Severity | Evidence (masked) | File |",
            "| --- | --- | --- | --- | --- |"]
    for s in tri.secrets:
        ev = json.dumps(mask_data(s.get("data")), ensure_ascii=False, sort_keys=True)
        rows.append(f"| {_cell(s.get('detector'))} | {_cell(s.get('kind'))} | {_cell(s.get('severity'))} | "
                    f"{_cell(ev)} | {_cell(s.get('source_file'))} |")
    return "\n".join(rows)


def _libs_section(tri):
    if not tri.libs:
        return "_none_"
    rows = ["| Library | Version | Severity | CVE | File |", "| --- | --- | --- | --- | --- |"]
    for lib in tri.libs:
        rows.append(f"| {_cell(lib.get('component'))} | {_cell(lib.get('version'))} | "
                    f"{_cell(lib.get('severity'))} | {_cell(', '.join((lib.get('cves') or [])[:3]))} | "
                    f"{_cell(lib.get('source_file'))} |")
    return "\n".join(rows)


def _pm_section(tri):
    if not tri.postmessage:
        return "_none_"
    rows = ["| Lead | Class | Party | origin_checked | target* | File:line |",
            "| --- | --- | --- | --- | --- | --- |"]
    for r in tri.postmessage[:30]:
        rows.append(f"| {'✅' if r.get('lead') else ''} | {_cell(r.get('pm_class'))} | {_cell(r.get('party'))} | "
                    f"{_cell(r.get('origin_checked'))} | {_cell(r.get('wildcard_target'))} | "
                    f"{_cell(str(r.get('file')) + ':' + str(r.get('line')))} |")
    return "\n".join(rows)


def _mini_list(title, rows, fmt):
    if not rows:
        return f"**{title}:** none"
    body = "\n".join("  - " + fmt(r) for r in rows[:20])
    more = f"\n  - … +{len(rows) - 20} more" if len(rows) > 20 else ""
    return f"**{title}:** {len(rows)}\n{body}{more}"


def _other_section(tri):
    parts = [
        _mini_list("Routes", tri.routes,
                   lambda r: f"{r.get('path')} ({r.get('kind')}{', ' + r.get('component') if r.get('component') else ''}) {r.get('file')}:{r.get('line')}"),
        _mini_list("Feature flags", tri.flags,
                   lambda f: f"{f.get('key')} [{f.get('kind')}/{f.get('provider')}] {f.get('file')}:{f.get('line')}"),
        _mini_list("Storage", tri.storage,
                   lambda s: f"{s.get('type')} {s.get('key')} ({s.get('op')}) {s.get('file')}:{s.get('line')}"),
        _mini_list("GraphQL ops", tri.graphql,
                   lambda g: f"{g.get('operation')} {g.get('operationName')} vars={g.get('variables')} {g.get('file')}:{g.get('line')}"),
    ]
    missing = [c for c in tri.chunks if c.get("present") is False]
    if missing:
        parts.append(_mini_list("Missing chunks (operator must capture)", missing,
                                 lambda c: f"{c.get('src') or c.get('file') or c.get('id')}"))
    return "\n\n".join(parts)


def _enrichment_section(enr):
    if not enr:
        return "_none_"
    lines = []
    b = enr.get("beautified") or {}
    if b.get("beautified"):
        lines.append(f"- Beautify: {b['beautified']} file via `{b.get('tool')}` (lead line numbers refer to beautified JS).")
    s = enr.get("sources") or {}
    lines.append(f"- Sourcemaps: recovered {s.get('recovered', 0)} source files "
                 f"(inline={s.get('inline', 0)}, external={s.get('external', 0)}, fetched={s.get('fetched', 0)}).")
    t = enr.get("tools") or {}
    if t:
        lines.append(f"- Tools: {', '.join(k for k, v in t.items() if v) or 'none'}"
                     + (f" | absent: {', '.join(k for k, v in t.items() if not v)}" if any(not v for v in t.values()) else ""))
    iss = enr.get("issues") or []
    if iss:
        lines.append(f"- ⚠ issues: {len(iss)} (see issues.json)")
        lines += [f"  - {_inline(x)}" for x in iss[:8]]
    return "\n".join(lines)


def _next_steps(leads):
    out = []
    for ld in sorted(leads or [], key=_lead_rank)[:6]:
        loc = f" @ {ld.get('source_file')}:{ld.get('line')}" if ld.get("source_file") else ""
        out.append(f"- {ld.get('suggested_skill')} untuk {ld['id']} ({ld['class']}{loc}).")
    if not out:
        out.append("- Belum ada lead otomatis; tinjau endpoints.json, sinks.json & routes.json manual.")
    out.append(f"- {_REMINDER}")
    return "\n".join(out)


def build_report(items, tri, leads, run, enrichment=None) -> str:
    fw = (tri.framework or {}).get("framework", "unknown")
    sections = [
        f"# JS Analysis — {_hosts(items, tri)} ({getattr(run, 'run_id', '?')})",
        "## Ringkasan\n"
        f"- {_counts(items, tri, leads)}\n"
        f"- Leads per skill: {', '.join(f'{k}: {v}' for k, v in Counter(l.get('suggested_skill') for l in (leads or [])).most_common()) or '-'}\n"
        f"- Framework: {fw}",
        "## Leads prioritas\n" + _leads_section(leads),
        "## Endpoints (fetchable)\n" + _endpoints_section(tri),
        "## Sinks (audit — ✅ = lead)\n" + _sinks_section(tri),
        "## Secrets (MASKED)\n" + _secrets_section(tri),
        "## Vulnerable libraries\n" + _libs_section(tri),
        "## postMessage\n" + _pm_section(tri),
        "## Lainnya\n" + _other_section(tri),
        "## Langkah berikutnya\n" + _next_steps(leads),
        "## Enrichment\n" + _enrichment_section(enrichment),
    ]
    return "\n\n".join(sections) + "\n"


def report_summary(run, items, tri, leads, issues=None) -> str:
    lines = [
        f"# JS Analysis — {_hosts(items, tri)} ({getattr(run, 'run_id', '?')})",
        _counts(items, tri, leads),
        f"Workspace: {getattr(run, 'dir', '')}",
        "Artefak: endpoints·sinks·postmessage·secrets·libs·graphql·flags·routes·storage·chunks·sourcemaps .json, leads.json, report.md",
    ]
    if issues:
        lines.append(f"⚠ issues: {len(issues)} (issues.json) — e.g. {_inline(issues[0])[:100]}")
    top = sorted(leads or [], key=_lead_rank)[:6]
    if top:
        lines.append("Top leads:")
        for ld in top:
            lines.append(f"- [{ld['id']}] {ld['class']} {ld.get('confidence')}/{ld.get('severity_hint')} "
                         f"→ {ld.get('suggested_skill')} — {_inline(ld.get('evidence'))[:60]}")
    else:
        lines.append("Top leads: none (review endpoints/sinks/routes artifacts)")
    lines.append(f"\nTriage with: leads('{getattr(run, 'run_id', '')}', …), query(run,file,q), read_span(run,file,line).")
    return "\n".join(lines) + "\n"
