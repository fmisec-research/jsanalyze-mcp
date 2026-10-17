"""Vulnerable JS library detection via retire.js (local, no network).

retire.js is run against the already-decoded local JS directory (never the
target). It ships a cached vulnerability DB under ``/tmp/.retire-cache`` and
works fully offline; it may *try* to refresh that DB over the network, but a
failed refresh is non-fatal and the cached data is still used. This enricher
ignores retire's exit code (non-zero simply means "vulnerabilities found") and
reads the JSON report it writes to a tempfile.

Each ``data[].results[]`` entry becomes ONE library record matching the shape
documented on :class:`jsanalyze.models.AnalysisResult`::

    {"component","version","severity","cves":[...],"cwe":[...],"summary",
     "below","detection","source_file","origin_url","detector":"retire"}
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from jsanalyze.enrichers import tools
from jsanalyze.utils.workspace import load_config

# severity ranking so we can pick the MAX across a component's vulnerabilities
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_SUMMARY_CAP = 3


def _path_to_url(items) -> dict:
    """Map every absolute spelling of an item's saved_path to its origin URL."""
    mapping: dict = {}
    for it in items or []:
        sp = getattr(it, "saved_path", None)
        if not sp:
            continue
        url = getattr(it, "url", None)
        for key in {sp, os.path.abspath(sp), os.path.realpath(sp)}:
            mapping[key] = url
    return mapping


def _read_json(path) -> "dict | None":
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return None
    text = text.strip()
    if not text:
        return None
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def _parse_retire(report: dict, path_to_url: dict) -> list[dict]:
    """Turn a retire.js JSON report into library records (one per result)."""
    if not isinstance(report, dict):
        return []

    # by-basename fallback so we still attribute an origin URL when the absolute
    # path retire scanned differs from the one we recorded (symlinks, relative).
    by_basename: dict = {}
    for k, v in path_to_url.items():
        by_basename.setdefault(os.path.basename(k), v)

    records: list[dict] = []
    for entry in report.get("data") or []:
        if not isinstance(entry, dict):
            continue
        file_path = entry.get("file") or ""
        for result in entry.get("results") or []:
            if not isinstance(result, dict):
                continue
            vulns = [v for v in (result.get("vulnerabilities") or []) if isinstance(v, dict)]

            cves: set = set()
            cwes: set = set()
            summaries: list[str] = []
            best_i = None
            best_rank = -1
            for i, v in enumerate(vulns):
                sev = (v.get("severity") or "").lower()
                rank = _SEV_ORDER.get(sev, 0)
                if rank > best_rank:          # strict > => keep FIRST of the max
                    best_rank = rank
                    best_i = i
                idents = v.get("identifiers") or {}
                for c in idents.get("CVE") or []:
                    if c:
                        cves.add(c)
                for w in v.get("cwe") or []:
                    if w:
                        cwes.add(w)
                summ = idents.get("summary")
                if summ and summ not in summaries:
                    summaries.append(summ)

            if best_i is not None:
                severity = (vulns[best_i].get("severity") or "").lower()
                below = vulns[best_i].get("below")
            else:
                severity = ""
                below = result.get("below")

            basename = os.path.basename(file_path) if file_path else ""
            origin_url = path_to_url.get(file_path) or (by_basename.get(basename) if basename else None)

            records.append({
                "component": result.get("component"),
                "version": result.get("version"),
                "severity": severity,
                "cves": sorted(cves),
                "cwe": sorted(cwes),
                "summary": "; ".join(summaries[:_SUMMARY_CAP]),
                "below": below,
                "detection": result.get("detection"),
                "source_file": basename,
                "origin_url": origin_url,
                "detector": "retire",
            })
    return records


def _dedupe(records: list[dict]) -> list[dict]:
    seen: set = set()
    out: list[dict] = []
    for r in records:
        key = (r.get("component"), r.get("version"), r.get("source_file"))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def scan_libs(js_dir, items, cfg=None) -> list[dict]:
    """Vulnerable JS libraries via retire.js (local, no network)."""
    cfg = cfg or load_config()
    try:
        if not tools.enabled("retire", cfg):
            return []
        retire_path = tools.resolve("retire", cfg)
        if not retire_path:
            return []

        path_to_url = _path_to_url(items)

        fd, tmp_out = tempfile.mkstemp(prefix="retire_", suffix=".json")
        os.close(fd)
        try:
            cmd = [
                retire_path,
                "--path", str(js_dir),
                "--outputformat", "json",
                "--outputpath", tmp_out,
            ]
            # Ignore the return value / exit code: non-zero just means "found".
            tools.run(cmd, timeout=int(cfg.get("retire_timeout_sec") or 300))
            report = _read_json(tmp_out)
        finally:
            try:
                os.remove(tmp_out)
            except OSError:
                pass

        if not report:
            return []
        return _dedupe(_parse_retire(report, path_to_url))
    except Exception:
        # Enrichers never raise into the pipeline.
        return []
