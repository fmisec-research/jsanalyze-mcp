"""Secrets enricher: trufflehog + gitleaks (+ secretfinder if present).

Runs the configured secret scanners on the LOCAL decoded JS directory and returns
NORMALIZED secret records (one dict per finding) in the shape documented on
:class:`jsanalyze.models.AnalysisResult`::

    {"detector": "...", "kind": "...", "severity": "...", "data": {...},
     "context": None, "source_file": "...", "origin_url": "...", "line": <int|None>}

These merge with jsluice's own ``secrets`` records elsewhere; this module only
dedupes WITHIN the tool output (trufflehog vs gitleaks reporting the same secret),
never against jsluice. Every external call goes through ``tools.run`` (stdin
closed, captured, timed out, never raises) and no failure is allowed to propagate
to the caller — a failed tool contributes an empty list.

STDLIB ONLY (json, os, tempfile).
"""

from __future__ import annotations

import json
import os
import tempfile

from jsanalyze.enrichers import tools
from jsanalyze.utils.workspace import load_config

# Whole-directory scans, so a generous fixed timeout rather than a per-file one.
_SCAN_TIMEOUT = 300


# --- helpers -----------------------------------------------------------------
def _build_path_to_url(items) -> dict:
    """Map every item's saved_path -> url, and also its basename -> url as a
    fallback (first-wins on basename collisions). ``items`` are objects exposing
    ``.saved_path`` and ``.url``."""
    mapping: dict = {}
    for it in (items or []):
        saved = getattr(it, "saved_path", None)
        url = getattr(it, "url", None)
        if not saved:
            continue
        mapping.setdefault(saved, url)
        mapping.setdefault(os.path.basename(saved), url)  # by-basename fallback
    return mapping


def _url_for(file_path: str, path_to_url: dict):
    """origin_url for a tool-reported absolute path: exact match first, then basename."""
    if not file_path:
        return None
    url = path_to_url.get(file_path)
    if url is None:
        url = path_to_url.get(os.path.basename(file_path))
    return url


def _secret_value(rec: dict):
    """The secret string used for cross-tool dedupe (trufflehog data.raw /
    gitleaks data.secret; data.match as a last resort)."""
    data = rec.get("data") or {}
    return data.get("raw") or data.get("secret") or data.get("match")


def _dedupe(records: list) -> list:
    """Dedupe combined tool output by (secret value, source_file), first-wins.
    Records with no extractable secret value are kept as-is (never collapsed)."""
    seen: set = set()
    out: list = []
    for rec in records:
        value = _secret_value(rec)
        if value:
            key = (value, rec.get("source_file"))
            if key in seen:
                continue
            seen.add(key)
        out.append(rec)
    return out


def _safe(fn, *args) -> list:
    """Run one tool stage so any failure contributes [] — never raises to caller."""
    try:
        result = fn(*args)
        return result if isinstance(result, list) else []
    except Exception:
        return []


# --- parsers (TESTABLE in isolation) -----------------------------------------
def _parse_trufflehog(stdout: str, path_to_url: dict) -> list[dict]:
    """Parse trufflehog line-delimited JSON (one finding per line) into normalized
    records. Lines that are not JSON dicts, or carry no DetectorName (e.g. the
    tool's own info/log lines), are skipped. The FULL secret is kept in data.raw."""
    records: list[dict] = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        kind = obj.get("DetectorName")
        if not kind:  # info/log lines and anything that isn't a finding
            continue
        fs = (((obj.get("SourceMetadata") or {}).get("Data") or {})
              .get("Filesystem") or {})
        file_path = fs.get("file") or ""
        raw = obj.get("Raw") or obj.get("RawV2") or obj.get("Redacted")
        records.append({
            "detector": "trufflehog",
            "kind": kind,
            "severity": "high",
            "data": {"raw": raw},
            "context": None,
            "source_file": os.path.basename(file_path) if file_path else "",
            "origin_url": _url_for(file_path, path_to_url),
            "line": fs.get("line"),
        })
    return records


def _parse_gitleaks(json_text: str, path_to_url: dict) -> list[dict]:
    """Parse a gitleaks JSON-array report into normalized records. Empty, invalid
    or non-array input yields []. Non-dict elements are skipped."""
    records: list[dict] = []
    text = (json_text or "").strip()
    if not text:
        return records
    try:
        arr = json.loads(text)
    except (ValueError, TypeError):
        return records
    if not isinstance(arr, list):
        return records
    for el in arr:
        if not isinstance(el, dict):
            continue
        file_path = el.get("File") or ""
        records.append({
            "detector": "gitleaks",
            "kind": el.get("RuleID"),
            "severity": "high",
            "data": {"secret": el.get("Secret"), "match": el.get("Match")},
            "context": el.get("Description"),
            "source_file": os.path.basename(file_path) if file_path else "",
            "origin_url": _url_for(file_path, path_to_url),
            "line": el.get("StartLine"),
        })
    return records


def _parse_secretfinder(stdout: str, file_path: str, path_to_url: dict) -> list[dict]:
    """Best-effort parse of SecretFinder CLI output (`-o cli`), stdlib only (no regex).

    SecretFinder is NOT installed on this box, so this branch is structured but
    untested. Conservative ``<name> : <value>`` lines become normalized records;
    everything else (banners, URL lists, prose) is ignored."""
    records: list[dict] = []
    base = os.path.basename(file_path) if file_path else ""
    url = _url_for(file_path, path_to_url)
    for line in (stdout or "").splitlines():
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().strip("[]+-> ").strip()
        value = value.strip()
        # conservative guards: plausible detector label + a single non-trivial token
        if not name or not value or " " in value:
            continue
        if len(value) < 8 or len(name) > 40:
            continue
        records.append({
            "detector": "secretfinder",
            "kind": name,
            "severity": "high",
            "data": {"raw": value},
            "context": None,
            "source_file": base,
            "origin_url": url,
            "line": None,
        })
    return records


# --- tool runners ------------------------------------------------------------
def _run_trufflehog(bin_path: str, js_dir, path_to_url: dict, cfg) -> list[dict]:
    # VERIFIED invocation. --no-update is REQUIRED (the self-updater fails on this
    # box and returns rc=1); returncode is IGNORED entirely and stdout parsed
    # regardless, while the updater error on stderr is ignored.
    cmd = [bin_path, "filesystem", str(js_dir), "--no-update",
           "--no-verification", "--results=verified,unknown", "--json"]
    cp = tools.run(cmd, timeout=_SCAN_TIMEOUT)
    if cp is None:
        return []
    return _parse_trufflehog(cp.stdout or "", path_to_url)


def _run_gitleaks(bin_path: str, js_dir, path_to_url: dict, cfg) -> list[dict]:
    # VERIFIED: write a JSON-array report to a system tempfile, then read it back.
    fd, tmp = tempfile.mkstemp(suffix=".json", prefix="gitleaks_")
    os.close(fd)
    try:
        cmd = [bin_path, "dir", str(js_dir), "-f", "json", "-r", tmp,
               "--no-banner", "--exit-code", "0"]
        cp = tools.run(cmd, timeout=_SCAN_TIMEOUT)
        if cp is None:
            return []
        try:
            with open(tmp, "r", encoding="utf-8", errors="replace") as fh:
                json_text = fh.read()
        except OSError:
            return []
        return _parse_gitleaks(json_text, path_to_url)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _run_secretfinder(bin_path: str, js_dir, items, path_to_url: dict, cfg) -> list[dict]:
    # SecretFinder scans one file at a time; resolved as a *.py script it needs a
    # python interpreter. Not installed here, so this never actually runs.
    prefix = [os.environ.get("PYTHON", "python3")] if bin_path.endswith(".py") else []
    records: list[dict] = []
    for it in (items or []):
        saved = getattr(it, "saved_path", None)
        if not saved or not os.path.isfile(saved):
            continue
        cp = tools.run(prefix + [bin_path, "-i", saved, "-o", "cli"],
                       timeout=_SCAN_TIMEOUT)
        if cp is None:
            continue
        records += _parse_secretfinder(cp.stdout or "", saved, path_to_url)
    return records


# --- entrypoint --------------------------------------------------------------
def scan_secrets(js_dir, items, cfg=None) -> list[dict]:
    """Normalized secret records from trufflehog + gitleaks (+ secretfinder if present).

    Runs each scanner only when it is enabled in config AND resolvable on this box;
    an absent or disabled tool is skipped silently. Each run is wrapped so a failure
    contributes [] and never raises. The combined tool output is deduped by secret
    value + source_file (first-wins) so trufflehog and gitleaks reporting the same
    secret do not double-count; jsluice records are merged (and deduped) elsewhere.
    """
    cfg = cfg or load_config()
    path_to_url = _build_path_to_url(items)
    records: list[dict] = []

    th = tools.resolve("trufflehog", cfg)
    if th and tools.enabled("trufflehog", cfg):
        records += _safe(_run_trufflehog, th, js_dir, path_to_url, cfg)

    gl = tools.resolve("gitleaks", cfg)
    if gl and tools.enabled("gitleaks", cfg):
        records += _safe(_run_gitleaks, gl, js_dir, path_to_url, cfg)

    sf = tools.resolve("secretfinder", cfg)
    if sf and tools.enabled("secretfinder", cfg):
        records += _safe(_run_secretfinder, sf, js_dir, items, path_to_url, cfg)

    return _dedupe(records)
