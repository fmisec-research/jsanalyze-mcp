"""Thin, robust wrapper around the jsluice CLI (fork github.com/0xshdax/jsluice).

Invocation facts obeyed here (empirically verified):

  * ``jsluice <mode> <file>`` — exactly one file argument.
  * Output is line-delimited JSON (one object per line) by DEFAULT.
  * NEVER pass ``-j`` (it yields empty output and can hang).
  * ALWAYS pass ``stdin=DEVNULL`` and a ``timeout`` or jsluice may block on
    stdin forever.

Each jsluice record already carries a ``filename`` field (absolute path of the
analyzed .js). The wrapper injects two extra fields into every record:

    "origin_url"  : the Burp URL the .js was served from (or None)
    "source_file" : os.path.basename(filename)

Records are deduplicated per mode (see ``_DEDUPE``) preserving first-occurrence
order, then returned as an :class:`AnalysisResult`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

from jsanalyze.models import AnalysisResult, Item, MODES
from jsanalyze.utils.workspace import load_config

__all__ = ["resolve_jsluice", "run_jsluice"]

_GO_BIN_FALLBACK = os.path.expanduser("~/go/bin/jsluice")

# jsluice `type` values that denote an actual request site (vs a bare string match).
_NON_FETCH_TYPES = {"stringLiteral", "comment", ""}


def _is_fetchable(url, rtype) -> bool:
    """True if a url record is a real HTTP(S)/WS endpoint rather than a code reference.

    jsluice on minified bundles emits many `stringLiteral` paths that are webpack/
    module specifiers (``./_lib/x/index.js``), not endpoints. We keep as fetchable:
      * absolute/protocol-relative URLs (http/https/ws/wss, ``//host``);
      * records from a real call site (type != stringLiteral/comment: fetch, axios.*,
        websocket, dynamicImport, xhr, sendBeacon, ...);
      * rooted absolute paths (``/api/...``).
    A relative module-ish string literal (``./x``, ``../x``, ``a/b/index.js``) is not.
    """
    u = (url or "").strip()
    if not u:
        return False
    if u.lower().startswith(("http://", "https://", "ws://", "wss://", "//")):
        return True
    if (rtype or "") not in _NON_FETCH_TYPES:
        return True
    return u.startswith("/")  # rooted path from a plain string literal


def resolve_jsluice(cfg=None) -> "str | None":
    """Return a usable jsluice path, or None.

    Order: ``cfg['jsluice_path']`` (if set and exists) -> ``shutil.which('jsluice')``
    -> ``~/go/bin/jsluice`` (if it exists) -> None.
    """
    cfg = cfg or load_config()
    configured = cfg.get("jsluice_path")
    if configured and os.path.exists(configured):
        return configured
    on_path = shutil.which("jsluice")
    if on_path:
        return on_path
    if os.path.exists(_GO_BIN_FALLBACK):
        return _GO_BIN_FALLBACK
    return None


def _dedupe_key(mode: str, rec: dict):
    """The per-mode identity used to drop duplicate records.

    urls        -> (url, method, type)
    secrets     -> (kind, json.dumps(data, sort_keys=True))
    sinks       -> (kind, line, source, filename)
    postmessage -> (line, source, filename)
    sourcemaps  -> (url, line, filename)
    """
    if mode == "urls":
        return (rec.get("url"), rec.get("method"), rec.get("type"))
    if mode == "secrets":
        return (rec.get("kind"), json.dumps(rec.get("data"), sort_keys=True))
    if mode == "sinks":
        return (rec.get("kind"), rec.get("line"), rec.get("source"), rec.get("filename"))
    if mode == "postmessage":
        return (rec.get("line"), rec.get("source"), rec.get("filename"))
    if mode == "sourcemaps":
        return (rec.get("url"), rec.get("line"), rec.get("filename"))
    # Unknown mode: identity is the whole record (defensive; should never run).
    return json.dumps(rec, sort_keys=True)


def run_jsluice(items, modes=None, cfg=None) -> AnalysisResult:
    """Run each mode over each ``item.saved_path``, parse, dedupe, return.

    A mode that errors or times out on a file contributes nothing (the run is
    never aborted); such issues are collected locally so one bad file cannot
    sink the whole analysis.
    """
    cfg = cfg or load_config()
    modes = modes or cfg["modes"]
    timeout = cfg["per_file_timeout_sec"]

    jsluice = resolve_jsluice(cfg)
    if jsluice is None:
        raise RuntimeError("jsluice not found — run setup")

    # saved_path -> origin URL (used to attribute each record to its Burp URL).
    path_to_url = {it.saved_path: it.url for it in items if getattr(it, "saved_path", None)}

    results: dict[str, list] = {m: [] for m in MODES}
    seen: dict[str, set] = {m: set() for m in MODES}
    issues: list[str] = []  # collected, never raised (no channel in AnalysisResult)

    for item in items:
        saved_path = getattr(item, "saved_path", None)
        if not saved_path:
            continue
        for mode in modes:
            if mode not in MODES:
                issues.append(f"unknown mode {mode!r} skipped")
                continue
            try:
                proc = subprocess.run(
                    [jsluice, mode, saved_path],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                issues.append(f"{mode} timed out on {saved_path}")
                continue
            except (OSError, ValueError) as exc:  # launch failure, bad args, ...
                issues.append(f"{mode} failed to launch on {saved_path}: {exc}")
                continue

            if proc.returncode != 0 and not (proc.stdout or "").strip():
                issues.append(
                    f"{mode} rc={proc.returncode} on {saved_path}: "
                    f"{(proc.stderr or '').strip()[:200]}"
                )
                # fall through: stdout is empty, loop below is a no-op.

            for line in (proc.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue  # skip lines that fail to parse
                if not isinstance(rec, dict):
                    continue

                filename = rec.get("filename")
                origin = path_to_url.get(filename)
                if origin is None:
                    origin = item.url or None
                rec["origin_url"] = origin
                rec["source_file"] = (
                    os.path.basename(filename) if filename else os.path.basename(saved_path)
                )
                if mode == "urls":
                    rec["fetchable"] = _is_fetchable(rec.get("url"), rec.get("type"))
                    rec.setdefault("detector", "jsluice")
                elif mode == "secrets":
                    rec.setdefault("detector", "jsluice")

                key = _dedupe_key(mode, rec)
                if key in seen[mode]:
                    continue
                seen[mode].add(key)
                results[mode].append(rec)

    return AnalysisResult(
        urls=results["urls"],
        secrets=results["secrets"],
        sinks=results["sinks"],
        postmessage=results["postmessage"],
        sourcemaps=results["sourcemaps"],
        issues=issues,
    )
