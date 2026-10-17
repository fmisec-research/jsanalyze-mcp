"""Enricher: de-minify JavaScript in place so line numbers are meaningful.

Beautifying every ``*.js`` BEFORE jsluice/LinkFinder run means a ``line`` field in
a sink/secret/url record points at a real, readable source line rather than
column N of a single minified megaline. Prefers the in-process ``jsbeautifier``
Python module (cleanest); falls back to the ``js-beautify`` CLI. A trailing
``//# sourceMappingURL=...`` comment is preserved. Never raises — a file that
fails to beautify is left exactly as it was and simply not counted.
"""

from __future__ import annotations

import os

from jsanalyze.enrichers import tools

# Trailing source-map pragma we must not lose when rewriting a bundle.
_SOURCEMAP_MARKER = "//# sourceMappingURL="


def beautify_dir(js_dir, cfg=None) -> dict:
    """Beautify every *.js in js_dir IN PLACE (de-minify so line numbers mean something).
    Returns {"beautified": <int count>, "tool": "<which>" | None}."""
    if not tools.enabled("beautify", cfg):
        return {"beautified": 0, "tool": None}

    try:
        entries = sorted(os.listdir(js_dir))
    except OSError:
        return {"beautified": 0, "tool": None}

    js_files = [
        os.path.join(js_dir, name)
        for name in entries
        if name.lower().endswith(".js") and os.path.isfile(os.path.join(js_dir, name))
    ]
    if not js_files:
        return {"beautified": 0, "tool": None}

    # Preferred path: the in-process jsbeautifier module.
    module = None
    try:
        import jsbeautifier  # type: ignore

        module = jsbeautifier
    except Exception:
        module = None

    if module is not None:
        count = sum(1 for path in js_files if _beautify_one_module(module, path))
        return {"beautified": count, "tool": "jsbeautifier-module"}

    # Fallback: the js-beautify CLI (replace in place with -r).
    cli = tools.resolve("js_beautify", cfg)
    if cli:
        count = sum(1 for path in js_files if _beautify_one_cli(cli, path, cfg))
        return {"beautified": count, "tool": cli}

    return {"beautified": 0, "tool": None}


def _read_text(path) -> "str | None":
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _write_text(path, text: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return True
    except OSError:
        return False


def _preserve_sourcemap(src_text: str, out_text: str) -> str:
    """jsbeautifier keeps comments by default, but be defensive: if the input ended
    with a ``//# sourceMappingURL=...`` line and the output lost it, re-append it."""
    marker_line = None
    for line in src_text.splitlines():
        stripped = line.strip()
        if stripped.startswith(_SOURCEMAP_MARKER):
            marker_line = stripped  # last one wins (it is a trailing pragma)
    if marker_line is None or _SOURCEMAP_MARKER in out_text:
        return out_text
    sep = "" if out_text.endswith("\n") else "\n"
    return f"{out_text}{sep}{marker_line}\n"


def _beautify_one_module(module, path) -> bool:
    """Beautify one file with the jsbeautifier module. Returns True on success;
    on any failure the file is left untouched and False is returned."""
    text = _read_text(path)
    if text is None:
        return False
    try:
        out = module.beautify(text)
    except Exception:
        return False
    if not isinstance(out, str):
        return False
    # Refuse an empty result from non-empty input (leave the file unchanged).
    if not out.strip() and text.strip():
        return False
    out = _preserve_sourcemap(text, out)
    return _write_text(path, out)


def _beautify_one_cli(cli, path, cfg) -> bool:
    """Beautify one file via the js-beautify CLI. Returns True on success; a failed
    run leaves the file as-is and returns False.

    CLI variants differ: the npm/standard js-beautify rewrites in place with ``-r``,
    while a minimal ``js-beautify <file>`` shim only prints to stdout and supports no
    flags. We try ``-r`` first, then fall back to capturing stdout and writing it
    back ourselves, so both kinds work. Comments (incl. the sourcemap pragma) are
    kept by default; we re-append the pragma defensively if it was lost."""
    src_text = _read_text(path)
    if src_text is None:
        return False
    timeout = (cfg or {}).get("per_file_timeout_sec", 60)

    # (1) In-place replace for CLIs that support it.
    proc = tools.run([cli, "-r", path], timeout=timeout)
    if proc is not None and proc.returncode == 0:
        out_text = _read_text(path)
        if out_text is None:
            return False
        if _SOURCEMAP_MARKER in src_text:
            fixed = _preserve_sourcemap(src_text, out_text)
            if fixed != out_text:
                _write_text(path, fixed)
        return True

    # (2) Portable fallback: beautify to stdout, write it back in place ourselves.
    proc = tools.run([cli, path], timeout=timeout)
    if proc is None or proc.returncode != 0:
        return False
    out_text = proc.stdout or ""
    if not out_text.strip() and src_text.strip():
        return False
    out_text = _preserve_sourcemap(src_text, out_text)
    return _write_text(path, out_text)
