"""Enricher: extract extra endpoint candidates with LinkFinder.

LinkFinder's regex pass over a JS file surfaces path/URL strings that jsluice's
AST pass can miss (and vice-versa). Each hit is normalized into a url record with
the SAME shape jsluice emits, tagged ``detector="linkfinder"`` / ``type="linkfinder"``
so the lead engine and report can attribute and dedupe it.

LinkFinder is a SCRIPT whose own launcher may point at a Python that lacks the
``jsbeautifier`` dependency, so we run it with ``sys.executable`` — the (venv)
interpreter the server itself runs under, which has jsbeautifier. Never raises;
on any trouble the offending file simply contributes nothing.
"""

from __future__ import annotations

import os
import sys

from jsanalyze.enrichers import tools
from jsanalyze.analyzers.jsluice_wrapper import _is_fetchable


def linkfinder_endpoints(items, cfg=None) -> list[dict]:
    """Extra endpoint records from LinkFinder, same shape as jsluice url records."""
    if not tools.enabled("linkfinder", cfg):
        return []
    script = tools.resolve("linkfinder", cfg)
    if not script:
        return []

    timeout = (cfg or {}).get("per_file_timeout_sec", 60)
    records: list[dict] = []
    seen: set = set()

    for item in items or []:
        saved_path = getattr(item, "saved_path", None)
        if not saved_path:
            continue

        proc = tools.run(
            [sys.executable, script, "-i", saved_path, "-o", "cli"],
            timeout=timeout,
        )
        if proc is None:
            continue
        stdout = proc.stdout or ""
        if proc.returncode != 0 and not stdout.strip():
            continue

        origin_url = getattr(item, "url", None)
        source_file = os.path.basename(saved_path)
        for raw in stdout.splitlines():
            ep = raw.strip()
            if not _looks_like_endpoint(ep):
                continue
            if ep in seen:  # dedupe within LinkFinder output by url (first wins)
                continue
            seen.add(ep)
            records.append(
                {
                    "url": ep,
                    "queryParams": [],
                    "bodyParams": [],
                    "method": "",
                    "type": "linkfinder",
                    "filename": saved_path,
                    "source_file": source_file,
                    "origin_url": origin_url,
                    "detector": "linkfinder",
                    "fetchable": _is_fetchable(ep, "linkfinder"),
                }
            )

    return records


def _looks_like_endpoint(line: str) -> bool:
    """A stripped stdout line that looks like an endpoint, discarding obvious noise
    (ANSI escapes, bracketed log lines, python tracebacks)."""
    if not line:
        return False
    # Noise: ANSI colour escapes and bracketed log/diagnostic lines.
    if "\x1b" in line or line.startswith("["):
        return False
    low = line.lower()
    # Noise: python traceback framing.
    if low.startswith(("traceback", 'file "', "file \"")) or line.lstrip().startswith("File \""):
        return False
    # Endpoint-ish: absolute URL / rooted path / websocket scheme.
    if line.startswith(("/", "http://", "https://", "ws")):
        return True
    # Endpoint-ish: a bare relative path (has a slash, no whitespace).
    if "/" in line and " " not in line and "\t" not in line:
        return True
    return False
