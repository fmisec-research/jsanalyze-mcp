"""Resolve optional enricher tools, report availability, run them safely.

All enrichers go through `run()` (stdin closed, captured, timed out, never raises)
and `resolve()` (config override -> PATH -> known fallback -> None).
"""

from __future__ import annotations

import os
import shutil
import subprocess

from jsanalyze.utils.workspace import load_config

# logical name -> commands to look up on $PATH
_WHICH = {
    "js_beautify": ["js-beautify"],
    "trufflehog": ["trufflehog"],
    "gitleaks": ["gitleaks"],
    "retire": ["retire"],
    "sourcemapper": ["sourcemapper"],
    "unwebpack_sourcemap": ["unwebpack-sourcemap"],
    "secretfinder": ["secretfinder", "SecretFinder.py"],
}

# logical name -> absolute fallbacks (checked after $PATH)
_PATHS = {
    "sourcemapper": [os.path.expanduser("~/go/bin/sourcemapper")],
    # LinkFinder is a SCRIPT run with a jsbeautifier-capable python (its own
    # launcher may point at a python that lacks jsbeautifier).
    "linkfinder": [
        "/home/kali/tools/LinkFinder/linkfinder.py",
        os.path.expanduser("~/tools/LinkFinder/linkfinder.py"),
    ],
}

ALL_TOOLS = (
    "js_beautify", "linkfinder", "trufflehog", "gitleaks",
    "retire", "sourcemapper", "unwebpack_sourcemap", "secretfinder",
)


def resolve(name: str, cfg=None) -> "str | None":
    """Path to the tool (binary or script), or None. Order: config override that
    exists -> $PATH candidates -> known absolute fallbacks."""
    cfg = cfg or load_config()
    override = (cfg.get("tools") or {}).get(name)
    if override and os.path.exists(override):
        return override
    for cand in _WHICH.get(name, []):
        found = shutil.which(cand)
        if found:
            return found
    for p in _PATHS.get(name, []):
        if os.path.exists(p):
            return p
    return None


def available(cfg=None) -> dict:
    cfg = cfg or load_config()
    return {name: resolve(name, cfg) is not None for name in ALL_TOOLS}


def enabled(name: str, cfg=None) -> bool:
    """True if the enricher is toggled on in config (default off for unknown)."""
    cfg = cfg or load_config()
    return bool((cfg.get("enrichers") or {}).get(name, False))


def run(cmd, timeout=120, cwd=None, env=None):
    """Run a command safely: stdin closed, output captured, timed out. Returns the
    CompletedProcess, or None if it could not run (never raises)."""
    try:
        return subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return None
