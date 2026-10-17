"""Workspace, config, hashing and secret-masking helpers (stdlib only)."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# repo_root/src/jsanalyze/utils/workspace.py -> parents[3] == repo_root
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_WORKSPACE = REPO_ROOT / "workspace"
DEFAULT_CONFIG = REPO_ROOT / "config" / "config.json"

_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


@dataclass
class Run:
    run_id: str
    dir: Path
    js_dir: Path


def slugify(text: str) -> str:
    text = _SLUG_RE.sub("-", (text or "run").strip()).strip("-._")
    return (text or "run")[:60]


def new_run(label: str, base: Path | None = None) -> Run:
    """Create workspace/<YYYY-MM-DD>_<label>/ (+ js/), unique per invocation."""
    base = base or DEFAULT_WORKSPACE
    stamp = _dt.date.today().isoformat()
    run_id = f"{stamp}_{slugify(label)}"
    run_dir = base / run_id
    # keep runs non-destructive: suffix -2, -3, ... if the id already exists
    n = 2
    while run_dir.exists():
        run_dir = base / f"{run_id}-{n}"
        n += 1
    js_dir = run_dir / "js"
    js_dir.mkdir(parents=True, exist_ok=True)
    return Run(run_id=run_dir.name, dir=run_dir, js_dir=js_dir)


def sha1_short(data: bytes | str, length: int = 10) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha1(data).hexdigest()[:length]


def write_json(path: Path, obj: Any) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_text(path: Path, text: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def cleanup_js(js_dir: Path) -> None:
    shutil.rmtree(js_dir, ignore_errors=True)


# --- config -------------------------------------------------------------------
def load_config(path: Path | None = None) -> dict[str, Any]:
    cfg_path = Path(path or os.environ.get("JSANALYZE_CONFIG") or DEFAULT_CONFIG)
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        cfg = {}
    cfg.setdefault("modes", ["urls", "secrets", "sinks", "postmessage", "sourcemaps"])
    cfg.setdefault("max_js_bytes", 5_242_880)
    cfg.setdefault("per_file_timeout_sec", 60)
    cfg.setdefault("mask_secrets_in_leads", True)
    cfg.setdefault("allow_network", False)  # Operator Gate: external fetch/verify stays off
    cfg.setdefault("enrichers", {
        "beautify": True, "linkfinder": True, "trufflehog": True,
        "gitleaks": True, "retire": True, "sourcemaps": True, "secretfinder": False,
    })
    cfg.setdefault("tools", {})
    cfg["_config_path"] = str(cfg_path)
    return cfg


def save_config(cfg: dict[str, Any], path: Path | None = None) -> Path:
    cfg_path = Path(path or cfg.get("_config_path") or DEFAULT_CONFIG)
    out = {k: v for k, v in cfg.items() if not k.startswith("_")}
    return write_json(cfg_path, out)


# --- secret masking -----------------------------------------------------------
def mask_value(value: str, keep_head: int = 4, keep_tail: int = 2) -> str:
    """'AKIAIOSFODNN7EXAMPLE' -> 'AKIA…[REDACTED]'. Short strings fully redacted."""
    if not isinstance(value, str):
        return value
    if len(value) <= keep_head + keep_tail + 2:
        return "…[REDACTED]"
    return f"{value[:keep_head]}…[REDACTED]…{value[-keep_tail:]}"


def mask_data(obj: Any) -> Any:
    """Recursively mask every string leaf — jsluice secret `data` has a variable shape
    ({key:...} vs {match:..., pattern:...}), so we mask values but keep structural keys."""
    if isinstance(obj, dict):
        # keep non-secret descriptor values (matcher name / kind) readable; mask the rest
        return {k: (v if k in ("pattern", "kind") else mask_data(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_data(v) for v in obj]
    if isinstance(obj, str):
        return mask_value(obj)
    return obj
