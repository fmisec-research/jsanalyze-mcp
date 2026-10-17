"""Reconstruct original sources from sourcemaps and feed them back into analysis
(critique point 6).

- Local-first: inline `data:` maps, and `.map` files provided beside the JS (from a
  directory/HAR input) or decoded from the Burp XML, are reconstructed with NO network.
- The recovered `sources/` are returned so `analyze` re-runs the whole triage over them,
  making leads point at `sources/<file>:<line>` instead of a minified bundle.
- A real external `.map` URL is only fetched when `allow_network` is on AND its host is in
  scope (the Operator Gate); then it is actually fetched, not just noted.
- Only genuine `//# sourceMappingURL=` references count — a library homepage URL in a
  comment is never a sourcemap (our own regex, not jsluice's broader comment scan).
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

from jsanalyze.enrichers import tools
from jsanalyze.utils.workspace import load_config

_SM_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)", re.IGNORECASE)
_DATA_RE = re.compile(r"^data:application/json(?:;charset=[^;,]+)?(;base64)?,(.*)$", re.I | re.S)


def _in_scope(host, scope_hosts):
    if not host or not scope_hosts:
        return False
    scope = {h.lower().lstrip("*.") for h in scope_hosts}
    return any(host == s or host.endswith("." + s) for s in scope)


def _stage_inline(data_url, maps_dir, stem):
    m = _DATA_RE.match(data_url)
    if not m:
        return False
    is_b64, payload = m.group(1), m.group(2)
    try:
        if is_b64:
            pad = "=" * (-len(payload) % 4)
            raw = base64.b64decode(payload + pad)
        else:
            raw = unquote(payload).encode("utf-8", "replace")
    except Exception:
        return False
    try:
        (maps_dir / f"{stem}.js.map").write_bytes(raw)
        return True
    except OSError:
        return False


def recover_sources(items, out_dir, cfg=None, map_items=None, scope_hosts=None) -> dict:
    cfg = cfg or load_config()
    out = {"recovered": 0, "inline": 0, "external": 0, "fetched": 0,
           "files": [], "refs": [], "issues": []}
    if not tools.enabled("sourcemaps", cfg):
        out["issues"].append("sourcemaps enricher disabled")
        return out

    out_dir = Path(out_dir)
    maps_dir = Path(tempfile.mkdtemp(prefix="jsa-maps-"))
    allow_net = bool(cfg.get("allow_network"))
    try:
        # 1) .map files supplied directly (directory / HAR / XML .map items)
        for mi in map_items or []:
            p = getattr(mi, "saved_path", None)
            if p and os.path.exists(p):
                try:
                    shutil.copy2(p, maps_dir / (Path(p).name if Path(p).name.endswith(".map")
                                               else Path(p).name + ".map"))
                    out["refs"].append({"url": getattr(mi, "url", ""), "kind": "file",
                                        "inline": False, "recovered": True})
                except OSError as e:
                    out["issues"].append(f"map copy failed: {e}")

        # 2) sourceMappingURL references inside the JS bodies
        for it in items or []:
            sp = getattr(it, "saved_path", None)
            if not sp or not os.path.exists(sp):
                continue
            try:
                text = Path(sp).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            stem = Path(sp).stem
            for ref in _SM_RE.findall(text):
                if ref.lower().startswith("data:"):
                    if _stage_inline(ref, maps_dir, stem):
                        out["inline"] += 1
                        out["refs"].append({"url": "(inline)", "kind": "inline",
                                            "inline": True, "recovered": True, "from": Path(sp).name})
                    continue
                # external .map URL
                out["external"] += 1
                abs_url = urljoin(getattr(it, "url", "") or "", ref)
                host = urlsplit(abs_url).netloc.split(":")[0].lower()
                rec = {"url": abs_url, "kind": "sourceMappingURL", "inline": False,
                       "recovered": False, "from": Path(sp).name}
                if allow_net and _in_scope(host, scope_hosts):
                    try:
                        req = urllib.request.Request(abs_url, headers={"User-Agent": "jsanalyze"})
                        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 (gated)
                            (maps_dir / f"{stem}.ext.js.map").write_bytes(r.read())
                        out["fetched"] += 1
                        rec["recovered"] = True
                    except Exception as e:
                        out["issues"].append(f"fetch {abs_url} failed: {e}")
                elif not allow_net:
                    rec["note"] = "external .map — fetch gated (allow_network=false)"
                else:
                    rec["note"] = "external .map — host out of scope, not fetched"
                out["refs"].append(rec)

        # 3) reconstruct staged maps with sourcemapper (local, no network)
        staged = list(maps_dir.glob("*.map"))
        if staged:
            smapper = tools.resolve("sourcemapper", cfg)
            if not smapper:
                out["issues"].append("sourcemapper not found; cannot reconstruct maps")
            else:
                out_dir.mkdir(parents=True, exist_ok=True)
                before = {str(p) for p in out_dir.rglob("*") if p.is_file()}
                proc = tools.run([smapper, "-dir", str(maps_dir), "-output", str(out_dir)], timeout=120)
                if proc is None:
                    out["issues"].append("sourcemapper run failed")
                after = {str(p) for p in out_dir.rglob("*") if p.is_file()}
                new = sorted(after - before)
                out["files"] = new
                out["recovered"] = len(new)
    finally:
        shutil.rmtree(maps_dir, ignore_errors=True)
    return out
