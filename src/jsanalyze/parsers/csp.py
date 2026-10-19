"""Extract Content-Security-Policy from the capture (critique point 6) — ZERO network.

The CSP is already in the data the operator handed us: it is a response HEADER on the
HTML items of a Burp XML / HAR (and sometimes a ``<meta http-equiv>`` in the HTML body).
Its ``connect-src`` / ``frame-src`` / ``default-src`` lists name the hosts the app is
ALLOWED to talk to or frame — frequently an internal API or an admin console that never
shows up in the JS bundle or in the captured traffic. The old parser split the HTTP
headers and then kept only ``<script>`` tags, throwing the policy away.

Contract: ``collect_csp(path, scope_hosts=None) -> dict``::

    {"known": bool,
     "policies": ["default-src 'self'; connect-src https://api.x ...", ...],
     "directives": [{"directive": "connect-src", "host": "api.x.com",
                     "source": "https://api.x.com", "from": "<page url>"}]}
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

from jsanalyze.parsers.burp_parser import _decode_body, _looks_binary, _maybe_b64, _split_http

__all__ = ["collect_csp"]

_META_CSP_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*['"]content-security-policy['"][^>]*\bcontent\s*=\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_HOST_DIRECTIVES = ("connect-src", "frame-src", "default-src", "script-src",
                    "child-src", "form-action", "frame-ancestors", "worker-src")
# keywords / non-host sources to skip inside a directive
_SKIP_TOKENS = {"'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'",
                "'unsafe-hashes'", "'report-sample'", "data:", "blob:", "filesystem:",
                "mediastream:", "*", "https:", "http:", "ws:", "wss:"}


def collect_csp(path, scope_hosts=None) -> dict:
    out = {"known": False, "policies": [], "directives": []}
    p = Path(path)
    try:
        if p.is_dir():
            return out
        suf = p.suffix.lower()
        if suf == ".har":
            _from_har(p, out)
        elif suf in (".xml", ".burp") or _looks_like_xml(p):
            _from_xml(p, out)
        else:
            return out
    except Exception:
        return out
    out["known"] = bool(out["policies"])
    _parse_directives(out)
    return out


def _add_policy(out, policy, page_url):
    policy = (policy or "").strip()
    if policy and policy not in out["policies"]:
        out["policies"].append(policy)
        out.setdefault("_pairs", []).append((policy, page_url))


def _parse_directives(out) -> None:
    seen = set()
    for policy, page_url in out.get("_pairs", []):
        for part in policy.split(";"):
            tokens = part.split()
            if not tokens:
                continue
            directive = tokens[0].lower()
            if directive not in _HOST_DIRECTIVES:
                continue
            for src in tokens[1:]:
                host = _host_of_source(src)
                if not host:
                    continue
                key = (directive, host)
                if key in seen:
                    continue
                seen.add(key)
                out["directives"].append({
                    "directive": directive, "host": host, "source": src, "from": page_url,
                })
    out.pop("_pairs", None)


def _host_of_source(src: str) -> str:
    s = (src or "").strip()
    if not s or s in _SKIP_TOKENS or s.startswith("'"):
        return ""
    if s.startswith(("sha256-", "sha384-", "sha512-", "nonce-")):
        return ""
    # strip scheme + wildcard label; keep the registrable host
    s = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", s, flags=re.I)
    s = s.split("/", 1)[0].split(":", 1)[0]
    s = s.lstrip("*.")
    if "." not in s or " " in s:
        return ""
    return s.lower()


def _html_items_xml(xml_path):
    for _ev, el in ET.iterparse(str(xml_path), events=("end",)):
        if el.tag != "item":
            continue
        mimetype = (el.findtext("mimetype") or "").strip().lower()
        url = (el.findtext("url") or "").strip()
        resp = _maybe_b64(el.find("response"))
        el.clear()
        _line, headers, body = _split_http(resp)
        ctype = ""
        for n, v in headers:
            if n.lower() == "content-type":
                ctype = v.lower()
        if "html" not in mimetype and "text/html" not in ctype:
            continue
        yield url, headers, body


def _from_xml(xml_path, out) -> None:
    for url, headers, body in _html_items_xml(xml_path):
        for n, v in headers:
            if n.lower() in ("content-security-policy", "content-security-policy-report-only"):
                _add_policy(out, v, url)
        try:
            raw = _decode_body(body, headers)
            if not _looks_binary(raw):
                for m in _META_CSP_RE.finditer(raw.decode("utf-8", "replace")):
                    _add_policy(out, m.group(1), url)
        except Exception:
            pass


def _from_har(har_path, out) -> None:
    import json
    with open(har_path, encoding="utf-8", errors="replace") as fh:
        har = json.load(fh)
    for ent in har.get("log", {}).get("entries", []) or []:
        resp = ent.get("response", {}) if isinstance(ent, dict) else {}
        url = (ent.get("request", {}) or {}).get("url", "")
        for h in resp.get("headers", []) or []:
            if (h.get("name", "") or "").lower() in (
                    "content-security-policy", "content-security-policy-report-only"):
                _add_policy(out, h.get("value", ""), url)
        content = resp.get("content", {}) or {}
        if "html" in (content.get("mimeType", "") or "").lower():
            for m in _META_CSP_RE.finditer(content.get("text", "") or ""):
                _add_policy(out, m.group(1), url)


def _looks_like_xml(p: Path) -> bool:
    try:
        with open(p, "rb") as fh:
            return fh.read(256).lstrip()[:1] == b"<"
    except OSError:
        return False
