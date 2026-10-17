"""Parse a Burp Suite XML export, decode the responses, extract the JavaScript.

Returns ``list[Item]`` for the rest of the pipeline. The robust HTTP decoding
(base64 -> de-chunk -> gunzip/inflate/brotli -> header/body split) is adapted from
the operator's own ``burp_parse.py`` — real CDN-served JS is almost always
compressed, so a naive plaintext read would hand jsluice garbage.

Contract: ``parse_burp_xml(xml_path, scope_hosts=None, out_dir=None) -> list[Item]``
  * keeps only JavaScript items (mimetype/extension/Content-Type/URL .js)
  * optional ``scope_hosts`` allow-list (exact host match)
  * dedupes identical bodies by short sha1
  * writes each body to ``out_dir/<name>.js`` and sets ``Item.saved_path``

STDLIB ONLY for gzip/deflate/chunked (zlib). brotli is an OPTIONAL dependency
(``pip install 'jsanalyze-mcp[brotli]'``); without it, brotli-encoded bodies are
skipped (and counted on stderr) rather than mis-parsed.
"""

from __future__ import annotations

import base64
import binascii
import sys
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from urllib.parse import urlsplit

from jsanalyze.models import Item
from jsanalyze.utils import workspace as W

try:  # optional: modern CDNs serve JS as brotli
    import brotli as _brotli
except ImportError:  # pragma: no cover
    _brotli = None

_MAX_BODY_BYTES = 25 * 1024 * 1024  # bound memory on a single decoded body


# --- low-level HTTP decoding (adapted from operator's burp_parse.py) ----------
def _maybe_b64(elem) -> bytes:
    if elem is None:
        return b""
    raw = elem.text or ""
    if (elem.get("base64", "false") or "").lower() == "true":
        try:
            return base64.b64decode(raw)
        except (binascii.Error, ValueError):
            return b""
    return raw.encode("utf-8", "replace")


def _split_http(raw: bytes):
    """raw HTTP message -> (start_line:str, headers:list[(name,value)], body:bytes)."""
    head, body = raw, b""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            head, body = raw[:idx], raw[idx + len(sep):]
            break
    lines = head.split(b"\r\n") if b"\r\n" in head else head.split(b"\n")
    start_line = lines[0].decode("utf-8", "replace").strip() if lines else ""
    headers = []
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        headers.append(
            (name.decode("utf-8", "replace").strip(),
             value.decode("utf-8", "replace").strip())
        )
    return start_line, headers, body


def _header_value(headers, name):
    low = name.lower()
    for n, v in headers:
        if n.lower() == low:
            return v
    return None


def _dechunk(body: bytes) -> bytes:
    out = bytearray()
    rest = body
    while True:
        nl = rest.find(b"\r\n")
        if nl == -1:
            return bytes(out) if out else body
        try:
            size = int(rest[:nl].split(b";")[0].strip(), 16)
        except ValueError:
            return bytes(out) if out else body
        if size == 0:
            return bytes(out)
        start = nl + 2
        out += rest[start:start + size]
        rest = rest[start + size:]
        # consume the CRLF (or lone LF) that terminates this chunk's data, so the
        # next iteration reads the following size line and not an empty one.
        if rest[:2] == b"\r\n":
            rest = rest[2:]
        elif rest[:1] == b"\n":
            rest = rest[1:]


def _decode_body(body: bytes, headers) -> bytes:
    """De-chunk then de-compress per Transfer-/Content-Encoding. Best-effort: on a
    decode error keep the raw bytes (Burp sometimes stores an already-decoded body
    while leaving the header in place) — the binary guard downstream catches the
    cases that truly stayed compressed (e.g. brotli without the lib)."""
    if (_header_value(headers, "Transfer-Encoding") or "").lower().find("chunked") != -1:
        body = _dechunk(body)

    ce = (_header_value(headers, "Content-Encoding") or "").lower().strip()
    if not ce or ce == "identity":
        return body
    try:
        if "gzip" in ce or "x-gzip" in ce:
            return zlib.decompress(body, 16 + zlib.MAX_WBITS)
        if "deflate" in ce:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
        if "br" in ce:
            return _brotli.decompress(body) if _brotli is not None else body
    except Exception:
        return body  # keep raw; the binary guard decides whether to drop it
    return body  # unknown encoding -> leave as-is, guard decides


def _looks_binary(data: bytes) -> bool:
    """True if `data` is not plausibly text (still-compressed / non-JS)."""
    if not data:
        return True
    if b"\x00" in data[:8192]:
        return True
    text = data.decode("utf-8", "replace")
    if not text:
        return True
    return text.count("�") / len(text) > 0.05


# --- JavaScript detection -----------------------------------------------------
def _is_javascript(url: str, mimetype: str, extension: str, ctype: str) -> bool:
    if (mimetype or "").lower() == "script":
        return True
    if (extension or "").lower().lstrip(".") == "js":
        return True
    low_ct = (ctype or "").lower()
    if "javascript" in low_ct or "ecmascript" in low_ct:
        return True
    path = urlsplit(url or "").path.lower()
    return path.endswith(".js") or path.endswith(".mjs")


def _js_name(url: str, sha1: str) -> str:
    base = Path(urlsplit(url or "").path).name or "inline"
    base = W.slugify(base)
    if not base.lower().endswith((".js", ".mjs")):
        base += ".js"
    return f"{base}__{sha1}.js"


# --- public API ---------------------------------------------------------------
def parse_burp_xml(xml_path, scope_hosts=None, out_dir=None, max_bytes=None, issues=None) -> list[Item]:
    xml_path = Path(xml_path)
    scope = {h.strip().lower().lstrip("*.") for h in scope_hosts} if scope_hosts else None
    out_dir = Path(out_dir) if out_dir is not None else None
    # config-driven cap (critique point 5: max_js_bytes must actually be read); the
    # 25 MiB constant stays only as a hard memory ceiling on the raw base64 payload.
    body_cap = int(max_bytes) if max_bytes else _MAX_BODY_BYTES
    issues = issues if issues is not None else []
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)

    items: list[Item] = []
    seen_sha: set[str] = set()
    skipped_binary = 0

    try:
        context = ET.iterparse(str(xml_path), events=("end",))
        for _event, elem in context:
            if elem.tag != "item":
                continue
            url = (elem.findtext("url") or "").strip()
            host = (elem.findtext("host") or "").strip()
            method = (elem.findtext("method") or "").strip()
            mimetype = (elem.findtext("mimetype") or "").strip() or None
            extension = (elem.findtext("extension") or "").strip()
            status_txt = (elem.findtext("status") or "").strip()
            resp_raw = _maybe_b64(elem.find("response"))
            elem.clear()  # flat memory

            if len(resp_raw) > _MAX_BODY_BYTES:
                continue

            _line, headers, body = _split_http(resp_raw)
            ctype = _header_value(headers, "Content-Type") or ""

            if not _is_javascript(url, mimetype or "", extension, ctype):
                continue
            if scope is not None:
                hl = host.lower()
                if not any(hl == s or hl.endswith("." + s) for s in scope):
                    continue

            body = _decode_body(body, headers)
            if _looks_binary(body):
                skipped_binary += 1
                continue

            js_body = body.decode("utf-8", "replace")
            if len(js_body) > body_cap:
                issues.append(f"skipped oversize JS (> {body_cap} bytes): {url}")
                continue
            sha1 = W.sha1_short(js_body)
            if sha1 in seen_sha:
                continue
            seen_sha.add(sha1)

            try:
                status = int(status_txt) if status_txt else None
            except ValueError:
                status = None

            saved_path = None
            if out_dir is not None:
                dest = (out_dir / _js_name(url, sha1)).resolve()
                dest.write_text(js_body, encoding="utf-8")
                saved_path = str(dest)

            items.append(
                Item(
                    url=url,
                    host=host,
                    method=method,
                    status=status,
                    mimetype=mimetype,
                    is_javascript=True,
                    js_body=js_body,
                    saved_path=saved_path,
                    sha1=sha1,
                )
            )
    except ET.ParseError as e:
        raise ValueError(f"malformed Burp XML: {xml_path} ({e})") from e
    except OSError as e:
        raise ValueError(f"cannot read XML: {xml_path} ({e})") from e

    if skipped_binary:
        enc = "brotli lib missing" if _brotli is None else "undecodable/compressed"
        print(
            f"[burp_parser] skipped {skipped_binary} JS item(s) with a non-text body "
            f"({enc}). Install the brotli extra if these were brotli-encoded.",
            file=sys.stderr,
        )
    return items
