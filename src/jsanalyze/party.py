"""Provenance classifier: first-party app code vs vendor bundle vs third-party host.

Keeping vendor/polyfill noise out of the leads queue (core of critique point 1) needs a
cheap, reliable party label on every sink/endpoint/record. This is filename- and
host-based (not content inference): a `vendors~bundle.chunk.js` is vendor, a
`4.chunk.js` app chunk is first, an absolute URL to an out-of-scope host is third.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

# vendor/runtime/polyfill tokens that appear in webpack/rollup chunk names
_VENDOR_RE = re.compile(
    r"(?:^|[/_~.\-])"
    r"(vendors?|chunk-vendors|core-?js|regenerator|polyfills?|runtime|webpack|"
    r"node_modules|commons?|framework|react-dom|scheduler|lodash|moment|jquery|"
    r"zone\.js|rxjs|es-abstract|babel|tslib|whatwg|axios|bootstrap)"
    r"(?:[/_~.\-0-9]|$)",
    re.IGNORECASE,
)

# library homepages / license URLs that show up in vendor comment banners — never
# a first-party signal, and never a sourcemap.
LIBRARY_COMMENT_HOSTS = (
    "github.com", "mths.be", "jquery.com", "jquery.org", "unpkg.com",
    "cdnjs.cloudflare.com", "jsdelivr.net", "npmjs.com", "lodash.com",
    "momentjs.com", "reactjs.org", "vuejs.org", "angular.io", "opensource.org",
    "apache.org", "mozilla.org", "w3.org", "tools.ietf.org", "ecma-international.org",
)


def _host(url: str) -> str:
    try:
        return urlsplit(url or "").netloc.split("@")[-1].split(":")[0].lower()
    except ValueError:
        return ""


def party_of(source_file: str = "", origin_url: str = "", scope_hosts=None) -> str:
    """Return 'first' | 'vendor' | 'third'.

    third  — an absolute URL whose host is not in `scope_hosts` (when scope is known).
    vendor — the file/chunk name looks like a bundled library/runtime.
    first  — the application's own code (default).
    """
    host = _host(origin_url)
    if host and scope_hosts:
        in_scope = {h.lower().lstrip("*.") for h in scope_hosts}
        if not any(host == s or host.endswith("." + s) for s in in_scope):
            return "third"
    name = (source_file or "").lower()
    # strip the parser's "__<sha1>.js" suffix so it doesn't hide the real stem
    name = re.sub(r"__[0-9a-f]{6,}\.js$", "", name)
    if _VENDOR_RE.search(name):
        return "vendor"
    return "first"


def is_library_comment_url(url: str) -> bool:
    """True if `url` is a library homepage/license link (a comment banner), not an
    application endpoint or a real sourceMappingURL."""
    h = _host(url)
    return any(h == d or h.endswith("." + d) for d in LIBRARY_COMMENT_HOSTS)
