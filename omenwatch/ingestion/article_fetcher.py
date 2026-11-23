"""
Fetches the full article page and extracts its plain text, for richer
severity/tag/IOC extraction than an RSS summary alone can provide.

Why this exists: RSS feed summaries are typically short teasers (one or
two sentences) — the real signal for IOC extraction (C2 IPs, file
hashes, full CVE lists) usually lives in the article body on the
publisher's site, not in the feed's teaser text. Scanning only the
teaser systematically under-detects IOCs.

This is best-effort and silent on failure: paywalls, bot-blocking,
timeouts, non-HTML responses, or any other failure just means falling
back to title+summary only for that item — never blocks storing it, and
never raises. See omenwatch/ingestion/connectors/rss.py for how the result is used.

The links come from the feed, not from whoever set OmenWatch up, so they
are not trusted: only http(s), and only public addresses unless the link
is on the feed's own host (an internal mirror's articles are internal
too). Redirects are checked the same way. Without this, a feed could make
OmenWatch read file:// paths or internal services.

The check happens where the connection is made (2.0): the name is looked
up once, the answer is checked, and the socket connects to exactly that
address. Checking first and letting urllib look the name up again would let
a hostile DNS server answer "public" to the check and "internal" to the
connection (DNS rebinding). Behind an HTTP proxy the proxy does the lookup,
so there only the up-front check applies.
"""
import http.client
import ipaddress
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from contextlib import suppress
from html.parser import HTMLParser

FETCH_TIMEOUT = 8  # seconds — don't let a slow publisher stall the whole poll
MAX_RAW_BYTES = 400_000  # cap what we read; real articles don't need more than this
MAX_TEXT_LENGTH = 20_000  # cap what we hand to the regex-based extractors
_SKIP_TAGS = {"script", "style", "noscript", "header", "footer", "nav", "svg", "aside", "form", "template"}
# Page furniture marked by class or id: menus, sidebars, "related stories",
# tag clouds, share bars and comments. Their words ("Ransomware" as a menu
# entry, say) used to be read as if the article said them.
_SKIP_MARKERS = re.compile(
    r"(?<![a-z])(?:menu|navbar|sidebar|widget|related|recommended|popular|trending|"
    r"breadcrumbs?|share|social|newsletter|subscribe|comments?|tags?|tag-?cloud|categor(?:y|ies)|"
    r"advert|ads?|promo|cookie|footer|header)(?![a-z])",
    re.I,
)
_MAIN_TAGS = {"article", "main"}
_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
MIN_MAIN_TEXT = 200  # an <article>/<main> shorter than this is a teaser card, not the story


class _TextExtractor(HTMLParser):
    """
    Collects visible text, leaving out page furniture. Text inside the first
    <article> or <main> is kept apart, so the story itself can be preferred
    over the whole page.
    """

    def __init__(self, use_markers: bool = True):
        super().__init__()
        self._use_markers = use_markers
        self._skip: list[str] = []  # open tags being skipped, innermost last
        self._main_depth = 0
        self._main_done = False
        self.chunks: list[str] = []
        self.main_chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in _VOID_TAGS:
            return
        if self._skip:
            self._skip.append(tag)
            return
        marker = " ".join(v or "" for k, v in attrs if k in ("class", "id", "role"))
        if tag in _SKIP_TAGS or (self._use_markers and tag not in _MAIN_TAGS and tag != "body" and _SKIP_MARKERS.search(marker)):
            self._skip.append(tag)
        elif tag in _MAIN_TAGS and not self._main_done:
            self._main_depth += 1

    def handle_endtag(self, tag):
        if tag in _VOID_TAGS:
            return
        if self._skip:
            # Pop back to the matching open tag; tolerates unclosed children.
            if tag in self._skip:
                while self._skip and self._skip.pop() != tag:
                    pass
            return
        if tag in _MAIN_TAGS and self._main_depth:
            self._main_depth -= 1
            if not self._main_depth and len(" ".join(self.main_chunks)) >= MIN_MAIN_TEXT:
                self._main_done = True

    def handle_data(self, data):
        if self._skip:
            return
        text = data.strip()
        if text:
            self.chunks.append(text)
            if self._main_depth and not self._main_done:
                self.main_chunks.append(text)


def _extract(html: str, use_markers: bool) -> str:
    parser = _TextExtractor(use_markers)
    with suppress(Exception):
        parser.feed(html)
    main = " ".join(parser.main_chunks)
    return main if len(main) >= MIN_MAIN_TEXT else " ".join(parser.chunks)


def html_to_text(html: str) -> str:
    text = _extract(html, use_markers=True)
    if len(text) < MIN_MAIN_TEXT:
        # A layout class such as "with-sidebar" on a wrapper can hide the
        # whole page; fall back to skipping only by tag.
        text = _extract(html, use_markers=False)
    return text


def allowed_url(url: str, trusted_host: str = "") -> bool:
    """http(s) only; on any host but the feed's own, every address the name resolves to must be public."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return False
    if trusted_host and parts.hostname.lower() == trusted_host.lower():
        return True
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError, ValueError):
        return False
    return bool(infos) and all(ipaddress.ip_address(info[4][0].split("%")[0]).is_global for info in infos)


def _checked_address(host: str, port: int, trusted_host: str):
    """
    Looks `host` up once and returns (family, address) to connect to, only if
    every address it has is public (or it is the feed's own host). Raises
    OSError otherwise, which urllib reports as a failed fetch.
    """
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"{host} has no address")
    trusted = bool(trusted_host) and host.lower() == trusted_host.lower()
    if not trusted and not all(ipaddress.ip_address(i[4][0].split("%")[0]).is_global for i in infos):
        raise OSError(f"{host} is not a public address")
    return infos[0][0], infos[0][4]


def _pinned_handlers(trusted_host: str):
    """urllib handlers whose connections go to the address _checked_address approved."""

    def open_socket(conn):
        family, address = _checked_address(conn.host, conn.port, trusted_host)
        sock = socket.socket(family, socket.SOCK_STREAM)
        if isinstance(conn.timeout, (int, float)):
            sock.settimeout(conn.timeout)
        try:
            sock.connect(address)
        except BaseException:
            sock.close()
            raise
        return sock

    class PinnedHTTPConnection(http.client.HTTPConnection):
        def connect(self):
            self.sock = open_socket(self)

    class PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            # Certificate and SNI still use the name, not the address.
            self.sock = self._context.wrap_socket(open_socket(self), server_hostname=self.host)

    class PinnedHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(PinnedHTTPConnection, req)

    class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(PinnedHTTPSConnection, req, context=self._context)

    return [PinnedHTTPHandler(), PinnedHTTPSHandler()]


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, trusted_host: str):
        super().__init__()
        self.trusted_host = trusted_host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(newurl, self.trusted_host):
            raise urllib.error.URLError("redirect to an address OmenWatch doesn't fetch articles from")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_article_text_sync(url: str, trusted_host: str = "") -> str:
    """Blocking. Call via loop.run_in_executor(). Returns '' on any failure — never raises."""
    if not url or not allowed_url(url, trusted_host):
        return ""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "OmenWatch/1.0"})
        handlers = [_CheckedRedirects(trusted_host)]
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in urllib.request.getproxies():
            handlers += _pinned_handlers(trusted_host)
        opener = urllib.request.build_opener(*handlers)
        with opener.open(req, timeout=FETCH_TIMEOUT) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if content_type and "html" not in content_type.lower():
                return ""
            raw = resp.read(MAX_RAW_BYTES)
        html = raw.decode("utf-8", errors="ignore")
        return html_to_text(html)[:MAX_TEXT_LENGTH]
    except Exception:
        return ""
