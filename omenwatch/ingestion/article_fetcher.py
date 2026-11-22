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
import socket
import urllib.error
import urllib.parse
import urllib.request
from contextlib import suppress
from html.parser import HTMLParser

FETCH_TIMEOUT = 8  # seconds — don't let a slow publisher stall the whole poll
MAX_RAW_BYTES = 400_000  # cap what we read; real articles don't need more than this
MAX_TEXT_LENGTH = 20_000  # cap what we hand to the regex-based extractors
_SKIP_TAGS = {"script", "style", "noscript", "header", "footer", "nav", "svg"}


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._skip_depth = 0
        self.chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data):
        if self._skip_depth == 0:
            text = data.strip()
            if text:
                self.chunks.append(text)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    with suppress(Exception):
        parser.feed(html)
    return " ".join(parser.chunks)


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
