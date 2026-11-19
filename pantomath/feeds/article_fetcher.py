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
never raises. See pantomath/connectors/rss.py for how the result is used.

The links come from the feed, not from whoever set Pantomath up, so they
are not trusted: only http(s), and only public addresses unless the link
is on the feed's own host (an internal mirror's articles are internal
too). Redirects are checked the same way. Without this, a feed could make
Pantomath read file:// paths or internal services.
"""
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


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, trusted_host: str):
        super().__init__()
        self.trusted_host = trusted_host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(newurl, self.trusted_host):
            raise urllib.error.URLError("redirect to an address Pantomath doesn't fetch articles from")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_article_text_sync(url: str, trusted_host: str = "") -> str:
    """Blocking. Call via loop.run_in_executor(). Returns '' on any failure — never raises."""
    if not url or not allowed_url(url, trusted_host):
        return ""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Pantomath/1.0"})
        opener = urllib.request.build_opener(_CheckedRedirects(trusted_host))
        with opener.open(req, timeout=FETCH_TIMEOUT) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if content_type and "html" not in content_type.lower():
                return ""
            raw = resp.read(MAX_RAW_BYTES)
        html = raw.decode("utf-8", errors="ignore")
        return html_to_text(html)[:MAX_TEXT_LENGTH]
    except Exception:
        return ""
