import os
import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from omenwatch.ingestion import article_fetcher
from omenwatch.ingestion.article_fetcher import allowed_url, fetch_article_text_sync, html_to_text


def test_html_to_text_strips_tags():
    html = "<html><body><p>Hello <b>world</b></p></body></html>"
    assert html_to_text(html) == "Hello world"


def test_html_to_text_skips_script_and_style():
    html = "<html><body><script>alert('x')</script><style>.a{color:red}</style><p>Real content</p></body></html>"
    result = html_to_text(html)
    assert "Real content" in result
    assert "alert" not in result
    assert "color:red" not in result


def test_html_to_text_skips_nav_and_footer():
    html = "<nav>Home | About</nav><p>Article body text</p><footer>Copyright 2026</footer>"
    result = html_to_text(html)
    assert "Article body text" in result
    assert "Home" not in result
    assert "Copyright" not in result


class _Pages(BaseHTTPRequestHandler):
    pages: dict[str, str] = {}

    def do_GET(self):
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", self.path.split("to=", 1)[1])
            self.end_headers()
            return
        body = self.pages.get(self.path, "").encode()
        self.send_response(200 if body else 404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def site():
    server = HTTPServer(("127.0.0.1", 0), _Pages)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_fetches_an_article_on_the_feeds_own_host(site):
    _Pages.pages["/a"] = "<html><body><p>Malware hash d41d8cd98f00b204e9800998ecf8427e found in payload.</p></body></html>"
    assert "d41d8cd98f00b204e9800998ecf8427e" in fetch_article_text_sync(f"{site}/a", trusted_host="127.0.0.1")


def test_truncates_to_max_length(site):
    _Pages.pages["/long"] = "<p>" + ("word " * 10000) + "</p>"
    assert 0 < len(fetch_article_text_sync(f"{site}/long", trusted_host="127.0.0.1")) <= 20_000


def test_returns_empty_for_blank_url_and_missing_page(site):
    assert fetch_article_text_sync("") == ""
    assert fetch_article_text_sync(f"{site}/missing", trusted_host="127.0.0.1") == ""


def test_a_feed_link_never_reads_local_files():
    fd, path = tempfile.mkstemp(suffix=".html")
    with os.fdopen(fd, "w") as f:
        f.write("<p>secret-local-file-content</p>")
    try:
        assert fetch_article_text_sync(f"file://{path}") == ""
        assert fetch_article_text_sync(f"file://{path}", trusted_host="") == ""
    finally:
        os.remove(path)


def test_internal_addresses_are_refused_unless_they_are_the_feeds_own_host(site):
    _Pages.pages["/internal"] = "<p>internal-service-content</p>"
    assert fetch_article_text_sync(f"{site}/internal") == ""                       # feed elsewhere
    assert fetch_article_text_sync(f"{site}/internal", trusted_host="feeds.example") == ""
    assert not allowed_url("http://169.254.169.254/latest/meta-data/")
    assert not allowed_url("http://10.0.0.5/")
    assert not allowed_url("gopher://example.com/")


def test_a_redirect_to_an_internal_address_is_refused(site, monkeypatch):
    _Pages.pages["/internal"] = "<p>internal-service-content</p>"
    # The first hop counts as public; the redirect it sends points at an internal address.
    public = allowed_url
    monkeypatch.setattr(article_fetcher, "allowed_url",
                        lambda url, trusted="": "/redirect" in url or public(url, trusted))
    assert fetch_article_text_sync(f"{site}/redirect?to={site}/internal") == ""


def test_public_addresses_are_allowed(monkeypatch):
    monkeypatch.setattr(article_fetcher.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.215.14", 443))])
    assert allowed_url("https://news.example/story")


def test_a_name_that_changes_address_after_the_check_is_not_fetched(site, monkeypatch):
    """DNS rebinding: public when checked, internal when connecting. Fixed in 2.0."""
    _Pages.pages["/secret"] = "<p>internal-service-content</p>"
    port = int(site.rsplit(":", 1)[1])
    real = socket.getaddrinfo
    answers = iter([[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", port))]])

    def rebinding(host, *args, **kwargs):
        if host == "rebind.example":
            # the first lookup sees a public address, every later one the internal server
            return next(answers, [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))])
        return real(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    assert fetch_article_text_sync(f"http://rebind.example:{port}/secret") == ""


def test_the_feeds_own_host_still_connects_to_its_internal_address(site):
    _Pages.pages["/own"] = "<p>mirror-article</p>"
    assert "mirror-article" in fetch_article_text_sync(f"{site}/own", trusted_host="127.0.0.1")
