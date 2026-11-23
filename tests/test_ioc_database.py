"""
1.0.0: the IOC database. Covers the rules SIEMs will rely on: one row per
value however often feeds send it, confidence that can be explained,
expiry, snapshot feeds, the allowlist and false-positive marks that feeds
can't undo, and /api/v1 being reachable with SIEM keys and nothing else.
"""
import http.server
import threading
import time

import pytest
from fastapi.testclient import TestClient

from omenwatch.app import app
from omenwatch.auth import sign_in
from omenwatch.database.sqlite import get_db
from omenwatch.ioc.db import get_ioc_db, init_ioc_db
from omenwatch.ioc.feeds import parse_list, run_feed
from omenwatch.ioc.normalize import IocValueError, candidates, normalize_typed
from omenwatch.ioc.store import Arrival, Source, apply_allowlist, end_snapshot, expire_due, ingest

client = TestClient(app)


@pytest.fixture(autouse=True)
async def fresh_ioc(fresh_db):
    await init_ioc_db()
    db = await get_ioc_db()
    for table in ("indicator_hits", "lookup_stats", "sightings", "indicators", "ioc_feeds", "allowlist", "ioc_settings"):
        await db.execute(f"DELETE FROM {table}")
    await db.commit()
    await db.close()
    from omenwatch.ioc.hits import hit_counter
    hit_counter._hits.clear()
    hit_counter._lookups.clear()
    resp = client.post("/api/settings/auth/setup", json={"password": "test-password-123"})
    client.headers["X-Settings-Token"] = resp.json()["token"]
    yield


async def _rows(sql, params=()):
    db = await get_ioc_db()
    try:
        cur = await db.execute(sql, params)
        return [dict(r) for r in await cur.fetchall()]
    finally:
        await db.close()


def _arrivals(*values):
    out = []
    for v in values:
        t, value, context = normalize_typed(None, v)
        out.append(Arrival(t, value, context))
    return out


# ---------------------------------------------------------------- values

@pytest.mark.parametrize("raw, expected", [
    ("8.8.8.8:443", ("ipv4", "8.8.8.8", {"port": 443})),
    ("hxxps://Evil[.]Example./path?x=1", ("url", "https://evil.example/path?x=1", {})),
    ("EVIL.example.", ("domain", "evil.example", {})),
    ("bücher.de", ("domain", "xn--bcher-kva.de", {})),
    ("44D88612FEA8A8F36DE82E1278ABB02F", ("md5", "44d88612fea8a8f36de82e1278abb02f", {})),
    ("Phish[at]Evil.com", ("email", "phish@evil.com", {})),
])
def test_values_are_normalized_to_one_spelling(raw, expected):
    assert normalize_typed(None, raw) == expected


@pytest.mark.parametrize("raw", ["10.1.2.3", "192.168.0.1", "127.0.0.1", "fe80::1", "224.0.0.1", "not an indicator"])
def test_private_addresses_and_junk_are_refused(raw):
    with pytest.raises(IocValueError):
        normalize_typed(None, raw)


def test_lookup_tries_every_type_a_hash_could_be():
    assert [t for t, _ in candidates("44d88612fea8a8f36de82e1278abb02f")] == ["md5", "ja3"]


# ----------------------------------------------------------- duplicates

async def test_a_value_is_stored_once_and_a_second_source_raises_confidence():
    db = await get_ioc_db()
    try:
        now = time.time()
        first = await ingest(db, Source("feed-a", "Feed A", confidence=75), _arrivals("8.8.8.8", "8.8.8.8:80"), now)
        assert first.new == 1
        again = await ingest(db, Source("feed-a", "Feed A", confidence=75), _arrivals("8.8.8.8"), now + 60)
        assert (again.new, again.unchanged) == (0, 1)
        other = await ingest(db, Source("feed-b", "Feed B", confidence=60), _arrivals("8.8.8.8"), now + 120)
        assert (other.new, other.refreshed) == (0, 1)
    finally:
        await db.close()
    rows = await _rows("SELECT * FROM indicators")
    assert len(rows) == 1
    assert rows[0]["confidence"] == 85          # highest source 75 + 10 for one more
    assert len(await _rows("SELECT * FROM sightings")) == 2


async def test_a_repeat_download_within_a_day_writes_nothing():
    db = await get_ioc_db()
    try:
        now = time.time()
        await ingest(db, Source("feed-a", "Feed A"), _arrivals("evil.example"), now)
        before = (await _rows("SELECT updated_at, last_seen FROM indicators"))[0]
        await ingest(db, Source("feed-a", "Feed A"), _arrivals("evil.example"), now + 3600)
        assert (await _rows("SELECT updated_at, last_seen FROM indicators"))[0] == before
        await ingest(db, Source("feed-a", "Feed A"), _arrivals("evil.example"), now + 2 * 86400)
        assert (await _rows("SELECT last_seen FROM indicators"))[0]["last_seen"] == now + 2 * 86400
    finally:
        await db.close()


async def test_feeds_fill_blanks_but_never_overwrite_or_undo_an_analyst():
    db = await get_ioc_db()
    try:
        await ingest(db, Source("feed-a", "Feed A"), [Arrival("domain", "evil.example", malware="QakBot")])
        await ingest(db, Source("feed-b", "Feed B"), [Arrival("domain", "evil.example", malware="Emotet")])
        assert (await _rows("SELECT malware FROM indicators"))[0]["malware"] == "QakBot"
        await db.execute("UPDATE indicators SET status = 'false_positive'")
        await db.commit()
        result = await ingest(db, Source("feed-c", "Feed C"), _arrivals("evil.example"))
        assert result.false_positive == 1
    finally:
        await db.close()
    assert (await _rows("SELECT status FROM indicators"))[0]["status"] == "false_positive"


async def test_snapshot_feed_drops_only_its_own_evidence():
    db = await get_ioc_db()
    try:
        now = time.time()
        await ingest(db, Source("snap", "Blocklist"), _arrivals("8.8.8.8", "8.8.4.4"), now)
        await ingest(db, Source("other", "Other"), _arrivals("8.8.4.4"), now)
        latest = await ingest(db, Source("snap", "Blocklist"), [], now + 3600)
        dropped = await end_snapshot(db, "snap", latest.seen_ids, now + 3600)
    finally:
        await db.close()
    assert dropped == 2
    status = {r["value"]: r["status"] for r in await _rows("SELECT value, status FROM indicators")}
    assert status == {"8.8.8.8": "expired", "8.8.4.4": "active"}   # Other still reports 8.8.4.4


async def test_indicators_expire_after_their_lifetime_and_hashes_never_do():
    db = await get_ioc_db()
    try:
        now = time.time()
        await ingest(db, Source("feed-a", "Feed A"), _arrivals("8.8.8.8", "44d88612fea8a8f36de82e1278abb02f"), now)
        expired, _ = await expire_due(db, now + 31 * 86400)
    finally:
        await db.close()
    assert expired == 1
    status = {r["type"]: r["status"] for r in await _rows("SELECT type, status FROM indicators")}
    assert status == {"ipv4": "expired", "md5": "active"}


async def test_expired_indicators_are_deleted_after_90_days_unless_kept_for_ever():
    db = await get_ioc_db()
    try:
        now = time.time()
        await ingest(db, Source("feed-a", "Feed A"), _arrivals("8.8.8.8"), now)
        assert await expire_due(db, now + 31 * 86400) == (1, 0)
        assert await expire_due(db, now + 100 * 86400) == (0, 0)   # 70 days after expiring: kept
        await db.execute("UPDATE indicators SET status = 'active'")
        await db.commit()
    finally:
        await db.close()
    assert client.get("/api/ioc/settings").json()["keep_expired_days"] == 90
    assert client.patch("/api/ioc/settings", json={"keep_expired_days": 0}).json() == {"keep_expired_days": 0}
    assert client.patch("/api/ioc/settings", json={"keep_expired_days": 12}).status_code == 400
    db = await get_ioc_db()
    try:
        assert await expire_due(db, now + 5000 * 86400) == (1, 0)   # for ever: nothing deleted
        await db.execute("UPDATE ioc_settings SET value = '90'")
        await db.commit()
        assert await expire_due(db, now + 5000 * 86400) == (0, 1)
    finally:
        await db.close()


async def test_allowlist_drops_on_arrival_and_sets_stored_values_aside():
    db = await get_ioc_db()
    try:
        await ingest(db, Source("feed-a", "Feed A"), _arrivals("http://cdn.supplier.example/a", "8.8.8.8"))
        await db.execute("INSERT INTO allowlist (id, type, value) VALUES ('1', 'domain', 'supplier.example')")
        await db.commit()
        assert await apply_allowlist(db) == 1
        result = await ingest(db, Source("feed-b", "Feed B"), _arrivals("mail.supplier.example"))
        assert result.allowlisted == 1
    finally:
        await db.close()
    status = {r["value"]: r["status"] for r in await _rows("SELECT value, status FROM indicators")}
    assert status == {"http://cdn.supplier.example/a": "allowlisted", "8.8.8.8": "active"}


# ----------------------------------------------------------------- lists

def test_text_lists_skip_comments_and_keep_the_first_word():
    parsed = parse_list("# Feodo Tracker\n\n8.8.8.8\n8.8.4.4  # since July\n10.0.0.1\n")
    assert [a.value for a in parsed.arrivals] == ["8.8.8.8", "8.8.4.4"]
    assert (parsed.skipped, parsed.rejected) == (2, 1)


def test_csv_reads_abuse_ch_style_header_in_a_comment():
    text = ('# MalwareBazaar\n# "first_seen_utc","sha256_hash","signature"\n'
            '"2026-10-01 10:00:00","' + "a" * 64 + '","QakBot"\n')
    parsed = parse_list(text, "csv", value_column="sha256_hash", malware_column="signature", date_column="first_seen_utc")
    assert [(a.type, a.malware, a.context["reported"]) for a in parsed.arrivals] == [("sha256", "QakBot", "2026-10-01 10:00:00")]


def test_csv_picks_the_value_column_when_none_is_chosen():
    parsed = parse_list("id,host,note\n1,evil.example,phish\n2,bad.example,c2\n", "csv")
    assert parsed.value_column == "host"
    assert [a.value for a in parsed.arrivals] == ["evil.example", "bad.example"]


class _ListHandler(http.server.BaseHTTPRequestHandler):
    body = b"8.8.8.8\n8.8.4.4\n"
    seen_keys: list = []

    def do_GET(self):
        _ListHandler.seen_keys.append(self.headers.get("Auth-Key"))
        if self.headers.get("If-None-Match") == '"v1"':
            self.send_response(304)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("ETag", '"v1"')
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args):
        pass


@pytest.fixture
def list_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ListHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _ListHandler.seen_keys = []
    yield f"http://127.0.0.1:{server.server_address[1]}/list.txt"
    server.shutdown()


async def test_a_feed_download_sends_its_key_and_skips_an_unchanged_list(list_server):
    feed = {"id": "f1", "name": "Test list", "url": list_server, "format": "text", "confidence": 75,
            "key_header": "Auth-Key", "key_value": "s3cret", "snapshot": 1}
    db = await get_ioc_db()
    try:
        await db.execute("INSERT INTO ioc_feeds (id, name, url, key_header, key_value, snapshot) VALUES ('f1', 'Test list', ?, 'Auth-Key', 's3cret', 1)",
                         (list_server,))
        await db.commit()
        first = await run_feed(db, feed)
        cur = await db.execute("SELECT * FROM ioc_feeds WHERE id = 'f1'")
        stored = dict(await cur.fetchone())
        second = await run_feed(db, stored)
    finally:
        await db.close()
    assert first["ok"] and first["new"] == 2
    assert second == {"ok": True, "unchanged": True}
    assert _ListHandler.seen_keys == ["s3cret", "s3cret"]
    assert "s3cret" not in client.get("/api/ioc/feeds").text
    assert len(await _rows("SELECT * FROM indicators WHERE status = 'active'")) == 2


# ------------------------------------------------------------------- API

def test_fresh_install_has_no_ioc_feeds_and_an_empty_database():
    feeds = client.get("/api/ioc/feeds").json()
    assert (feeds["feeds"], feeds["manual"], feeds["promoted"]) == ([], 0, 0)   # built-in readers are offered, none added
    assert len(feeds["readers"]) == 6
    presets = {p["name"]: p for p in feeds["presets"]}
    assert presets["c2intel-ips"]["format"] == "csv" and presets["c2intel-ips"]["value_column"] == "ip"
    assert presets["tor-exits"]["group"] == "Use with care"
    assert client.get("/api/ioc/summary").json()["active"] == 0


def test_manual_entry_lookup_and_false_positive_through_the_api():
    out = client.post("/api/ioc/indicators", json={"text": "hxxp://evil[.]example/x\n10.0.0.1\n8.8.8.8", "confidence": 80, "malware": "QakBot"}).json()
    assert (out["added"], out["rejected"]) == (2, 1)
    result = client.post("/api/v1/lookup", json={"values": ["http://evil.example/x", "1.1.1.1"]}).json()
    assert (result["checked"], result["matched"]) == (2, 1)
    hit = result["results"][0]
    assert hit["match"] and hit["malware"] == "QakBot" and hit["confidence"] == 80
    assert result["results"][1] == {"value": "1.1.1.1", "type": "ipv4", "match": False}

    ip = client.get("/api/ioc/indicators", params={"q": "8.8.8.8"}).json()["items"][0]
    assert client.patch(f"/api/ioc/indicators/{ip['id']}", json={"status": "false_positive"}).json()["status"] == "false_positive"
    assert client.get("/api/v1/lookup", params={"value": "8.8.8.8"}).json()["match"] is False
    assert client.get("/api/v1/export", params={"format": "txt"}).text == "http://evil.example/x\n"


def test_export_since_includes_what_stopped_matching():
    client.post("/api/ioc/indicators", json={"text": "8.8.8.8\n8.8.4.4", "confidence": 80})
    # The cursor is rounded down to the second, so a row changed in the same
    # second as an export is sent again next time: repeated, never missed.
    time.sleep(1.1)
    since = client.get("/api/v1/export").headers["X-OmenWatch-Exported-At"]
    time.sleep(1.1)
    ip = client.get("/api/ioc/indicators", params={"q": "8.8.4.4"}).json()["items"][0]
    client.patch(f"/api/ioc/indicators/{ip['id']}", json={"status": "false_positive"})
    changed = client.get("/api/v1/export", params={"format": "json", "since": since}).json()["indicators"]
    assert [(i["value"], i["status"]) for i in changed] == [("8.8.4.4", "false_positive")]


def test_batch_lookup_is_limited_to_1000_values():
    assert client.post("/api/v1/lookup", json={"values": ["8.8.8.8"] * 1001}).status_code == 400


def test_changing_the_ioc_database_needs_the_settings_password():
    locked = TestClient(app)
    assert locked.post("/api/ioc/indicators", json={"text": "8.8.8.8"}).status_code == 401
    assert locked.get("/api/ioc/feeds").status_code == 401
    assert locked.get("/api/ioc/summary").status_code == 200   # browsing doesn't


async def test_siem_keys_open_api_v1_and_nothing_else(monkeypatch):
    monkeypatch.delenv("OMENWATCH_OPEN_DASHBOARD", raising=False)
    siem = client.post("/api/auth/siem-keys", json={"label": "Wazuh"}).json()["key"]
    db = await get_db()
    try:
        api_key, _ = await sign_in.create_session(db, "api", False, "", "", kind="api", label="script")
    finally:
        await db.close()
    as_siem = TestClient(app, headers={"Authorization": f"Bearer {siem}"})
    as_api = TestClient(app, headers={"Authorization": f"Bearer {api_key}"})

    assert as_siem.get("/api/v1/health").status_code == 200
    assert as_siem.get("/api/v1/lookup", params={"value": "8.8.8.8"}).status_code == 200
    assert as_siem.get("/api/items").status_code == 401
    assert as_siem.get("/api/ioc/summary").status_code == 401
    assert as_api.get("/api/items").status_code == 200          # existing keys keep their access
    assert as_api.get("/api/v1/health").status_code == 401      # and gain none
    assert TestClient(app).get("/api/v1/health").status_code == 401

    keys = client.get("/api/auth/sessions").json()
    assert [k["label"] for k in keys["siem_keys"]] == ["Wazuh"]
    assert [k["label"] for k in keys["api_keys"]] == ["script"]


# ------------------------------------------------------------- phase 2

THREATFOX_EXPORT = """{"1974474": [{"ioc_value": "18.8.8.81:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
  "malware": "win.cobalt_strike", "malware_printable": "Cobalt Strike", "first_seen_utc": "2026-10-19 16:54:13",
  "confidence_level": 100, "reference": null, "tags": "CobaltStrike"}],
 "1974475": [{"ioc_value": "evil.example", "ioc_type": "domain", "threat_type": "payload_delivery",
  "malware_printable": "Unknown malware", "confidence_level": 50, "tags": null}]}"""


def test_threatfox_reader_keeps_its_confidence_malware_and_link():
    from omenwatch.ioc.readers import READERS
    parsed = READERS["threatfox"].parse(THREATFOX_EXPORT)
    ip, domain = parsed.arrivals
    assert (ip.type, ip.value, ip.context["port"], ip.confidence, ip.malware) == ("ipv4", "18.8.8.81", 443, 100, "Cobalt Strike")
    assert ip.reference == "https://threatfox.abuse.ch/ioc/1974474/"
    assert (domain.confidence, domain.tags) == (50, "")


def test_malwarebazaar_reader_stores_each_hash_and_names_the_others():
    from omenwatch.ioc.readers import READERS
    row = '"2026-10-19 16:25:11", "' + "a" * 64 + '", "' + "b" * 32 + '", "' + "c" * 40 + '", "abuse_ch", "x.exe", "exe", "application/x", "RatonRAT", "n/a"'
    parsed = READERS["malwarebazaar"].parse('# "first_seen_utc","sha256_hash"\n' + row)
    assert [a.type for a in parsed.arrivals] == ["sha256", "md5", "sha1"]
    assert parsed.arrivals[1].context["same_file"] == {"sha256": "a" * 64, "sha1": "c" * 40}
    assert {a.malware for a in parsed.arrivals} == {"RatonRAT"}


def test_sslbl_and_abuseipdb_readers():
    from omenwatch.ioc.readers import READERS
    ssl = READERS["sslbl"].parse("# Listingdate,SHA1,Listingreason\n2026-10-18 12:25:30," + "d" * 40 + ",QakBot C&C\n")
    assert [(a.type, a.malware, a.threat_type) for a in ssl.arrivals] == [("x509", "QakBot", "c2")]
    ips = READERS["abuseipdb"].parse('{"data": [{"ipAddress": "8.8.8.8", "abuseConfidenceScore": 97, "countryCode": "US"}]}')
    assert [(a.value, a.confidence) for a in ips.arrivals] == [("8.8.8.8", 97)]
    with pytest.raises(Exception, match="Authentication failed"):
        READERS["abuseipdb"].parse('{"errors": [{"detail": "Authentication failed."}]}')


async def test_a_list_read_with_the_wrong_format_fails_and_names_the_reader():
    from omenwatch.ioc.feeds import nothing_readable
    text = '# "first_seen_utc","sha256_hash"\n"2026-10-19 16:25:11", "' + "a" * 64 + '"\n'
    parsed = parse_list(text, "text")                       # MalwareBazaar's CSV read as plain text
    assert (len(parsed.arrivals), parsed.rejected) == (0, 1)
    message = nothing_readable({"url": "https://bazaar.abuse.ch/export/csv/recent/", "format": "text"}, parsed)
    assert "set Format to the MalwareBazaar (abuse.ch) reader" in message


def test_abuseipdb_feed_cant_be_fetched_more_often_than_its_free_plan_allows():
    resp = client.post("/api/ioc/feeds", json={"name": "A", "url": "https://api.abuseipdb.com/api/v2/blacklist",
                                                "format": "abuseipdb", "interval_seconds": 3600})
    assert resp.status_code == 400


def test_promoted_values_get_their_own_source():
    out = client.post("/api/ioc/indicators", json={"text": "8.8.8.8", "promoted": True, "confidence": 50,
                                                    "reference": "https://news.example/a"}).json()
    assert out["added"] == 1
    item = client.get("/api/ioc/indicators", params={"source": "promoted"}).json()["items"][0]
    detail = client.get(f"/api/ioc/indicators/{item['id']}").json()
    assert detail["sightings"][0]["source_name"] == "Promoted from the news"
    assert detail["sightings"][0]["reference"] == "https://news.example/a"


async def test_mentions_reads_matching_articles_from_the_news_database():
    db = await get_db()
    try:
        await db.execute("INSERT INTO sources (id, name, url) VALUES ('s1', 'News', 'http://x.example/feed')")
        await db.execute("INSERT INTO items (id, source_id, title, guid, fetched_at, ips) VALUES ('i1', 's1', 'C2 found', 'g1', 1000, '1.2.3.4,8.8.8.8')")
        await db.execute("INSERT INTO items (id, source_id, title, guid, fetched_at, ips) VALUES ('i2', 's1', 'Other', 'g2', 1001, '18.8.8.80')")
        await db.commit()
    finally:
        await db.close()
    client.post("/api/ioc/indicators", json={"text": "8.8.8.8"})
    item = client.get("/api/ioc/indicators").json()["items"][0]
    mentions = client.get(f"/api/ioc/indicators/{item['id']}/mentions").json()
    assert (mentions["count"], mentions["field"], [i["id"] for i in mentions["items"]]) == (1, "ips", ["i1"])


async def test_siem_lookups_are_counted_without_writing_until_flushed():
    from omenwatch.ioc.hits import hit_counter
    from omenwatch.workers.main import ioc_worker as ioc_scheduler
    client.post("/api/ioc/indicators", json={"text": "8.8.8.8\n8.8.4.4"})
    client.post("/api/v1/lookup", json={"values": ["8.8.8.8", "1.1.1.1"]})
    client.get("/api/v1/lookup", params={"value": "8.8.8.8"})
    client.post("/api/ioc/lookup", json={"values": ["8.8.4.4"]})    # the tab's own lookups don't count
    assert await _rows("SELECT * FROM indicator_hits") == []          # nothing written yet
    summary = client.get("/api/ioc/summary").json()["siem"]
    assert (summary["lookups_today"], summary["matches_today"], summary["indicators_seen_week"]) == (3, 2, 1)
    assert client.get("/api/ioc/indicators", params={"seen_days": 1}).json()["total"] == 1   # before the write too
    await ioc_scheduler.flush_hits()
    assert [r["count"] for r in await _rows("SELECT count FROM indicator_hits")] == [2]
    seen = client.get("/api/ioc/indicators", params={"seen_days": 7}).json()
    assert [(i["value"], i["hits_week"]) for i in seen["items"]] == [("8.8.8.8", 2)]
    assert hit_counter.pending_for(seen["items"][0]["id"]) == [0, 0.0]


def test_ioc_backup_is_a_usable_copy(tmp_path):
    import sqlite3
    client.post("/api/ioc/indicators", json={"text": "8.8.8.8"})
    resp = client.get("/api/ioc/backup")
    assert resp.status_code == 200
    copy = tmp_path / "copy.db"
    copy.write_bytes(resp.content)
    assert sqlite3.connect(copy).execute("SELECT value FROM indicators").fetchall() == [("8.8.8.8",)]
    assert TestClient(app).get("/api/ioc/backup").status_code == 401


def test_cdb_export_is_a_wazuh_list():
    client.post("/api/ioc/indicators", json={"text": "8.8.8.8\nhttp://evil.example:8080/x\n2606:4700::1111", "confidence": 80})
    lines = sorted(client.get("/api/v1/export", params={"format": "cdb"}).text.splitlines())
    assert lines == ['"2606:4700::1111":80', '"http://evil.example:8080/x":80', "8.8.8.8:80"]
    assert client.get("/api/v1/export", params={"format": "cdb", "since": "0"}).status_code == 400


def test_presets_are_readable_lists():
    from omenwatch.ioc.normalize import TYPES
    from omenwatch.ioc.parsing import parse_list
    from omenwatch.ioc.presets import PRESETS
    from omenwatch.ioc.readers import READERS

    samples = {"ipv4": "18.8.8.81", "domain": "c2.example.com", "url": "http://phish.example.net/login",
               "sha256": "a" * 64, "": "18.8.8.82"}
    for preset in PRESETS.values():
        assert preset.name not in READERS
        assert preset.url.startswith("https://") and preset.terms_url.startswith("https://")
        assert preset.format in ("text", "csv") and (not preset.default_type or preset.default_type in TYPES)
        assert 0 <= preset.confidence <= 100 and preset.interval >= 900
        value = samples[preset.default_type]
        text = f"# comment\n{preset.value_column},note\n{value},x\n" if preset.format == "csv" else f"# comment\n{value}\n"
        result = parse_list(text, preset.format, preset.default_type, preset.value_column)
        assert result.rejected == 0, preset.name
