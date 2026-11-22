"""2.0: correlation between articles, the IOC database and KEV; /metrics; /api/health."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from omenwatch.app import app
from omenwatch.database.migrations import main as main_steps
from omenwatch.database.sqlite import get_db
from omenwatch.ioc.db import get_ioc_db, init_ioc_db

client = TestClient(app)


@pytest.fixture(autouse=True)
async def fresh(fresh_db):
    await init_ioc_db()
    db = await get_ioc_db()
    for table in ("sightings", "indicators", "ioc_feeds", "allowlist"):
        await db.execute(f"DELETE FROM {table}")
    await db.commit()
    await db.close()
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url) VALUES ('s1', 'Example News', 'https://news.example/feed')")
    await db.commit()
    await db.close()
    yield


async def _item(item_id, published, **columns):
    db = await get_db()
    names = ", ".join(columns)
    await db.execute(
        f"INSERT INTO items (id, source_id, title, link, guid, published, fetched_at{', ' + names if names else ''}) "
        f"VALUES (?, 's1', ?, ?, ?, ?, ?{', ?' * len(columns)})",
        (item_id, f"Article {item_id}", f"https://news.example/{item_id}", item_id, published, published, *columns.values()),
    )
    await db.commit()
    await db.close()


async def _entities(item_id):
    db = await get_db()
    cur = await db.execute("SELECT kind, value FROM item_entities WHERE item_id = ? ORDER BY kind, value", (item_id,))
    rows = [tuple(r) for r in await cur.fetchall()]
    await db.close()
    return rows


async def test_entities_follow_inserts_updates_and_deletes():
    await _item("a", 1, cves="CVE-2026-1111,CVE-2026-2222", ips="18.8.8.81", actors="APT99", vendors="Acme")
    assert await _entities("a") == [("actor", "apt99"), ("cve", "cve-2026-1111"), ("cve", "cve-2026-2222"),
                                    ("ip", "18.8.8.81"), ("vendor", "acme")]
    db = await get_db()
    await db.execute("UPDATE items SET cves = 'CVE-2026-3333', ips = '' WHERE id = 'a'")   # reprocessed
    await db.execute("UPDATE items SET bookmarked = 1 WHERE id = 'a'")                      # not an extraction column
    await db.commit()
    await db.close()
    assert await _entities("a") == [("actor", "apt99"), ("cve", "cve-2026-3333"), ("vendor", "acme")]
    db = await get_db()
    await db.execute("DELETE FROM items WHERE id = 'a'")
    await db.commit()
    await db.close()
    assert await _entities("a") == []


async def test_odd_characters_in_a_name_do_not_break_the_split():
    await _item("q", 1, actors='Say "hi",Back\\slash')
    assert await _entities("q") == [("actor", "back\\slash"), ("actor", 'say "hi"')]


async def test_migration_fills_in_articles_stored_before_it():
    await _item("old", 1, cves="CVE-2026-1111", hashes="44d88612fea8a8f36de82e1278abb02f")
    db = await get_db()
    await db.execute("DROP TABLE item_entities")
    for trigger in ("insert", "update", "delete"):
        await db.execute(f"DROP TRIGGER item_entities_{trigger}")
    await db.execute("PRAGMA user_version = 1")
    await db.commit()
    from omenwatch.database.migrations import migrate
    await migrate(db, main_steps.STEPS, "test")
    await db.close()
    assert await _entities("old") == [("cve", "cve-2026-1111"), ("hash", "44d88612fea8a8f36de82e1278abb02f")]


async def test_related_articles_rank_shared_indicators_above_shared_actors_and_ignore_vendors():
    await _item("main", 10, cves="CVE-2026-1111", ips="18.8.8.81", actors="APT99", vendors="Acme")
    await _item("same-ip", 5, ips="18.8.8.81")
    await _item("same-actor", 9, actors="APT99")
    await _item("same-vendor", 8, vendors="Acme")
    await _item("same-cve-and-actor", 4, cves="CVE-2026-1111", actors="APT99")
    out = client.get("/api/items/main/related").json()
    order = [r["id"] for r in out["related"]]
    assert order == ["same-ip", "same-cve-and-actor", "same-actor"]   # 3, 2+1 (older), 1; a vendor never relates
    assert [r["score"] for r in out["related"]] == [3, 3, 1]
    assert sorted((s["kind"], s["value"]) for s in out["related"][1]["shared"]) == [("actor", "apt99"), ("cve", "CVE-2026-1111")]
    assert out["related"][0]["source_name"] == "Example News"
    assert client.get("/api/items/missing/related").status_code == 404


async def test_an_article_shows_what_the_ioc_database_and_kev_know():
    token = client.post("/api/settings/auth/setup", json={"password": "test-password-123"}).json()["token"]
    added = client.post("/api/ioc/indicators", json={"text": "18.8.8.81", "confidence": 90, "malware": "QakBot"},
                        headers={"X-Settings-Token": token}).json()
    assert added["added"] == 1
    db = await get_db()
    await db.execute("INSERT INTO kev (cve, vendor, product, name, date_added) VALUES ('CVE-2026-1111', 'Acme', 'Gateway', 'Acme Gateway RCE', '2026-11-01')")
    await db.commit()
    await db.close()
    await _item("main", 10, cves="CVE-2026-1111", ips="18.8.8.81,198.51.100.9")
    entities = {e["value"]: e for e in client.get("/api/items/main/related").json()["entities"]}
    assert entities["CVE-2026-1111"]["kev"]["product"] == "Gateway"
    assert entities["18.8.8.81"]["indicator"]["malware"] == "QakBot"
    assert "indicator" not in entities["198.51.100.9"]


async def test_pivot_on_a_value_lists_its_articles_and_what_they_mention_alongside_it():
    await _item("a", 1, cves="CVE-2026-1111", actors="APT99")
    await _item("b", 2, cves="CVE-2026-1111", actors="APT99", ips="18.8.8.81")
    await _item("c", 3, cves="CVE-2026-9999")
    out = client.get("/api/correlate", params={"kind": "cve", "value": "cve-2026-1111"}).json()
    assert out["value"] == "CVE-2026-1111" and out["articles"] == 2
    assert [i["id"] for i in out["items"]] == ["b", "a"]
    assert out["mentioned_with"][0] == {"kind": "actor", "value": "apt99", "articles": 2}
    by_type = client.get("/api/correlate", params={"kind": "ipv4", "value": "18.8.8.81"}).json()   # an IOC tab type
    assert by_type["kind"] == "ip" and [i["id"] for i in by_type["items"]] == ["b"]
    assert client.get("/api/correlate", params={"kind": "domain", "value": "x"}).status_code == 400


def test_health_is_public_and_names_failed_checks(monkeypatch):
    with TestClient(app) as running:   # lifespan starts the workers
        out = running.get("/api/health")
        assert out.status_code == 200 and out.json()["status"] == "ok"
        from omenwatch.monitoring import health
        monkeypatch.setattr(health, "MIN_FREE_BYTES", 1 << 62)
        out = running.get("/api/health")
        assert out.status_code == 503 and out.json()["checks"]["disk_space"] == "fail"


def test_metrics_cover_sources_indicators_and_siem_lookups():
    client.post("/api/v1/lookup", json={"values": ["203.0.113.50"]})
    text = client.get("/metrics").text
    assert 'omenwatch_sources{state="pending"} 1' in text
    assert "# TYPE omenwatch_siem_lookup_duration_seconds histogram" in text
    assert 'omenwatch_siem_lookup_duration_seconds_count{endpoint="batch"}' in text
    assert 'omenwatch_siem_lookup_duration_seconds_bucket{endpoint="batch",le="+Inf"}' in text
    assert "https://news.example/feed" not in text                       # URLs can carry keys; never labels
    for line in text.splitlines():                                       # every sample line parses
        if line and not line.startswith("#"):
            name_labels, value = line.rsplit(" ", 1)
            float(value)


def test_metrics_need_signing_in(monkeypatch):
    monkeypatch.delenv("OMENWATCH_OPEN_DASHBOARD")
    assert TestClient(app).get("/metrics").status_code == 401
    assert TestClient(app).get("/api/correlate", params={"kind": "cve", "value": "x"}).status_code == 401


def test_item_entities_query_uses_the_index():
    from omenwatch.core import config
    with sqlite3.connect(config.DB_PATH) as raw:
        plan = " ".join(r[3] for r in raw.execute(
            "EXPLAIN QUERY PLAN SELECT item_id FROM item_entities WHERE kind = 'cve' AND value = 'x'"))
    assert "USING PRIMARY KEY" in plan or "USING INDEX" in plan
