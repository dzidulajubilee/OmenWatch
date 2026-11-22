"""
Correlation (2.0): which articles share a CVE, an indicator or an actor, and
what the IOC database and the CISA KEV catalog know about them.

Articles keep what was found in them as comma-separated columns on `items`
(cves, ips, hashes, emails, actors, vendors). `item_entities` holds the same
values one per row, indexed by value, so "every article that mentions X" is
an index lookup instead of a scan. SQLite triggers keep it in step with
`items`: every insert, re-extraction (reprocess) and deletion (retention,
source removal) updates it, whatever code made the change, and a restored
backup is filled in by the migration that creates it.

Values are stored lower-case; CVE ids are shown upper-case again.
"""
from omenwatch.ioc.lookup import lookup_values

# items column -> entity kind
COLUMNS = {"cves": "cve", "ips": "ip", "hashes": "hash", "emails": "email", "actors": "actor", "vendors": "vendor"}
KINDS = tuple(COLUMNS.values())

# How much a shared value says about two articles being about the same thing.
# A shared indicator is strong; a shared actor is weak; a vendor ("Microsoft")
# says almost nothing, so vendors are listed but never relate articles.
WEIGHT = {"ip": 3, "hash": 3, "email": 3, "cve": 2, "actor": 1}
# A value in more articles than this (a CVE everyone wrote about) is too
# common to relate two of them.
TOO_COMMON = 200


def _split(column: str, row: str) -> str:
    """SQL: the values of a comma-separated column as json_each rows (quotes and backslashes escaped)."""
    escaped = f"replace(replace({row}.{column}, '\\', '\\\\'), '\"', '\\\"')"
    return f"""json_each('["' || replace({escaped}, ',', '","') || '"]')"""


def _insert_entities(row: str, item_id: str) -> str:
    return "\n".join(
        f"""INSERT OR IGNORE INTO item_entities (kind, value, item_id)
            SELECT '{kind}', lower(trim(j.value)), {item_id} FROM {_split(column, row)} AS j
            WHERE {row}.{column} != '' AND trim(j.value) != '';"""
        for column, kind in COLUMNS.items()
    )


SCHEMA = f"""
CREATE TABLE IF NOT EXISTS item_entities (
    kind TEXT NOT NULL,      -- cve | ip | hash | email | actor | vendor
    value TEXT NOT NULL,     -- lower-case
    item_id TEXT NOT NULL,
    PRIMARY KEY (kind, value, item_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_item_entities_item ON item_entities(item_id);

CREATE TRIGGER IF NOT EXISTS item_entities_insert AFTER INSERT ON items BEGIN
{_insert_entities("new", "new.id")}
END;
CREATE TRIGGER IF NOT EXISTS item_entities_update AFTER UPDATE OF {", ".join(COLUMNS)} ON items BEGIN
DELETE FROM item_entities WHERE item_id = old.id;
{_insert_entities("new", "new.id")}
END;
CREATE TRIGGER IF NOT EXISTS item_entities_delete AFTER DELETE ON items BEGIN
DELETE FROM item_entities WHERE item_id = old.id;
END;
"""

BACKFILL = "\n".join(
    f"""INSERT OR IGNORE INTO item_entities (kind, value, item_id)
        SELECT '{kind}', lower(trim(j.value)), items.id FROM items, {_split(column, "items")} AS j
        WHERE items.{column} != '' AND trim(j.value) != '';"""
    for column, kind in COLUMNS.items()
)


def _shown(kind: str, value: str) -> str:
    return value.upper() if kind == "cve" else value


def _item(r) -> dict:
    return {"id": r["id"], "title": r["title"], "link": r["link"], "source_id": r["source_id"],
            "source_name": r["source_name"], "published": r["published"], "severity": r["severity"]}


_ITEM_COLUMNS = """i.id, i.title, i.link, i.source_id, i.published, i.severity,
                   COALESCE(s.name, '') AS source_name"""


async def _counts(db, entities: list[tuple[str, str]]) -> dict[tuple[str, str], int]:
    counts = {}
    for kind, value in entities:
        cur = await db.execute("SELECT COUNT(*) FROM item_entities WHERE kind = ? AND value = ?", (kind, value))
        counts[(kind, value)] = (await cur.fetchone())[0]
    return counts


async def _known(ioc_db, entities: list[tuple[str, str]]) -> dict[str, dict]:
    """Indicators among the values that are active in the IOC database, by value."""
    values = [value for kind, value in entities if kind in ("ip", "hash", "email")]
    if not values or ioc_db is None:
        return {}
    found = await lookup_values(ioc_db, values)
    return {r["value"]: r for r in found["results"] if r["match"]}


async def _kev(db, cves: list[str]) -> dict[str, dict]:
    if not cves:
        return {}
    cur = await db.execute(
        f"SELECT cve, vendor, product, name, date_added, due_date, ransomware FROM kev WHERE cve IN ({','.join('?' * len(cves))})",
        [c.upper() for c in cves],
    )
    return {r["cve"]: dict(r) for r in await cur.fetchall()}


async def related_to_item(db, ioc_db, item_id: str, limit: int = 20) -> dict | None:
    """What one article mentions, what is known about it, and the articles it shares the most with."""
    cur = await db.execute("SELECT 1 FROM items WHERE id = ?", (item_id,))
    if not await cur.fetchone():
        return None
    cur = await db.execute("SELECT kind, value FROM item_entities WHERE item_id = ? ORDER BY kind, value", (item_id,))
    entities = [(r["kind"], r["value"]) for r in await cur.fetchall()]
    counts = await _counts(db, entities)
    known = await _known(ioc_db, entities)
    kev = await _kev(db, [v for k, v in entities if k == "cve"])

    linking = [(k, v) for k, v in entities if k in WEIGHT and counts[(k, v)] <= TOO_COMMON]
    related = []
    if linking:
        pairs = " OR ".join("(e.kind = ? AND e.value = ?)" for _ in linking)
        weight = " ".join(f"WHEN '{k}' THEN {w}" for k, w in WEIGHT.items())
        cur = await db.execute(
            f"""SELECT {_ITEM_COLUMNS}, SUM(CASE e.kind {weight} ELSE 0 END) AS score,
                       group_concat(e.kind || ':' || e.value, char(31)) AS shared
                FROM item_entities e JOIN items i ON i.id = e.item_id LEFT JOIN sources s ON s.id = i.source_id
                WHERE ({pairs}) AND e.item_id != ?
                GROUP BY i.id ORDER BY score DESC, i.published DESC LIMIT ?""",
            [x for pair in linking for x in pair] + [item_id, limit],
        )
        for r in await cur.fetchall():
            shared = [s.split(":", 1) for s in r["shared"].split("\x1f")]
            related.append({**_item(r), "score": r["score"],
                            "shared": [{"kind": k, "value": _shown(k, v)} for k, v in shared]})

    return {
        "item_id": item_id,
        "entities": [
            {"kind": k, "value": _shown(k, v), "articles": counts[(k, v)],
             **({"indicator": known[v]} if v in known else {}),
             **({"kev": kev[v.upper()]} if k == "cve" and v.upper() in kev else {})}
            for k, v in entities
        ],
        "related": related,
    }


async def pivot(db, ioc_db, kind: str, value: str, limit: int = 50) -> dict:
    """Every article that mentions one value, what else those articles mention, and what is known about it."""
    value = value.strip().lower()
    cur = await db.execute("SELECT COUNT(*) FROM item_entities WHERE kind = ? AND value = ?", (kind, value))
    total = (await cur.fetchone())[0]
    cur = await db.execute(
        f"""SELECT {_ITEM_COLUMNS} FROM item_entities e JOIN items i ON i.id = e.item_id
            LEFT JOIN sources s ON s.id = i.source_id
            WHERE e.kind = ? AND e.value = ? ORDER BY i.published DESC LIMIT ?""",
        (kind, value, limit),
    )
    items = [_item(r) for r in await cur.fetchall()]
    cur = await db.execute(
        """SELECT o.kind, o.value, COUNT(*) AS n FROM item_entities e
           JOIN item_entities o ON o.item_id = e.item_id AND NOT (o.kind = e.kind AND o.value = e.value)
           WHERE e.kind = ? AND e.value = ? AND o.kind != 'vendor'
           GROUP BY o.kind, o.value ORDER BY n DESC, o.value LIMIT 15""",
        (kind, value),
    )
    together = [{"kind": r["kind"], "value": _shown(r["kind"], r["value"]), "articles": r["n"]}
                for r in await cur.fetchall()]
    result = {"kind": kind, "value": _shown(kind, value), "articles": total, "items": items,
              "mentioned_with": together}
    known = await _known(ioc_db, [(kind, value)])
    if value in known:
        result["indicator"] = known[value]
    if kind == "cve":
        kev = await _kev(db, [value])
        if value.upper() in kev:
            result["kev"] = kev[value.upper()]
    return result


# IOC database types that articles can mention, and the entity kind they are found under.
INDICATOR_KINDS = {"ipv4": "ip", "md5": "hash", "sha1": "hash", "sha256": "hash", "email": "email"}
