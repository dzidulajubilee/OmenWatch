"""
Re-rates stored articles with the current wording rules and shows what would
change, before anything is written (`omenwatch-admin rescore`).

By default it works offline from what is stored: the title, the feed summary
and the CVEs found earlier. `fetch=True` re-reads each article page first, as
a full reprocess does. Indicators, tags and "Affects us" are left alone;
only the wording rating and the priority are worked out again.
"""
from collections import Counter

from omenwatch.news.priority import LEVELS, RANK, compute_priority, exploited_counts
from omenwatch.news.reprocessor import _fetch_article_texts
from omenwatch.news.scoring import score_severity_detail

_BATCH = 500


async def rescore(db, apply: bool = False, fetch: bool = False, examples: int = 8) -> dict:
    before: Counter = Counter()
    after: Counter = Counter()
    down: list[dict] = []
    up: list[dict] = []
    changed, last_rowid = 0, 0
    while True:
        cur = await db.execute(
            """SELECT rowid, id, title, summary, link, cves, watch_hits, kev_cves, severity,
                      content_severity, content_keyword
               FROM items WHERE rowid > ? ORDER BY rowid LIMIT ?""",
            (last_rowid, _BATCH),
        )
        rows = [dict(r) for r in await cur.fetchall()]
        if not rows:
            break
        bodies = await _fetch_article_texts(rows) if fetch else {}
        updates = []
        for row in rows:
            content, keyword = score_severity_detail(
                row["title"], row["summary"] or "", bodies.get(row["id"], ""), has_cve=bool(row["cves"])
            )
            level = compute_priority(
                content, bool(row["watch_hits"]), exploited_counts(row["title"], row["cves"], row["kev_cves"])
            )
            old = row["severity"] if row["severity"] in RANK else "low"
            before[old] += 1
            after[level] += 1
            if level != old:
                changed += 1
                moved = {"title": row["title"], "before": old, "after": level, "keyword": keyword}
                bucket = down if RANK[level] < RANK[old] else up
                if len(bucket) < examples:
                    bucket.append(moved)
            if (content, keyword, level) != (row["content_severity"], row["content_keyword"], row["severity"]):
                updates.append((content, keyword, level, row["id"]))
        if apply and updates:
            await db.executemany(
                "UPDATE items SET content_severity = ?, content_keyword = ?, severity = ? WHERE id = ?", updates
            )
            await db.commit()
        last_rowid = rows[-1]["rowid"]
    return {
        "before": {lv: before[lv] for lv in reversed(LEVELS)},
        "after": {lv: after[lv] for lv in reversed(LEVELS)},
        "changed": changed,
        "lowered": down,
        "raised": up,
        "applied": apply,
    }
