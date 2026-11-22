"""
The news side: items, tags, the indicators found in articles, stats, overview
and analytics.
"""
import bisect
import time

from fastapi import HTTPException

from omenwatch.api.dependencies import router
from omenwatch.api.routes.sources import SOURCE_STATE_ORDER, source_health
from omenwatch.database.sqlite import get_db
from omenwatch.news.priority import explain_priority

# Page sizes. SQLite reads a negative LIMIT as "no limit", so an unchecked
# ?limit=-1 would load every stored item into memory at once. The IOC
# list is larger because the IOCs page exports from it.
MAX_ITEMS_PAGE = 1000
MAX_TAGS_PAGE = 500
MAX_IOCS_PAGE = 100_000


def _bounded(limit: int, most: int) -> int:
    return max(1, min(limit, most))


def _row_to_item(row: dict) -> dict:
    row["vendors"] = [v for v in (row.get("vendors") or "").split(",") if v]
    row["actors"] = [a for a in (row.get("actors") or "").split(",") if a]
    row["cves"] = [c for c in (row.get("cves") or "").split(",") if c]
    row["ips"] = [i for i in (row.get("ips") or "").split(",") if i]
    row["hashes"] = [h for h in (row.get("hashes") or "").split(",") if h]
    row["emails"] = [e for e in (row.get("emails") or "").split(",") if e]
    row["watch_hits"] = [w for w in (row.get("watch_hits") or "").split(",") if w]
    row["kev_cves"] = [k for k in (row.get("kev_cves") or "").split(",") if k]
    row["priority_reasons"] = explain_priority(
        row.get("content_severity") or "", row.get("content_keyword") or "", row["watch_hits"], row["kev_cves"]
    )
    row["bookmarked"] = bool(row.get("bookmarked"))
    return row


# -------------------------------------------------------------------- items

# What the keyword filter searches: the text, the source, and everything
# OmenWatch extracted from the item.
_KEYWORD_COLUMNS = (
    "items.title", "items.summary", "sources.name", "items.vendors", "items.actors",
    "items.cves", "items.ips", "items.hashes", "items.emails", "items.watch_hits", "items.kev_cves",
)


def _build_item_conditions(
    source_id=None, category=None, severity=None, keyword=None, vendor=None, actor=None,
    ioc_type=None, ioc_value=None, has_cve=False, has_actor=False, bookmarked_only=False,
    date_from=None, date_to=None, affects_us=False, exploited=False,
):
    """
    Shared WHERE-condition builder for GET /api/items and GET
    /api/items/count — kept in one place so the two can never drift out
    of sync (an accurate total is meaningless if it's computed with
    different filter logic than the page of results it's counting).
    """
    conditions = []
    params = []
    if source_id:
        conditions.append("items.source_id = ?")
        params.append(source_id)
    if category:
        conditions.append("sources.category = ?")
        params.append(category)
    if severity:
        # comma-separated for multi-select (e.g. "high,medium"); a single
        # value works the same as before via a one-element IN clause.
        values = [s.strip() for s in severity.split(",") if s.strip()]
        if values:
            placeholders = ",".join("?" * len(values))
            conditions.append(f"items.severity IN ({placeholders})")
            params += values
    if keyword:
        # Every word must appear somewhere in the item, in any order and in
        # any field: "fortinet exploited" finds an item tagged Fortinet whose
        # title says exploited.
        for word in keyword.split():
            pattern = "%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            conditions.append("(" + " OR ".join(f"{column} LIKE ? ESCAPE '\\'" for column in _KEYWORD_COLUMNS) + ")")
            params += [pattern] * len(_KEYWORD_COLUMNS)
    if vendor:
        conditions.append("(',' || items.vendors || ',') LIKE ?")
        params.append(f"%,{vendor},%")
    if actor:
        conditions.append("(',' || items.actors || ',') LIKE ?")
        params.append(f"%,{actor},%")
    if ioc_type and ioc_value:
        ioc_column = {"cve": "cves", "ip": "ips", "hash": "hashes", "email": "emails"}.get(ioc_type)
        if not ioc_column:
            raise HTTPException(400, f"Unknown ioc_type '{ioc_type}'. Use one of: cve, ip, hash, email.")
        conditions.append(f"(',' || items.{ioc_column} || ',') LIKE ?")
        params.append(f"%,{ioc_value},%")
    elif ioc_type:
        # ioc_type given without a specific ioc_value: "has at least one IOC
        # of this type" — powers the IOC calendar's day drilldown (all CVEs
        # mentioned on a given day, not just occurrences of one specific CVE).
        ioc_column = {"cve": "cves", "ip": "ips", "hash": "hashes", "email": "emails"}.get(ioc_type)
        if not ioc_column:
            raise HTTPException(400, f"Unknown ioc_type '{ioc_type}'. Use one of: cve, ip, hash, email.")
        conditions.append(f"items.{ioc_column} != ''")
    if has_cve:
        conditions.append("items.cves != ''")
    if has_actor:
        conditions.append("items.actors != ''")
    if bookmarked_only:
        conditions.append("items.bookmarked = 1")
    if affects_us:
        conditions.append("items.watch_hits != ''")
    if exploited:
        conditions.append("items.kev_cves != ''")
    if date_from:
        conditions.append("items.fetched_at >= ?")
        params.append(_day_start_ts(date_from))
    if date_to:
        conditions.append("items.fetched_at <= ?")
        params.append(_day_end_ts(date_to))
    return conditions, params


@router.get("/api/items")
async def list_items(
    limit: int = 100,
    offset: int = 0,
    source_id: str | None = None,
    category: str | None = None,
    severity: str | None = None,  # single value, or comma-separated for multiple (e.g. "high,medium")
    keyword: str | None = None,
    vendor: str | None = None,
    actor: str | None = None,
    ioc_type: str | None = None,   # 'cve' | 'ip' | 'hash' | 'email'
    ioc_value: str | None = None,
    has_cve: bool = False,  # items with at least one extracted CVE, regardless of source category
    has_actor: bool = False,  # items with at least one detected threat actor (ransomware gang/APT group)
    bookmarked_only: bool = False,
    affects_us: bool = False,  # items that mention something on Settings -> Our stack
    exploited: bool = False,   # items that mention a CVE on CISA's KEV catalog
    date_from: str | None = None,  # 'YYYY-MM-DD', inclusive, matched against fetched_at
    date_to: str | None = None,    # 'YYYY-MM-DD', inclusive
):
    db = await get_db()
    try:
        q = """SELECT items.*, sources.name as source_name, sources.color as source_color,
                      sources.icon_url as source_icon, sources.category as category
               FROM items JOIN sources ON items.source_id = sources.id"""
        conditions, params = _build_item_conditions(
            source_id, category, severity, keyword, vendor, actor, ioc_type, ioc_value,
            has_cve, has_actor, bookmarked_only, date_from, date_to,
            affects_us=affects_us, exploited=exploited,
        )
        if conditions:
            q += " WHERE " + " AND ".join(conditions)
        # Newest arrivals first; within one poll (items stored in the same
        # minute) newest *published* first, so a feed's batch reads in order
        # instead of in whatever order the publisher listed it.
        q += f" ORDER BY CAST(items.fetched_at / 60 AS INTEGER) DESC, {_EFFECTIVE_TS_ITEMS} DESC LIMIT ? OFFSET ?"
        params += [_bounded(limit, MAX_ITEMS_PAGE), max(0, offset)]
        cur = await db.execute(q, params)
        return [_row_to_item(dict(r)) for r in await cur.fetchall()]
    finally:
        await db.close()


@router.get("/api/items/count")
async def count_items(
    source_id: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    keyword: str | None = None,
    vendor: str | None = None,
    actor: str | None = None,
    ioc_type: str | None = None,
    ioc_value: str | None = None,
    has_cve: bool = False,
    has_actor: bool = False,
    bookmarked_only: bool = False,
    affects_us: bool = False,  # items that mention something on Settings -> Our stack
    exploited: bool = False,   # items that mention a CVE on CISA's KEV catalog
    date_from: str | None = None,
    date_to: str | None = None,
):
    """Total matching items for the same filters GET /api/items accepts — powers numbered pagination."""
    db = await get_db()
    try:
        q = "SELECT COUNT(*) as total FROM items JOIN sources ON items.source_id = sources.id"
        conditions, params = _build_item_conditions(
            source_id, category, severity, keyword, vendor, actor, ioc_type, ioc_value,
            has_cve, has_actor, bookmarked_only, date_from, date_to,
            affects_us=affects_us, exploited=exploited,
        )
        if conditions:
            q += " WHERE " + " AND ".join(conditions)
        cur = await db.execute(q, params)
        row = await cur.fetchone()
        return {"total": row["total"]}
    finally:
        await db.close()


def _day_start_ts(date_str: str) -> float:
    import datetime
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d")
    return dt.timestamp()


def _day_end_ts(date_str: str) -> float:
    import datetime
    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d") + datetime.timedelta(days=1) - datetime.timedelta(seconds=1)
    return dt.timestamp()


def _date_range_where(date_from: str | None, date_to: str | None) -> tuple[str, list]:
    """
    Builds a `fetched_at BETWEEN ...`-style WHERE fragment (empty string if
    neither bound given) plus its params, for endpoints that scope a query
    to a date range — shared by /api/iocs, /api/iocs/summary, and
    /api/iocs/calendar so date handling can't drift out of sync between them.
    """
    clauses = []
    params: list = []
    if date_from:
        clauses.append("fetched_at >= ?")
        params.append(_day_start_ts(date_from))
    if date_to:
        clauses.append("fetched_at <= ?")
        params.append(_day_end_ts(date_to))
    return " AND ".join(clauses), params


@router.get("/api/items/range")
async def items_date_range():
    """Earliest/latest stored item timestamps — lets the UI bound a date picker to actual data."""
    db = await get_db()
    try:
        cur = await db.execute("SELECT MIN(fetched_at) as earliest, MAX(fetched_at) as latest, COUNT(*) as total FROM items")
        row = await cur.fetchone()
        return {"earliest": row["earliest"], "latest": row["latest"], "total": row["total"]}
    finally:
        await db.close()


@router.patch("/api/items/{item_id}/bookmark")
async def toggle_bookmark(item_id: str, bookmarked: bool):
    db = await get_db()
    try:
        await db.execute("UPDATE items SET bookmarked = ? WHERE id = ?", (int(bookmarked), item_id))
        await db.commit()
        return {"ok": True}
    finally:
        await db.close()


def _comma_column_counts_query(column: str, extra_where: str = "") -> str:
    """
    Builds a query that counts occurrences of each value in a comma-joined
    TEXT column (e.g. items.vendors = "Microsoft,Cisco") without ever
    pulling the raw column values into Python. A recursive CTE splits
    each row's comma list inside SQLite itself; only the final
    (value, count) pairs cross into the app.

    Previously these endpoints did `SELECT {col} FROM items WHERE {col}
    != ''`, loaded every matching row's full text into a Python list, and
    split/counted it there — memory and CPU cost scaling with total
    matching rows, on every request, on some of the most-hit endpoints
    (Dashboard, IOCs page). This does the same job inside the SQL engine.
    """
    where = f"{column} != ''" + (f" AND {extra_where}" if extra_where else "")
    return f"""
        WITH RECURSIVE
          base AS (SELECT {column} || ',' AS rest FROM items WHERE {where}),
          split(tag, rest) AS (
            SELECT substr(rest, 1, instr(rest, ',') - 1), substr(rest, instr(rest, ',') + 1) FROM base
            UNION ALL
            SELECT substr(rest, 1, instr(rest, ',') - 1), substr(rest, instr(rest, ',') + 1)
            FROM split WHERE rest != ''
          )
        SELECT tag AS name, COUNT(*) AS count FROM split WHERE tag != ''
        GROUP BY tag
    """


def _ioc_detail_query(column: str, extra_where: str = "", tag_filter: str = "") -> str:
    """
    Like _comma_column_counts_query, but carries each item's severity,
    fetch time and source through the split, so every distinct value also
    gets: number of sources, worst severity, first and last seen.

    Mentions, sources and severity respect `extra_where` (a selected day);
    first/last seen never do: "first seen" means the first time OmenWatch
    ever saw the value, not the first time on the selected day.
    """
    where = f"{column} != ''" + (f" AND {extra_where}" if extra_where else "")
    return f"""
        WITH RECURSIVE
          base AS (SELECT {column} || ',' AS rest, severity, fetched_at, source_id FROM items WHERE {where}),
          split(tag, rest, severity, fetched_at, source_id) AS (
            SELECT substr(rest, 1, instr(rest, ',') - 1), substr(rest, instr(rest, ',') + 1),
                   severity, fetched_at, source_id FROM base
            UNION ALL
            SELECT substr(rest, 1, instr(rest, ',') - 1), substr(rest, instr(rest, ',') + 1),
                   severity, fetched_at, source_id FROM split WHERE rest != ''
          ),
          ranged AS (
            SELECT tag AS name, COUNT(*) AS count, COUNT(DISTINCT source_id) AS sources,
                   MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) AS severity_rank
            FROM split WHERE tag != ''{tag_filter} GROUP BY tag
          ),
          all_base AS (SELECT {column} || ',' AS rest, fetched_at FROM items WHERE {column} != ''),
          all_split(tag, rest, fetched_at) AS (
            SELECT substr(rest, 1, instr(rest, ',') - 1), substr(rest, instr(rest, ',') + 1), fetched_at FROM all_base
            UNION ALL
            SELECT substr(rest, 1, instr(rest, ',') - 1), substr(rest, instr(rest, ',') + 1), fetched_at
            FROM all_split WHERE rest != ''
          ),
          seen AS (
            SELECT tag, MIN(fetched_at) AS first_seen, MAX(fetched_at) AS last_seen
            FROM all_split WHERE tag != '' GROUP BY tag
          )
        SELECT ranged.name, ranged.count, ranged.sources, ranged.severity_rank, seen.first_seen, seen.last_seen
        FROM ranged JOIN seen ON seen.tag = ranged.name
    """


@router.get("/api/tags")
async def list_tags(type: str = "vendor", limit: int = 20):
    """Distinct vendor/threat-actor tags with counts, for chip filters and the Vendors/Threat Actors pages."""
    col = "vendors" if type == "vendor" else "actors"
    db = await get_db()
    try:
        query = _comma_column_counts_query(col) + " ORDER BY count DESC, name ASC LIMIT ?"
        cur = await db.execute(query, (_bounded(limit, MAX_TAGS_PAGE),))
        return [dict(r) for r in await cur.fetchall()]
    finally:
        await db.close()


_IOC_COLUMNS = {"cve": "cves", "ip": "ips", "hash": "hashes", "email": "emails"}


@router.get("/api/iocs")
async def list_iocs(
    type: str = "cve", limit: int = 20, offset: int = 0,
    date_from: str | None = None, date_to: str | None = None,
    detail: bool = False, q: str | None = None,
):
    """
    Distinct IOCs of one type with occurrence counts, paginated —
    powers the IOCs page's bar chart and chip list. `offset` lets the
    frontend page through every distinct IOC of a type instead of only
    ever seeing the top `limit`; pair with GET /api/iocs/summary's
    per-type distinct count to know how many pages exist.

    Ranked by count descending, then by name ascending as a tiebreaker
    — without a deterministic tiebreak, IOCs with equal counts could
    silently swap pages between requests (dict ordering isn't a
    stable ranking), which would be confusing while paginating.

    date_from/date_to (both 'YYYY-MM-DD', inclusive) scope the count to
    just that range — used when a day is selected on the IOCs page's
    calendar, so "top CVEs" reflects that day instead of all-time.
    """
    col = _IOC_COLUMNS.get(type)
    if not col:
        raise HTTPException(400, f"Unknown IOC type '{type}'. Use one of: {', '.join(_IOC_COLUMNS)}.")
    date_where, date_params = _date_range_where(date_from, date_to)
    db = await get_db()
    try:
        if not detail:
            query = _comma_column_counts_query(col, extra_where=date_where) + " ORDER BY count DESC, name ASC LIMIT ? OFFSET ?"
            cur = await db.execute(query, (*date_params, _bounded(limit, MAX_IOCS_PAGE), max(0, offset)))
            return [dict(r) for r in await cur.fetchall()]

        # detail=1 (Indicators table, 0.6.0): same ranking, plus how many
        # sources mentioned each value, the worst severity it appeared with,
        # and when OmenWatch first/last saw it. `q` narrows by substring.
        # Opt-in so the plain {name, count} shape stays exactly as it was.
        tag_filter, q_params = "", ()
        if q and q.strip():
            tag_filter, q_params = " AND instr(lower(tag), lower(?)) > 0", (q.strip(),)
        query = _ioc_detail_query(col, extra_where=date_where, tag_filter=tag_filter) + " ORDER BY count DESC, name ASC LIMIT ? OFFSET ?"
        cur = await db.execute(query, (*date_params, *q_params, limit, offset))
        ranks = {4: "critical", 3: "high", 2: "medium", 1: "low"}
        rows = []
        for r in await cur.fetchall():
            row = dict(r)
            row["severity"] = ranks.get(row.pop("severity_rank"), "low")
            rows.append(row)
        return rows
    finally:
        await db.close()


@router.get("/api/iocs/summary")
async def iocs_summary(date_from: str | None = None, date_to: str | None = None):
    """
    Distinct-IOC-count per type — powers the IOC type distribution chart.
    date_from/date_to optionally scope it to a range, same as /api/iocs,
    so the donut reflects a selected calendar day instead of all-time.
    """
    date_where, date_params = _date_range_where(date_from, date_to)
    db = await get_db()
    try:
        summary = {}
        for ioc_type, col in _IOC_COLUMNS.items():
            query = f"SELECT COUNT(*) AS n FROM ({_comma_column_counts_query(col, extra_where=date_where)})"
            cur = await db.execute(query, date_params)
            row = await cur.fetchone()
            summary[ioc_type] = row["n"]
        return summary
    finally:
        await db.close()


@router.get("/api/iocs/calendar")
async def iocs_calendar(type: str = "cve", date_from: str | None = None, date_to: str | None = None):
    """
    Per-day counts for the Indicators page's calendar: how many distinct
    indicators of the given type were seen that day (`count`, matching the
    table for that day) and in how many items (`articles`). Until 0.6.1
    `count` was the number of items, which never matched the table.

    date_from/date_to (both 'YYYY-MM-DD', inclusive) scope it to the
    currently-displayed month rather than the item's entire history —
    with a database running for a year+, an unbounded version of this
    would return one row per day since install, most of them irrelevant
    to whatever month the user is currently looking at.

    Returns a plain list — [{"date": "2026-07-14", "count": 3, "articles": 2}, ...] —
    computed entirely in SQL (a single GROUP BY), not by loading rows
    into Python and bucketing them there.
    """
    col = _IOC_COLUMNS.get(type)
    if not col:
        raise HTTPException(400, f"Unknown IOC type '{type}'. Use one of: {', '.join(_IOC_COLUMNS)}.")
    date_where, date_params = _date_range_where(date_from, date_to)
    where = f"{col} != ''" + (f" AND {date_where}" if date_where else "")
    # `count` is the number of distinct indicators of this type seen that
    # day: the same unit as the Indicators table and /api/iocs/summary for
    # that day, so the calendar and the list next to it always agree.
    # `articles` is how many items they appeared in (for the tooltip).
    query = f"""
        WITH RECURSIVE
          base AS (SELECT id, {col} || ',' AS rest,
                          strftime('%Y-%m-%d', fetched_at, 'unixepoch', 'localtime') AS date
                   FROM items WHERE {where}),
          split(id, date, tag, rest) AS (
            SELECT id, date, substr(rest, 1, instr(rest, ',') - 1), substr(rest, instr(rest, ',') + 1) FROM base
            UNION ALL
            SELECT id, date, substr(rest, 1, instr(rest, ',') - 1), substr(rest, instr(rest, ',') + 1)
            FROM split WHERE rest != ''
          )
        SELECT date, COUNT(DISTINCT tag) AS count, COUNT(DISTINCT id) AS articles
        FROM split WHERE tag != '' GROUP BY date ORDER BY date
    """
    db = await get_db()
    try:
        cur = await db.execute(query, date_params)
        return [dict(r) for r in await cur.fetchall()]
    finally:
        await db.close()


# -------------------------------------------------------------------- stats

@router.get("/api/stats")
async def get_stats():
    db = await get_db()
    try:
        now = time.time()
        day_ago = now - 86400
        week_ago = now - (86400 * 7)

        async def scalar(query, params=()):
            cur = await db.execute(query, params)
            row = await cur.fetchone()
            return row[0] if row else 0

        total_articles = await scalar("SELECT COUNT(*) FROM items")
        new_today = await scalar("SELECT COUNT(*) FROM items WHERE fetched_at > ?", (day_ago,))
        critical_alerts = await scalar(
            "SELECT COUNT(*) FROM items WHERE severity = 'high' AND fetched_at > ?", (day_ago,)
        )
        sources_count = await scalar("SELECT COUNT(*) FROM sources WHERE enabled = 1")
        total_sources = await scalar("SELECT COUNT(*) FROM sources")

        cur = await db.execute("SELECT severity, COUNT(*) c FROM items GROUP BY severity")
        severity_dist = {r["severity"]: r["c"] for r in await cur.fetchall()}

        cur = await db.execute(
            """SELECT sources.category as category, COUNT(*) c FROM items
               JOIN sources ON items.source_id = sources.id GROUP BY sources.category"""
        )
        category_dist = {r["category"]: r["c"] for r in await cur.fetchall()}

        cur = await db.execute(
            """SELECT sources.name as name, COUNT(*) c FROM items
               JOIN sources ON items.source_id = sources.id
               GROUP BY sources.name ORDER BY c DESC LIMIT 5"""
        )
        top_sources = [{"name": r["name"], "count": r["c"]} for r in await cur.fetchall()]

        cur = await db.execute(
            _comma_column_counts_query("vendors", extra_where="fetched_at > ?") + " ORDER BY count DESC, name ASC LIMIT 5",
            (week_ago,),
        )
        top_vendors = [(r["name"], r["count"]) for r in await cur.fetchall()]

        # articles/day for the last 7 days — bucketed in SQL rather than
        # pulling every fetched_at timestamp into Python and grouping there.
        # 'localtime' matches the previous behavior (time.localtime bucketing).
        cur = await db.execute(
            """SELECT strftime('%Y-%m-%d', fetched_at, 'unixepoch', 'localtime') AS day, COUNT(*) AS c
               FROM items WHERE fetched_at > ? GROUP BY day""",
            (week_ago,),
        )
        day_buckets = {r["day"]: r["c"] for r in await cur.fetchall()}

        return {
            "total_articles": total_articles,
            "new_today": new_today,
            "critical_alerts": critical_alerts,
            "sources_active": sources_count,
            "sources_total": total_sources,
            "severity_distribution": severity_dist,
            "category_distribution": category_dist,
            "top_sources": top_sources,
            "top_vendors": [{"name": n, "count": c} for n, c in top_vendors],
            "articles_by_day": day_buckets,
        }
    finally:
        await db.close()



# "When was this published", for anything the dashboard counts or sorts.
# The feed's own date, unless it claims to be later than when OmenWatch
# fetched it (a wrong clock or timezone on the publisher's side — allowed
# an hour of slack), in which case the fetch time is the honest answer.
# Counting by fetch time instead (what /api/stats does) makes a newly
# added source's whole backlog look like it all happened "today".
_EFFECTIVE_TS = "(CASE WHEN published > 0 AND published <= fetched_at + 3600 THEN published ELSE fetched_at END)"
_EFFECTIVE_TS_ITEMS = _EFFECTIVE_TS.replace("published", "items.published").replace("fetched_at", "items.fetched_at")


@router.get("/api/overview")
async def get_overview(hours: int = 24, since: float | None = None):
    """
    Everything the dashboard and the header's status indicators need, in
    one public call. Additive on purpose: /api/stats keeps its exact
    shape and fetch-time semantics for anything already relying on it.

    - `hours` (1 to 2160, default 24): window for the high-severity count
      and the "needs attention" list, by published date.
    - `since` (unix seconds): "new since you last looked" counts items
      OmenWatch *stored* after this moment — that question is about what
      the viewer hasn't seen, not about publication dates. Defaults to 24h
      ago; ignored if it's in the future.
    """
    hours = max(1, min(hours, 24 * 90))
    now = time.time()
    window_start = now - hours * 3600
    if since is None or since <= 0 or since > now:
        since = now - 86400
    local = time.localtime(now)
    today_start = time.mktime((local.tm_year, local.tm_mon, local.tm_mday, 0, 0, 0, 0, 0, -1))
    week_start = today_start - 6 * 86400  # today plus the six days before it

    db = await get_db()
    try:
        async def scalar(query, params=()):
            cur = await db.execute(query, params)
            row = await cur.fetchone()
            return row[0] if row else 0

        # "High" on the dashboard means high priority or above.
        high_in_window = await scalar(
            f"SELECT COUNT(*) FROM items WHERE severity IN ('critical', 'high') AND {_EFFECTIVE_TS} > ?", (window_start,)
        )
        critical_in_window = await scalar(
            f"SELECT COUNT(*) FROM items WHERE severity = 'critical' AND {_EFFECTIVE_TS} > ?", (window_start,)
        )
        published_today = await scalar(f"SELECT COUNT(*) FROM items WHERE {_EFFECTIVE_TS} >= ?", (today_start,))
        published_week = await scalar(f"SELECT COUNT(*) FROM items WHERE {_EFFECTIVE_TS} >= ?", (week_start,))
        new_since = await scalar("SELECT COUNT(*) FROM items WHERE fetched_at > ?", (since,))
        affects_us = await scalar(f"SELECT COUNT(*) FROM items WHERE watch_hits != '' AND {_EFFECTIVE_TS} > ?", (window_start,))
        affects_us_exploited = await scalar(
            f"SELECT COUNT(*) FROM items WHERE watch_hits != '' AND kev_cves != '' AND {_EFFECTIVE_TS} > ?", (window_start,)
        )
        exploited = await scalar(f"SELECT COUNT(*) FROM items WHERE kev_cves != '' AND {_EFFECTIVE_TS} > ?", (window_start,))
        watchlist_size = await scalar("SELECT COUNT(*) FROM watchlist")
        kev_size = await scalar("SELECT COUNT(*) FROM kev")
        kev_off = await scalar("SELECT COUNT(*) FROM settings WHERE key = 'kev_enabled' AND value = '0'")

        indicators_week = {}
        for column, key in (("cves", "cve"), ("ips", "ip"), ("hashes", "hash"), ("emails", "email")):
            inner = _comma_column_counts_query(column, extra_where=f"{_EFFECTIVE_TS} >= ?")
            indicators_week[key] = await scalar(f"SELECT COUNT(*) FROM ({inner})", (week_start,))

        cur = await db.execute(
            f"""SELECT items.*, sources.name AS source_name, sources.color AS source_color,
                       sources.icon_url AS source_icon, sources.category AS category
                FROM items JOIN sources ON items.source_id = sources.id
                WHERE items.severity IN ('critical', 'high') AND {_EFFECTIVE_TS_ITEMS} > ?
                ORDER BY items.severity = 'critical' DESC, {_EFFECTIVE_TS_ITEMS} DESC LIMIT 8""",
            (window_start,),
        )
        attention = [_row_to_item(dict(r)) for r in await cur.fetchall()]

        cur = await db.execute(
            f"""SELECT strftime('%Y-%m-%d', {_EFFECTIVE_TS}, 'unixepoch', 'localtime') AS day,
                       severity, COUNT(*) AS c
                FROM items WHERE {_EFFECTIVE_TS} >= ? GROUP BY day, severity""",
            (week_start,),
        )
        buckets: dict[str, dict[str, int]] = {}
        for r in await cur.fetchall():
            buckets.setdefault(r["day"], {})[r["severity"]] = r["c"]
        by_day = []
        for offset in range(6, -1, -1):
            day = time.strftime("%Y-%m-%d", time.localtime(today_start - offset * 86400 + 43200))
            counts = buckets.get(day, {})
            by_day.append({"date": day, **{s: counts.get(s, 0) for s in ("critical", "high", "medium", "low")}})

        # 2.0: the dashboard's main chart. Hourly for a day or two, otherwise
        # one bar per local day, over the selected range; `new` counts what
        # arrived after `since`, for the "last looked" line.
        if hours <= 48:
            step, end = 3600, (int(now // 3600) + 1) * 3600
            starts = [end - (hours - k) * 3600 for k in range(hours)]
        else:
            step, days = 86400, hours // 24
            starts = [today_start - (days - 1 - k) * 86400 for k in range(days)]
            starts = [time.mktime(time.localtime(t)[:3] + (0, 0, 0, 0, 0, -1)) for t in starts]
        first = starts[0]
        cur = await db.execute(
            f"""SELECT {_EFFECTIVE_TS} AS ts, severity, fetched_at > ? AS is_new
                FROM items WHERE {_EFFECTIVE_TS} >= ?""",
            (since, first),
        )
        timeline = [{"start": t, "critical": 0, "high": 0, "other": 0, "new": 0} for t in starts]
        for r in await cur.fetchall():
            k = bisect.bisect_right(starts, r["ts"]) - 1
            if k < 0 or r["ts"] >= starts[k] + step + 3600:
                continue
            bucket = timeline[k]
            bucket[r["severity"] if r["severity"] in ("critical", "high") else "other"] += 1
            bucket["new"] += r["is_new"]

        cur = await db.execute(
            "SELECT id, name, category, enabled, last_status, last_fetched, last_success, failing_since FROM sources"
        )
        health = [source_health(dict(r)) for r in await cur.fetchall()]
        health.sort(key=lambda h: (SOURCE_STATE_ORDER[h["state"]], h["name"].lower()))
    finally:
        await db.close()

    count = {state: sum(1 for h in health if h["state"] == state) for state in SOURCE_STATE_ORDER}
    return {
        "generated_at": now,
        "hours": hours,
        "since": since,
        "high_in_window": high_in_window,
        "critical_in_window": critical_in_window,
        "new_since": new_since,
        # Counts only: the watchlist itself is Settings-only.
        "affects_us": {"items": affects_us, "exploited": affects_us_exploited, "watchlist": watchlist_size},
        "exploited": {"items": exploited, "catalog": kev_size, "enabled": not kev_off},
        "published_today": published_today,
        "published_week": published_week,
        "indicators_week": indicators_week,
        "attention": attention,
        "by_day": by_day,
        "timeline": {"step": step, "buckets": timeline},
        "sources": {"total": len(health), **count, "list": health},
    }


@router.get("/api/analytics")
async def get_analytics(days: int = 30):
    """
    Everything the Analytics page shows, by published date (the same
    _EFFECTIVE_TS rule as the dashboard), for the last `days` days
    (1 to 365, default 30) including today. Also returns the previous
    period of the same length, so the page can show change, and a
    weekday x hour matrix of when items get published (server local
    time). Public, like the rest of the dashboard.
    """
    days = max(1, min(days, 365))
    now = time.time()
    local = time.localtime(now)
    today_start = time.mktime((local.tm_year, local.tm_mon, local.tm_mday, 0, 0, 0, 0, 0, -1))
    start = today_start - (days - 1) * 86400
    prev_start = start - days * 86400

    db = await get_db()
    try:
        async def severity_counts(lo, hi):
            cur = await db.execute(
                f"SELECT severity, COUNT(*) AS c FROM items WHERE {_EFFECTIVE_TS} >= ? AND {_EFFECTIVE_TS} < ? GROUP BY severity",
                (lo, hi),
            )
            counts = {r["severity"]: r["c"] for r in await cur.fetchall()}
            return {sev: counts.get(sev, 0) for sev in ("critical", "high", "medium", "low")}

        current = await severity_counts(start, now + 86400)
        previous = await severity_counts(prev_start, start)

        cur = await db.execute(
            f"""SELECT strftime('%Y-%m-%d', {_EFFECTIVE_TS}, 'unixepoch', 'localtime') AS day, severity, COUNT(*) AS c
                FROM items WHERE {_EFFECTIVE_TS} >= ? GROUP BY day, severity""",
            (start,),
        )
        buckets: dict[str, dict[str, int]] = {}
        for r in await cur.fetchall():
            buckets.setdefault(r["day"], {})[r["severity"]] = r["c"]
        by_day = []
        for offset in range(days - 1, -1, -1):
            day = time.strftime("%Y-%m-%d", time.localtime(today_start - offset * 86400 + 43200))
            counts = buckets.get(day, {})
            by_day.append({"date": day, **{sev: counts.get(sev, 0) for sev in ("critical", "high", "medium", "low")}})

        cur = await db.execute(
            f"""SELECT sources.category AS name, COUNT(*) AS count FROM items JOIN sources ON items.source_id = sources.id
                WHERE {_EFFECTIVE_TS_ITEMS} >= ? GROUP BY sources.category ORDER BY count DESC""",
            (start,),
        )
        by_category = [dict(r) for r in await cur.fetchall()]

        cur = await db.execute(
            f"""SELECT sources.name AS name, COUNT(*) AS count,
                       SUM(CASE WHEN items.severity IN ('critical', 'high') THEN 1 ELSE 0 END) AS high
                FROM items JOIN sources ON items.source_id = sources.id
                WHERE {_EFFECTIVE_TS_ITEMS} >= ? GROUP BY sources.id ORDER BY count DESC, name ASC LIMIT 8""",
            (start,),
        )
        top_sources = [dict(r) for r in await cur.fetchall()]

        cur = await db.execute(f"SELECT COUNT(DISTINCT source_id) FROM items WHERE {_EFFECTIVE_TS} >= ?", (start,))
        active_sources = (await cur.fetchone())[0]

        async def top_tags(column):
            query = _comma_column_counts_query(column, extra_where=f"{_EFFECTIVE_TS} >= ?") + " ORDER BY count DESC, name ASC LIMIT 8"
            cur = await db.execute(query, (start,))
            return [dict(r) for r in await cur.fetchall()]

        top_vendors = await top_tags("vendors")
        top_actors = await top_tags("actors")

        indicators = {}
        for column, key in (("cves", "cve"), ("ips", "ip"), ("hashes", "hash"), ("emails", "email")):
            inner = _comma_column_counts_query(column, extra_where=f"{_EFFECTIVE_TS} >= ?")
            cur = await db.execute(f"SELECT COUNT(*) FROM ({inner})", (start,))
            indicators[key] = (await cur.fetchone())[0]

        cur = await db.execute(
            f"""SELECT CAST(strftime('%w', {_EFFECTIVE_TS}, 'unixepoch', 'localtime') AS INTEGER) AS wd,
                       CAST(strftime('%H', {_EFFECTIVE_TS}, 'unixepoch', 'localtime') AS INTEGER) AS hr, COUNT(*) AS c
                FROM items WHERE {_EFFECTIVE_TS} >= ? GROUP BY wd, hr""",
            (start,),
        )
        heatmap = [[0] * 24 for _ in range(7)]  # [weekday 0=Sunday][hour]
        for r in await cur.fetchall():
            heatmap[r["wd"]][r["hr"]] = r["c"]
    finally:
        await db.close()

    return {
        "days": days,
        "start": start,
        "generated_at": now,
        "totals": {**current, "items": sum(current.values())},
        "previous": {**previous, "items": sum(previous.values())},
        "active_sources": active_sources,
        "indicators": indicators,
        "by_day": by_day,
        "by_category": by_category,
        "top_sources": top_sources,
        "top_vendors": top_vendors,
        "top_actors": top_actors,
        "heatmap": heatmap,
    }
