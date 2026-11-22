"""
Prometheus metrics at /metrics, in the plain text exposition format (no
client library needed).

Two kinds: counters and a latency histogram kept in memory for SIEM lookups
(they reset when the service restarts, which Prometheus handles), and
gauges read from the databases when scraped: sources and IOC feeds with
their state and last success, item and indicator counts. Feed and source
names are labels; URLs never are (they can carry keys).
"""
import os
import time

from omenwatch import __version__

STARTED = time.time()
# Seconds; covers the 15 ms target with room either side.
BUCKETS = (0.0025, 0.005, 0.01, 0.015, 0.025, 0.05, 0.1, 0.15, 0.25, 0.5, 1.0, 2.5)


class Histogram:
    def __init__(self):
        self.counts = [0] * len(BUCKETS)
        self.total = 0
        self.sum = 0.0

    def observe(self, seconds: float) -> None:
        self.total += 1
        self.sum += seconds
        for i, bound in enumerate(BUCKETS):
            if seconds <= bound:
                self.counts[i] += 1
                break


class LookupMetrics:
    """SIEM lookups (/api/v1/lookup), per endpoint: single or batch."""

    def __init__(self):
        self.requests = {"single": 0, "batch": 0}
        self.values = 0
        self.matches = 0
        self.duration = {"single": Histogram(), "batch": Histogram()}

    def record(self, endpoint: str, values: int, matches: int, seconds: float) -> None:
        self.requests[endpoint] += 1
        self.values += values
        self.matches += matches
        self.duration[endpoint].observe(seconds)


lookups = LookupMetrics()


def _label(value) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(**labels) -> str:
    if not labels:
        return ""
    return "{" + ",".join(f'{k}="{_label(v)}"' for k, v in labels.items()) + "}"


class Exposition:
    def __init__(self):
        self.lines: list[str] = []

    def metric(self, name: str, kind: str, help_text: str, samples: list[tuple[dict, float]]) -> None:
        self.lines.append(f"# HELP {name} {help_text}")
        self.lines.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            self.lines.append(f"{name}{_labels(**labels)} {value:g}" if isinstance(value, float) else
                              f"{name}{_labels(**labels)} {value}")

    def histogram(self, name: str, help_text: str, by_label: str, histograms: dict[str, Histogram]) -> None:
        self.lines.append(f"# HELP {name} {help_text}")
        self.lines.append(f"# TYPE {name} histogram")
        for key, h in histograms.items():
            running = 0
            for bound, count in zip(BUCKETS, h.counts, strict=True):
                running += count
                self.lines.append(f"{name}_bucket{_labels(**{by_label: key, 'le': f'{bound:g}'})} {running}")
            self.lines.append(f"{name}_bucket{_labels(**{by_label: key, 'le': '+Inf'})} {h.total}")
            self.lines.append(f"{name}_sum{_labels(**{by_label: key})} {h.sum:.6f}")
            self.lines.append(f"{name}_count{_labels(**{by_label: key})} {h.total}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


def _rss_bytes() -> int:
    try:
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return 0


def _state(enabled, status: str) -> str:
    if not enabled:
        return "paused"
    if status == "ok":
        return "healthy"
    if (status or "").startswith("error"):
        return "failing"
    return "pending"


async def render(db, ioc_db, websocket_clients: int) -> str:
    out = Exposition()
    out.metric("omenwatch_info", "gauge", "Version of OmenWatch running.", [({"version": __version__}, 1)])
    out.metric("omenwatch_start_time_seconds", "gauge", "When the service started, as a Unix time.", [({}, STARTED)])
    out.metric("omenwatch_resident_memory_bytes", "gauge", "Resident memory of the service.", [({}, _rss_bytes())])
    out.metric("omenwatch_websocket_clients", "gauge", "Dashboards connected for live updates.", [({}, websocket_clients)])

    cur = await db.execute("SELECT id, name, enabled, last_status, last_success, last_duration_ms FROM sources")
    sources = await cur.fetchall()
    out.metric("omenwatch_source_up", "gauge", "1 if the news source's last poll worked, 0 if it failed (paused and new sources are left out).",
               [({"source": s["id"], "name": s["name"]}, 1 if s["last_status"] == "ok" else 0)
                for s in sources if _state(s["enabled"], s["last_status"]) in ("healthy", "failing")])
    out.metric("omenwatch_source_last_success_timestamp_seconds", "gauge", "Last successful poll of each news source.",
               [({"source": s["id"], "name": s["name"]}, float(s["last_success"] or 0)) for s in sources])
    out.metric("omenwatch_source_poll_duration_seconds", "gauge", "How long each news source's last poll took.",
               [({"source": s["id"], "name": s["name"]}, (s["last_duration_ms"] or 0) / 1000) for s in sources])
    states = {"healthy": 0, "failing": 0, "pending": 0, "paused": 0}
    for s in sources:
        states[_state(s["enabled"], s["last_status"])] += 1
    out.metric("omenwatch_sources", "gauge", "News sources by state.", [({"state": k}, v) for k, v in states.items()])
    cur = await db.execute("SELECT COUNT(*) FROM items")
    out.metric("omenwatch_items", "gauge", "Articles stored.", [({}, (await cur.fetchone())[0])])

    if ioc_db is not None:
        cur = await ioc_db.execute("SELECT type, status, COUNT(*) AS n FROM indicators GROUP BY type, status")
        out.metric("omenwatch_ioc_indicators", "gauge", "Indicators in the IOC database by type and status.",
                   [({"type": r["type"], "status": r["status"]}, r["n"]) for r in await cur.fetchall()])
        cur = await ioc_db.execute("SELECT id, name, enabled, last_status, last_success FROM ioc_feeds")
        feeds = await cur.fetchall()
        out.metric("omenwatch_ioc_feed_up", "gauge", "1 if the IOC feed's last update worked, 0 if it failed (paused and new feeds are left out).",
                   [({"feed": f["id"], "name": f["name"]}, 1 if f["last_status"] == "ok" else 0)
                    for f in feeds if _state(f["enabled"], f["last_status"]) in ("healthy", "failing")])
        out.metric("omenwatch_ioc_feed_last_success_timestamp_seconds", "gauge", "Last successful update of each IOC feed.",
                   [({"feed": f["id"], "name": f["name"]}, float(f["last_success"] or 0)) for f in feeds])

    out.metric("omenwatch_siem_lookup_requests_total", "counter", "SIEM lookup requests since the service started.",
               [({"endpoint": k}, v) for k, v in lookups.requests.items()])
    out.metric("omenwatch_siem_lookup_values_total", "counter", "Values looked up by SIEMs since the service started.",
               [({}, lookups.values)])
    out.metric("omenwatch_siem_lookup_matches_total", "counter", "SIEM lookups that matched an active indicator since the service started.",
               [({}, lookups.matches)])
    out.histogram("omenwatch_siem_lookup_duration_seconds", "Time to answer a SIEM lookup request.", "endpoint",
                  lookups.duration)
    return out.text()
