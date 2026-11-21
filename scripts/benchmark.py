"""
IOC lookup benchmark for the v2 performance targets.

    python scripts/benchmark.py --size 1000000 --data /var/tmp/pantomath-bench

Builds an IOC database of --size synthetic indicators with Pantomath's own
import code (kept in --data, so a second run reuses it), starts a real
server on it, and measures, with --clients SIEM clients at once and about
half of the looked-up values matching:

  - the database lookup alone, in-process (no HTTP);
  - GET /api/v1/lookup for one value;
  - POST /api/v1/lookup with 100 and with 1,000 values;
  - single lookups again while a feed of --import-size new values is
    imported through the IOC feeds API, as a real feed would be;
  - the server's memory (RSS) throughout.

Results go to --data/results-<size>.json and are printed as a table.
Everything is synthetic: no real indicators, hosts or keys.
"""
import argparse
import asyncio
import contextlib
import http.server
import ipaddress
import json
import os
import random
import socket
import sqlite3
import subprocess
import sys
import threading
import time

TARGETS = {  # ms, P95
    "db_single": 5, "http_single": 15, "http_batch_100": 50, "http_batch_1000": 150,
}
MIX = (("sha256", 0.4), ("md5", 0.1), ("ipv4", 0.2), ("domain", 0.2), ("url", 0.1))
CHUNK = 100_000
SETTINGS_PASSWORD = "benchmark-password-1"
SAMPLE = 20_000


# ------------------------------------------------------------------ data

def _global_ipv4(rng):
    while True:
        ip = ipaddress.IPv4Address(rng.getrandbits(32))
        if ip.is_global and not ip.is_multicast:
            return str(ip)


def make_value(rng, kind, tag):
    if kind == "sha256":
        return f"{rng.getrandbits(256):064x}"
    if kind == "md5":
        return f"{rng.getrandbits(128):032x}"
    if kind == "ipv4":
        return _global_ipv4(rng)
    host = f"{tag}{rng.getrandbits(48):x}.net"
    if kind == "domain":
        return host
    return f"http://{host}/{rng.getrandbits(32):x}/download.php"


def values(rng, n, tag):
    kinds = [k for k, _ in MIX]
    weights = [w for _, w in MIX]
    for _ in range(n):
        kind = rng.choices(kinds, weights)[0]
        yield kind, make_value(rng, kind, tag)


async def seed(data, size):
    from pantomath.database.sqlite import init_db
    from pantomath.ioc import normalize
    from pantomath.ioc.db import get_ioc_db, init_ioc_db
    from pantomath.ioc.store import Arrival, Source, ingest

    await init_db()
    await init_ioc_db()
    sample_path = os.path.join(data, "sample.json")
    db = await get_ioc_db()
    try:
        cur = await db.execute("SELECT COUNT(*) FROM indicators")
        have = (await cur.fetchone())[0]
        if have and os.path.exists(sample_path):
            with open(sample_path) as f:
                sample = json.load(f)
            return sample, await _siem_key(), None, have
        rng = random.Random(1)
        sample, started = [], time.perf_counter()
        source = Source(id="bench", name="Benchmark feed", confidence=80, lifetime_days=-1)
        batch = []
        for i, (kind, value) in enumerate(values(rng, size, "m")):
            if i < 1000:   # the generator must produce what Pantomath stores
                assert normalize.normalize_typed(kind, value)[1] == value, value
            if len(sample) < SAMPLE:
                sample.append(value)
            elif rng.random() < SAMPLE / (i + 1):
                sample[rng.randrange(SAMPLE)] = value
            if have:
                continue
            batch.append(Arrival(kind, value))
            if len(batch) == CHUNK:
                await ingest(db, source, batch)
                batch = []
                print(f"  seeded {i + 1:,} ({(i + 1) / (time.perf_counter() - started):,.0f}/s)", flush=True)
        if batch:
            await ingest(db, source, batch)
        seed_rate = None if have else size / (time.perf_counter() - started)
    finally:
        await db.close()
    with open(sample_path, "w") as f:
        json.dump(sample, f)
    return sample, await _siem_key(), seed_rate, have


async def _siem_key():
    """A SIEM key for /api/v1, and an ordinary API key for the Settings calls."""
    from pantomath.auth import settings_auth, sign_in
    from pantomath.database.sqlite import get_db

    db = await get_db()
    try:
        if not await settings_auth.is_password_configured(db):
            await settings_auth.setup_password(db, SETTINGS_PASSWORD)
        siem, _ = await sign_in.create_session(db, sign_in.SIEM_ROLE, False, "127.0.0.1", "",
                                               kind="api", label="Benchmark SIEM")
        api, _ = await sign_in.create_session(db, "team", False, "127.0.0.1", "",
                                              kind="api", label="Benchmark")
    finally:
        await db.close()
    return siem, api


# ---------------------------------------------------------------- server

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rss_mb(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    return 0.0


class Memory:
    """Samples the server's RSS every 200 ms; `peak` per phase."""

    def __init__(self, pid):
        self.pid, self.peak, self.current = pid, 0.0, 0.0
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                self.current = rss_mb(self.pid)
            except OSError:
                return
            self.peak = max(self.peak, self.current)
            time.sleep(0.2)

    def phase(self):
        peak, self.peak = self.peak, self.current
        return round(peak, 1)


def serve_file(path):
    folder, name = os.path.split(path)
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=folder, **k)  # noqa: E731
    http.server.SimpleHTTPRequestHandler.log_message = lambda *a: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_port}/{name}"


# ------------------------------------------------------------------ load

def pct(samples, p):
    if not samples:
        return None
    ordered = sorted(samples)
    return round(ordered[min(len(ordered) - 1, int(len(ordered) * p))], 2)


def summary(samples, seconds):
    return {"requests": len(samples), "per_second": round(len(samples) / seconds, 1),
            "p50": pct(samples, 0.50), "p95": pct(samples, 0.95), "p99": pct(samples, 0.99),
            "max": round(max(samples), 2) if samples else None}


def lookup_values(rng, sample, n):
    """About half known values, half new ones."""
    out = []
    for _ in range(n):
        if rng.random() < 0.5:
            out.append(rng.choice(sample))
        else:
            kind = rng.choices([k for k, _ in MIX], [w for _, w in MIX])[0]
            out.append(make_value(rng, kind, "x"))
    return out


async def load(client, sample, batch, clients, seconds, stop=None):
    samples, errors = [], 0
    deadline = time.perf_counter() + seconds

    async def worker(n):
        nonlocal errors
        rng = random.Random(n)
        while time.perf_counter() < deadline and not (stop and stop.is_set()):
            vals = lookup_values(rng, sample, batch)
            start = time.perf_counter()
            if batch == 1:
                resp = await client.get("/api/v1/lookup", params={"value": vals[0]})
            else:
                resp = await client.post("/api/v1/lookup", json={"values": vals})
            elapsed = (time.perf_counter() - start) * 1000
            if resp.status_code == 200:
                samples.append(elapsed)
            else:
                errors += 1

    started = time.perf_counter()
    await asyncio.gather(*(worker(n) for n in range(clients)))
    result = summary(samples, time.perf_counter() - started)
    result["errors"] = errors
    return result


async def db_only(sample, runs=3000):
    from pantomath.ioc.db import get_ioc_db
    from pantomath.ioc.routes import lookup_values as lookup

    rng = random.Random(7)
    db = await get_ioc_db()
    try:
        samples = []
        for _ in range(runs):
            vals = lookup_values(rng, sample, 1)
            start = time.perf_counter()
            await lookup(db, vals)
            samples.append((time.perf_counter() - start) * 1000)
    finally:
        await db.close()
    return summary(samples, sum(samples) / 1000)


async def during_import(client, token, api_key, sample, clients, data, import_size):
    feed_path = os.path.join(data, f"feed-{import_size}.txt")
    if not os.path.exists(feed_path):
        with open(feed_path, "w") as f:
            for _, value in values(random.Random(99), import_size, "f"):
                f.write(value + "\n")
    url = serve_file(feed_path)
    headers = {"X-Settings-Token": token, "Authorization": f"Bearer {api_key}"}
    size_mb = os.path.getsize(feed_path) // (1024 * 1024) + 10
    resp = await client.post("/api/ioc/feeds", headers=headers, timeout=600,
                             json={"name": "Benchmark import", "url": url, "format": "text",
                                   "max_mb": size_mb, "enabled": False})
    resp.raise_for_status()
    feed_id = resp.json()["id"]

    stop = asyncio.Event()

    async def run_import():
        start = time.perf_counter()
        r = await client.post(f"/api/ioc/feeds/{feed_id}/run", headers=headers, timeout=3600)
        stop.set()
        return r.json(), time.perf_counter() - start

    task = asyncio.create_task(run_import())
    await asyncio.sleep(0.5)
    lookups = await load(client, sample, 1, clients, 3600, stop)
    outcome, seconds = await task
    return lookups, outcome, seconds


async def settings_token(client, api_key):
    resp = await client.post("/api/settings/auth/login", json={"password": SETTINGS_PASSWORD},
                             headers={"Authorization": f"Bearer {api_key}"})
    resp.raise_for_status()
    return resp.json()["token"]


# ------------------------------------------------------------------ main

async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--size", type=int, default=100_000)
    ap.add_argument("--data", default="/var/tmp/pantomath-bench")
    ap.add_argument("--clients", type=int, default=20)
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--import-size", type=int, default=500_000)
    args = ap.parse_args()

    data = os.path.join(args.data, str(args.size))
    os.makedirs(data, exist_ok=True)
    os.environ["PANTOMATH_DB"] = os.path.join(data, "pantomath.db")
    base_ioc = os.path.join(data, "ioc.db")
    os.environ["PANTOMATH_IOC_DB"] = base_ioc
    os.environ.pop("PANTOMATH_OPEN_DASHBOARD", None)
    print(f"== {args.size:,} indicators in {data}")
    sample, (key, api_key), seed_rate, had = await seed(data, args.size)
    print("  reused the existing database" if had else f"  seeded at {seed_rate:,.0f} indicators/s")
    work_ioc = os.path.join(data, "ioc-run.db")
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(FileNotFoundError):
            os.remove(work_ioc + suffix)
    # The server imports into a copy, so the base database stays at --size.
    with sqlite3.connect(base_ioc) as src, sqlite3.connect(work_ioc) as dst:
        src.backup(dst)
    os.environ["PANTOMATH_IOC_DB"] = work_ioc

    print("  database lookup, in-process")
    results = {"size": args.size, "clients": args.clients, "seed_per_second": seed_rate,
               "python": sys.version.split()[0], "cpus": os.cpu_count(),
               "db_single": await db_only(sample)}

    import httpx

    port = free_port()
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "pantomath.app:app",
                               "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"])
    try:
        memory = Memory(server.pid)
        limits = httpx.Limits(max_connections=args.clients + 5, max_keepalive_connections=args.clients + 5)
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", limits=limits, timeout=60,
                                     headers={"Authorization": f"Bearer {key}"}) as client:
            for _ in range(100):
                with contextlib.suppress(httpx.TransportError):
                    if (await client.get("/api/v1/health")).status_code == 200:
                        break
                await asyncio.sleep(0.2)
            await asyncio.sleep(1)
            results["memory_idle_mb"] = round(memory.current, 1)
            memory.phase()

            await load(client, sample, 1, args.clients, 3)   # warm up
            for name, batch in (("http_single", 1), ("http_batch_100", 100), ("http_batch_1000", 1000)):
                print(f"  {name}: {args.clients} clients, {args.seconds}s")
                results[name] = await load(client, sample, batch, args.clients, args.seconds)
                results[name]["memory_peak_mb"] = memory.phase()

            print(f"  single lookups while importing {args.import_size:,} new values")
            token = await settings_token(client, api_key)
            lookups, outcome, seconds = await during_import(client, token, api_key, sample, args.clients, data,
                                                            args.import_size)
            lookups["memory_peak_mb"] = memory.phase()
            results["http_single_during_import"] = lookups
            results["import"] = {"seconds": round(seconds, 1), "per_second": round(args.import_size / seconds),
                                 "outcome": outcome}
    finally:
        server.terminate()
        server.wait(10)

    with open(os.path.join(data, f"results-{args.size}.json"), "w") as f:
        json.dump(results, f, indent=2)
    report(results)


def report(r):
    def line(name, label, target):
        s = r[name]
        verdict = "" if target is None else ("PASS" if s["p95"] is not None and s["p95"] < target else "FAIL")
        print(f"| {label:<34} | {s['p50']!s:>7} | {s['p95']!s:>7} | {s['p99']!s:>7} | "
              f"{s['per_second']:>8} | {'' if target is None else f'< {target}':>6} | {verdict:<4} |")

    print(f"\n{r['size']:,} indicators, {r['clients']} clients, Python {r['python']}, {r['cpus']} CPUs (ms)\n")
    print("| Test                               |     P50 |     P95 |     P99 |    req/s | Target | Result |")
    print("|---|---|---|---|---|---|---|")
    line("db_single", "Database lookup (in-process)", TARGETS["db_single"])
    line("http_single", "Single lookup", TARGETS["http_single"])
    line("http_batch_100", "Batch of 100", TARGETS["http_batch_100"])
    line("http_batch_1000", "Batch of 1,000", TARGETS["http_batch_1000"])
    idle = r["http_single"]["p95"]
    line("http_single_during_import", "Single lookup during import", round(idle * 2, 2))
    peak = max(r[k]["memory_peak_mb"] for k in ("http_single", "http_batch_100", "http_batch_1000",
                                                 "http_single_during_import"))
    print(f"\nMemory: {r['memory_idle_mb']} MB idle, {peak} MB peak (target < 500 MB at 5M)")
    print(f"Import: {r['import']['per_second']:,}/s over the API ({r['import']['seconds']}s); "
          f"outcome {json.dumps(r['import']['outcome'])[:200]}")
    errors = sum(r[k].get("errors", 0) for k in ("http_single", "http_batch_100", "http_batch_1000",
                                                  "http_single_during_import"))
    if errors:
        print(f"Errors: {errors} requests didn't return 200")


if __name__ == "__main__":
    asyncio.run(main())
