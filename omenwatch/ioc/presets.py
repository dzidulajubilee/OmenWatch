"""
Known public lists that the plain text and CSV formats already read, offered
as one-click starting points in Settings, IOC feeds ("Start from").

A preset only fills in the form: name, URL, format, type, CSV column,
interval and so on. Nothing is added until the person tests and saves it,
and every field can still be changed. The built-in readers (readers.py) are
offered in the same list.

Each one was checked against parse_list() in November 2026. Lists change:
the Test button in the form is the real check. Check each publisher's terms
before relying on its data, especially for commercial use.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Preset:
    name: str
    label: str
    url: str
    gives: str                  # what the list holds, shown in the form
    format: str = "text"        # "text" or "csv"
    default_type: str = ""      # "" lets each value's type be detected
    value_column: str = ""
    interval: int = 21600
    snapshot: bool = True       # these lists are current state: a value that drops off has gone
    confidence: int = 75
    threat_type: str = ""
    terms_url: str = ""
    group: str = "Lists"        # "Lists" or "Use with care"

    def describe(self) -> dict:
        return {k: getattr(self, k) for k in (
            "name", "label", "url", "gives", "format", "default_type", "value_column", "interval",
            "snapshot", "confidence", "threat_type", "terms_url", "group")}


CAREFUL = "Use with care"

PRESETS: dict[str, Preset] = {p.name: p for p in (
    Preset("c2intel-ips", "C2IntelFeeds: C2 IPs (30 days)",
           "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
           "Command-and-control server IPs (Cobalt Strike and others) seen in the last 30 days, about 200",
           format="csv", default_type="ipv4", value_column="ip", interval=21600, confidence=80,
           threat_type="c2", terms_url="https://github.com/drb-ra/C2IntelFeeds"),
    Preset("c2intel-domains", "C2IntelFeeds: C2 domains (30 days)",
           "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv",
           "Command-and-control domains from the last 30 days, with abused shared services filtered out, under 100",
           format="csv", default_type="domain", value_column="domain", interval=21600, confidence=80,
           threat_type="c2", terms_url="https://github.com/drb-ra/C2IntelFeeds"),
    Preset("threatview-cobaltstrike", "ThreatView: Cobalt Strike C2",
           "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt",
           "Cobalt Strike team servers, IPs and a few domains, about 1,200",
           format="csv", value_column="IP", interval=43200, confidence=80,
           threat_type="c2", terms_url="https://threatview.io/"),
    Preset("openphish", "OpenPhish (free feed)", "https://openphish.com/feed.txt",
           "Phishing URLs seen recently, about 300 at a time",
           default_type="url", interval=21600, confidence=75,
           threat_type="phishing", terms_url="https://openphish.com/"),
    Preset("et-compromised", "Emerging Threats: compromised IPs",
           "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
           "Hosts Proofpoint's Emerging Threats team sees as compromised, about 600",
           default_type="ipv4", interval=43200, confidence=70,
           threat_type="compromised", terms_url="https://rules.emergingthreats.net/"),
    Preset("threatview-ips", "ThreatView: high-confidence IPs",
           "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt",
           "Malicious IPs ThreatView rates high confidence, about 14,000",
           default_type="ipv4", interval=86400, confidence=65,
           threat_type="malicious", terms_url="https://threatview.io/"),
    Preset("ipsum-3", "IPsum, level 3",
           "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
           "IPs on at least 3 public blocklists, about 18,000. Levels 4 to 8 in the URL give fewer, surer IPs",
           default_type="ipv4", interval=86400, confidence=60,
           threat_type="malicious", terms_url="https://github.com/stamparm/ipsum"),
    Preset("botvrij-sha256", "Botvrij.eu: SHA-256",
           "https://www.botvrij.eu/data/ioclist.sha256.raw",
           "SHA-256 hashes from Botvrij.eu's public reports, a small list",
           default_type="sha256", interval=86400, confidence=70,
           threat_type="payload", terms_url="https://www.botvrij.eu/"),
    Preset("cins-army", "CINS Army: bad IPs", "https://cinsscore.com/list/ci-badguys.txt",
           "About 15,000 IPs, mostly scanners and brute-force sources: context for a SIEM, rarely a sign of compromise",
           default_type="ipv4", interval=86400, confidence=40,
           threat_type="scanner", terms_url="https://cinsscore.com/", group=CAREFUL),
    Preset("blocklist-de", "blocklist.de: all attackers", "https://lists.blocklist.de/lists/all.txt",
           "About 20,000 IPv4 and IPv6 addresses reported for brute force and spam: context, rarely a sign of compromise",
           interval=86400, confidence=40,
           threat_type="abuse", terms_url="https://www.blocklist.de/en/index.html", group=CAREFUL),
    Preset("tor-exits", "Tor exit nodes", "https://check.torproject.org/torbulkexitlist",
           "The current Tor exit relays, about 1,200. Not malicious: shows traffic that came through Tor",
           default_type="ipv4", interval=21600, confidence=20,
           threat_type="tor_exit", terms_url="https://check.torproject.org/", group=CAREFUL),
)}
