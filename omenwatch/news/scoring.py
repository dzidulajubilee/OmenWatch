"""
The wording rating: High, Medium or Low, from what an article says. It is a
fast first sort for a person reading the feed, not CVSS or EPSS.

2.0.1 rules, after "one word anywhere on the page makes it High" turned
most articles High:

  - Only the title, the feed summary and the opening of the article are
    rated (LEDE_CHARS). The rest of the page, and any menus or "related
    stories" that survived extraction, still feed indicator extraction but
    never the rating.
  - High is kept for things to act on: exploitation (URGENT), or a serious
    flaw (SERIOUS) in an article that names a CVE. Topic words such as
    ransomware, malware, breach or APT describe what an article is about,
    not how urgent it is, so they rate Medium at most.
  - The title weighs more than the text. A phrase in the title scores 2,
    each mention in the summary or opening scores 1, and High needs 2. So
    one passing mention in the text is Medium, while the title, or two
    mentions, make it High.

Matching rules, so the lists stay plain phrases:
  - a keyword must not be glued to a letter/digit on its left;
  - on its right it may take a plain plural/past suffix (s, es, ed), so
    "breach" still covers "breaches"/"breached" and "zero-day" covers
    "zero-days";
  - a keyword ending in "-" is a prefix ("cve-" matches "CVE-2026-1234").
"""
import re

LEDE_CHARS = 1500  # how much of the article body counts towards the rating

URGENT = [
    "zero-day", "0-day",
    "exploited in the wild", "actively exploited", "under active exploitation",
]

# Serious only when the article names a CVE: "critical flaw" in a story
# with no CVE is usually commentary, not something to patch.
SERIOUS = [
    "rce", "remote code execution",
    "critical vulnerability", "critical flaw", "critical bug", "critical severity", "critical-severity",
    "critical security flaw", "critical security vulnerability", "critical security bug",
]

KEYWORDS_MEDIUM = [
    "cve-", "vulnerability", "vulnerabilities", "ransomware", "apt", "breach", "malware",
    "phishing", "backdoor", "supply chain", "data leak",
]

# Kept for anything that imported the old name.
KEYWORDS_HIGH = URGENT + SERIOUS

HIGH_POINTS = 2


def _keyword_pattern(keywords: list[str]) -> re.Pattern:
    parts = []
    for k in keywords:
        body = re.escape(k.lower())
        tail = "" if k.endswith("-") else r"(?:s|es|ed)?(?![a-z0-9])"
        parts.append(rf"(?<![a-z0-9]){body}{tail}")
    return re.compile("|".join(parts))


_URGENT = _keyword_pattern(URGENT)
_SERIOUS = _keyword_pattern(SERIOUS)
_MEDIUM = _keyword_pattern(KEYWORDS_MEDIUM)
_CVE = re.compile(r"(?<![a-z0-9])cve-\d{4}-\d{4,}", re.I)


def _points(pattern: re.Pattern, title: str, text: str) -> tuple[int, str]:
    """Title hit = 2 points, each text mention = 1; returns (points, first phrase found)."""
    title_hit = pattern.search(title)
    text_hits = pattern.findall(text)
    phrase = title_hit.group(0) if title_hit else (text_hits[0] if text_hits else "")
    return (HIGH_POINTS if title_hit else 0) + len(text_hits), phrase


def score_severity_detail(title: str, summary: str, body: str = "", has_cve: bool | None = None) -> tuple[str, str]:
    """
    The wording rating and the phrase that decided it, e.g. ("high",
    "zero-days") or ("low", ""). The phrase is shown to people as part of
    the reason for an item's priority.

    `summary` is the feed's teaser and `body` the full article text, when
    it was fetched. `has_cve` says whether the article names a CVE
    anywhere; left as None it is worked out from all of the text.
    """
    title = title.lower()
    text = f"{summary} {body[:LEDE_CHARS]}".lower()
    if has_cve is None:
        has_cve = bool(_CVE.search(f"{title} {summary} {body}"))

    urgent, urgent_phrase = _points(_URGENT, title, text)
    serious, serious_phrase = _points(_SERIOUS, title, text)
    if not has_cve:
        serious = 0
    if urgent + serious >= HIGH_POINTS:
        return "high", urgent_phrase or serious_phrase
    if urgent_phrase or serious_phrase:
        return "medium", urgent_phrase or serious_phrase

    match = _MEDIUM.search(title) or _MEDIUM.search(text)
    if match:
        return "medium", match.group(0)
    if has_cve:  # names a CVE further down, e.g. a patch roundup
        return "medium", ""
    return "low", ""


def score_severity(title: str, summary: str, body: str = "") -> str:
    return score_severity_detail(title, summary, body)[0]
