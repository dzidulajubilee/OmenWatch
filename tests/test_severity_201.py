"""
2.0.1 severity rules: rate the article not the page, High only for things to
act on, title weighs more, CISA's list counts only when the article is about
the CVE, and `rescore` shows the change before writing it.
"""
import pytest

from omenwatch.database.sqlite import get_db
from omenwatch.ingestion.article_fetcher import html_to_text
from omenwatch.news.priority import explain_priority, exploited_counts
from omenwatch.news.rescore import rescore
from omenwatch.news.scoring import LEDE_CHARS, score_severity_detail

FILLER = "The company published a statement about the quarter. " * 60


# --- 1. Rate the article, not the page ---

def test_words_past_the_opening_do_not_rate():
    body = FILLER + " Actively exploited zero-day ransomware."
    assert len(FILLER) > LEDE_CHARS
    assert score_severity_detail("Company results", "Quarterly figures", body) == ("low", "")


def test_opening_of_the_body_still_rates():
    body = "Attackers are actively exploited the flaw; this zero-day hits gateways. " + FILLER
    assert score_severity_detail("Gateway advisory", "", body)[0] == "high"


ARTICLE_PAGE = """<html><body>
<div class="site-menu"><a>Ransomware</a><a>Zero-Day</a></div>
<div class="with-sidebar"><article><h1>Botnet taken down</h1><p>{story}</p></article>
<aside><h3>Related</h3><a>Actively exploited zero-day in VPN</a></aside></div>
<section class="related-posts"><a>Ransomware gang leaks data</a></section>
<div class="tags">ransomware malware</div>
</body></html>"""


def test_page_furniture_is_left_out():
    story = "Police and technology firms dismantled a botnet of streaming boxes. " * 5
    text = html_to_text(ARTICLE_PAGE.format(story=story))
    assert "dismantled a botnet" in text
    for furniture in ("Ransomware", "Zero-Day", "Actively exploited", "malware"):
        assert furniture.lower() not in text.lower()


def test_layout_class_on_a_wrapper_does_not_hide_the_page():
    story = "A long story about a patched router and what changed in it. " * 6
    page = f'<html><body><div class="page with-sidebar"><div><p>{story}</p></div></div></body></html>'
    assert "patched router" in html_to_text(page)


def test_short_article_card_falls_back_to_the_page():
    page = "<html><body><article><a>Teaser</a></article><div><p>" + "Main story text here. " * 20 + "</p></div></body></html>"
    assert "Main story text" in html_to_text(page)


# --- 2. High only for things to act on ---

@pytest.mark.parametrize("title", [
    "Who runs the ransomware group?",
    "CTO of a ransomware help desk indicted",
    "Malware campaign targets retailers",
    "Data breach at a hotel chain",
    "APT group phishing diplomats",
])
def test_topic_words_rate_medium_at_most(title):
    assert score_severity_detail(title, "")[0] == "medium"


def test_serious_flaw_needs_a_cve():
    assert score_severity_detail("Remote code execution in mail server", "")[0] == "medium"
    assert score_severity_detail("Remote code execution in mail server", "Tracked as CVE-2099-1001")[0] == "high"
    assert score_severity_detail("Remote code execution in mail server", "", has_cve=True)[0] == "high"


# --- 3. The title weighs more than the text ---

def test_title_alone_is_enough():
    assert score_severity_detail("Zero-day in VPN appliance", "") == ("high", "zero-day")


def test_one_mention_in_the_text_is_medium():
    assert score_severity_detail("Vendor ships update", "It fixes a zero-day.")[0] == "medium"


def test_two_mentions_in_the_text_are_high():
    assert score_severity_detail("Vendor ships update", "It fixes a zero-day that is actively exploited.")[0] == "high"


# --- 4. CISA's list counts when the article is about the CVE ---

def test_exploited_counts_for_a_focused_article():
    assert exploited_counts("Patch now", "CVE-2099-1", "CVE-2099-1")
    assert exploited_counts("Patch now", ["CVE-2099-1", "CVE-2099-2", "CVE-2099-3"], ["CVE-2099-2"])


def test_exploited_ignored_in_a_roundup_unless_in_the_title():
    many = ",".join(f"CVE-2099-{n}" for n in range(1, 60))
    assert not exploited_counts("Patch Tuesday fixes 59 flaws", many, "CVE-2099-7")
    assert exploited_counts("Patch CVE-2099-7 now, and 58 others", many, "CVE-2099-7")
    assert not exploited_counts("Anything", many, "")


def test_reason_says_when_the_list_did_not_count():
    reasons = explain_priority("medium", "vulnerabilities", [], ["CVE-2099-7"], exploited=False, cve_count=59)
    assert reasons[0] == "Mentions CVE-2099-7 from CISA's list, among 59 CVEs"


# --- 5. Dry run first, then apply ---

async def _seed(db):
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'Example News', 'http://x.example/feed', 'news')")
    rows = [
        ("a", "Who runs the ransomware group?", "A profile.", "", ""),
        ("b", "Zero-day in VPN appliance", "Patch now.", "", ""),
        ("c", "Patch Tuesday fixes 59 flaws", "Monthly fixes.", ",".join(f"CVE-2099-{n}" for n in range(1, 60)), "CVE-2099-7"),
    ]
    for item_id, title, summary, cves, kev in rows:
        await db.execute(
            """INSERT INTO items (id, source_id, title, summary, guid, fetched_at, severity, content_severity,
                                 content_keyword, cves, kev_cves, watch_hits)
               VALUES (?, 's1', ?, ?, ?, 1000, 'high', 'high', 'x', ?, ?, '')""",
            (item_id, title, summary, item_id, cves, kev),
        )
    await db.commit()


async def test_rescore_dry_run_writes_nothing(fresh_db):
    db = await get_db()
    await _seed(db)
    result = await rescore(db)
    cur = await db.execute("SELECT COUNT(*) FROM items WHERE severity = 'high'")
    still_high = (await cur.fetchone())[0]
    await db.close()
    assert result["before"]["high"] == 3
    assert result["after"] == {"critical": 0, "high": 1, "medium": 2, "low": 0}
    assert result["changed"] == 2 and not result["applied"]
    assert {m["title"] for m in result["lowered"]} == {"Who runs the ransomware group?", "Patch Tuesday fixes 59 flaws"}
    assert still_high == 3


async def test_rescore_apply_saves(fresh_db):
    db = await get_db()
    await _seed(db)
    await rescore(db, apply=True)
    cur = await db.execute("SELECT id, severity, content_keyword FROM items ORDER BY id")
    rows = [tuple(r) for r in await cur.fetchall()]
    await db.close()
    assert rows == [("a", "medium", "ransomware"), ("b", "high", "zero-day"), ("c", "medium", "")]
