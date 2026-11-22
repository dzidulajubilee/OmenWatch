from omenwatch.feeds.parser import domain_from_url, normalize_entry
from omenwatch.feeds.rss import FeedFetchError, fetch_raw

# NOTE: Scheduler is deliberately NOT re-exported here. It depends on
# omenwatch.connectors.registry, which depends on omenwatch.connectors.rss,
# which depends on omenwatch.feeds.parser — importing Scheduler at this
# package's top level would re-trigger this very __init__.py mid-import
# and cause a circular import. Import it directly where needed:
#     from omenwatch.feeds.scheduler import Scheduler
# (this is exactly what omenwatch/app.py does).

__all__ = ["FeedFetchError", "fetch_raw", "normalize_entry", "domain_from_url"]