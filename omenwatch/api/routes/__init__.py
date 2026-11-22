"""
The dashboard's HTTP routes, one module per area. Importing this package
registers every route on the shared routers in omenwatch.api.dependencies.
"""
from omenwatch.api.dependencies import auth_router, protected_router, router
from omenwatch.api.routes import alerts, auth, ioc, live, news, siem, sources, system, watchlist  # noqa: F401 (registers routes)
from omenwatch.api.routes.live import broadcast
from omenwatch.api.routes.sources import make_poll_now_route

__all__ = ["auth_router", "broadcast", "make_poll_now_route", "protected_router", "router"]
