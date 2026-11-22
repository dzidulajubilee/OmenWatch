"""
Everything OmenWatch reads from its environment, in one place.

The packaged service sets OMENWATCH_DB and OMENWATCH_PORT (omenwatch.service);
the others are for development, tests and unusual installs. Paths are read
once, at import, so set them before importing OmenWatch.
"""
import os
import pathlib

# Where the code is: /opt/omenwatch in the package, the repository in development.
APP_ROOT = pathlib.Path(__file__).resolve().parents[2]

DB_PATH = os.environ.get("OMENWATCH_DB", "/var/lib/omenwatch/omenwatch.db")
# The IOC database lives next to the dashboard's own database by default.
IOC_DB_PATH = os.environ.get("OMENWATCH_IOC_DB", os.path.join(os.path.dirname(os.path.abspath(DB_PATH)), "ioc.db"))
ICON_CACHE_DIR = os.environ.get("OMENWATCH_ICON_CACHE", os.path.join(os.path.dirname(DB_PATH), "icons"))
# Optional starter list of feeds. Ships empty, so no source ever appears that
# the user didn't add.
FEEDS_CONFIG_PATH = os.environ.get("OMENWATCH_FEEDS_CONFIG", str(APP_ROOT / "config" / "feeds.json"))


def port() -> str:
    """The port the service listens on (the HTTPS setup puts nginx in front of it)."""
    return os.environ.get("OMENWATCH_PORT", "7373")


def open_dashboard() -> bool:
    """OMENWATCH_OPEN_DASHBOARD=1 turns sign-in off, for installs behind an
    authenticating proxy. Read on every call, so tests can switch it."""
    return os.environ.get("OMENWATCH_OPEN_DASHBOARD", "") == "1"
