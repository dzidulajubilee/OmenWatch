"""
OmenWatch — threat intelligence RSS feed aggregator.

Deliberately does NOT import `omenwatch.app` here. Doing so would make
every `import omenwatch.<anything>` eagerly construct the FastAPI app
(mounting static files, registering routes) as a side effect, which is
unwanted for lightweight uses like `from omenwatch.news.scoring
import score_severity` in a script or test. Import `omenwatch.app` (or
just run `uvicorn omenwatch.app:app`) explicitly when you actually want
the app.
"""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("omenwatch")
except PackageNotFoundError:
    # Not pip-installed (e.g. running via PYTHONPATH=. in dev without
    # `pip install -e .`) — see pyproject.toml for the real version.
    __version__ = "0.0.0-dev"