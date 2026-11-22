"""
The service's log. Messages go to stderr, which systemd sends to the journal
(journalctl -u omenwatch), so no timestamps here: the journal adds them.
"""
import logging
import sys

_ROOT = "omenwatch"


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"{_ROOT}.{name}")


def setup(level: int = logging.INFO) -> None:
    """Once, when the service starts. uvicorn configures only its own loggers."""
    root = logging.getLogger(_ROOT)
    if root.handlers:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False
