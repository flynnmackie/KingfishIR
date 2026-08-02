"""Centralised path resolution - works both as a script and as a packaged exe.

- Tool state (config, hosts) lives in %APPDATA%\\KingfishIR on Windows
  (a stable per-user location that survives moving the exe).

- Evidence output (collected/launched/audits) uses a user-set output root when
  configured and valid, otherwise falls back to the app-data dir.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "KingfishIR"


def app_data_dir() -> Path:
    """Per-user writable dir for the tool's own state. Created if missing."""
    base = os.environ.get("APPDATA")            # Windows: C:\\Users\\<u>\\AppData\\Roaming
    if not base:                                 # non-Windows fallback
        base = os.path.expanduser("~/.config")
    d = Path(base) / APP_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def resource_path(name: str) -> str:
    """Absolute path to a bundled read-only resource (image/icon)."""
    if getattr(sys, "frozen", False):            # packaged exe
        base = Path(getattr(sys, "_MEIPASS", "."))
    else:                                         # running from source
        base = Path(__file__).resolve().parent.parent    # project root
    return str(base / name)


def config_path() -> Path:
    return app_data_dir() / "config.json"


def hosts_path() -> Path:
    return app_data_dir() / "hosts.json"


def output_root() -> Path:
    """Where evidence output goes: the user-set root if configured, else the
    app-data dir. Does NOT validate here - callers validate before writing so
    they can fail loudly on an inaccessible evidence location.
    """
    try:
        from core.config import load_config
        root = (load_config().get("output_root") or "").strip()
    except Exception:
        root = ""
    return Path(root) if root else app_data_dir()

def output_base() -> Path:
    """The KingfishIR output parent - wraps collected/launched/audits under a
    named folder for attribution, inside the output root (user-set or default).
    """
    return output_root() / "kingfishir_output"

def audit_path(filename: str) -> Path:
    """Audit CSVs sit flat in the app-data dir - a stable, consistent location
    for the chain-of-custody record, separate from the evidence output tree.
    """
    return app_data_dir() / filename