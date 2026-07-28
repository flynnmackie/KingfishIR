"""Non-secret app configuration (external tool paths).

Paths only - Not credentials.
"""
from __future__ import annotations

import json
from pathlib import Path

CONFIG_PATH = Path("config.json")


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except Exception:
            return {}
    return {}


def save_config(data: dict) -> None:
    CONFIG_PATH.write_text(json.dumps(data, indent=2))

def save_profiles(skeletons: list[dict]) -> None:
    """Persist profile skeletons (NO secrets - NFR4). Paths+metadata only."""
    data = load_config()
    data["profiles"] = skeletons
    save_config(data)


def load_profiles() -> list[dict]:
    return load_config().get("profiles", [])