"""In-memory credential profile store.

Profiles are created by the operator (Tab 2) and assigned to hosts/groups.
Secrets live only for the lifetime of the process and are never persisted
(NFR4). Do not add save()/load() that writes secrets to disk.
"""

from __future__ import annotations

from .models import CredentialProfile


class CredentialStore:
    def __init__(self) -> None:
        self._profiles: dict[str, CredentialProfile] = {}

    def add(self, profile: CredentialProfile) -> None:
        self._profiles[profile.name] = profile

    def remove(self, name: str) -> None:
        self._profiles.pop(name, None)

    def get(self, name: str) -> CredentialProfile | None:
        return self._profiles.get(name)

    def names(self) -> list[str]:
        return list(self._profiles)

    def clear(self) -> None:
        """Wipe all profiles (e.g. on exit)."""
        self._profiles.clear()
