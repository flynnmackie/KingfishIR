"""Common transport interface.

Both the WinRM and SSH transports implement this, so collection.py can dispatch
to a host without caring which protocol is underneath. This abstraction is a
deliberate design decision worth noting in Chapter 4.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import AccessState, CredentialProfile


class Transport(ABC):
    def __init__(self, host_ip: str, profile: CredentialProfile, audit=None):
        self.host_ip = host_ip
        self.profile = profile
        self.audit = audit

    def _log_command(self, command: str, use_sudo: bool = False, show_sudo: bool = True):
        """Record every remote command for command-level chain of custody."""
        if getattr(self, "audit", None) is not None:
            prefix = f"[sudo={'yes' if use_sudo else 'no'}] " if show_sudo else ""
            self.audit.log(
                self.host_ip, "remote command", outcome="ok",
                detail=f"{prefix}{command}")

    @abstractmethod
    def test_access(self) -> AccessState:
        """Return ABSENT / PRESENT_NO_AUTH / AUTHENTICATED for this host."""

    @abstractmethod
    def run_command(self, command: str) -> bytes:
        """Execute a command on the target and return its raw output."""

    @abstractmethod
    def fetch_file(self, remote_path: str) -> bytes:
        """Retrieve a file's bytes from the target."""

    @abstractmethod
    def remote_hash(self, remote_path: str) -> str | None:
        """Compute a SHA-256 hash of a file ON the target, if feasible.

        Hashing at source (NFR1) lets us compare against the received hash.
        Return None if the target cannot hash in place and you must hash only
        on receipt (note this limitation in the evaluation).
        """

    def close(self) -> None:  # optional override
        pass
