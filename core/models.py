"""Shared data models for the remote triage tool.

These types are passed between the three core modules (discovery -> access ->
collection) and the GUI. Keeping them here decouples the modules from each
other and from the interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class OSFamily(Enum):
    WINDOWS = "windows"
    UNIX = "unix"
    UNKNOWN = "unknown"


class AccessState(Enum):
    """Three-state channel status (see methodology s3.5.3)."""
    ABSENT = "absent"                 # no WinRM/SSH service listening
    PRESENT_NO_AUTH = "present"       # service present, credentials not accepted
    AUTHENTICATED = "authenticated"   # usable session established


class CredKind(Enum):
    DOMAIN_KERBEROS = "domain_kerberos"
    LOCAL_NTLM = "local_ntlm"
    SSH_KEY = "ssh_key"
    SSH_PASSWORD = "ssh_password"


@dataclass
class Host:
    ip: str
    hostname: Optional[str] = None
    is_up: bool = False
    os_guess: OSFamily = OSFamily.UNKNOWN
    confidence: str = "unknown"          # e.g. "high" / "medium" / "low"
    fingerprint_basis: str = ""          # e.g. "TTL 128, 445 open"
    actual_os: Optional[OSFamily] = None  # confirmed at authentication
    winrm_state: AccessState = AccessState.ABSENT
    ssh_state: AccessState = AccessState.ABSENT
    profile_name: Optional[str] = None   # assigned credential profile
    last_scanned: str = ""
    last_verified: str = ""
    verified_this_session: bool = False    # runtime only - never persisted


@dataclass
class CredentialProfile:
    """A reusable credential set assigned to hosts or groups.

    The secret is held in memory only and must never be written to disk or
    into the audit log (NFR2/NFR4).
    """
    name: str
    kind: CredKind
    username: str
    secret: str = field(repr=False, default="")  # password or key path; repr hidden
    domain: Optional[str] = None
    sudo_secret: str = field(repr=False, default="")  # optional; falls back to `secret`


@dataclass
class Artefact:
    """A collectable artefact definition from the catalogue (core/artefacts.py)."""
    id: str
    name: str
    category: str
    os_family: OSFamily
    volatility: int          # higher = more volatile; collection sorts desc
    spec: str                # command to run, or remote path to copy
    is_command: bool = True  # True => run command; False => fetch file/path
    prepare: str | None = None   # optional command that produces an unlocked copy at `spec`
    is_archive: bool = False     # if True, fetched file is a zip to unpack locally into the category folder
    requires_sudo: bool = False
    output_ext: str = "txt"  # if True (Unix), run this artefact's prepare/command via sudo -S

@dataclass
class CollectionResult:
    host_ip: str
    artefact_id: str
    collected: bool = False
    source_hash: Optional[str] = None
    received_hash: Optional[str] = None
    output_path: Optional[str] = None
    error: Optional[str] = None

    @property
    def hash_match(self) -> Optional[bool]:
        if self.source_hash is None or self.received_hash is None:
            return None
        return self.source_hash.lower() == self.received_hash.lower()
