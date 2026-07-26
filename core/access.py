"""Module 2 - remote-access verification (methodology s3.5.3).

For each host, using its assigned credential profile, built the right transport
and record a three-state result on the Host (winrm_state / ssh_state). Confirmed
the OS guess here: successful WinRM auth => actual_os = WINDOWS, successful SSH
=> UNIX.
"""

from __future__ import annotations

from .audit import AuditLog
from .credentials import CredentialStore
from .models import AccessState, CredKind, Host, OSFamily
from transports.ssh_transport import SSHTransport
from transports.winrm_transport import WinRMTransport

_STATE_TEXT = {
    AccessState.ABSENT: "no service listening (absent)",
    AccessState.PRESENT_NO_AUTH: "service present, credentials rejected",
    AccessState.AUTHENTICATED: "authenticated",
}


def verify_host(host: Host, store: CredentialStore, audit: AuditLog | None = None) -> Host:
    """Test the appropriate channel for `host` and update its state fields."""
    # 1. Find the credential profile assigned to this host.
    profile = store.get(host.profile_name) if host.profile_name else None
    if profile is None:
        if audit:
            hn = f", hostname={host.hostname}" if host.hostname else ""
            audit.log(host.ip, "verify",
                      outcome=f"{channel}: {_STATE_TEXT[state]}",
                      detail=f"profile={profile.name}, mechanism={profile.kind.value}{hn}")

    # 2. Choose the transport based on the credential kind.
    if profile.kind in (CredKind.SSH_KEY, CredKind.SSH_PASSWORD):
        transport = SSHTransport(host.ip, profile)
        channel = "ssh"
    else:  # DOMAIN_KERBEROS / LOCAL_NTLM  (WinRM path - built next)
        transport = WinRMTransport(host.ip, profile)
        channel = "winrm"

    # 3. Test access and record the three-state result on the right field.
    state = transport.test_access()
    if channel == "ssh":
        host.ssh_state = state
    else:
        host.winrm_state = state

    # 4. A successful auth CONFIRMS the OS family (turns the guess into fact).
    if state is AccessState.AUTHENTICATED:
        host.hostname = getattr(transport, "hostname", None)
        host.actual_os = OSFamily.UNIX if channel == "ssh" else OSFamily.WINDOWS

    # 5. Log the outcome - mechanism and result, never the secret (NFR2/NFR4).
    if audit:
        audit.log(
            host.ip,
            "verify",
            outcome=f"{channel}: {_STATE_TEXT[state]}",
            detail=f"profile={profile.name}, mechanism={profile.kind.value}",
        )

    transport.close()
    return host