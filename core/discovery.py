"""Module 1 - host discovery and OS fingerprinting (methodology s3.5.2).

Liveness = responds to ping OR to a probed TCP port.
OS guess  = primarily default-TTL (Windows ~128, Unix ~64, net gear ~255);
            secondarily characteristic open ports. On one subnet no router
            decrements TTL, so 64 vs 128 is unambiguous.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from typing import Iterable

from .models import Host, OSFamily

WINDOWS_HINT_PORTS = (445, 3389, 5985, 5986)
UNIX_HINT_PORTS = (22,)


def tcp_port_open(ip: str, port: int, timeout: float = 0.6) -> bool:
    """Return True if a TCP connection to ip:port succeeds."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0


def ping_ttl(ip: str, timeout_ms: int = 800) -> int | None:
    """Ping once and parse the TTL from the OS ping output.

    Returns the TTL as an int, or None if no reply. Works by parsing the
    system ping tool, avoiding raw sockets / packet-capture drivers.
    """
    is_win = platform.system().lower().startswith("win")
    if is_win:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW",0),
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return None
    m = re.search(r"ttl[=|:]\s*(\d+)", out, re.IGNORECASE)
    return int(m.group(1)) if m else None


def os_from_ttl(ttl: int | None) -> OSFamily:
    if ttl is None:
        return OSFamily.UNKNOWN
    # Values are typically decremented slightly; bucket by nearest default.
    if ttl <= 64:
        return OSFamily.UNIX
    if ttl <= 128:
        return OSFamily.WINDOWS
    return OSFamily.UNKNOWN  # ~255 => likely network gear


def expand_targets(spec: str) -> list[str]:
    """Expand '192.168.1.0/24', '192.168.1.10-50', or a single IP to a list.

    Raises ValueError with a readable message if the input is malformed.
    """
    spec = spec.strip()
    if not spec:
        raise ValueError("No target entered.")

    try:
        # Case 1 - CIDR, e.g. "192.168.1.0/24"
        if "/" in spec:
            network = ipaddress.ip_network(spec, strict=False)
            return [str(ip) for ip in network.hosts()]

        # Case 2 - last-octet dash range, e.g. "192.168.1.10-20"
        if "-" in spec:
            base, end_str = spec.split("-", 1)
            octets = base.split(".")
            if len(octets) != 4:
                raise ValueError("Range must look like 192.168.1.10-20")
            start = int(octets[3])
            end = int(end_str)
            if not (0 <= start <= 255 and 0 <= end <= 255):
                raise ValueError("Octets must be 0-255")
            if end < start:
                raise ValueError("Range end is before its start")
            prefix = ".".join(octets[:3])
            # Validate the base is a real IP by constructing the first address.
            ipaddress.ip_address(f"{prefix}.{start}")
            return [f"{prefix}.{octet}" for octet in range(start, end + 1)]

        # Case 3 - single IP: validate it's genuinely an IP address.
        ipaddress.ip_address(spec)
        return [spec]

    except ValueError:
        raise                       # re-raise our own clear messages as-is
    except Exception:
        raise ValueError(f"'{spec}' is not a valid IP, range, or CIDR.")



def discover(targets: Iterable[str], progress=None) -> list[Host]:
    """Probe each target and return Host objects with liveness + OS guess.
 
    Liveness = a ping reply OR any hint port answering. OS guess combines the
    TTL read (primary) with open hint ports (corroboration) into a confidence
    of high / medium / low.
    """
    hosts: list[Host] = []
 
    for ip in targets:
        host = Host(ip=ip)
 
        # 1. Ping for a TTL.
        ttl = ping_ttl(ip)
 
        # 2. Probe the hint ports (which ones are open?).
        win_ports_open = [p for p in WINDOWS_HINT_PORTS if tcp_port_open(ip, p)]
        nix_ports_open = [p for p in UNIX_HINT_PORTS if tcp_port_open(ip, p)]
 
        # 3. Liveness: up if we got a TTL OR any port answered.
        host.is_up = (ttl is not None) or bool(win_ports_open or nix_ports_open)
 
        # 4. If it's not up, skip fingerprinting.
        if not host.is_up:
            hosts.append(host)
            continue
 
        # 5. Fingerprint: combine TTL (primary) with hint ports (corroboration).
        ttl_guess = os_from_ttl(ttl)
 
        if win_ports_open and not nix_ports_open:
            port_guess = OSFamily.WINDOWS
        elif nix_ports_open and not win_ports_open:
            port_guess = OSFamily.UNIX
        else:
            port_guess = OSFamily.UNKNOWN  # none open, or both (ambiguous)
 
        if ttl_guess is not OSFamily.UNKNOWN and ttl_guess == port_guess:
            host.os_guess = ttl_guess
            host.confidence = "high"      # TTL and a port agree
        elif ttl_guess is not OSFamily.UNKNOWN and port_guess is OSFamily.UNKNOWN:
            host.os_guess = ttl_guess
            host.confidence = "medium"    # TTL only, nothing to corroborate
        elif ttl_guess is OSFamily.UNKNOWN and port_guess is not OSFamily.UNKNOWN:
            host.os_guess = port_guess
            host.confidence = "low"       # ports only, no usable TTL
        elif ttl_guess is not OSFamily.UNKNOWN and port_guess is not OSFamily.UNKNOWN:
            host.os_guess = ttl_guess     # signals conflict; keep TTL, flag doubt
            host.confidence = "low"
        else:
            host.os_guess = OSFamily.UNKNOWN
            host.confidence = "low"
 
        # Human-readable reason, for the results table and the log.
        parts = []
        if ttl is not None:
            parts.append(f"TTL {ttl}")
        if win_ports_open:
            parts.append("win ports " + ",".join(str(p) for p in win_ports_open))
        if nix_ports_open:
            parts.append("ssh " + ",".join(str(p) for p in nix_ports_open))
        host.fingerprint_basis = ", ".join(parts) if parts else "no signal"
 
        hosts.append(host)
        if progress:
            progress(host)
        
 
    return hosts
