"""Launch an interactive shell to a host in a new terminal window.

Windows (WinRM/PSSession): auto-adds the host to TrustedHosts (shown, elevates
if needed) and auto-authenticates via a PSCredential built from a password passed
in the environment (not the command line - avoids process-list leakage).
Unix (SSH): launches ssh; the user types their password (ssh resists non-
interactive password auth by design).
Assumes a Windows controller.
"""
from __future__ import annotations
import os
import subprocess

from core.models import OSFamily


def open_shell(host, profile, audit=None):
    """Open an interactive terminal to the host. Returns (ok, message)."""
    user = profile.username
    if profile.domain:
        user = f"{profile.domain}\\{user}"

    if host.actual_os is OSFamily.UNIX:
        # ssh in a new window; ssh prompts for the password (by design)
        cmd = f'start "SSH {host.ip}" cmd /k ssh {user}@{host.ip}'
        try:
            subprocess.Popen(cmd, shell=True)
            if audit:
                audit.log(host.ip, "shell opened", outcome="ok",
                          detail="interactive SSH shell launched (password prompt)")
            return True, "SSH shell launched"
        except Exception as exc:
            if audit:
                audit.log(host.ip, "shell", outcome="error", detail=str(exc))
            return False, str(exc)

    # ---- Windows: TrustedHosts add (shown+elevated) + env-var credential ----
    # Build a PowerShell script that: shows & adds TrustedHosts (self-elevating if
    # needed), then builds a credential from the env-var password and connects.
    pw_env = "RTC_SHELL_PW"
    ps_lines = [
        "$ErrorActionPreference = 'Stop'",
        # show what we're about to do
        f"Write-Host 'Adding {host.ip} to TrustedHosts...' -ForegroundColor Cyan",
        # test if we can write TrustedHosts; if not, self-elevate just for that step
        "try {",
        f"  Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '{host.ip}' -Concatenate -Force",
        "} catch {",
        "  Write-Host 'Elevating to update TrustedHosts...' -ForegroundColor Yellow",
        f"  Start-Process powershell -Verb RunAs -Wait -ArgumentList '-Command',"
        f"\"Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value '{host.ip}' -Concatenate -Force\"",
        "}",
        # build credential from the env-var password (not the command line)
        f"$pw = ConvertTo-SecureString $env:{pw_env} -AsPlainText -Force",
        f"$cred = New-Object System.Management.Automation.PSCredential('{user}', $pw)",
        f"Remove-Item Env:\\{pw_env} -ErrorAction SilentlyContinue",   # scrub the env var
        f"Write-Host 'Connecting to {host.ip}...' -ForegroundColor Cyan",
        f"Enter-PSSession -ComputerName {host.ip} -Credential $cred -Authentication Negotiate",
    ]
    ps_script = "; ".join(ps_lines)

    # pass the password via the child process ENVIRONMENT, not the command line
    child_env = dict(os.environ)
    child_env[pw_env] = profile.secret or ""

    cmd = f'start "PSSession {host.ip}" powershell -NoExit -Command "{ps_script}"'
    try:
        subprocess.Popen(cmd, shell=True, env=child_env)
        if audit:
            audit.log(host.ip, "shell opened", outcome="ok",
                      detail=f"interactive PSSession launched; {host.ip} added to TrustedHosts")
        return True, "PSSession shell launched"
    except Exception as exc:
        if audit:
            audit.log(host.ip, "shell", outcome="error", detail=str(exc))
        return False, str(exc)