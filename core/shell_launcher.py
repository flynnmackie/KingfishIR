"""Launch an interactive shell to a host in a new terminal window.

Windows (WinRM/PSSession): adds the host to TrustedHosts (elevated, UAC prompt)
as its own step, then launches a PSSession that auto-authenticates via a
PSCredential built from a password passed in the environment (not the command
line - avoids process-list leakage).
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

    # ================= UNIX / SSH =================
    if host.actual_os is OSFamily.UNIX:
        cmd = f'start "SSH {host.ip}" cmd /k ssh {user}@{host.ip}'
        try:
            subprocess.Popen(cmd, shell=True)
            if audit:
                audit.log(host.ip, "shell opened", outcome="ok",
                          detail=f"logged in via tool's shell (SSH) as {user}")
            return True, "SSH shell launched"
        except Exception as exc:
            if audit:
                audit.log(host.ip, "shell", outcome="error", detail=str(exc))
            return False, str(exc)

    # ================= WINDOWS / WinRM (PSSession) =================
    # Step 1: add the host to TrustedHosts, elevated (its own process so the
    # nested quoting stays simple). -Verb RunAs triggers a UAC prompt; -Wait so
    # it completes before we try to connect.
    th_cmd = (f'Set-Item WSMan:\\localhost\\Client\\TrustedHosts '
              f'-Value \\"{host.ip}\\" -Concatenate -Force')
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Start-Process powershell -Verb RunAs -Wait "
             f"-ArgumentList '-NoProfile','-Command','{th_cmd}'"],
            check=False)
        if audit:
            audit.log(host.ip, "trustedhosts edit", outcome="ok",
                      detail=f"added {host.ip} to TrustedHosts")
    except Exception as exc:
        if audit:
            audit.log(host.ip, "trustedhosts edit", outcome="error", detail=str(exc))

    # Step 2: launch the interactive PSSession window. The password is passed via
    # the child process ENVIRONMENT (not the command line), then scrubbed.
    pw_env = "RTC_SHELL_PW"
    ps_lines = [
        f"$pw = ConvertTo-SecureString $env:{pw_env} -AsPlainText -Force",
        f"$cred = New-Object System.Management.Automation.PSCredential('{user}', $pw)",
        f"Remove-Item Env:\\{pw_env} -ErrorAction SilentlyContinue",
        f"Write-Host 'Connecting to {host.ip} as {user}...' -ForegroundColor Cyan",
        f"Enter-PSSession -ComputerName {host.ip} -Credential $cred -Authentication Negotiate",
    ]
    ps_script = "; ".join(ps_lines)

    child_env = dict(os.environ)
    child_env[pw_env] = profile.secret or ""

    cmd = f'start "PSSession {host.ip}" powershell -NoExit -Command "{ps_script}"'
    try:
        subprocess.Popen(cmd, shell=True, env=child_env)
        if audit:
            audit.log(host.ip, "shell opened", outcome="ok",
                      detail=f"Logged in via tool's shell (PSSession) as {user} ({host.ip} in TrustedHosts.)")
        return True, "PSSession shell launched"
    except Exception as exc:
        if audit:
            audit.log(host.ip, "shell", outcome="error", detail=str(exc))
        return False, str(exc)