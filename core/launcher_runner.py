"""Launcher: deploy/run external tools on hosts. Operational, not forensic.
    agents PERSIST.
"""
from __future__ import annotations
from core.models import OSFamily


def deploy_sysmon(host, transport, sysmon_exe, sysmon_config, audit):
    """Push Sysmon + config to a Windows host, install, and verify the service."""
    ip = host.ip
    stage = r"C:\ProgramData\rtc_sysmon"
    remote_exe = rf"{stage}\Sysmon64.exe"
    remote_cfg = rf"{stage}\sysmon_config.xml"

    try:
        audit.log(ip, "sysmon push", artefact="Sysmon", outcome="ok",
                  detail="pushing Sysmon exe + config to target")
        transport.make_dir(stage)
        transport.put_file(sysmon_exe, remote_exe)
        transport.put_file(sysmon_config, remote_cfg)

        # Install: -accepteula silences the EULA prompt, -i installs with config
        audit.log(ip, "sysmon install", artefact="Sysmon", outcome="ok",
                  detail="installing Sysmon service (-accepteula -i)")
        out = transport.run_command(
            f'cmd /c ""{remote_exe}" -accepteula -i "{remote_cfg}""').decode(errors="replace")

        # Verify: is the Sysmon service present and running?
        svc = transport.run_command(
            "powershell -Command \"(Get-Service Sysmon* -ErrorAction SilentlyContinue "
            "| Select-Object -First 1).Status\""
        ).decode(errors="replace").strip()

        if svc.lower() == "running":
            audit.log(ip, "sysmon verify", artefact="Sysmon", outcome="ok",
                      detail="Sysmon service confirmed RUNNING")
            audit.log(ip, "sysmon deployed", artefact="Sysmon", outcome="ok",
                      detail=rf"tooling left on host at {stage} (exe + config) for management")
            return True
        else:
            audit.log(ip, "sysmon verify", artefact="Sysmon", outcome="error",
                      detail=f"Sysmon service not running (status: {svc or 'not found'})")
            return False

    except Exception as exc:
        audit.log(ip, "sysmon", artefact="Sysmon", outcome="error", detail=str(exc))
        return False
    # NOTE: no cleanup - Sysmon is meant to persist. We do remove the pushed
    # installer files though (the service is already installed from them).
 
def deploy_velociraptor(host, transport, velo_package, audit):
    """Deploy Velociraptor via its installer (MSI on Windows via scheduled task, DEB on Linux)."""
    ip = host.ip
    is_windows = host.actual_os is OSFamily.WINDOWS

    # 1. pick paths per platform
    if is_windows:
        stage = r"C:\ProgramData\rtc_velo"
        remote_pkg = rf"{stage}\velo_client.msi"
    else:
        stage = "/tmp/rtc_velo"
        remote_pkg = f"{stage}/velo_client.deb"

    try:
        # 2. push the installer
        audit.log(ip, "velo push", artefact="Velociraptor", outcome="ok",
                  detail="pushing Velociraptor installer package")
        transport.make_dir(stage)
        transport.put_file(velo_package, remote_pkg)

        # 3. install per platform
        if is_windows:
            audit.log(ip, "velo install", artefact="Velociraptor", outcome="ok",
                      detail="installing MSI via scheduled task (SYSTEM context)")
            bat = rf"{stage}\velo_install.bat"
            bat_body = f'msiexec /i "{remote_pkg}" /quiet /norestart\r\n'
            transport.run_command(
                f"powershell -Command \"Set-Content -Path '{bat}' -Value @'\n{bat_body}'@\"")
            # Register with the action INLINED (a $a variable does not survive the
            # single-line -Command string), run it, wait. -Confirm:0 not $false
            # (which mangles to the string 'False' through the command layers).
            ps = (
                "Register-ScheduledTask -TaskName 'rtc_velo_install' "
                f"-Action (New-ScheduledTaskAction -Execute '{bat}') "
                "-User 'SYSTEM' -RunLevel Highest -Force | Out-Null; "
                "Start-ScheduledTask -TaskName 'rtc_velo_install'; "
                "Start-Sleep -Seconds 30; "
                "Unregister-ScheduledTask -TaskName 'rtc_velo_install' -Confirm:0"
            )
            transport.run_command(f'powershell -Command "{ps}"')
            # poll for the service (can take a moment to register)
            svc = ""
            for _ in range(6):
                svc = transport.run_command(
                    "powershell -Command \"(Get-Service Velociraptor* -ErrorAction SilentlyContinue "
                    "| Select-Object -First 1).Status\""
                ).decode(errors="replace").strip()
                if svc.lower() == "running":
                    break
                import time
                time.sleep(10)
            running = svc.lower() == "running"
            detail = f"service status: {svc or 'not found'}"
        else:
            audit.log(ip, "velo install", artefact="Velociraptor", outcome="ok",
                      detail="installing via dpkg")
            transport.run_command(f"dpkg -i {remote_pkg}", use_sudo=True)
            chk = transport.run_command(
                "systemctl is-active velociraptor_client 2>/dev/null || "
                "systemctl is-active velociraptor 2>/dev/null || echo inactive",
                use_sudo=True).decode(errors="replace").strip()
            running = "active" in chk and "inactive" not in chk
            detail = f"systemctl is-active: {chk}"

        # 4. verify
        if running:
            audit.log(ip, "velo verify", artefact="Velociraptor", outcome="ok",
                      detail="Velociraptor client service confirmed RUNNING")
            audit.log(ip, "velo deployed", artefact="Velociraptor", outcome="ok",
                      detail=f"client left on host at {stage}")
            return True
        else:
            audit.log(ip, "velo verify", artefact="Velociraptor", outcome="error",
                      detail=f"Velociraptor not confirmed running ({detail})")
            return False
    except Exception as exc:
        audit.log(ip, "velo", artefact="Velociraptor", outcome="error", detail=str(exc))
        return False


def stub():
    ()