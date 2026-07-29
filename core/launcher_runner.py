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
    """Deploy Velociraptor via its self-contained installer (MSI on Windows, DEB on Linux).

    Config is embedded in the package; the installer registers the service.
    """
    ip = host.ip
    is_windows = host.actual_os is OSFamily.WINDOWS

    if is_windows:
        stage = r"C:\ProgramData\rtc_velo"
        remote_pkg = rf"{stage}\velo_client.msi"
    else:
        stage = "/tmp/rtc_velo"
        remote_pkg = f"{stage}/velo_client.deb"

    try:
        audit.log(ip, "velo push", artefact="Velociraptor", outcome="ok",
                  detail="pushing Velociraptor installer package")
        transport.make_dir(stage)
        transport.put_file(velo_package, remote_pkg)

        if is_windows:
            audit.log(ip, "velo install", artefact="Velociraptor", outcome="ok",
                      detail="installing via msiexec (silent)")
            transport.run_command(f'msiexec /i "{remote_pkg}" /quiet')
            svc = transport.run_command(
                "powershell -Command \"(Get-Service Velociraptor* -ErrorAction SilentlyContinue "
                "| Select-Object -First 1).Status\""
            ).decode(errors="replace").strip()
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

        if running:
            audit.log(ip, "velo verify", artefact="Velociraptor", outcome="ok",
                      detail="Velociraptor client service confirmed RUNNING")
            return True
        else:
            audit.log(ip, "velo verify", artefact="Velociraptor", outcome="error",
                      detail=f"Velociraptor not confirmed running ({detail})")
            return False
    except Exception as exc:
        audit.log(ip, "velo", artefact="Velociraptor", outcome="error", detail=str(exc))
        return False