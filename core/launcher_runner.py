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

def deploy_velociraptor(host, transport, velo_binary, velo_config, audit):
    """Push Velociraptor client + config to a host, install as a service, verify.

    Cross-platform: Windows via WinRM, Linux via SSH+sudo. Agent persists.
    """
    ip = host.ip
    is_windows = host.actual_os is OSFamily.WINDOWS

    if is_windows:
        stage = r"C:\ProgramData\rtc_velo"
        remote_bin = rf"{stage}\velociraptor.exe"
        remote_cfg = rf"{stage}\client.config.yaml"
    else:
        stage = "/opt/rtc_velo"
        remote_bin = f"{stage}/velociraptor"
        remote_cfg = f"{stage}/client.config.yaml"

    try:
        audit.log(ip, "velo push", artefact="Velociraptor", outcome="ok",
                  detail="pushing Velociraptor client + config to target")
        transport.make_dir(stage)
        transport.put_file(velo_binary, remote_bin)
        transport.put_file(velo_config, remote_cfg)

        if is_windows:
            audit.log(ip, "velo install", artefact="Velociraptor", outcome="ok",
                      detail="installing Velociraptor service (Windows)")
            transport.run_command(
                f'cmd /c ""{remote_bin}" --config "{remote_cfg}" service install"')
            # verify: service running?
            svc = transport.run_command(
                "powershell -Command \"(Get-Service Velociraptor* -ErrorAction SilentlyContinue "
                "| Select-Object -First 1).Status\""
            ).decode(errors="replace").strip()
            running = svc.lower() == "running"
            status_detail = f"service status: {svc or 'not found'}"
        else:
            audit.log(ip, "velo install", artefact="Velociraptor", outcome="ok",
                      detail="installing Velociraptor service (Linux, sudo)")
            transport.run_command(f"chmod +x {remote_bin}", use_sudo=True)
            transport.run_command(
                f"{remote_bin} --config {remote_cfg} service install", use_sudo=True)
            # verify: is the process/service active?
            chk = transport.run_command(
                "systemctl is-active velociraptor 2>/dev/null || echo inactive",
                use_sudo=True).decode(errors="replace").strip()
            running = "active" in chk and "inactive" not in chk
            status_detail = f"systemctl is-active: {chk}"

        if running:
            audit.log(ip, "velo verify", artefact="Velociraptor", outcome="ok",
                      detail="Velociraptor service confirmed RUNNING")
            audit.log(ip, "velo deployed", artefact="Velociraptor", outcome="ok",
                      detail=f"client + config left on host at {stage}")
            return True
        else:
            audit.log(ip, "velo verify", artefact="Velociraptor", outcome="error",
                      detail=f"Velociraptor not confirmed running ({status_detail})")
            return False

    except Exception as exc:
        audit.log(ip, "velo", artefact="Velociraptor", outcome="error", detail=str(exc))
        return False