"""Launcher: deploy/run external tools on hosts. Operational, not forensic.
    agents PERSIST.
"""
from __future__ import annotations


def deploy_sysmon(host, transport, sysmon_exe, sysmon_config, audit):
    """Push Sysmon + config to a Windows host, install, and verify the service."""
    ip = host.ip
    stage = r"C:\Windows\Temp\rtc_sysmon"
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
        tail = out.strip().splitlines()[-3:] if out.strip() else ["(no output)"]
        audit.log(ip, "sysmon output", artefact="Sysmon", outcome="ok",
                  detail=" | ".join(tail))

        # Verify: is the Sysmon service present and running?
        svc = transport.run_command(
            "powershell -Command \"(Get-Service Sysmon* -ErrorAction SilentlyContinue "
            "| Select-Object -First 1).Status\""
        ).decode(errors="replace").strip()

        if svc.lower() == "running":
            audit.log(ip, "sysmon verify", artefact="Sysmon", outcome="ok",
                      detail="Sysmon service confirmed RUNNING")
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
    finally:
        try:
            transport.remove_dir(stage)
        except Exception:
            pass