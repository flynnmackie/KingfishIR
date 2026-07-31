"""Launcher: deploy/run external tools on hosts. Operational, not forensic.
    agents PERSIST.
"""
from __future__ import annotations
from core.models import OSFamily
import os
from pathlib import Path
#WINRM safe limit defined
_WINRM_SAFE_MB = 200


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

def run_custom_launcher(host, transport, launcher, audit, out_root, run_folder):
    """Run a user-defined custom launcher (command / push / pull).

    `launcher` is a dict: name, os, mode, command, exe, execute, delete_after,
    remote_path, size_limit_mb, shell, work_path.
    """
    ip = host.ip
    name = launcher.get("name", "custom")
    mode = launcher.get("mode", "command")
    is_windows = host.actual_os is OSFamily.WINDOWS
    use_sudo = not is_windows        # elevate on Unix; Windows session is already admin

    # launcher output goes to a SEPARATE top-level 'launched/' tree (not mixed
    # with forensic 'collected/' evidence - keeps chain of custody clean)
    dest_dir = Path("launched") / run_folder / ip / name
    dest_dir.mkdir(parents=True, exist_ok=True)

    # default working location = the authenticating user's home directory
    work_path = launcher.get("work_path", "").strip()
    if not work_path:
        if is_windows:
            work_path = transport.run_command(
                "powershell -Command \"$env:USERPROFILE\"").decode(errors="replace").strip()
        else:
            work_path = transport.run_command(
                "echo $HOME", use_sudo=use_sudo).decode(errors="replace").strip()
        if not work_path:      # fallback if resolution fails
            work_path = r"C:\Windows\Temp\rtc_launch" if is_windows else "/tmp/rtc_launch"

    def _wrap(cmd):
        """Wrap a Windows command for the chosen shell; Unix passes through."""
        if is_windows and launcher.get("shell", "powershell") == "cmd":
            return f'cmd /c "{cmd}"'
        return cmd

    try:
        # ================= RUN COMMAND =================
        if mode == "command":
            cmd = launcher.get("command", "")
            audit.log(ip, "launch run", artefact=name, outcome="ok",
                      detail=f"running command ({launcher.get('shell','sh')})")
            out = transport.run_command(_wrap(cmd), use_sudo=use_sudo).decode(errors="replace")
            (dest_dir / "stdout.txt").write_text(out, errors="replace")
            audit.log(ip, "launch collect", artefact=name, outcome="ok",
                      detail=f"captured stdout -> Launched/{name}/stdout.txt")
            return True

        # ================= PUSH FILE =================
        elif mode == "push":
            local_file = launcher.get("exe", "")
            fname = os.path.basename(local_file)
            transport.make_dir(work_path)
            remote_file = (rf"{work_path}\{fname}" if is_windows
                           else f"{work_path}/{fname}")
            audit.log(ip, "launch push", artefact=name, outcome="ok",
                      detail=f"pushing {fname} -> {remote_file}")
            transport.put_file(local_file, remote_file)

            if launcher.get("execute"):
                # substitute {exe} with the pushed file's remote path
                cmd = launcher.get("command", "").replace("{exe}", f'"{remote_file}"')
                audit.log(ip, "launch run", artefact=name, outcome="ok",
                          detail="executing pushed file")
                out = transport.run_command(_wrap(cmd), use_sudo=use_sudo).decode(errors="replace")
                (dest_dir / "stdout.txt").write_text(out, errors="replace")
                audit.log(ip, "launch collect", artefact=name, outcome="ok",
                          detail=f"captured stdout -> Launched/{name}/stdout.txt")

            if launcher.get("delete_after"):
                try:
                    transport.delete_remote(remote_file)
                    audit.log(ip, "launch cleanup", artefact=name, outcome="ok",
                              detail=f"removed {remote_file}")
                except Exception as exc:
                    audit.log(ip, "launch cleanup", artefact=name, outcome="error",
                              detail=f"could not remove {remote_file}: {exc}")
            return True

        # ================= PULL FILE =================
        elif mode == "pull":
            remote_path = launcher.get("remote_path", "")
            limit_mb = 5120        # fixed 5GB cap; larger files auto-rejected

            # check the remote file size first
            if is_windows:
                size_out = transport.run_command(
                    f"powershell -Command \"if(Test-Path '{remote_path}')"
                    f"{{(Get-Item '{remote_path}').Length}}else{{'MISSING'}}\""
                ).decode(errors="replace").strip()
            else:
                size_out = transport.run_command(
                    f"if [ -f '{remote_path}' ]; then stat -c %s '{remote_path}'; "
                    f"else echo MISSING; fi", use_sudo=use_sudo).decode(errors="replace").strip()

            if size_out == "MISSING" or not size_out.isdigit():
                audit.log(ip, "launch pull", artefact=name, outcome="error",
                          detail=f"file not found: {remote_path}")
                return False

            size_mb = int(size_out) // (1024 * 1024)
            if size_mb > limit_mb:
                audit.log(ip, "launch pull", artefact=name, outcome="error",
                          detail=f"{size_mb}MB exceeds {limit_mb}MB limit - skipped")
                return False

            fname = (remote_path.replace("\\", "/").rstrip("/").split("/")[-1]) or "pulled_file"
            dest = dest_dir / fname

            # route: large Windows files via SMB, else normal fetch
            if is_windows and size_mb > _WINRM_SAFE_MB:
                audit.log(ip, "launch pull", artefact=name, outcome="ok",
                          detail=f"{size_mb}MB - retrieving via SMB (445 must be reachable)")
                transport.fetch_file_smb(remote_path, str(dest))
            else:
                audit.log(ip, "launch pull", artefact=name, outcome="ok",
                          detail=f"retrieving {size_mb}MB via {'SFTP' if not is_windows else 'WinRM'}")
                data = transport.fetch_file(remote_path)
                dest.write_bytes(data)

            audit.log(ip, "launch collect", artefact=name, outcome="ok",
                      detail=f"retrieved {fname} -> Launched/{name}/")
            return True

        else:
            audit.log(ip, "launch", artefact=name, outcome="error",
                      detail=f"unknown mode: {mode}")
            return False

    except Exception as exc:
        audit.log(ip, "launch", artefact=name, outcome="error", detail=str(exc))
        return False