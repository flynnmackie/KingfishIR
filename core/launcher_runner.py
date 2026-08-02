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
    stage = r"C:\ProgramData\kingfishir_sysmon"
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
        stage = r"C:\ProgramData\kingfishir_velo"
        remote_pkg = rf"{stage}\velo_client.msi"
    else:
        stage = "/tmp/kingfishir_velo"
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
                "Register-ScheduledTask -TaskName 'kingfishir_velo_install' "
                f"-Action (New-ScheduledTaskAction -Execute '{bat}') "
                "-User 'SYSTEM' -RunLevel Highest -Force | Out-Null; "
                "Start-ScheduledTask -TaskName 'kingfishir_velo_install'; "
                "Start-Sleep -Seconds 30; "
                "Unregister-ScheduledTask -TaskName 'kingfishir_velo_install' -Confirm:0"
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
    use_sudo = (not is_windows) and bool(launcher.get("sudo", False))        # elevate on Unix if requested; Windows session is already admin

    # launcher output goes to a SEPARATE top-level 'launched/' tree (not mixed
    # with forensic 'collected/' evidence - keeps chain of custody clean)
    from core.paths import output_base
    dest_dir = output_base() / "launched" / run_folder / ip / name
    dest_dir.mkdir(parents=True, exist_ok=True)

    # default working location = the authenticating user's home directory
    work_path = launcher.get("work_path", "").strip()
    if not work_path:
        if is_windows:
            work_path = transport.run_command(
                "cmd /c echo %USERPROFILE%").decode(errors="replace").strip()
        else:
            work_path = transport.run_command(
                "echo $HOME", use_sudo=use_sudo).decode(errors="replace").strip()
        if not work_path or work_path.startswith("%"):   # fallback if resolution fails
            work_path = r"C:\Windows\Temp\kingfishir_launch" if is_windows else "/tmp/kingfishir_launch"

    def _wrap(cmd):
        """Wrap a Windows command for the chosen shell; Unix passes through."""
        if is_windows and launcher.get("shell", "powershell") == "cmd":
            return f'cmd /c "{cmd}"'
        return cmd

    try:
        # ================= RUN COMMAND =================
        if mode == "command":
            cmd = launcher.get("command", "")
            if not cmd.strip():
                audit.log(ip, "launch run", artefact=name, outcome="error",
                          detail="launcher has no command - skipped")
                return False
            # run from the working path
            if is_windows:
                if launcher.get("shell", "powershell") == "cmd":
                    full = f'cd /d "{work_path}" && {cmd}'
                else:
                    full = f"Set-Location '{work_path}'; {cmd}"
            else:
                full = f"bash -c \"cd '{work_path}' && {cmd}\""
            audit.log(ip, "launch run", artefact=name, outcome="ok",
                      detail=f"running command in {work_path}: {full}")
            out = transport.run_command(_wrap(full), use_sudo=use_sudo).decode(errors="replace")
            (dest_dir / f"{name}_stdout.txt").write_text(out if out else "(no output)", errors="replace")
            audit.log(ip, "launch collect", artefact=name, outcome="ok",
                      detail=f"captured stdout -> launched/{name}/{name}_stdout.txt")
            return True

        # ================= PUSH FILE / DIRECTORY =================
        elif mode == "push":
            local_path = launcher.get("exe", "")
            is_dir = launcher.get("push_dir", False)
            transport.make_dir(work_path)

            # ---------- DIRECTORY: zip locally -> push -> extract on target ----------
            if is_dir:
                import shutil, tempfile
                base = os.path.basename(local_path.rstrip("/\\")) or "pushed_dir"
                tmp_zip = os.path.join(tempfile.gettempdir(), f"kingfishir_push_{base}.zip")
                audit.log(ip, "launch archive", artefact=name, outcome="ok",
                          detail=f"zipping {local_path} locally")
                # make_archive appends .zip; strip it from the base we pass
                shutil.make_archive(tmp_zip[:-4], "zip", local_path)

                if is_windows:
                    remote_zip = rf"{work_path}\{base}.zip"
                    remote_dest = rf"{work_path}\{base}"
                else:
                    remote_zip = f"{work_path}/{base}.zip"
                    remote_dest = f"{work_path}/{base}"

                audit.log(ip, "launch push", artefact=name, outcome="ok",
                          detail=f"pushing directory archive -> {remote_zip}")
                transport.put_file(tmp_zip, remote_zip)

                audit.log(ip, "launch extract", artefact=name, outcome="ok",
                          detail=f"extracting -> {remote_dest}")
                if is_windows:
                    transport.run_command(
                        f"powershell -Command \"Expand-Archive -Path '{remote_zip}' "
                        f"-DestinationPath '{remote_dest}' -Force\"")
                else:
                    transport.run_command(f"mkdir -p '{remote_dest}'", use_sudo=use_sudo)
                    transport.run_command(
                        f"unzip -o '{remote_zip}' -d '{remote_dest}'", use_sudo=use_sudo)

                # remove the pushed zip from target (keep the extracted content)
                try:
                    transport.delete_remote(remote_zip)
                except Exception:
                    pass
                try:
                    os.unlink(tmp_zip)      # local temp
                except Exception:
                    pass

                if launcher.get("delete_after"):
                    try:
                        transport.remove_dir(remote_dest)
                        audit.log(ip, "launch cleanup", artefact=name, outcome="ok",
                                  detail=f"removed {remote_dest}")
                    except Exception as exc:
                        audit.log(ip, "launch cleanup", artefact=name, outcome="error",
                                  detail=f"could not remove {remote_dest}: {exc}")

                audit.log(ip, "launch collect", artefact=name, outcome="ok",
                          detail=f"directory deployed -> {remote_dest}")
                return True

            # ---------- FILE: push, optionally execute ----------
            fname = os.path.basename(local_path)
            remote_file = (rf"{work_path}\{fname}" if is_windows
                           else f"{work_path}/{fname}")
            audit.log(ip, "launch push", artefact=name, outcome="ok",
                      detail=f"pushing {fname} -> {remote_file}")
            transport.put_file(local_path, remote_file)

            if launcher.get("execute"):
                extra = launcher.get("command", "").strip()
                if is_windows and launcher.get("shell", "powershell") != "cmd":
                    cmd = f'& "{remote_file}" {extra}'.strip()
                else:
                    cmd = f'"{remote_file}" {extra}'.strip()
                audit.log(ip, "launch run", artefact=name, outcome="ok",
                          detail=f"executing: {cmd.lstrip('& ').strip()}")
                out = transport.run_command(_wrap(cmd), use_sudo=use_sudo).decode(errors="replace")
                (dest_dir / f"{name}_stdout.txt").write_text(out if out else "(no output)", errors="replace")
                audit.log(ip, "launch collect", artefact=name, outcome="ok",
                          detail=f"captured stdout -> launched/{name}/{name}_stdout.txt")

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
            limit_mb = 5120        # fixed 5GB cap
            cleanup_remote = None   # set if we create a temp archive to remove after

            # determine whether the path is a FILE or a DIRECTORY (or missing)
            if is_windows:
                kind = transport.run_command(
                    f"powershell -Command \"if(Test-Path -LiteralPath '{remote_path}' -PathType Container)"
                    f"{{'DIR'}}elseif(Test-Path -LiteralPath '{remote_path}'){{'FILE'}}else{{'MISSING'}}\""
                ).decode(errors="replace").strip()
            else:
                kind = transport.run_command(
                    f"if [ -d '{remote_path}' ]; then echo DIR; "
                    f"elif [ -f '{remote_path}' ]; then echo FILE; else echo MISSING; fi",
                    use_sudo=use_sudo).decode(errors="replace").strip()

            if kind == "MISSING":
                audit.log(ip, "launch pull", artefact=name, outcome="error",
                          detail=f"path not found: {remote_path}")
                return False

            # if a directory, archive it on the target first, then pull the archive
            if kind == "DIR":
                base = (remote_path.replace("\\", "/").rstrip("/").split("/")[-1]) or "dir"
                if is_windows:
                    archive = rf"C:\Windows\Temp\kingfishir_pull_{base}.zip"
                    audit.log(ip, "launch archive", artefact=name, outcome="ok",
                              detail=f"zipping directory {remote_path} on target")
                    transport.run_command(
                        f"powershell -Command \"Compress-Archive -Path '{remote_path}\\*' "
                        f"-DestinationPath '{archive}' -Force\"")
                else:
                    archive = f"/tmp/kingfishir_pull_{base}.tar.gz"
                    audit.log(ip, "launch archive", artefact=name, outcome="ok",
                              detail=f"tarring directory {remote_path} on target")
                    transport.run_command(
                        f"tar -czf '{archive}' -C '{remote_path}' .", use_sudo=use_sudo)
                fetch_path = archive
                cleanup_remote = archive
            else:
                fetch_path = remote_path

            # size-check the thing we're about to fetch (file or archive)
            if is_windows:
                size_out = transport.run_command(
                    f"powershell -Command \"if(Test-Path -LiteralPath '{fetch_path}')"
                    f"{{(Get-Item -LiteralPath '{fetch_path}').Length}}else{{'MISSING'}}\""
                ).decode(errors="replace").strip()
            else:
                size_out = transport.run_command(
                    f"if [ -f '{fetch_path}' ]; then stat -c %s '{fetch_path}'; "
                    f"else echo MISSING; fi", use_sudo=use_sudo).decode(errors="replace").strip()

            if size_out == "MISSING" or not size_out.isdigit():
                audit.log(ip, "launch pull", artefact=name, outcome="error",
                          detail=f"could not read {fetch_path} (archive may have failed)")
                return False


            size_bytes = int(size_out)
            size_mb = size_bytes // (1024 * 1024)

            # empty files break WinRM's fetch (crypto transform on null input) -
            # create the empty local file directly instead of fetching
            if size_bytes == 0:
                fname = (fetch_path.replace("\\", "/").rstrip("/").split("/")[-1]) or "pulled"
                (dest_dir / fname).write_bytes(b"")
                if cleanup_remote:
                    try:
                        transport.delete_remote(cleanup_remote)
                    except Exception:
                        pass
                audit.log(ip, "launch collect", artefact=name, outcome="ok",
                          detail=f"retrieved empty file -> launched/{name}/{fname}")
                return True

            
            if size_mb > limit_mb:
                audit.log(ip, "launch pull", artefact=name, outcome="error",
                          detail=f"{size_mb}MB exceeds {limit_mb}MB limit - skipped")
                if cleanup_remote:
                    try: transport.delete_remote(cleanup_remote)
                    except Exception: pass
                return False

            fname = (fetch_path.replace("\\", "/").rstrip("/").split("/")[-1]) or "pulled"
            dest = dest_dir / fname

            if is_windows and size_mb > _WINRM_SAFE_MB:
                audit.log(ip, "launch pull", artefact=name, outcome="ok",
                          detail=f"{size_mb}MB - retrieving via SMB (445 must be reachable)")
                transport.fetch_file_smb(fetch_path, str(dest))
            else:
                audit.log(ip, "launch pull", artefact=name, outcome="ok",
                          detail=f"retrieving {size_mb}MB via {'SFTP' if not is_windows else 'WinRM'}")
                data = transport.fetch_file(fetch_path)
                dest.write_bytes(data)

            # remove the temp archive from the target
            if cleanup_remote:
                try:
                    transport.delete_remote(cleanup_remote)
                    audit.log(ip, "launch cleanup", artefact=name, outcome="ok",
                              detail=f"removed temp archive {cleanup_remote}")
                except Exception:
                    pass

            kind_word = "directory (as archive)" if kind == "DIR" else "file"
            audit.log(ip, "launch collect", artefact=name, outcome="ok",
                      detail=f"retrieved {kind_word} -> launched/{name}/{fname}")
            return True

    except Exception as exc:
        audit.log(ip, "launch", artefact=name, outcome="error", detail=str(exc))
        return False