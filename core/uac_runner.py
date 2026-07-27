"""Optional UAC integration: push UAC to a Unix target, run it, pull the output back.

This is a LAUNCHER for an external collector (UAC).
"""
from __future__ import annotations

import os
import tarfile
import tempfile
from pathlib import Path


def run_uac(host, transport, uac_local_folder, audit, out_root, run_folder):
    """Run UAC on one Unix host and retrieve its output.

    Steps: archive the local UAC folder -> push -> extract on target ->
    run with sudo -> pull the produced archive -> clean up both ends.
    """
    ip = host.ip
    stage = "/tmp/rtc_uac"
    remote_tar = f"{stage}/uac.tar.gz"
    remote_uac_dir = f"{stage}/uac"
    local_tmp = None

    try:
        # 1. archive the local UAC folder into a single .tar.gz
        audit.log(ip, "uac stage", artefact="UAC", outcome="ok",
                  detail=f"archiving {uac_local_folder}")
        fd, local_tmp = tempfile.mkstemp(suffix=".tar.gz")
        os.close(fd)
        with tarfile.open(local_tmp, "w:gz") as tar:
            # arcname="uac" so it extracts to a predictable folder name
            tar.add(uac_local_folder, arcname="uac")

        # 2. make the staging dir and push the archive across
        transport.run_command(f"mkdir -p {stage}")
        transport.put_file(local_tmp, remote_tar)
        audit.log(ip, "uac push", artefact="UAC", outcome="ok",
                  detail=f"pushed archive to {remote_tar}")

        # 3. extract on the target
        transport.run_command(f"tar -xzf {remote_tar} -C {stage}")

        # 4. run UAC with sudo, capturing its output
        transport.run_command(f"chmod +x {remote_uac_dir}/uac")
        audit.log(ip, "uac run", artefact="UAC", outcome="ok",
                  detail="running: ./uac -p ir_triage")
        run_cmd = (f"bash -c 'cd {remote_uac_dir} && bash ./uac -p ir_triage {stage}; "
                   f"echo EXIT_CODE=$?'")
        uac_out = transport.run_command(run_cmd, use_sudo=True).decode(errors="replace")
        audit.log(ip, "uac output", artefact="UAC", outcome="ok",
                  detail=uac_out.strip().replace(chr(10), " | ")[-200:])

        # 5. find UAC's output archive anywhere in the stage dir
        listing = transport.run_command(
            f"ls -1 {stage}").decode(errors="replace").strip()
        audit.log(ip, "uac listing", artefact="UAC", outcome="ok",
                  detail=f"stage contains: {listing.replace(chr(10), ', ')}")
        archives = transport.run_command(
            f"find {stage} -name 'uac-*.tar.gz' 2>/dev/null").decode(errors="replace").strip()
        produced = [l.strip() for l in archives.splitlines() if l.strip()]
        if not produced:
            audit.log(ip, "uac collect", artefact="UAC", outcome="error",
                      detail="no UAC output archive found")
            return False
        remote_output = produced[0]
        data = transport.fetch_file(remote_output)

        # 6. save into the host's collection folder
        dest_dir = Path(out_root) / run_folder / ip / "UAC"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / Path(remote_output).name
        dest.write_bytes(data)
        audit.log(ip, "uac collect", artefact="UAC",
                  size_bytes=str(len(data)), outcome="ok",
                  detail=f"retrieved {dest.name}")
        return True

    except Exception as exc:
        audit.log(ip, "uac", artefact="UAC", outcome="error", detail=str(exc))
        return False

    finally:
        # 7. clean up target (whole stage dir) and the local temp archive
        try:
            transport.run_command(f"rm -rf {stage}", use_sudo=True)
            audit.log(ip, "uac cleanup", artefact="UAC", outcome="ok",
                      detail=f"removed {stage} on target")
        except Exception:
            pass
        if local_tmp and os.path.exists(local_tmp):
            os.remove(local_tmp)