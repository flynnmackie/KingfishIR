"""Optional KAPE integration: push KAPE to a Windows target, run it, pull output back.

Launcher for an external collector (KAPE),the operator points at
their own copy via Settings.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path


def run_kape(host, transport, kape_local_folder, audit, out_root, run_folder):
    ip = host.ip
    stage = r"C:\Windows\Temp\rtc_kape"
    remote_zip = rf"{stage}\kape.zip"
    remote_kape_dir = rf"{stage}\kape"
    tdest = rf"{stage}\tout"          # KAPE target output
    mdest = rf"{stage}\mout"          # KAPE module output
    local_tmp = None

    try:
        # 1. zip the local KAPE folder
        audit.log(ip, "kape stage", artefact="KAPE", outcome="ok",
                  detail=f"archiving {kape_local_folder}")
        local_tmp = tempfile.mktemp(suffix=".zip")
        base = local_tmp[:-4]        # shutil adds .zip
        shutil.make_archive(base, "zip", kape_local_folder)

        # 2. push + expand on target
        transport.make_dir(stage)
        transport.put_file(local_tmp, remote_zip)
        audit.log(ip, "kape push", artefact="KAPE", outcome="ok",
                  detail=f"pushed archive to {remote_zip}")
        transport.run_command(
            f"powershell -Command \"Expand-Archive -Path '{remote_zip}' "
            f"-DestinationPath '{remote_kape_dir}' -Force\"")

        # 3. locate kape.exe (may be in a subfolder depending on how it zipped)
        find = transport.run_command(
            f"powershell -Command \"(Get-ChildItem -Path '{remote_kape_dir}' "
            f"-Recurse -Filter kape.exe | Select-Object -First 1).FullName\""
        ).decode(errors="replace").strip()
        if not find:
            audit.log(ip, "kape run", artefact="KAPE", outcome="error",
                      detail="kape.exe not found after extraction")
            return False
        kape_exe = find

        # 4. run KAPE: SANS triage target + EZParser module
        audit.log(ip, "kape run", artefact="KAPE", outcome="ok",
                  detail="running: --target !SANS_Triage --module !EZParser")
        kape_cmd = (
            f'"{kape_exe}" --tsource C: --target !SANS_Triage '
            f'--tdest "{tdest}" --module !EZParser --mdest "{mdest}" --gui'
        )
        out = transport.run_command(
            f'powershell -Command "& {kape_cmd}"').decode(errors="replace")
        tail = out.strip().splitlines()[-3:] if out.strip() else ["(no output)"]
        audit.log(ip, "kape output", artefact="KAPE", outcome="ok",
                  detail=" | ".join(tail))

        # 5. zip KAPE's output on the target
        out_zip = rf"{stage}\kape_output.zip"
        transport.run_command(
            f"powershell -Command \"Compress-Archive -Path '{tdest}','{mdest}' "
            f"-DestinationPath '{out_zip}' -Force\"")

        # 6. pull it back
        data = transport.fetch_file(out_zip)
        dest_dir = Path(out_root) / run_folder / ip / "KAPE"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / "kape_output.zip"
        dest.write_bytes(data)
        audit.log(ip, "kape collect", artefact="KAPE",
                  size_bytes=str(len(data)), outcome="ok",
                  detail=f"retrieved {dest.name}")
        return True

    except Exception as exc:
        audit.log(ip, "kape", artefact="KAPE", outcome="error", detail=str(exc))
        return False

    finally:
        # 7. clean up target + local temp
        try:
            transport.remove_dir(stage)
            audit.log(ip, "kape cleanup", artefact="KAPE", outcome="ok",
                      detail=f"removed {stage} on target")
        except Exception:
            pass
        if local_tmp and os.path.exists(local_tmp):
            os.remove(local_tmp)