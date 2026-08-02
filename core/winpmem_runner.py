"""Optional memory acquisition: push WinPmem to a Windows target, dump RAM, pull it back."""
from __future__ import annotations


from pathlib import Path


def run_winpmem(host, transport, winpmem_exe, audit, out_root, run_folder):
    ip = host.ip
    stage = r"C:\Windows\Temp\kingfishir_mem"
    remote_exe = rf"{stage}\winpmem.exe"
    remote_dump = rf"{stage}\memory.raw"
    # Pre-flight: confirm SMB (445) is reachable before the expensive dump
    import socket
    audit.log(ip, "memory preflight", artefact="Memory", outcome="ok",
              detail="checking SMB (445) reachability…")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    reachable = (s.connect_ex((ip, 445)) == 0)
    s.close()
    if not reachable:
        audit.log(ip, "memory preflight", artefact="Memory", outcome="error",
                  detail="SMB port 445 not reachable - cannot retrieve dump, skipping. "
                         "Enable File & Printer Sharing (SMB-In) on the target firewall.")
        return False

    try:
        audit.log(ip, "memory stage", artefact="Memory", outcome="ok",
                  detail="pushing WinPmem to target")
        transport.make_dir(stage)
        transport.put_file(winpmem_exe, remote_exe)

        # Run WinPmem - CLI, dumps physical memory to memory.raw
        audit.log(ip, "memory dump", artefact="Memory", outcome="ok",
                  detail="acquiring memory (this can take several minutes)…")
        out = transport.run_command(
            f'cmd /c ""{remote_exe}" "{remote_dump}""').decode(errors="replace")
        tail = out.strip().splitlines()[-3:] if out.strip() else ["(no output)"]
        audit.log(ip, "memory output", artefact="Memory", outcome="ok",
                  detail=" | ".join(tail))

        # Confirm the dump exists and has size
        size_check = transport.run_command(
            f"powershell -Command \"if(Test-Path '{remote_dump}'){{(Get-Item '{remote_dump}').Length}}else{{'MISSING'}}\""
        ).decode(errors="replace").strip()
        if size_check == "MISSING" or size_check == "0":
            audit.log(ip, "memory collect", artefact="Memory", outcome="error",
                      detail="WinPmem produced no dump")
            return False

        # Pull it back via SMB (admin share C$) - streamed in chunks to disk,
        # because WinRM's fetch cannot handle multi-GB files.
        mb = int(size_check) // (1024 * 1024)
        audit.log(ip, "memory transfer", artefact="Memory", outcome="ok",
                  detail=f"retrieving {mb} MB dump via SMB (large - please wait)…")

        dest_dir = Path(out_root) / run_folder / ip / "Memory"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / "memory.raw"

        written = transport.fetch_file_smb(remote_dump, str(dest))

        audit.log(ip, "memory collect", artefact="Memory",
                  size_bytes=str(written), outcome="ok",
                  detail=f"retrieved memory.raw ({written // (1024*1024)} MB) via SMB")
        return True

    except Exception as exc:
        audit.log(ip, "memory", artefact="Memory", outcome="error", detail=str(exc))
        return False

    finally:
        try:
            transport.remove_dir(stage)
            audit.log(ip, "memory cleanup", artefact="Memory", outcome="ok",
                      detail=f"removed {stage} on target")
        except Exception:
            pass