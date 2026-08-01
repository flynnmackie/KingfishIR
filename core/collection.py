"""Module 3 - artefact collection (methodology s3.5.4).

Selection is free-order but DISPATCH is ordered by volatility (NFR3). Each
artefact is hashed at source and on receipt (NFR1); every step is logged (NFR2);
output is written per host (FR6).
"""

from __future__ import annotations

from pathlib import Path

from .audit import AuditLog
from .hashing import sha256_bytes
from .models import Artefact, CollectionResult, Host

from datetime import datetime
import zipfile


def run_timestamp() -> str:
    """One folder name per run: sorts chronologically, no illegal characters."""
    return datetime.now().strftime("%Y-%m-%d-%H%M_%Ss")


def order_by_volatility(artefacts: list[Artefact]) -> list[Artefact]:
    """Most volatile first (order of volatility, RFC 3227 / NFR3)."""
    return sorted(artefacts, key=lambda a: a.volatility, reverse=True)


def _basename(remote_path: str) -> str:
    """Last path component, tolerant of both / and \\ separators."""
    return remote_path.replace("\\", "/").rstrip("/").split("/")[-1] or "artefact"

def _extract_zip(zip_bytes: bytes, dest_dir: Path) -> int:
    """Write the fetched zip to dest_dir and unpack it there. Returns file count."""
    import io
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.extractall(dest_dir)
        return len(zf.namelist())


def _stage_dir(host: Host, run_folder: str) -> str:
    """Per-run working directory on the TARGET, platform-appropriate."""
    from .models import OSFamily
    if host.actual_os is OSFamily.UNIX:
        return f"/tmp/kingfishir_{run_folder}"
    return rf"C:\ProgramData\kingfishir\{run_folder}"


def collect_from_host(
    host: Host,
    artefacts: list[Artefact],
    transport,
    audit: AuditLog,
    out_root: str | Path,
    run_folder: str,
) -> list[CollectionResult]:
    """Collect the selected artefacts from one host, most volatile first."""
    ordered = order_by_volatility(artefacts)
    results: list[CollectionResult] = []

    host_dir = Path(out_root) / run_folder / host.ip
    host_dir.mkdir(parents=True, exist_ok=True)

    # Per-run working directory on the target (created now, removed at the end).
    stage = _stage_dir(host, run_folder)
    staged = False
    if any(a.prepare for a in ordered):
        try:
            transport.make_dir(stage)
            staged = True
            audit.log(host.ip, "stage", outcome="ok", detail=f"created {stage}")
        except Exception as exc:
            audit.log(host.ip, "stage", outcome="error", detail=str(exc))

    try:
        for artefact in ordered:
            result = CollectionResult(host_ip=host.ip, artefact_id=artefact.id)
            prepared_temp = None
            try:
                if artefact.is_command:
                    data = transport.run_command(artefact.spec)
                    source_hash = None
                    out_name = f"{artefact.id}.{artefact.output_ext}"
                else:
                    spec = artefact.spec.replace("{stage}", stage)
                    if artefact.prepare:
                        prep = artefact.prepare.replace("{stage}", stage)
                        transport.run_command(prep, use_sudo=artefact.requires_sudo)
                        prepared_temp = spec
                    source_hash = transport.remote_hash(spec)
                    data = transport.fetch_file(spec)
                    out_name = f"{artefact.id}_{_basename(spec)}"

                received_hash = sha256_bytes(data)

                category_dir = host_dir / artefact.category
                category_dir.mkdir(parents=True, exist_ok=True)

                if artefact.is_archive:
                    # extract into a named subfolder so multiple archives in one
                    # category don't mingle their files
                    archive_dir = category_dir / artefact.id
                    count = _extract_zip(data, archive_dir)
                    out_path = archive_dir
                    audit.log(host.ip, "extract", artefact=artefact.name,
                              outcome="ok", detail=f"{count} files -> {archive_dir}")
                else:
                    out_path = category_dir / out_name
                    out_path.write_bytes(data)

                result.collected = True
                result.source_hash = source_hash
                result.received_hash = received_hash
                result.output_path = str(out_path)

                audit.log(
                    host.ip, "collect", artefact=artefact.name,
                    source_hash=source_hash or "", received_hash=received_hash,
                    size_bytes=str(len(data)),
                    outcome="ok" if data else "ok (empty)",
                )
            except Exception as exc:
                result.collected = False
                result.error = str(exc)
                audit.log(host.ip, "collect", artefact=artefact.name,
                          outcome="error", detail=str(exc))
            finally:
                if prepared_temp is not None:
                    try:
                        transport.delete_remote(prepared_temp)
                        audit.log(host.ip, "cleanup", artefact=artefact.name,
                                  outcome="ok", detail=f"removed {prepared_temp}")
                    except Exception as exc:
                        audit.log(host.ip, "cleanup", artefact=artefact.name,
                                  outcome="error", detail=str(exc))

            results.append(result)
    finally:
        # Remove the whole per-run working directory (footprint teardown, NFR4).
        if staged:
            try:
                transport.remove_dir(stage)
                audit.log(host.ip, "stage", outcome="ok", detail=f"removed {stage}")
            except Exception as exc:
                audit.log(host.ip, "stage", outcome="error", detail=str(exc))

    return results