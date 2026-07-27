"""Activity log / chain-of-custody trail (NFR2).

Every action the tool performs against a host is recorded here with a
timestamp. Records are (a) appended to a CSV file so results survive the run
and can be pasted into Chapter 4 / an appendix, and (b) pushed to any
registered observer so the GUI log panel updates live.

Credentials/secrets must NEVER be passed to log().
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional


@dataclass
class AuditRecord:
    timestamp: str
    host: str
    action: str
    artefact: str = ""
    source_hash: str = ""
    received_hash: str = ""
    size_bytes: str = ""
    match: str = ""
    outcome: str = ""
    detail: str = ""


class AuditLog:
    FIELDS = list(AuditRecord.__annotations__.keys())

    def __init__(self, csv_path: str | Path):
        self.csv_path = Path(csv_path)
        self.records: list[AuditRecord] = []
        self._observers: list[Callable[[AuditRecord], None]] = []
        self._ensure_header()

    def _ensure_header(self) -> None:
            # Write a header if the file is missing OR exists but is empty/headerless.
            needs_header = True
            if self.csv_path.exists() and self.csv_path.stat().st_size > 0:
                with open(self.csv_path, "r", newline="") as f:
                    first = f.readline().strip()
                needs_header = (first != ",".join(self.FIELDS))
            if needs_header:
                with open(self.csv_path, "w", newline="") as f:
                    csv.DictWriter(f, fieldnames=self.FIELDS).writeheader()

    def subscribe(self, callback: Callable[[AuditRecord], None]) -> None:
        """Register an observer (e.g. the GUI log panel)."""
        self._observers.append(callback)

    def unsubscribe(self, callback) -> None:
        if callback in self._observers:
            self._observers.remove(callback)

    def log(
        self,
        host: str,
        action: str,
        artefact: str = "",
        source_hash: str = "",
        received_hash: str = "",
        size_bytes: str = "",
        outcome: str = "",
        detail: str = "",
    ) -> AuditRecord:
        match = ""
        if source_hash and received_hash:
            match = "Y" if source_hash == received_hash else "N"
        rec = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            host=host,
            action=action,
            artefact=artefact,
            source_hash=source_hash,
            received_hash=received_hash,
            size_bytes=size_bytes,
            match=match,
            outcome=outcome,
            detail=detail,
        )
        self.records.append(rec)
        with open(self.csv_path, "a", newline="") as f:
            csv.DictWriter(f, fieldnames=self.FIELDS).writerow(asdict(rec))
        for cb in self._observers:
            cb(rec)
        return rec
