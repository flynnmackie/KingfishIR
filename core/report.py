"""Generate a  HTML summary report for a collection or launch run."""
from __future__ import annotations

import html
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


_CSS = """
body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
       background: #f4f6f8; color: #1a1a1a; }
.header { background: #12303f; color: #fff; padding: 20px 32px; }
.header h1 { margin: 0; font-size: 22px; }
.header .sub { color: #9fd0e6; font-size: 13px; margin-top: 4px; }
.wrap { padding: 24px 32px; max-width: 1100px; }
.cards { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 24px; }
.card { background: #fff; border-radius: 8px; padding: 14px 18px; min-width: 120px;
        box-shadow: 0 1px 3px rgba(0,0,0,.08); }
.card .n { font-size: 26px; font-weight: 700; }
.card .l { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: .5px; }
table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px;
        overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); margin-bottom: 24px; }
th { background: #e8edf1; text-align: left; padding: 10px 12px; font-size: 12px;
     text-transform: uppercase; letter-spacing: .4px; color: #445; }
td { padding: 9px 12px; border-top: 1px solid #eef1f4; font-size: 13px; }
.ok { color: #1b7a34; font-weight: 600; }
.err { color: #c0392b; font-weight: 600; }
.warn { color: #b8860b; font-weight: 600; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.match-y { color: #1b7a34; font-weight: 700; }
.match-n { color: #c0392b; font-weight: 700; background: #fdecea; }
.foot { color: #888; font-size: 12px; padding: 8px 32px 24px; }
"""


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def generate_collection_report(records, run_folder, hosts, out_path):
    """Build an HTML collection report from this run's audit records.

    records: list of AuditRecord for this run
    run_folder: the run identifier (folder name)
    hosts: the Host objects that were in the run (for hostname/OS/profile)
    out_path: Path to write report.html
    """
    host_meta = {h.ip: h for h in hosts}

    # group records by host
    by_host = defaultdict(list)
    for r in records:
        if r.host and r.host != "-":
            by_host[r.host].append(r)

    # per-host tallies
    rows = []
    tot_collected = tot_failed = tot_matches = tot_mismatches = 0
    for ip, recs in by_host.items():
        h = host_meta.get(ip)
        hostname = (h.hostname if h else "") or ""
        os_name = (h.os_guess.value if h and hasattr(h.os_guess, "value") else "") if h else ""
        profile = (h.profile_name if h else "") or ""

        collected = sum(1 for r in recs if r.action == "collect" and r.outcome.startswith("ok"))
        failed = sum(1 for r in recs if r.action == "collect" and r.outcome == "error")
        matches = sum(1 for r in recs if r.match == "Y")
        mismatches = sum(1 for r in recs if r.match == "N")
        tot_collected += collected
        tot_failed += failed
        tot_matches += matches
        tot_mismatches += mismatches

        mismatch_cell = (f'<span class="match-n">{mismatches}</span>'
                         if mismatches else '<span class="match-y">0</span>')
        rows.append(
            f"<tr><td class='mono'>{_esc(ip)}</td><td>{_esc(hostname)}</td>"
            f"<td>{_esc(os_name)}</td><td>{_esc(profile)}</td>"
            f"<td class='ok'>{collected}</td>"
            f"<td class='{'err' if failed else ''}'>{failed}</td>"
            f"<td>{matches}</td><td>{mismatch_cell}</td></tr>")

    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    integrity_class = "err" if tot_mismatches else "ok"
    integrity_text = (f"{tot_mismatches} MISMATCH(ES)" if tot_mismatches
                      else "All hashes verified")

    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>KingfishIR Collection Report - {_esc(run_folder)}</title>
<style>{_CSS}</style></head><body>
<div class="header">
  <h1>KingfishIR — Collection Report</h1>
  <div class="sub">Run: {_esc(run_folder)} &nbsp;·&nbsp; Generated: {_esc(generated)}</div>
</div>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="n">{len(by_host)}</div><div class="l">Hosts</div></div>
    <div class="card"><div class="n">{tot_collected}</div><div class="l">Artefacts collected</div></div>
    <div class="card"><div class="n">{tot_failed}</div><div class="l">Failed / absent</div></div>
    <div class="card"><div class="n">{tot_matches}</div><div class="l">Hash matches</div></div>
    <div class="card"><div class="n {integrity_class}">{tot_mismatches}</div><div class="l">Hash mismatches</div></div>
  </div>
  <p>Integrity: <span class="{integrity_class}">{integrity_text}</span></p>
  <table>
    <tr><th>Host</th><th>Hostname</th><th>OS</th><th>Profile</th>
        <th>Collected</th><th>Failed/absent</th><th>Matches</th><th>Mismatches</th></tr>
    {''.join(rows)}
  </table>
</div>
<div class="foot">Generated by KingfishIR. This report summarises the audit record for
this run; the authoritative chain-of-custody log is in triage_audit.csv.</div>
</body></html>"""

    Path(out_path).write_text(doc, encoding="utf-8")
    return out_path


def generate_launch_report(records, run_folder, hosts, out_path):
    """Build an HTML launch report from this run's audit records."""
    host_meta = {h.ip: h for h in hosts}
    by_host = defaultdict(list)
    for r in records:
        if r.host and r.host != "-":
            by_host[r.host].append(r)

    rows = []
    tot_actions = tot_errors = 0
    for ip, recs in by_host.items():
        h = host_meta.get(ip)
        hostname = (h.hostname if h else "") or ""
        os_name = (h.os_guess.value if h and hasattr(h.os_guess, "value") else "") if h else ""

        # launcher-relevant actions (deploys, runs, pushes, pulls)
        launch_actions = [r for r in recs if r.action in (
            "launch run", "launch push", "launch pull", "launch collect",
            "launch extract", "launch archive", "sysmon", "velo", "deploy")]
        errors = sum(1 for r in recs if r.outcome == "error")
        tot_actions += len(launch_actions)
        tot_errors += errors

        # short list of what was done
        done = "; ".join(sorted({r.action for r in launch_actions})) or "—"
        rows.append(
            f"<tr><td class='mono'>{_esc(ip)}</td><td>{_esc(hostname)}</td>"
            f"<td>{_esc(os_name)}</td><td>{_esc(done)}</td>"
            f"<td class='{'err' if errors else 'ok'}'>{errors}</td></tr>")

    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>KingfishIR Launch Report - {_esc(run_folder)}</title>
<style>{_CSS}</style></head><body>
<div class="header">
  <h1>KingfishIR — Launch Report</h1>
  <div class="sub">Run: {_esc(run_folder)} &nbsp;·&nbsp; Generated: {_esc(generated)}</div>
</div>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="n">{len(by_host)}</div><div class="l">Hosts</div></div>
    <div class="card"><div class="n">{tot_actions}</div><div class="l">Launch actions</div></div>
    <div class="card"><div class="n {'err' if tot_errors else 'ok'}">{tot_errors}</div><div class="l">Errors</div></div>
  </div>
  <table>
    <tr><th>Host</th><th>Hostname</th><th>OS</th><th>Actions performed</th><th>Errors</th></tr>
    {''.join(rows)}
  </table>
</div>
<div class="foot">Generated by KingfishIR. Operational launch summary; the authoritative
record is in launcher_audit.csv.</div>
</body></html>"""

    Path(out_path).write_text(doc, encoding="utf-8")
    return out_path