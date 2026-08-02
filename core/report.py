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
_CSS_L2 = """
details { background: #fff; border-radius: 8px; margin-bottom: 8px;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); overflow: hidden; }
summary { padding: 12px 16px; cursor: pointer; font-size: 14px; user-select: none; }
summary:hover { background: #f0f4f7; }
.detail-table { margin: 0; border-radius: 0; box-shadow: none; }
.detail-table th { background: #f0f4f7; font-size: 11px; }
.detail-table td { font-size: 12px; }
.detail { color: #777; font-size: 11px; max-width: 320px; }
h3 { margin: 26px 0 10px; color: #33454f; }
"""


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


_ABSENT_HINTS = ("not found", "does not exist", "cannot find", "no such file",
                 "missing", "not present", "path not found", "cannot be found")


def _short_hash(h):
    """Truncate a hash for display; full value available via title attribute."""
    if not h:
        return ""
    return f'<span class="mono" title="{_esc(h)}">{_esc(h[:12])}…</span>'


def _classify_collect(rec):
    """Return (label, css_class) for a collect record: collected / absent / failed."""
    if rec.outcome.startswith("ok"):
        return "Collected", "ok"
    detail_l = (rec.detail or "").lower()
    if any(hint in detail_l for hint in _ABSENT_HINTS):
        return "Absent (not present)", "warn"
    return "Failed", "err"


def generate_collection_report(records, run_folder, hosts, out_path):
    """Build an HTML collection report (summary + per-host per-artefact detail)."""
    host_meta = {h.ip: h for h in hosts}

    by_host = defaultdict(list)
    for r in records:
        if r.host and r.host != "-":
            by_host[r.host].append(r)

    summary_rows = []
    host_sections = []
    tot_collected = tot_absent = tot_failed = tot_matches = tot_mismatches = 0

    for ip, recs in by_host.items():
        h = host_meta.get(ip)
        hostname = (h.hostname if h else "") or ""
        os_name = (h.os_guess.value if h and hasattr(h.os_guess, "value") else "") if h else ""
        profile = (h.profile_name if h else "") or ""

        collect_recs = [r for r in recs if r.action == "collect"]
        h_collected = h_absent = h_failed = h_match = h_mismatch = 0
        art_rows = []
        for r in collect_recs:
            label, cls = _classify_collect(r)
            if cls == "ok":
                h_collected += 1
            elif cls == "warn":
                h_absent += 1
            else:
                h_failed += 1
            if r.match == "Y":
                h_match += 1
            elif r.match == "N":
                h_mismatch += 1

            match_cell = ""
            if r.match == "Y":
                match_cell = '<span class="match-y">✓ match</span>'
            elif r.match == "N":
                match_cell = '<span class="match-n">✗ MISMATCH</span>'

            art_rows.append(
                f"<tr><td>{_esc(r.artefact)}</td>"
                f"<td class='{cls}'>{_esc(label)}</td>"
                f"<td>{_short_hash(r.source_hash)}</td>"
                f"<td>{_short_hash(r.received_hash)}</td>"
                f"<td>{match_cell}</td>"
                f"<td class='mono'>{_esc(r.size_bytes)}</td>"
                f"<td class='detail'>{_esc(r.detail)}</td></tr>")

        tot_collected += h_collected
        tot_absent += h_absent
        tot_failed += h_failed
        tot_matches += h_match
        tot_mismatches += h_mismatch

        mism_txt = (f' · <span class="match-n">{h_mismatch} mismatch</span>'
                    if h_mismatch else "")
        summary_rows.append(
            f"<tr><td class='mono'>{_esc(ip)}</td><td>{_esc(hostname)}</td>"
            f"<td>{_esc(os_name)}</td><td>{_esc(profile)}</td>"
            f"<td class='ok'>{h_collected}</td>"
            f"<td class='{'warn' if h_absent else ''}'>{h_absent}</td>"
            f"<td class='{'err' if h_failed else ''}'>{h_failed}</td>"
            f"<td>{h_match}</td>"
            f"<td>{'<span class=match-n>'+str(h_mismatch)+'</span>' if h_mismatch else '0'}</td></tr>")

        # collapsible per-host detail section
        art_table = ("".join(art_rows) if art_rows
                     else "<tr><td colspan='7' class='detail'>No artefact records.</td></tr>")
        host_sections.append(f"""
  <details>
    <summary><b>{_esc(ip)}</b> {_esc(hostname)} — {h_collected} collected,
      {h_absent} absent, {h_failed} failed{mism_txt}</summary>
    <table class="detail-table">
      <tr><th>Artefact</th><th>Status</th><th>Source hash</th><th>Received hash</th>
          <th>Integrity</th><th>Size</th><th>Detail</th></tr>
      {art_table}
    </table>
  </details>""")

    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    integrity_class = "err" if tot_mismatches else "ok"
    integrity_text = (f"{tot_mismatches} MISMATCH(ES) — review required" if tot_mismatches
                      else "All collected artefacts passed integrity verification")

    doc = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>KingfishIR Collection Report - {_esc(run_folder)}</title>
<style>{_CSS}{_CSS_L2}</style></head><body>
<div class="header">
  <h1>KingfishIR — Collection Report</h1>
  <div class="sub">Run: {_esc(run_folder)} &nbsp;·&nbsp; Generated: {_esc(generated)}</div>
</div>
<div class="wrap">
  <div class="cards">
    <div class="card"><div class="n">{len(by_host)}</div><div class="l">Hosts</div></div>
    <div class="card"><div class="n ok">{tot_collected}</div><div class="l">Collected</div></div>
    <div class="card"><div class="n warn">{tot_absent}</div><div class="l">Absent</div></div>
    <div class="card"><div class="n {'err' if tot_failed else ''}">{tot_failed}</div><div class="l">Failed</div></div>
    <div class="card"><div class="n">{tot_matches}</div><div class="l">Hash matches</div></div>
    <div class="card"><div class="n {integrity_class}">{tot_mismatches}</div><div class="l">Mismatches</div></div>
  </div>
  <p>Integrity: <span class="{integrity_class}">{integrity_text}</span></p>

  <h3>Per-host summary</h3>
  <table>
    <tr><th>Host</th><th>Hostname</th><th>OS</th><th>Profile</th>
        <th>Collected</th><th>Absent</th><th>Failed</th><th>Matches</th><th>Mismatches</th></tr>
    {''.join(summary_rows)}
  </table>

  <h3>Per-host detail <span style="font-weight:400;color:#888;font-size:13px">(click a host to expand)</span></h3>
  {''.join(host_sections)}
</div>
<div class="foot">Generated by KingfishIR. This report summarises the audit record for
this run; the authoritative chain-of-custody log is in triage_audit.csv. Hash values
are truncated for display — hover to see the full value.</div>
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