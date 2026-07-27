"""The artefact catalogue (Tab 3, methodology s3.5.4).

Curated triage set of high-value artefacts, mapped to the KAPE (Windows) and
UAC (Unix) categories reviewed in Chapter 2. This is deliberately a TRIAGE set,
not full-disk parity - breadth is where the single-platform incumbents win and
is out of scope (see future work).

Collection patterns used:
  - command        : is_command=True, output captured as text/CSV
  - unlocked file  : is_command=False
  - locked file    : is_command=False + prepare= (export an unlocked copy first)
  - directory      : is_command=False + prepare= (zip on target) + is_archive=True

Volatility drives collection order (NFR3): live command output is most volatile
(80-95); on-disk artefacts are persistent (10-20).
"""

from __future__ import annotations

from .models import Artefact, OSFamily

_WIN_STAGE = "{stage}"      # filled in per-run by collection with the working dir

# --- Windows ---------------------------------------------------------------
WINDOWS_CATALOGUE: list[Artefact] = [
    # Volatile - live state, collected first.
    Artefact("win_proc", "Running processes", "Volatile", OSFamily.WINDOWS,
             volatility=95,
             spec="Get-Process | Select-Object * | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_netconn", "Network connections", "Volatile", OSFamily.WINDOWS,
             volatility=95,
             spec="Get-NetTCPConnection | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_sessions", "Logged-on users", "Volatile", OSFamily.WINDOWS,
             volatility=90, spec="query user"),
    Artefact("win_services", "Services", "Volatile", OSFamily.WINDOWS,
             volatility=85,
             spec="Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_tasks", "Scheduled tasks", "Volatile", OSFamily.WINDOWS,
             volatility=80,
             spec="Get-ScheduledTask | Select-Object TaskName,TaskPath,State | ConvertTo-Csv -NoTypeInformation"),

    # Registry hives - locked; export an unlocked copy with reg save.
    Artefact("win_reg_system", "SYSTEM hive", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\rtc_system.hiv",
             prepare=rf"reg save HKLM\SYSTEM {_WIN_STAGE}\rtc_system.hiv /y"),
    Artefact("win_reg_software", "SOFTWARE hive", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\rtc_software.hiv",
             prepare=rf"reg save HKLM\SOFTWARE {_WIN_STAGE}\rtc_software.hiv /y"),
    Artefact("win_reg_sam", "SAM hive", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\rtc_sam.hiv",
             prepare=rf"reg save HKLM\SAM {_WIN_STAGE}\rtc_sam.hiv /y"),
    Artefact("win_reg_security", "SECURITY hive", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\rtc_sechive.hiv",
             prepare=rf"reg save HKLM\SECURITY {_WIN_STAGE}\rtc_sechive.hiv /y"),

    # Event logs - locked; export with wevtutil epl.
    Artefact("win_evtx_security", "Security event log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\rtc_security.evtx",
             prepare=rf"wevtutil epl Security {_WIN_STAGE}\rtc_security.evtx /ow:true"),
    Artefact("win_evtx_system", "System event log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\rtc_system_evtx.evtx",
             prepare=rf"wevtutil epl System {_WIN_STAGE}\rtc_system_evtx.evtx /ow:true"),
    Artefact("win_evtx_application", "Application event log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\rtc_application.evtx",
             prepare=rf"wevtutil epl Application {_WIN_STAGE}\rtc_application.evtx /ow:true"),
    Artefact("win_evtx_powershell", "PowerShell operational log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\rtc_pwsh.evtx",
             prepare=rf'wevtutil epl "Microsoft-Windows-PowerShell/Operational" {_WIN_STAGE}\rtc_pwsh.evtx /ow:true'),

    # Evidence of Execution.
    Artefact("win_prefetch", "Prefetch", "EvidenceOfExecution", OSFamily.WINDOWS,
             volatility=15, is_command=False, is_archive=True,
             spec=rf"{_WIN_STAGE}\rtc_prefetch.zip",
             prepare=(rf"robocopy C:\Windows\Prefetch {_WIN_STAGE}\pf *.pf /B /R:0 /W:0 /NP /NFL /NDL /NJH /NJS > $null 2>&1; "
                      rf"Compress-Archive -Path {_WIN_STAGE}\pf\* -DestinationPath {_WIN_STAGE}\rtc_prefetch.zip -Force")),
    Artefact("win_amcache", "Amcache", "EvidenceOfExecution", OSFamily.WINDOWS,
             volatility=15, is_command=False,
             spec=rf"{_WIN_STAGE}\rtc_amcache.hve",
             prepare=(rf"robocopy C:\Windows\AppCompat\Programs {_WIN_STAGE}\amc Amcache.hve "
                      rf"/B /R:0 /W:0 /NP /NFL /NDL /NJH /NJS > $null 2>&1; "
                      rf"Move-Item {_WIN_STAGE}\amc\Amcache.hve {_WIN_STAGE}\rtc_amcache.hve -Force")),

    Artefact("win_srum", "SRUM database", "EvidenceOfExecution", OSFamily.WINDOWS,
             volatility=15, is_command=False,
             spec=rf"{_WIN_STAGE}\rtc_srudb.dat",
             prepare=(rf"robocopy C:\Windows\System32\sru {_WIN_STAGE}\sru SRUDB.dat "
                      rf"/B /R:0 /W:0 /NP /NFL /NDL /NJH /NJS > $null 2>&1; "
                      rf"Move-Item {_WIN_STAGE}\sru\SRUDB.dat {_WIN_STAGE}\rtc_srudb.dat -Force")),
]
# --- Unix-like -------------------------------------------------------------
_NIX_STAGE = "{stage}"

UNIX_CATALOGUE: list[Artefact] = [
    # Volatile.
    Artefact("nix_proc", "Running processes", "Volatile", OSFamily.UNIX,
             volatility=95, spec="ps aux"),
    Artefact("nix_netconn", "Network connections", "Volatile", OSFamily.UNIX,
             volatility=95, spec="ss -tunap"),
    Artefact("nix_who", "Logged-on users", "Volatile", OSFamily.UNIX,
             volatility=90, spec="who -a"),
    Artefact("nix_cron_list", "User crontab", "Volatile", OSFamily.UNIX,
             volatility=80, spec="crontab -l 2>/dev/null; echo '--- /etc/crontab ---'; cat /etc/crontab 2>/dev/null"),

    # Logs - root-owned; zip via sudo into /tmp, chmod so UnixUser can fetch it.
    Artefact("nix_varlog", "System logs (/var/log)", "SystemLogs", OSFamily.UNIX,
             volatility=15, is_command=False, is_archive=True, requires_sudo=True,
             spec=f"{_NIX_STAGE}/rtc_varlog.zip",
             prepare=f"sh -c 'cd /var/log && zip -r {_NIX_STAGE}/rtc_varlog.zip . >/dev/null 2>&1; chmod 644 {_NIX_STAGE}/rtc_varlog.zip'"),

    # Root shell history - copy out via sudo, then fetch the readable copy.
    Artefact("nix_bash_history", "Root shell history", "History", OSFamily.UNIX,
             volatility=15, is_command=False, requires_sudo=True,
             spec=f"{_NIX_STAGE}/rtc_root_bash_history",
             prepare=f"sh -c 'cp /root/.bash_history {_NIX_STAGE}/rtc_root_bash_history; chmod 644 {_NIX_STAGE}/rtc_root_bash_history'"),
 
    Artefact("nix_lastlog", "Last login per user", "Volatile", OSFamily.UNIX,
             volatility=85, spec="lastlog"),
]

def catalogue_for(os_family: OSFamily) -> list[Artefact]:
    if os_family is OSFamily.WINDOWS:
        return WINDOWS_CATALOGUE
    if os_family is OSFamily.UNIX:
        return UNIX_CATALOGUE
    return []