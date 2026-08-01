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
    # Live State - volatile, collected first (volatility drives order).
    Artefact("win_proc", "Running processes", "Live State", OSFamily.WINDOWS,
             volatility=95, output_ext="csv",
             spec="Get-Process | Select-Object * | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_netconn", "Network connections", "Live State", OSFamily.WINDOWS,
             volatility=95, output_ext="csv",
             spec="Get-NetTCPConnection | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_sessions", "Logged-on users", "Live State", OSFamily.WINDOWS,
             volatility=90, spec="query user"),
    Artefact("win_services", "Services", "Live State", OSFamily.WINDOWS,
             volatility=85, output_ext="csv",
             spec="Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_tasks", "Scheduled tasks", "Live State", OSFamily.WINDOWS,
             volatility=80, output_ext="csv",
             spec="Get-ScheduledTask | Select-Object TaskName,TaskPath,State | ConvertTo-Csv -NoTypeInformation"),

    # Network state (volatile).
    Artefact("win_arp", "ARP cache", "Network", OSFamily.WINDOWS,
             volatility=90, spec="arp -a"),
    Artefact("win_dns", "DNS cache", "Network", OSFamily.WINDOWS,
             volatility=90, output_ext="csv", spec="Get-DnsClientCache | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_netcfg", "Network configuration", "Network", OSFamily.WINDOWS,
             volatility=85, spec="ipconfig /all"),
    Artefact("win_routes", "Routing table", "Network", OSFamily.WINDOWS,
             volatility=85, output_ext="csv", spec="Get-NetRoute | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_smb_sessions", "SMB sessions", "Network", OSFamily.WINDOWS,
             volatility=90, output_ext="csv", spec="Get-SmbSession | ConvertTo-Csv -NoTypeInformation 2>$null"),

    # System context.
    Artefact("win_sysinfo", "System information", "System Info", OSFamily.WINDOWS,
             volatility=70, spec="systeminfo"),
    Artefact("win_localusers", "Local users", "System Info", OSFamily.WINDOWS,
             volatility=70, output_ext="csv",
             spec="Get-LocalUser | Select-Object Name,Enabled,LastLogon,SID | ConvertTo-Csv -NoTypeInformation"),
    Artefact("win_localadmins", "Local administrators", "System Info", OSFamily.WINDOWS,
             volatility=70, output_ext="csv",
             spec="Get-LocalGroupMember -Group Administrators | ConvertTo-Csv -NoTypeInformation 2>$null"),
    Artefact("win_hotfixes", "Installed patches", "System Info", OSFamily.WINDOWS,
             volatility=60, output_ext="csv",
             spec="Get-HotFix | Select-Object HotFixID,InstalledOn,Description | ConvertTo-Csv -NoTypeInformation"),

    # Persistence.
    Artefact("win_autoruns_reg", "Run keys (autostart)", "Persistence", OSFamily.WINDOWS,
             volatility=40,
             spec=(r"reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run; "
                   r"reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run")),
    Artefact("win_startup_folder", "Startup folder", "Persistence", OSFamily.WINDOWS,
             volatility=40, output_ext="csv",
             spec=(r'Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",'
                   r'"$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" '
                   r'-Recurse -ErrorAction SilentlyContinue | Select-Object FullName | ConvertTo-Csv -NoTypeInformation')),
    Artefact("win_tasks_xml", "Scheduled task definitions", "Persistence", OSFamily.WINDOWS,
             volatility=40, is_command=False, is_archive=True,
             spec=rf"{_WIN_STAGE}\kingfishir_tasks.zip",
             prepare=(rf"robocopy C:\Windows\System32\Tasks {_WIN_STAGE}\tasks /E "
                      rf"/R:0 /W:0 /NP /NFL /NDL /NJH /NJS > $null 2>&1; "
                      rf"Compress-Archive -Path {_WIN_STAGE}\tasks\* -DestinationPath {_WIN_STAGE}\kingfishir_tasks.zip -Force")),

    # Registry hives - locked; export an unlocked copy with reg save.
    Artefact("win_reg_system", "SYSTEM hive", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\kingfishir_system.hiv",
             prepare=rf"reg save HKLM\SYSTEM {_WIN_STAGE}\kingfishir_system.hiv /y"),
    Artefact("win_reg_software", "SOFTWARE hive", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\kingfishir_software.hiv",
             prepare=rf"reg save HKLM\SOFTWARE {_WIN_STAGE}\kingfishir_software.hiv /y"),
    Artefact("win_reg_sam", "SAM hive (Alerts Defender)", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\kingfishir_sam.hiv",
             prepare=rf"reg save HKLM\SAM {_WIN_STAGE}\kingfishir_sam.hiv /y"),
    Artefact("win_reg_security", "SECURITY hive (Alerts Defender)", "Hives", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\kingfishir_sechive.hiv",
             prepare=rf"reg save HKLM\SECURITY {_WIN_STAGE}\kingfishir_sechive.hiv /y"),

    # Event logs - locked; export with wevtutil epl.

    # Entire event-log folder - ALL .evtx (hundreds), not just the four above.
    Artefact("win_evtx_all", "ALL EVENT LOGS (entire winevt folder)", "EventLogs",
             OSFamily.WINDOWS, volatility=15, is_command=False, is_archive=True,
             spec=rf"{_WIN_STAGE}\kingfishir_all_evtx.zip",
             prepare=(rf"robocopy C:\Windows\System32\winevt\Logs {_WIN_STAGE}\evtx *.evtx "
                      rf"/B /R:0 /W:0 /NP /NFL /NDL /NJH /NJS > $null 2>&1; "
                      rf"Compress-Archive -Path {_WIN_STAGE}\evtx\* -DestinationPath {_WIN_STAGE}\kingfishir_all_evtx.zip -Force")),
    Artefact("win_evtx_security", "Security event log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\kingfishir_security.evtx",
             prepare=rf"wevtutil epl Security {_WIN_STAGE}\kingfishir_security.evtx /ow:true"),
    Artefact("win_evtx_system", "System event log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\kingfishir_system_evtx.evtx",
             prepare=rf"wevtutil epl System {_WIN_STAGE}\kingfishir_system_evtx.evtx /ow:true"),
    Artefact("win_evtx_application", "Application event log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\kingfishir_application.evtx",
             prepare=rf"wevtutil epl Application {_WIN_STAGE}\kingfishir_application.evtx /ow:true"),
    Artefact("win_evtx_powershell", "PowerShell operational log", "EventLogs", OSFamily.WINDOWS,
             volatility=15, is_command=False, spec=rf"{_WIN_STAGE}\kingfishir_pwsh.evtx",
             prepare=rf'wevtutil epl "Microsoft-Windows-PowerShell/Operational" {_WIN_STAGE}\kingfishir_pwsh.evtx /ow:true'),

    # Evidence of Execution.
    Artefact("win_prefetch", "Prefetch", "EvidenceOfExecution", OSFamily.WINDOWS,
             volatility=15, is_command=False, is_archive=True,
             spec=rf"{_WIN_STAGE}\kingfishir_prefetch.zip",
             prepare=(rf"robocopy C:\Windows\Prefetch {_WIN_STAGE}\pf *.pf /B /R:0 /W:0 /NP /NFL /NDL /NJH /NJS > $null 2>&1; "
                      rf"Compress-Archive -Path {_WIN_STAGE}\pf\* -DestinationPath {_WIN_STAGE}\kingfishir_prefetch.zip -Force")),

    Artefact("win_srum", "SRUM database", "EvidenceOfExecution", OSFamily.WINDOWS,
             volatility=15, is_command=False,
             spec=rf"{_WIN_STAGE}\kingfishir_srudb.dat",
             prepare=(rf"robocopy C:\Windows\System32\sru {_WIN_STAGE}\sru SRUDB.dat "
                      rf"/B /R:0 /W:0 /NP /NFL /NDL /NJH /NJS > $null 2>&1; "
                      rf"Move-Item {_WIN_STAGE}\sru\SRUDB.dat {_WIN_STAGE}\kingfishir_srudb.dat -Force")),

    # --- Browser history (per-user; high value) ---
    Artefact("win_browser", "Browser history (Chrome/Edge)", "Browser", OSFamily.WINDOWS,
             volatility=20, is_command=False, is_archive=True,
             spec=rf"{_WIN_STAGE}\kingfishir_browser.zip",
             prepare=(
                 rf"$d='{_WIN_STAGE}\browser'; md $d -Force | Out-Null; "
                 r"gci C:\Users -Directory | % { "
                 r"$c=Join-Path $_.FullName 'AppData\Local\Google\Chrome\User Data\Default\History'; "
                 r"$e=Join-Path $_.FullName 'AppData\Local\Microsoft\Edge\User Data\Default\History'; "
                 r"if(Test-Path $c){cp $c (Join-Path $d ($_.Name+'_chrome_History')) -Force -EA 0}; "
                 r"if(Test-Path $e){cp $e (Join-Path $d ($_.Name+'_edge_History')) -Force -EA 0} }; "
                 rf"Compress-Archive $d\* {_WIN_STAGE}\kingfishir_browser.zip -Force -EA 0")),

    # --- Recent files / LNK ---
    Artefact("win_recent", "Recent files (LNK)", "EvidenceOfExecution", OSFamily.WINDOWS,
             volatility=20, is_command=False, is_archive=True,
             spec=rf"{_WIN_STAGE}\kingfishir_recent.zip",
             prepare=(
                 rf"$d='{_WIN_STAGE}\recent'; md $d -Force | Out-Null; "
                 r"gci C:\Users -Directory | % { "
                 r"$r=Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent'; "
                 r"if(Test-Path $r){cp $r (Join-Path $d $_.Name) -Recurse -Force -EA 0} }; "
                 rf"Compress-Archive $d\* {_WIN_STAGE}\kingfishir_recent.zip -Force -EA 0")),

    Artefact("win_jumplists", "Jump Lists", "EvidenceOfExecution", OSFamily.WINDOWS,
             volatility=20, is_command=False, is_archive=True,
             spec=rf"{_WIN_STAGE}\kingfishir_jumplists.zip",
             prepare=(
                 rf"$d='{_WIN_STAGE}\jump'; md $d -Force | Out-Null; "
                 r"gci C:\Users -Directory | % { "
                 r"$a=Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations'; "
                 r"$c=Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations'; "
                 r"if(Test-Path $a){cp $a (Join-Path $d ($_.Name+'_Automatic')) -Recurse -Force -EA 0}; "
                 r"if(Test-Path $c){cp $c (Join-Path $d ($_.Name+'_Custom')) -Recurse -Force -EA 0} }; "
                 rf"Compress-Archive $d\* {_WIN_STAGE}\kingfishir_jumplists.zip -Force -EA 0")),

    # --- WMI persistence (event subscriptions) ---
    Artefact("win_wmi_persist", "WMI event subscriptions", "Persistence", OSFamily.WINDOWS,
             volatility=40, output_ext="csv",
             spec=("Get-WmiObject -Namespace root\\Subscription -Class __EventFilter "
                   "-ErrorAction SilentlyContinue | Select-Object Name,Query | "
                   "ConvertTo-Csv -NoTypeInformation; "
                   "Get-WmiObject -Namespace root\\Subscription -Class CommandLineEventConsumer "
                   "-ErrorAction SilentlyContinue | Select-Object Name,CommandLineTemplate | "
                   "ConvertTo-Csv -NoTypeInformation")),

]
# --- Unix-like -------------------------------------------------------------
_NIX_STAGE = "{stage}"

UNIX_CATALOGUE: list[Artefact] = [
    # --- Live State (volatile) ---
    Artefact("nix_lsof", "Open files", "Live State", OSFamily.UNIX,
             volatility=90, spec="lsof -n 2>/dev/null | head -n 5000"),
    Artefact("nix_lsmod", "Loaded kernel modules", "Live State", OSFamily.UNIX,
             volatility=85, spec="lsmod"),
    Artefact("nix_mounts", "Mounted filesystems", "Live State", OSFamily.UNIX,
             volatility=85, spec="mount; echo '--- /proc/mounts ---'; cat /proc/mounts"),
    Artefact("nix_env", "Process environment (init)", "Live State", OSFamily.UNIX,
             volatility=80, spec="cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n'"),

    # --- Network state (volatile) ---
    Artefact("nix_listen", "Listening sockets", "Network", OSFamily.UNIX,
             volatility=90, spec="ss -tulpn 2>/dev/null"),
    Artefact("nix_routes", "Routing table", "Network", OSFamily.UNIX,
             volatility=85, spec="ip route show 2>/dev/null; echo '--- rules ---'; ip rule show 2>/dev/null"),
    Artefact("nix_arp", "ARP / neighbour cache", "Network", OSFamily.UNIX,
             volatility=90, spec="ip neigh show 2>/dev/null"),
    Artefact("nix_ifconfig", "Network interfaces", "Network", OSFamily.UNIX,
             volatility=85, spec="ip addr show 2>/dev/null"),
    Artefact("nix_iptables", "Firewall rules", "Network", OSFamily.UNIX,
             volatility=70, requires_sudo=True,
             spec="iptables-save 2>/dev/null; echo '--- nft ---'; nft list ruleset 2>/dev/null"),
    Artefact("nix_netcfg", "Network config files", "Network", OSFamily.UNIX,
             volatility=40, spec="cat /etc/hosts /etc/resolv.conf /etc/hostname 2>/dev/null"),

    # --- System Info ---
    Artefact("nix_uname", "Kernel / OS version", "System Info", OSFamily.UNIX,
             volatility=60, spec="uname -a; echo '--- release ---'; cat /etc/os-release 2>/dev/null"),
    Artefact("nix_uptime", "Uptime / load", "System Info", OSFamily.UNIX,
             volatility=70, spec="uptime; echo '--- boot ---'; who -b 2>/dev/null"),
    Artefact("nix_packages", "Installed packages", "System Info", OSFamily.UNIX,
             volatility=40,
             spec="(dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || apk info 2>/dev/null)"),

    # --- Accounts ---
    Artefact("nix_passwd", "User accounts (passwd/group)", "Accounts", OSFamily.UNIX,
             volatility=30,
             spec="echo '=== passwd ==='; cat /etc/passwd; echo '=== group ==='; cat /etc/group"),
    Artefact("nix_shadow", "Password hashes (shadow)", "Accounts", OSFamily.UNIX,
             volatility=30, is_command=False, requires_sudo=True,
             spec=f"{_NIX_STAGE}/kingfishir_shadow",
             prepare=f"sh -c 'cp /etc/shadow {_NIX_STAGE}/kingfishir_shadow; chmod 644 {_NIX_STAGE}/kingfishir_shadow'"),
    Artefact("nix_sudoers", "Sudoers configuration", "Accounts", OSFamily.UNIX,
             volatility=30, is_command=False, requires_sudo=True,
             spec=f"{_NIX_STAGE}/kingfishir_sudoers",
             prepare=f"sh -c 'cp /etc/sudoers {_NIX_STAGE}/kingfishir_sudoers 2>/dev/null; cat /etc/sudoers.d/* >> {_NIX_STAGE}/kingfishir_sudoers 2>/dev/null; chmod 644 {_NIX_STAGE}/kingfishir_sudoers'"),

    # --- Persistence ---
    Artefact("nix_cron_system", "System cron jobs", "Persistence", OSFamily.UNIX,
             volatility=40, requires_sudo=True,
             spec=("sh -c 'echo === /etc/crontab ===; cat /etc/crontab 2>/dev/null; "
                   "echo === cron.d ===; cat /etc/cron.d/* 2>/dev/null; "
                   "echo === user spools ===; cat /var/spool/cron/crontabs/* 2>/dev/null'")),
    Artefact("nix_systemd_units", "Systemd services", "Persistence", OSFamily.UNIX,
             volatility=40,
             spec="systemctl list-unit-files --type=service --no-pager 2>/dev/null"),
    Artefact("nix_authkeys", "SSH authorized_keys", "Persistence", OSFamily.UNIX,
             volatility=30, requires_sudo=True,
             spec=("sh -c 'for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; "
                   "do echo \"=== $f ===\"; cat \"$f\" 2>/dev/null; done'")),

    # --- Shell history per user (high-value: attacker commands) ---
    Artefact("nix_user_history", "Shell history (all users)", "Live State", OSFamily.UNIX,
             volatility=35, requires_sudo=True,
             spec=("sh -c 'for f in /root/.bash_history /root/.zsh_history "
                   "/home/*/.bash_history /home/*/.zsh_history; "
                   "do echo \"=== $f ===\"; cat \"$f\" 2>/dev/null; done'")),

    # --- SSH client artefacts per user (lateral movement) ---
    Artefact("nix_ssh_client", "SSH known_hosts & config (all users)", "Persistence", OSFamily.UNIX,
             volatility=30, requires_sudo=True,
             spec=("sh -c 'for f in /root/.ssh/known_hosts /root/.ssh/config "
                   "/home/*/.ssh/known_hosts /home/*/.ssh/config; "
                   "do echo \"=== $f ===\"; cat \"$f\" 2>/dev/null; done'")),

    # --- Authentication / login records ---
    Artefact("nix_auth_logs", "Auth logs (wtmp/btmp/auth)", "Accounts", OSFamily.UNIX,
             volatility=35, is_command=False, requires_sudo=True, is_archive=True,
             spec=f"{_NIX_STAGE}/kingfishir_authlogs.zip",
             prepare=(f"sh -c 'mkdir -p {_NIX_STAGE}/auth; "
                      f"cp /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/auth.log* "
                      f"/var/log/secure* {_NIX_STAGE}/auth/ 2>/dev/null; "
                      f"cd {_NIX_STAGE} && zip -r kingfishir_authlogs.zip auth >/dev/null 2>&1; "
                      f"chmod 644 {_NIX_STAGE}/kingfishir_authlogs.zip'")),

    # --- Recently modified files (triage staple) ---
    Artefact("nix_recent_files", "Recently modified files (7 days)", "Live State", OSFamily.UNIX,
             volatility=40, requires_sudo=True,
             spec=("sh -c 'find /etc /root /home /var /tmp /usr/local -xdev -mtime -7 "
                   "-type f 2>/dev/null | head -n 5000'")),

    # --- Kernel ring buffer (volatile) ---
    Artefact("nix_dmesg", "Kernel ring buffer (dmesg)", "Live State", OSFamily.UNIX,
             volatility=80, requires_sudo=True, spec="dmesg 2>/dev/null | tail -n 2000"),
]

def catalogue_for(os_family: OSFamily) -> list[Artefact]:
    if os_family is OSFamily.WINDOWS:
        return WINDOWS_CATALOGUE
    if os_family is OSFamily.UNIX:
        return UNIX_CATALOGUE
    return []