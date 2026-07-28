# Remote Triage Collector (working title)

Cross-platform, agentless forensic triage tool. Python controller reaching
Windows targets over WinRM/PowerShell Remoting (pypsrp) and Unix-like targets
over SSH (paramiko).

## Layout

* `core/`        research logic: discovery, access, collection, models, hashing, audit, credentials, artefacts
* `transports/`  protocol wrappers behind one `Transport` interface
* `gui/`         thin GUI layer (three tabs + log panel)
* `main.py`      entry point

