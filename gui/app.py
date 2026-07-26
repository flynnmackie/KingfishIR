"""Main GUI window. Single-file for now; split into per-tab modules later."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem, QMessageBox,
    QComboBox, QListWidget, QListWidgetItem, QHeaderView
)
from PySide6.QtCore import QThread, Signal, QObject, Qt, QSize
from PySide6.QtGui import QColor, QIcon

from core.discovery import expand_targets, discover
from core.models import OSFamily

from core.credentials import CredentialStore
from core.models import OSFamily, CredentialProfile, CredKind, AccessState

from core.artefacts import catalogue_for
from core.collection import collect_from_host, run_timestamp
from transports.winrm_transport import WinRMTransport
from transports.ssh_transport import SSHTransport



# Colour palette (soft backgrounds so text stays readable).
_CONF_COLOURS = {
    "high":   QColor(200, 230, 201),   # green
    "medium": QColor(255, 236, 179),   # amber
    "low":    QColor(224, 224, 224),   # grey
}
_OS_COLOURS = {
    OSFamily.WINDOWS: QColor(187, 222, 251),   # blue
    OSFamily.UNIX:    QColor(255, 224, 178),   # orange
}


class AppState:
    """Shared data the tabs pass between each other (discovery -> access -> collect)."""
    def __init__(self):
        self.hosts = []
        self.store = CredentialStore()      # shared credential profiles


class ScanWorker(QObject):
    host_found = Signal(object)
    progress = Signal(int, int, str)      # done, total
    finished = Signal(int)
    error = Signal(str)

    def __init__(self, ips):
            super().__init__()
            self.ips = ips
            self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
            total = len(self.ips)
            self._done = 0
            def on_start(ip):
                self._done += 1
                self.progress.emit(self._done, total, ip)     # announce as we begin
            def on_host(host):
                if host.is_up:
                    self.host_found.emit(host)
            try:
                discover(self.ips, progress=on_host,
                        should_stop=lambda: self._stop, on_start=on_start)
            except Exception as exc:
                self.error.emit(str(exc))
            self.finished.emit(total)

class VerifyWorker(QObject):
    """Runs verify_host for each host on a background thread."""
    host_done = Signal(object)      # emits a Host after verification
    finished = Signal()
    error = Signal(str)

    def __init__(self, hosts, store, audit):
        super().__init__()
        self.hosts = hosts
        self.store = store
        self.audit = audit

    def run(self):
        from core.access import verify_host
        for host in self.hosts:
            try:
                verify_host(host, self.store, self.audit)
            except Exception as exc:
                self.audit.log(host.ip, "verify", outcome="error", detail=str(exc))
            self.host_done.emit(host)
        self.finished.emit()

class DiscoveryTab(QWidget):
    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self.scanned_count = 0
        layout = QVBoxLayout(self)

        row = QHBoxLayout()
        row.addWidget(QLabel("Target(s):"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("10.10.10.100-103   ·   192.168.1.0/24   ·   single IP")
        row.addWidget(self.target_input)
        self.scan_btn = QPushButton("Scan")
        self.scan_btn.clicked.connect(self.on_scan)
        row.addWidget(self.scan_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.on_stop)
        self.stop_btn.setEnabled(False)
        row.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.on_clear)
        self.clear_btn.setStyleSheet(
            "QPushButton { background-color: #a33; color: white; }"
            "QPushButton:hover { background-color: #c44; }"
        )
        row.addWidget(self.clear_btn)

        layout.addLayout(row)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["Host", "Status", "Last Scanned", "OS Guess", "Confidence", "Basis", ""])
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setColumnWidth(6, 110)      # fixed, sensible width for the button column
        layout.addWidget(self.table)

        self.status_label = QLabel("Ready.")
        layout.addWidget(self.status_label)

    def on_scan(self):
        text = self.target_input.text().strip()
        if not text:
            return
        try:
            ips = expand_targets(text)
        except Exception as exc:
            QMessageBox.warning(self, "Invalid target", f"Could not parse that:\n{exc}")
            return

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.scan_btn.setText("Scanning…")
        self.status_label.setText(f"Scanning {len(ips)} address(es)…")


        self.thread = QThread()
        self.worker = ScanWorker(ips)
        self.worker.error.connect(lambda msg: QMessageBox.warning(self, "Scan error", msg))
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.host_found.connect(self.on_host_found)
        self.worker.finished.connect(self.on_scan_done)
        self.worker.finished.connect(self.thread.quit)
        self.worker.progress.connect(self.on_progress)
        self.thread.start()

    def on_clear(self):
        if not self.state.hosts:
            return
        reply = QMessageBox.question(
            self, "Clear hosts",
            "Remove all discovered hosts? Assigned profiles and verification results will be lost.",
        )
        if reply != QMessageBox.Yes:
            return
        self.state.hosts = []
        self.table.setRowCount(0)
        self.status_label.setText("Host list cleared.")

    def on_host_found(self, host):
        from datetime import datetime
        now = datetime.now().strftime("%H:%M:%S")
        # If already in the list, refresh its last-scanned time and row.
        for existing in self.state.hosts:
            if existing.ip == host.ip:
                existing.last_scanned = now
                self.refresh_row(existing)
                return
        host.last_scanned = now
        self.state.hosts.append(host)
        self.add_row(host)

    def on_scan_done(self, total_scanned):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.scan_btn.setText("Scan")
        total = len(self.state.hosts)
        self.status_label.setText(f"{total} host(s) in list ({total_scanned} scanned this pass).")

    def on_stop(self):
            if hasattr(self, "worker") and self.worker:
                self.worker.stop()
            self.status_label.setText("Stopping…")
            self.stop_btn.setEnabled(False)

    def on_progress(self, done, total, current_ip):
        self.status_label.setText(f"Scanning {done} of {total} addresses… ({current_ip})")

    def add_row(self, h):
        r = self.table.rowCount()
        self.table.insertRow(r)
        cells = [
            h.ip,
            "UP",
            h.last_scanned,
            h.os_guess.value.capitalize(),
            h.confidence.upper(),
            h.fingerprint_basis,
        ]
        for c, val in enumerate(cells):
            item = QTableWidgetItem(str(val))
            self.table.setItem(r, c, item)

        for col in (1, 2, 3, 4):          # Status, Last Scanned, OS, Confidence
            self.table.item(r, col).setTextAlignment(Qt.AlignCenter)

        # OS guess is now column 3, Confidence column 4.
        os_colour = _OS_COLOURS.get(h.os_guess)
        if os_colour:
            self.table.item(r, 3).setBackground(os_colour)
            self.table.item(r, 3).setForeground(QColor(20, 20, 20))
        conf_colour = _CONF_COLOURS.get(h.confidence)
        if conf_colour:
            self.table.item(r, 4).setBackground(conf_colour)
            self.table.item(r, 4).setForeground(QColor(20, 20, 20))

        self.table.item(r, 1).setForeground(QColor(46, 125, 50))
        # Per-host remove button (captures IP, not row - rows shift on delete).
        remove_btn = QPushButton("Remove")
        remove_btn.setMaximumWidth(90)
        remove_btn.setStyleSheet(
            "QPushButton { background-color: #a33; color: white; padding: 2px 8px; }"
            "QPushButton:hover { background-color: #c44; }"
        )
        remove_btn.clicked.connect(lambda _, ip=h.ip: self.remove_host(ip))
        self.table.setCellWidget(r, 6, remove_btn)

    def refresh_row(self, h):
            from PySide6.QtCore import QTimer
            for r in range(self.table.rowCount()):
                if self.table.item(r, 0).text() == h.ip:
                    item = QTableWidgetItem(h.last_scanned)
                    item.setTextAlignment(Qt.AlignCenter)
                    item.setForeground(QColor(80, 220, 100))       # flash GREEN TEXT
                    self.table.setItem(r, 2, item)
                    QTimer.singleShot(800, lambda rr=r: self._clear_flash(rr))
                    break

    def _clear_flash(self, r):
        if r < self.table.rowCount():
            cell = self.table.item(r, 2)
            if cell:
                cell.setForeground(QColor(224, 224, 244))          # back to dark bg

    def remove_host(self, ip):
        # Remove from the shared list.
        self.state.hosts = [h for h in self.state.hosts if h.ip != ip]
        # Remove from the table by finding its current row.
        for r in range(self.table.rowCount()):
            if self.table.item(r, 0) and self.table.item(r, 0).text() == ip:
                self.table.removeRow(r)
                break
        self.status_label.setText(f"Removed {ip}. {len(self.state.hosts)} host(s) in list.")
# Friendly labels -> the CredKind the model expects.
_KIND_CHOICES = {
    "Windows (domain)": CredKind.DOMAIN_KERBEROS,
    "Windows (standalone)": CredKind.LOCAL_NTLM,
    "Linux (SSH)": CredKind.SSH_PASSWORD,
}

class AccessTab(QWidget):
    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        from core.audit import AuditLog
        self.audit = AuditLog("triage_audit.csv")
        layout = QHBoxLayout(self)

        # ---- Left: host table with a profile dropdown per row ----
        left = QVBoxLayout()
        left.addWidget(QLabel("Discovered hosts"))
        self.host_table = QTableWidget(0, 5)
        self.host_table.setHorizontalHeaderLabels(
            ["Host", "OS", "Profile", "WinRM", "SSH"])
        header = self.host_table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Fixed)     # Host
        self.host_table.setColumnWidth(0, 120)
        header.setSectionResizeMode(1, QHeaderView.Fixed)     # OS
        self.host_table.setColumnWidth(1, 110)
        header.setSectionResizeMode(2, QHeaderView.Fixed)     # Profile
        self.host_table.setColumnWidth(2, 150)
        header.setSectionResizeMode(3, QHeaderView.Stretch)   # WinRM
        header.setSectionResizeMode(4, QHeaderView.Stretch)   # SSH
        left.addWidget(self.host_table)

        btn_row = QHBoxLayout()
        self.load_btn = QPushButton("Load hosts from discovery")
        self.load_btn.clicked.connect(self.load_hosts)
        btn_row.addWidget(self.load_btn)
        self.verify_btn = QPushButton("Verify access")
        self.verify_btn.clicked.connect(self.on_verify)
        self.verify_btn.setEnabled(False)
        btn_row.addWidget(self.verify_btn)
        left.addLayout(btn_row)
        layout.addLayout(left, 5)

        # ---- Right: credential profile creation ----
        right = QVBoxLayout()
        right.addWidget(QLabel("Create credential profile"))

        self.name_in = QLineEdit(); self.name_in.setPlaceholderText("Profile name")
        self.kind_in = QComboBox(); self.kind_in.addItems(_KIND_CHOICES.keys())
        self.domain_in = QLineEdit(); self.domain_in.setPlaceholderText("Domain")
        self.user_in = QLineEdit(); self.user_in.setPlaceholderText("Username")
        self.pass_in = QLineEdit(); self.pass_in.setPlaceholderText("Password")
        self.pass_in.setEchoMode(QLineEdit.Password)
        self.sudo_in = QLineEdit(); self.sudo_in.setPlaceholderText("Sudo password (optional)")
        self.sudo_in.setEchoMode(QLineEdit.Password)

        for w in (self.name_in, self.kind_in, self.domain_in,
                  self.user_in, self.pass_in, self.sudo_in):
            right.addWidget(w)

        self.add_profile_btn = QPushButton("Add profile")
        self.add_profile_btn.clicked.connect(self.add_profile)
        right.addWidget(self.add_profile_btn)

        right.addWidget(QLabel("Profiles"))
        self.profile_list = QListWidget()
        right.addWidget(self.profile_list)
        right.addStretch()
        layout.addLayout(right, 1)

        # show/hide the right fields based on the selected kind
        self.kind_in.currentTextChanged.connect(self.update_fields)
        self.update_fields()          # set initial visibility

    def update_fields(self):
        """Show only the fields relevant to the selected credential kind."""
        kind = _KIND_CHOICES[self.kind_in.currentText()]
        is_domain = kind is CredKind.DOMAIN_KERBEROS
        is_ssh = kind in (CredKind.SSH_KEY, CredKind.SSH_PASSWORD)
        # Domain field only for Windows domain; sudo field only for Linux.
        self.domain_in.setVisible(is_domain)
        self.sudo_in.setVisible(is_ssh)

    # ---- profile creation ----
    def add_profile(self):
        name = self.name_in.text().strip()
        user = self.user_in.text().strip()
        if not name or not user:
            QMessageBox.warning(self, "Missing fields", "Profile needs at least a name and username.")
            return
        kind = _KIND_CHOICES[self.kind_in.currentText()]
        profile = CredentialProfile(
            name=name, kind=kind, username=user,
            secret=self.pass_in.text(),
            domain=self.domain_in.text().strip() or None,
            sudo_secret=self.sudo_in.text(),
        )
        self.state.store.add(profile)
        self.refresh_profiles()
        for w in (self.name_in, self.domain_in, self.user_in, self.pass_in, self.sudo_in):
            w.clear()

    def refresh_profiles(self):
        self.profile_list.clear()
        for name in self.state.store.names():
            # a row: profile name + a small red delete button
            row = QWidget()
            row_lay = QHBoxLayout(row)
            row_lay.setContentsMargins(4, 2, 4, 2)
            row_lay.addWidget(QLabel(name))
            row_lay.addStretch()
            del_btn = QPushButton("Delete")
            del_btn.setMaximumWidth(70)
            del_btn.setStyleSheet(
                "QPushButton { background-color: #a33; color: white; padding: 2px 8px; }"
                "QPushButton:hover { background-color: #c44; }")
            del_btn.clicked.connect(lambda _, n=name: self.delete_profile(n))
            row_lay.addWidget(del_btn)

            item = QListWidgetItem()
            hint = row.sizeHint()
            hint.setHeight(34)
            item.setSizeHint(hint)
            self.profile_list.addItem(item)
            self.profile_list.setItemWidget(item, row)

        # keep every host row's dropdown in sync with the current profiles
        for r in range(self.host_table.rowCount()):
            combo = self.host_table.cellWidget(r, 2)
            if combo:
                current = combo.currentText()
                combo.clear()
                combo.addItem("— none —")
                combo.addItems(self.state.store.names())
                combo.setCurrentText(current if current in self.state.store.names() else "— none —")

    # ---- host loading ----
    def load_hosts(self):
        hosts = self.state.hosts
        self.host_table.setRowCount(0)
        for h in hosts:
            r = self.host_table.rowCount()
            self.host_table.insertRow(r)
            host_item = QTableWidgetItem(h.ip)
            host_item.setTextAlignment(Qt.AlignCenter)
            font = host_item.font()
            font.setBold(True)
            host_item.setFont(font)
            self.host_table.setItem(r, 0, host_item)
            os_item = QTableWidgetItem(h.os_guess.value.capitalize())
            os_item.setTextAlignment(Qt.AlignCenter)
            os_colour = _OS_COLOURS.get(h.os_guess)
            if os_colour:
                os_item.setBackground(os_colour)
                os_item.setForeground(QColor(20, 20, 20))
            self.host_table.setItem(r, 1, os_item)
            combo = QComboBox()
            combo.setStyleSheet("QComboBox { text-align: center; }")
            combo.setMaximumWidth(120)
            combo.addItem("— none —")
            combo.addItems(self.state.store.names())
            self.host_table.setCellWidget(r, 2, combo)
            self.host_table.setItem(r, 3, QTableWidgetItem("—"))
            self.host_table.setItem(r, 4, QTableWidgetItem("—"))
        self.verify_btn.setEnabled(len(hosts) > 0)

    def delete_profile(self, name):
        self.state.store.remove(name)
        # unassign it from any host that was using it
        for h in self.state.hosts:
            if h.profile_name == name:
                h.profile_name = None
        self.refresh_profiles()

    def on_verify(self):
        hosts = self.state.hosts
        for r, host in enumerate(hosts):
            combo = self.host_table.cellWidget(r, 2)
            choice = combo.currentText() if combo else "— none —"
            host.profile_name = None if choice == "— none —" else choice

        if not any(h.profile_name for h in hosts):
            QMessageBox.warning(self, "No profiles assigned",
                                "Assign a credential profile to at least one host first.")
            return

        self.verify_btn.setEnabled(False)
        self.verify_btn.setText("Verifying…")

        self.v_thread = QThread()
        self.v_worker = VerifyWorker(hosts, self.state.store, self.audit)
        self.v_worker.moveToThread(self.v_thread)
        self.v_thread.started.connect(self.v_worker.run)
        self.v_worker.host_done.connect(self.on_host_verified)
        self.v_worker.finished.connect(self.on_verify_done)
        self.v_worker.finished.connect(self.v_thread.quit)
        self.v_thread.start()

    def on_host_verified(self, host):
        for r in range(self.host_table.rowCount()):
            if self.host_table.item(r, 0).text() == host.ip:
                self._set_state_cell(r, 3, host.winrm_state, host.hostname)
                self._set_state_cell(r, 4, host.ssh_state, host.hostname)
                break

    def on_verify_done(self):
        self.verify_btn.setEnabled(True)
        self.verify_btn.setText("Verify access")

    def _set_state_cell(self, row, col, state, hostname=None):
        labels = {
            AccessState.AUTHENTICATED: ("Authenticated", QColor(200, 230, 201)),
            AccessState.PRESENT_NO_AUTH: ("Creds Rejected", QColor(255, 205, 210)),
            AccessState.ABSENT: ("absent", QColor(224, 224, 224)),
        }
        text, colour = labels.get(state, ("—", None))
        if state is AccessState.AUTHENTICATED and hostname:
            text = f"Authenticated · {hostname}"
        item = QTableWidgetItem(text)
        item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        if colour:
            item.setBackground(colour)
            item.setForeground(QColor(20, 20, 20))
        if state is AccessState.AUTHENTICATED and hostname:
            font = item.font()
            font.setBold(True)
            item.setFont(font)
        self.host_table.setItem(row, col, item)

class CollectWorker(QObject):
    """Runs collection for each selected host on a background thread."""
    log_row = Signal(object)        # emits an AuditRecord as it happens
    host_done = Signal(str, int, int)   # ip, ok_count, total
    finished = Signal(str)          # run folder
    error = Signal(str)

    def __init__(self, hosts, selected_ids, store, audit, run_folder):
        super().__init__()
        self.hosts = hosts
        self.selected_ids = selected_ids     # set of artefact ids the user ticked
        self.store = store
        self.audit = audit
        self.run_folder = run_folder

    def run(self):
        # live-feed the audit log into the Log tab
        self.audit.subscribe(self.log_row.emit)
        for host in self.hosts:
            try:
                profile = self.store.get(host.profile_name)
                if host.actual_os is OSFamily.UNIX:
                    transport = SSHTransport(host.ip, profile)
                else:
                    transport = WinRMTransport(host.ip, profile)

                # platform-filter: only this host's-OS artefacts that were ticked
                catalogue = catalogue_for(host.actual_os)
                chosen = [a for a in catalogue if a.id in self.selected_ids]

                results = collect_from_host(host, chosen, transport, self.audit,
                                            out_root="collected", run_folder=self.run_folder)
                transport.close()
                ok = sum(1 for r in results if r.collected)
                self.host_done.emit(host.ip, ok, len(results))
            except Exception as exc:
                self.error.emit(f"{host.ip}: {exc}")
        self.finished.emit(self.run_folder)

class CollectTab(QWidget):
    def __init__(self, state: AppState, audit, log_tab):
        super().__init__()
        self.state = state
        self.audit = audit
        self.log_tab = log_tab
        self.current_os = OSFamily.WINDOWS
        self.checked_artefacts = set()      # artefact ids checked, survives OS switch
        layout = QHBoxLayout(self)

        # ---- Left: host checklist ----
        left = QVBoxLayout()
        left.addWidget(QLabel("Collect from (authenticated hosts)"))
        self.host_list = QListWidget()
        left.addWidget(self.host_list)
        self.load_btn = QPushButton("Load authenticated hosts")
        self.load_btn.clicked.connect(self.load_hosts)
        left.addWidget(self.load_btn)
        layout.addLayout(left, 1)

        # ---- Right: artefact selection with OS toggle ----
        right = QVBoxLayout()
        right.addWidget(QLabel("Artefacts to collect"))

        toggle_row = QHBoxLayout()
        toggle_row.setSpacing(0)
        self.win_btn = QPushButton("Windows")
        self.win_btn.clicked.connect(lambda: self.switch_os(OSFamily.WINDOWS))
        self.unix_btn = QPushButton("Unix")
        self.unix_btn.clicked.connect(lambda: self.switch_os(OSFamily.UNIX))
        toggle_row.addWidget(self.win_btn)
        toggle_row.addWidget(self.unix_btn)
        right.addLayout(toggle_row)

        self.artefact_list = QListWidget()
        self.artefact_list.setSelectionMode(QListWidget.NoSelection)
        self.artefact_list.itemChanged.connect(self.on_item_changed)
        self.artefact_list.setObjectName("artefactList")
        right.addWidget(self.artefact_list)

        self.collect_btn = QPushButton("Start collection")
        self.collect_btn.clicked.connect(self.on_collect)
        right.addWidget(self.collect_btn)
        self.status = QLabel("")
        right.addWidget(self.status)
        layout.addLayout(right, 1)

        self.switch_os(OSFamily.WINDOWS)     # initial view

    def _toggle_style(self, active):
        """Return (windows_style, unix_style) with the active side underlined."""
        blue, orange = "#bbdefb", "#ffe0b2"        # match _OS_COLOURS
        win_border = "4px solid #1976d2" if active is OSFamily.WINDOWS else "4px solid transparent"
        unix_border = "4px solid #e07a24" if active is OSFamily.UNIX else "4px solid transparent"
        win = (f"QPushButton {{ background-color: {blue}; color: #141414; "
               f"border: none; border-bottom: {win_border}; padding: 8px; }}")
        unix = (f"QPushButton {{ background-color: {orange}; color: #141414; "
                f"border: none; border-bottom: {unix_border}; padding: 8px; }}")
        return win, unix

    def switch_os(self, os_family):
        self.current_os = os_family
        win_style, unix_style = self._toggle_style(os_family)
        self.win_btn.setStyleSheet(win_style)
        self.unix_btn.setStyleSheet(unix_style)
        self.populate_artefacts()

    def populate_artefacts(self):
        self.artefact_list.blockSignals(True)     # don't fire itemChanged while building
        self.artefact_list.clear()
        for a in catalogue_for(self.current_os):
            item = QListWidgetItem(a.name)
            item.setSizeHint(QSize(0, 18))
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if a.id in self.checked_artefacts else Qt.Unchecked)
            item.setData(Qt.UserRole, a.id)
            self.artefact_list.addItem(item)
        self.artefact_list.blockSignals(False)

    def on_item_changed(self, item):
        # keep the persistent set in sync as the user ticks/unticks
        aid = item.data(Qt.UserRole)
        if item.checkState() == Qt.Checked:
            self.checked_artefacts.add(aid)
        else:
            self.checked_artefacts.discard(aid)

    def load_hosts(self):
        self.host_list.clear()
        for h in self.state.hosts:
            authed = (h.winrm_state is AccessState.AUTHENTICATED or
                      h.ssh_state is AccessState.AUTHENTICATED)
            if not authed:
                continue
            label = f"{h.ip} · {h.hostname}" if h.hostname else h.ip
            item = QListWidgetItem(label)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            item.setData(Qt.UserRole, h.ip)
            os_colour = _OS_COLOURS.get(h.actual_os)
            if os_colour:
                item.setForeground(os_colour)
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            self.host_list.addItem(item)

    def on_collect(self):
        chosen_ips = {self.host_list.item(i).data(Qt.UserRole)
                      for i in range(self.host_list.count())
                      if self.host_list.item(i).checkState() == Qt.Checked}
        hosts = [h for h in self.state.hosts if h.ip in chosen_ips]
        selected_ids = set(self.checked_artefacts)      # from the persistent set

        if not hosts or not selected_ids:
            QMessageBox.warning(self, "Nothing selected",
                                "Tick at least one host and one artefact.")
            return

        self.collect_btn.setEnabled(False)
        self.collect_btn.setText("Collecting…")
        self.log_tab.clear()

        run_folder = run_timestamp()
        self.c_thread = QThread()
        self.c_worker = CollectWorker(hosts, selected_ids, self.state.store,
                                      self.audit, run_folder)
        self.c_worker.moveToThread(self.c_thread)
        self.c_thread.started.connect(self.c_worker.run)
        self.c_worker.log_row.connect(self.log_tab.add_row)
        self.c_worker.host_done.connect(self.on_host_done)
        self.c_worker.error.connect(lambda m: QMessageBox.warning(self, "Collection error", m))
        self.c_worker.finished.connect(self.on_done)
        self.c_worker.finished.connect(self.c_thread.quit)
        self.c_thread.start()

    def on_host_done(self, ip, ok, total):
        self.status.setText(f"{ip}: {ok}/{total} artefacts collected")

    def on_done(self, run_folder):
        self.collect_btn.setEnabled(True)
        self.collect_btn.setText("Start collection")
        self.status.setText(f"Done. Output under collected/{run_folder}/")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Remote Triage Collector")
        self.resize(1200, 500)
        self.state = AppState()

        tabs = QTabWidget()
        tabs.addTab(DiscoveryTab(self.state), "1 · Discovery")
        access = AccessTab(self.state)
        tabs.addTab(access, "2 · Access")
        log_tab = LogTab()
        collect = CollectTab(self.state, access.audit, log_tab)
        tabs.addTab(collect, "3 · Collect")
        tabs.addTab(log_tab, "Log")
        self.setCentralWidget(tabs)

class LogTab(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Activity log (chain of custody)"))
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Host", "Action", "Artefact", "Size", "Match"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

    def clear(self):
        self.table.setRowCount(0)

    def add_row(self, rec):
        r = self.table.rowCount()
        self.table.insertRow(r)
        cells = [rec.timestamp.split("T")[-1], rec.host, rec.action,
                 rec.artefact, rec.size_bytes, rec.match]
        for c, v in enumerate(cells):
            self.table.setItem(r, c, QTableWidgetItem(str(v)))
        if rec.match == "Y":
            self.table.item(r, 5).setBackground(QColor(200, 230, 201))
            self.table.item(r, 5).setForeground(QColor(20, 20, 20))   # after line 515
        elif rec.outcome == "error":
            self.table.item(r, 2).setBackground(QColor(255, 205, 210))
            self.table.item(r, 2).setForeground(QColor(20, 20, 20))   # after line 517

def run():
    app = QApplication([])
    app.setWindowIcon(QIcon("kingfisher.ico"))
    app.setStyleSheet("""
        QWidget { background-color: #1e1e1e; color: #e0e0e0; }
        QLineEdit, QComboBox, QListWidget, QTableWidget {
            background-color: #2b2b2b; color: #e0e0e0; border: 1px solid #3c3c3c;
        }
        QPushButton {
            background-color: #0e639c; color: white; border: none;
            padding: 6px 14px; border-radius: 3px;
        }
        QPushButton:hover { background-color: #1177bb; }
        QPushButton:disabled { background-color: #3c3c3c; color: #888; }
        QHeaderView::section {
            background-color: #333; color: #e0e0e0; padding: 4px; border: none;
        }
        QTabBar::tab {
            background: #2b2b2b; color: #bbb; padding: 8px 16px;
        }
        QTabBar::tab:selected { background: #1e1e1e; color: white; }

        QListWidget::item {
            padding: 6px 4px;
            border-bottom: 1px solid #3c3c3c;
        }
        QListWidget::indicator {
            width: 16px;
            height: 16px;
            border: 1px solid #6a6a6a;
            border-radius: 3px;
            background-color: #4a4a4a;
        }
        QListWidget::indicator:checked {
            background-color: #1b5e20;
            border: 1px solid #43a047;
        }
        QListWidget#artefactList { font-size: 12px; }
        QListWidget#artefactList::indicator {
            width: 13px;
            height: 13px;
        }
    """)
    window = MainWindow()
    window.show()
    app.exec()