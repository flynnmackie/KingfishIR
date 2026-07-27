"""Unix-like transport over SSH via paramiko.

IMPLEMENT the methods below. Pointers:
  - paramiko.SSHClient(); set_missing_host_key_policy(...) (decide your policy
    deliberately and note it for the evaluation); connect(host, username=...,
    password=... OR key_filename=...).
  - exec_command(cmd) returns (stdin, stdout, stderr); read stdout for output.
  - open_sftp().get(remote, local) to fetch files.
  - remote_hash: run `sha256sum <path>` on the target and parse the first field.
"""

from __future__ import annotations

import socket

import paramiko

from core.models import AccessState, CredentialProfile, CredKind
from .base import Transport

SSH_PORT = 22


class SSHTransport(Transport):
    def __init__(self, host_ip: str, profile: CredentialProfile):
        super().__init__(host_ip, profile)
        self._client: paramiko.SSHClient | None = None

    def _connect(self) -> paramiko.SSHClient:
        """Open (once) and return an authenticated paramiko client."""
        if self._client is not None:
            return self._client

        client = paramiko.SSHClient()
        # Lab policy: auto-accept unknown host keys. Deliberate, and noted for
        # the evaluation - a stricter policy would verify keys first.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs = {
            "hostname": self.host_ip,
            "port": SSH_PORT,
            "username": self.profile.username,
            "timeout": 8,
            "allow_agent": False,     # don't try the SSH agent
            "look_for_keys": False,   # don't try random keys on disk
        }
        if self.profile.kind is CredKind.SSH_KEY:
            kwargs["key_filename"] = self.profile.secret  # path to private key
        else:  # SSH_PASSWORD
            kwargs["password"] = self.profile.secret

        client.connect(**kwargs)
        self._client = client
        return client

    def test_access(self) -> AccessState:
        self.hostname = None
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex((self.host_ip, SSH_PORT)) != 0:
                return AccessState.ABSENT
        try:
            self._connect()
        except paramiko.AuthenticationException:
            return AccessState.PRESENT_NO_AUTH
        except (paramiko.SSHException, OSError):
            return AccessState.PRESENT_NO_AUTH
        try:
            self.hostname = self.run_command("hostname").decode(errors="replace").strip() or None
        except Exception:
            self.hostname = None
        return AccessState.AUTHENTICATED

    def run_command(self, command: str, use_sudo: bool = False) -> bytes:
        client = self._connect()
        if use_sudo:
            # -S reads the password from stdin (no TTY to prompt on);
            # -p '' suppresses the prompt text so it doesn't pollute output.
            sudo_pw = self.profile.sudo_secret or self.profile.secret
            stdin, stdout, _stderr = client.exec_command(f"sudo -S -p '' {command}")
            stdin.write(sudo_pw + "\n")
            stdin.flush()
            return stdout.read()
        _stdin, stdout, _stderr = client.exec_command(command)
        return stdout.read()

    def fetch_file(self, remote_path: str) -> bytes:
        client = self._connect()
        sftp = client.open_sftp()
        try:
            with sftp.open(remote_path, "rb") as f:
                return f.read()
        finally:
            sftp.close()

    def put_file(self, local_path: str, remote_path: str) -> None:
        """Upload a local file to the target over SFTP (the cross-machine copy)."""
        client = self._connect()
        sftp = client.open_sftp()
        try:
            sftp.put(local_path, remote_path)
        finally:
            sftp.close()

    def remote_hash(self, remote_path: str) -> str | None:
        out = self.run_command(f"sha256sum {remote_path}").decode(errors="replace")
        parts = out.split()          # "<hash>  <path>"
        return parts[0] if parts else None

    def delete_remote(self, remote_path: str) -> None:
        # Cleanup should be quiet; -f so a missing file isn't an error.
        self.run_command(f"rm -f {remote_path}", use_sudo=True)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def make_dir(self, path: str) -> None:
        self.run_command(f"mkdir -p {path}")

    def remove_dir(self, path: str) -> None:
        self.run_command(f"rm -rf {path}", use_sudo=True)