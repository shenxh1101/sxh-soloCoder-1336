import os
import re
import json
import time
import shlex
import socket
import struct
import ipaddress
import platform
import logging
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Optional, Callable, Any

logger = logging.getLogger(__name__)


@dataclass
class BlacklistEntry:
    ip_address: str
    added_at: datetime
    reason: str = ""
    rule_id: str = ""
    expire_at: Optional[datetime] = None
    hits: int = 1
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        if self.expire_at is None:
            return False
        return datetime.now() > self.expire_at

    def to_dict(self) -> dict:
        data = asdict(self)
        data['added_at'] = self.added_at.isoformat()
        data['expire_at'] = self.expire_at.isoformat() if self.expire_at else None
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "BlacklistEntry":
        entry = cls(
            ip_address=data['ip_address'],
            added_at=datetime.fromisoformat(data['added_at']) if isinstance(data.get('added_at'), str) else data.get('added_at', datetime.now()),
            reason=data.get('reason', ''),
            rule_id=data.get('rule_id', ''),
            expire_at=datetime.fromisoformat(data['expire_at']) if data.get('expire_at') else None,
            hits=data.get('hits', 1),
            extra=data.get('extra', {}),
        )
        return entry


class SystemCommandExecutor:
    def __init__(self, dry_run: bool = False, timeout: int = 30):
        self.dry_run = dry_run
        self.timeout = timeout
        self._system = platform.system().lower()

    @property
    def is_linux(self) -> bool:
        return self._system == 'linux'

    @property
    def is_windows(self) -> bool:
        return self._system == 'windows'

    @property
    def is_macos(self) -> bool:
        return self._system == 'darwin'

    def run(self, command: str, shell: bool = False) -> tuple[int, str, str]:
        logger.debug(f"Executing command: {command}")

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would execute: {command}")
            return 0, "", ""

        try:
            if not shell and self.is_windows:
                args = command
                use_shell = True
            elif not shell:
                args = shlex.split(command)
                use_shell = False
            else:
                args = command
                use_shell = True

            result = subprocess.run(
                args,
                shell=use_shell,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            if result.returncode != 0:
                logger.error(
                    f"Command failed (exit {result.returncode}): {command}\n"
                    f"stderr: {result.stderr}"
                )
            else:
                logger.debug(f"Command succeeded: {command}")

            return result.returncode, result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {self.timeout}s: {command}")
            return -1, "", "Timeout"
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            return -2, "", str(e)


class IPTablesManager:
    CHAIN_NAME = "FW_ANALYZER_BLOCK"

    def __init__(self, executor: Optional[SystemCommandExecutor] = None):
        self.executor = executor or SystemCommandExecutor()

    def block_ip(self, ip: str, permanent: bool = True, comment: str = "") -> bool:
        if not self._validate_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False

        if self.is_ip_blocked(ip):
            logger.info(f"IP {ip} is already blocked")
            return True

        comment_str = f' -m comment --comment "{comment}"' if comment else ''

        commands = [
            f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null",
        ]

        rc, _, _ = self.executor.run(commands[0], shell=True)
        if rc == 0:
            logger.info(f"IP {ip} already blocked (rule exists)")
            return True

        block_cmd = f"iptables -I INPUT -s {ip} -j DROP{comment_str}"
        rc, _, _ = self.executor.run(block_cmd, shell=True)
        if rc == 0:
            logger.info(f"Successfully blocked IP: {ip}")
            return True
        else:
            alt_cmd = f"iptables -A INPUT -s {ip} -j DROP{comment_str}"
            rc, _, _ = self.executor.run(alt_cmd, shell=True)
            return rc == 0

    def unblock_ip(self, ip: str) -> bool:
        if not self._validate_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False

        removed = False
        for chain in ['INPUT', 'FORWARD']:
            while True:
                cmd = f"iptables -D {chain} -s {ip} -j DROP 2>/dev/null"
                rc, _, _ = self.executor.run(cmd, shell=True)
                if rc == 0:
                    removed = True
                else:
                    break

        if removed:
            logger.info(f"Successfully unblocked IP: {ip}")
        else:
            logger.debug(f"No blocking rules found for IP: {ip}")

        return removed

    def is_ip_blocked(self, ip: str) -> bool:
        cmd = f"iptables -L INPUT -n -v | grep '{ip}'"
        rc, stdout, _ = self.executor.run(cmd, shell=True)
        if rc == 0 and ip in stdout:
            return True
        return False

    def list_blocked_ips(self) -> list[str]:
        cmd = "iptables -L INPUT -n | awk '/DROP/ {print $4}'"
        rc, stdout, _ = self.executor.run(cmd, shell=True)
        if rc == 0:
            ips = [line.strip() for line in stdout.strip().split('\n') if line.strip()]
            return list(set(ips))
        return []

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


class WindowsFirewallManager:
    RULE_NAME_PREFIX = "FWAnalyzer_Block_"

    def __init__(self, executor: Optional[SystemCommandExecutor] = None):
        self.executor = executor or SystemCommandExecutor()

    def block_ip(self, ip: str, permanent: bool = True, comment: str = "") -> bool:
        if not self._validate_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False

        if self.is_ip_blocked(ip):
            logger.info(f"IP {ip} is already blocked")
            return True

        rule_name = f"{self.RULE_NAME_PREFIX}{ip}"
        display_name = comment if comment else f"FW Analyzer - Block {ip}"

        cmd = (
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f'dir=in action=block remoteip={ip} enable=yes profile=any '
            f'description="{display_name}"'
        )

        rc, stdout, stderr = self.executor.run(cmd, shell=True)
        if rc == 0 or '已经存在' in stdout or 'already exists' in stdout.lower():
            logger.info(f"Successfully blocked IP: {ip}")
            return True
        else:
            ps_cmd = (
                f'New-NetFirewallRule -DisplayName "{display_name}" '
                f'-Direction Inbound -Action Block -RemoteAddress {ip} '
                f'-Name "{rule_name}" -ErrorAction SilentlyContinue'
            )
            rc2, _, _ = self.executor.run(f'powershell -Command "{ps_cmd}"', shell=True)
            if rc2 == 0:
                logger.info(f"Successfully blocked IP via PowerShell: {ip}")
                return True

        logger.error(f"Failed to block IP {ip}: {stderr}")
        return False

    def unblock_ip(self, ip: str) -> bool:
        if not self._validate_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False

        rule_name = f"{self.RULE_NAME_PREFIX}{ip}"
        removed = False

        cmd1 = f'netsh advfirewall firewall delete rule name="{rule_name}" remoteip={ip}'
        rc1, _, _ = self.executor.run(cmd1, shell=True)
        removed = removed or (rc1 == 0)

        cmd2 = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        rc2, stdout, _ = self.executor.run(cmd2, shell=True)
        if rc2 == 0 and ('删除' in stdout or 'deleted' in stdout.lower() or 'No' not in stdout):
            removed = True

        ps_cmd = f'Remove-NetFirewallRule -Name "{rule_name}" -ErrorAction SilentlyContinue'
        rc3, _, _ = self.executor.run(f'powershell -Command "{ps_cmd}"', shell=True)
        removed = removed or (rc3 == 0)

        if removed:
            logger.info(f"Successfully unblocked IP: {ip}")
        else:
            logger.debug(f"No blocking rules found for IP: {ip}")

        return removed

    def is_ip_blocked(self, ip: str) -> bool:
        rule_name = f"{self.RULE_NAME_PREFIX}{ip}"
        cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
        rc, stdout, _ = self.executor.run(cmd, shell=True)
        if rc == 0 and ('规则' in stdout or 'Rule Name' in stdout or 'Block' in stdout):
            return True
        return False

    def list_blocked_ips(self) -> list[str]:
        ips = []
        cmd = 'netsh advfirewall firewall show rule name=all | findstr "RemoteIP FWAnalyzer"'
        rc, stdout, _ = self.executor.run(cmd, shell=True)
        if rc == 0:
            for line in stdout.strip().split('\n'):
                line = line.strip()
                match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
                if match:
                    ips.append(match.group(1))
        return list(set(ips))

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


class NullFirewallManager:
    def __init__(self):
        self._blocked: set[str] = set()

    def block_ip(self, ip: str, permanent: bool = True, comment: str = "") -> bool:
        self._blocked.add(ip)
        logger.info(f"[NULL-BLOCK] Would block IP: {ip} (comment: {comment})")
        return True

    def unblock_ip(self, ip: str) -> bool:
        if ip in self._blocked:
            self._blocked.remove(ip)
            logger.info(f"[NULL-UNBLOCK] Would unblock IP: {ip}")
            return True
        return False

    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def list_blocked_ips(self) -> list[str]:
        return sorted(self._blocked)


class BlacklistManager:
    def __init__(
        self,
        storage_path: Optional[str] = None,
        auto_save: bool = True,
        default_expire_hours: Optional[int] = None,
    ):
        self.storage_path = storage_path
        self.auto_save = auto_save
        self.default_expire_hours = default_expire_hours
        self._entries: dict[str, BlacklistEntry] = {}
        self._on_block_callbacks: list[Callable[[BlacklistEntry], None]] = []
        self._on_unblock_callbacks: list[Callable[[BlacklistEntry], None]] = []

        system = platform.system().lower()
        if system == 'linux':
            self.firewall = IPTablesManager()
        elif system == 'windows':
            self.firewall = WindowsFirewallManager()
        else:
            self.firewall = NullFirewallManager()
            logger.warning(f"Unsupported platform: {system}, using null firewall manager")

        if storage_path and os.path.exists(storage_path):
            self._load()

    def on_block(self, callback: Callable[[BlacklistEntry], None]):
        self._on_block_callbacks.append(callback)

    def on_unblock(self, callback: Callable[[BlacklistEntry], None]):
        self._on_unblock_callbacks.append(callback)

    def block_ip(
        self,
        ip: str,
        reason: str = "",
        rule_id: str = "",
        expire_hours: Optional[int] = None,
        extra: Optional[dict] = None,
    ) -> bool:
        if not self._validate_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False

        if ip in self._entries:
            entry = self._entries[ip]
            entry.hits += 1
            entry.added_at = datetime.now()
            entry.reason = reason or entry.reason
            entry.rule_id = rule_id or entry.rule_id
            if extra:
                entry.extra.update(extra)
        else:
            expire_at = None
            expire_h = expire_hours if expire_hours is not None else self.default_expire_hours
            if expire_h:
                expire_at = datetime.now() + timedelta(hours=expire_h)

            entry = BlacklistEntry(
                ip_address=ip,
                added_at=datetime.now(),
                reason=reason,
                rule_id=rule_id,
                expire_at=expire_at,
                extra=extra or {},
            )
            self._entries[ip] = entry

        comment = f"{rule_id}: {reason}".strip(": ")
        success = self.firewall.block_ip(ip, comment=comment)

        if success:
            logger.warning(
                f"IP BLOCKED: {ip} | reason: {reason or 'N/A'} | "
                f"rule: {rule_id or 'N/A'} | "
                f"expires: {entry.expire_at.isoformat() if entry.expire_at else 'never'}"
            )
            for cb in self._on_block_callbacks:
                try:
                    cb(entry)
                except Exception as e:
                    logger.error(f"Error in block callback: {e}")

            if self.auto_save:
                self._save()

        return success

    def unblock_ip(self, ip: str) -> bool:
        if ip not in self._entries:
            logger.debug(f"IP {ip} not in blacklist")
            return self.firewall.unblock_ip(ip)

        entry = self._entries.pop(ip)
        success = self.firewall.unblock_ip(ip)

        logger.info(f"IP UNBLOCKED: {ip} | was blocked at: {entry.added_at.isoformat()}")

        for cb in self._on_unblock_callbacks:
            try:
                cb(entry)
            except Exception as e:
                logger.error(f"Error in unblock callback: {e}")

        if self.auto_save:
            self._save()

        return success

    def is_blocked(self, ip: str) -> bool:
        if ip in self._entries:
            entry = self._entries[ip]
            if entry.is_expired:
                logger.debug(f"IP {ip} blacklist entry expired, removing...")
                self.unblock_ip(ip)
                return False
            return True
        return False

    def get_entry(self, ip: str) -> Optional[BlacklistEntry]:
        entry = self._entries.get(ip)
        if entry and entry.is_expired:
            self.unblock_ip(ip)
            return None
        return entry

    def list_entries(self) -> list[BlacklistEntry]:
        self._cleanup_expired()
        return list(self._entries.values())

    def list_ips(self) -> list[str]:
        self._cleanup_expired()
        return list(self._entries.keys())

    def cleanup_expired(self) -> int:
        return self._cleanup_expired()

    def _cleanup_expired(self) -> int:
        expired = [ip for ip, entry in self._entries.items() if entry.is_expired]
        for ip in expired:
            self.unblock_ip(ip)
        return len(expired)

    def _save(self):
        if not self.storage_path:
            return
        try:
            data = {
                'saved_at': datetime.now().isoformat(),
                'entries': [entry.to_dict() for entry in self._entries.values()],
            }
            dir_path = os.path.dirname(self.storage_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.debug(f"Blacklist saved to {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to save blacklist: {e}")

    def _load(self):
        if not self.storage_path or not os.path.exists(self.storage_path):
            return
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            entries_data = data.get('entries', [])
            loaded = 0
            for ed in entries_data:
                try:
                    entry = BlacklistEntry.from_dict(ed)
                    if entry.is_expired:
                        continue
                    self._entries[entry.ip_address] = entry
                    loaded += 1
                except Exception:
                    continue
            logger.info(f"Loaded {loaded} blacklist entries from {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to load blacklist: {e}")

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def execute_custom_command(self, command: str, ip: Optional[str] = None) -> tuple[int, str, str]:
        if ip:
            command = command.replace('{IP}', ip)
            command = command.replace('$IP', ip)
        executor = getattr(self.firewall, 'executor', SystemCommandExecutor())
        return executor.run(command, shell=True)
