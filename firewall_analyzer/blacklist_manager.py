import os
import re
import json
import time
import shlex
import socket
import struct
import threading
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
        auto_sync: bool = True,
        sync_interval_seconds: int = 300,
        strict_consistency: bool = True,
    ):
        self.storage_path = storage_path
        self.auto_save = auto_save
        self.default_expire_hours = default_expire_hours
        self.auto_sync = auto_sync
        self.sync_interval = sync_interval_seconds
        self.strict_consistency = strict_consistency

        self._entries: dict[str, BlacklistEntry] = {}
        self._on_block_callbacks: list[Callable[[BlacklistEntry], None]] = []
        self._on_unblock_callbacks: list[Callable[[BlacklistEntry], None]] = []
        self._last_sync = 0.0
        self._sync_lock = threading.Lock()
        self._stats = {
            'block_attempts': 0,
            'block_success': 0,
            'block_failed': 0,
            'unblock_attempts': 0,
            'unblock_success': 0,
            'unblock_failed': 0,
            'sync_count': 0,
            'inconsistencies_found': 0,
        }

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
            if self.strict_consistency:
                self.sync_with_system(save=False)

    def on_block(self, callback: Callable[[BlacklistEntry], None]):
        self._on_block_callbacks.append(callback)

    def on_unblock(self, callback: Callable[[BlacklistEntry], None]):
        self._on_unblock_callbacks.append(callback)

    def _check_in_blacklist(self, ip: str) -> bool:
        try:
            return self.firewall.is_ip_blocked(ip)
        except Exception as e:
            logger.error(f"Error checking system block status for {ip}: {e}")
            return ip in self._entries

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

        self._stats['block_attempts'] += 1

        if self.strict_consistency and self._check_in_blacklist(ip):
            logger.info(f"IP {ip} is already blocked at system level")
            existing = self._entries.get(ip)
            if existing:
                existing.hits += 1
                existing.added_at = datetime.now()
                existing.reason = reason or existing.reason
                existing.rule_id = rule_id or existing.rule_id
                if extra:
                    existing.extra.update(extra)
                if self.auto_save:
                    self._save()
                self._stats['block_success'] += 1
                return True

        comment = f"{rule_id}: {reason}".strip(": ")
        logger.debug(f"[BLOCK-ATTEMPT] Executing system command to block {ip}...")
        success = self.firewall.block_ip(ip, comment=comment)

        if not success:
            self._stats['block_failed'] += 1
            logger.error(
                f"[BLOCK-FAILED] System command failed for IP {ip}. "
                f"Not adding to internal blacklist to maintain consistency."
            )
            return False

        expire_at = None
        expire_h = expire_hours if expire_hours is not None else self.default_expire_hours
        if expire_h:
            expire_at = datetime.now() + timedelta(hours=expire_h)

        if ip in self._entries:
            entry = self._entries[ip]
            entry.hits += 1
            entry.added_at = datetime.now()
            entry.reason = reason or entry.reason
            entry.rule_id = rule_id or entry.rule_id
            entry.expire_at = expire_at
            if extra:
                entry.extra.update(extra)
        else:
            entry = BlacklistEntry(
                ip_address=ip,
                added_at=datetime.now(),
                reason=reason,
                rule_id=rule_id,
                expire_at=expire_at,
                extra=extra or {},
            )
            self._entries[ip] = entry

        self._stats['block_success'] += 1

        if self.strict_consistency and not self._check_in_blacklist(ip):
            logger.warning(
                f"[INCONSISTENCY] System reports IP {ip} is NOT blocked, "
                f"but our command said it succeeded. Removing from internal list."
            )
            self._entries.pop(ip, None)
            self._stats['block_success'] -= 1
            self._stats['block_failed'] += 1
            self._stats['inconsistencies_found'] += 1
            return False

        logger.warning(
            f"[BLOCK-SUCCESS] {ip} | reason: {reason or 'N/A'} | "
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

        return True

    def unblock_ip(self, ip: str) -> bool:
        if not self._validate_ip(ip):
            logger.error(f"Invalid IP address: {ip}")
            return False

        self._stats['unblock_attempts'] += 1
        in_internal = ip in self._entries
        in_system = self._check_in_blacklist(ip)

        if not in_internal and not in_system:
            logger.debug(f"IP {ip} not blocked in internal list or system")
            return True

        entry = self._entries.get(ip)

        logger.debug(f"[UNBLOCK-ATTEMPT] Executing system command to unblock {ip}...")
        system_success = self.firewall.unblock_ip(ip)

        if self.strict_consistency and not system_success and in_system:
            self._stats['unblock_failed'] += 1
            logger.error(
                f"[UNBLOCK-FAILED] System command failed for IP {ip}. "
                f"Keeping in internal list to maintain consistency."
            )
            return False

        if self.strict_consistency and self._check_in_blacklist(ip):
            self._stats['unblock_failed'] += 1
            logger.warning(
                f"[INCONSISTENCY] System still reports IP {ip} is blocked. "
                f"Not removing from internal list."
            )
            self._stats['inconsistencies_found'] += 1
            return False

        if ip in self._entries:
            self._entries.pop(ip)

        self._stats['unblock_success'] += 1

        if entry:
            logger.info(
                f"[UNBLOCK-SUCCESS] {ip} | was blocked at: {entry.added_at.isoformat()} | "
                f"reason: {entry.reason or 'N/A'}"
            )

            for cb in self._on_unblock_callbacks:
                try:
                    cb(entry)
                except Exception as e:
                    logger.error(f"Error in unblock callback: {e}")

        if self.auto_save:
            self._save()

        return True

    def is_blocked(self, ip: str) -> bool:
        if self.auto_sync and (time.time() - self._last_sync) > self.sync_interval:
            self.sync_with_system(save=True)

        if ip in self._entries:
            entry = self._entries[ip]
            if entry.is_expired:
                logger.debug(f"IP {ip} blacklist entry expired, removing...")
                self.unblock_ip(ip)
                return False

            if self.strict_consistency:
                if not self._check_in_blacklist(ip):
                    logger.warning(
                        f"[INCONSISTENCY] IP {ip} in internal list but not blocked at system level. "
                        f"Removing from internal list."
                    )
                    self._entries.pop(ip, None)
                    self._stats['inconsistencies_found'] += 1
                    if self.auto_save:
                        self._save()
                    return False
            return True

        return False

    def sync_with_system(self, save: bool = True) -> dict:
        with self._sync_lock:
            self._last_sync = time.time()
            self._stats['sync_count'] += 1

            result = {
                'added_to_internal': [],
                'removed_from_internal': [],
                'added_to_system': [],
                'system_blocked': [],
                'internal_blocked': list(self._entries.keys()),
            }

            try:
                system_blocked = set(self.firewall.list_blocked_ips())
                result['system_blocked'] = list(system_blocked)
            except Exception as e:
                logger.error(f"Error getting system blocked IPs: {e}")
                return result

            internal_blocked = set(self._entries.keys())

            only_in_system = system_blocked - internal_blocked
            only_in_internal = internal_blocked - system_blocked

            for ip in only_in_system:
                if self.strict_consistency:
                    entry = BlacklistEntry(
                        ip_address=ip,
                        added_at=datetime.now(),
                        reason="Synced from system firewall",
                        rule_id="system_sync",
                        expire_at=None,
                        extra={'source': 'system_sync'},
                    )
                    self._entries[ip] = entry
                    result['added_to_internal'].append(ip)
                    self._stats['inconsistencies_found'] += 1
                    logger.info(f"[SYNC] Added IP {ip} from system firewall to internal list")

            for ip in only_in_internal:
                entry = self._entries.get(ip)
                if entry and not entry.is_expired:
                    if self.strict_consistency:
                        logger.warning(
                            f"[SYNC] IP {ip} in internal list but not in system. "
                            f"Attempting to re-block..."
                        )
                        success = self.firewall.block_ip(
                            ip,
                            comment=f"{entry.rule_id}: {entry.reason}".strip(": ")
                        )
                        if success:
                            result['added_to_system'].append(ip)
                            logger.info(f"[SYNC] Re-blocked IP {ip} at system level")
                        else:
                            logger.warning(
                                f"[SYNC] Failed to re-block {ip}. Removing from internal list."
                            )
                            self._entries.pop(ip, None)
                            result['removed_from_internal'].append(ip)
                            self._stats['inconsistencies_found'] += 1
                else:
                    logger.info(f"[SYNC] Removing expired IP {ip} from internal list")
                    self._entries.pop(ip, None)
                    result['removed_from_internal'].append(ip)

            if (result['added_to_internal'] or result['removed_from_internal'] or result['added_to_system']) and save:
                logger.info(
                    f"[SYNC] Completed: +{len(result['added_to_internal'])} from system, "
                    f"+{len(result['added_to_system'])} to system, "
                    f"-{len(result['removed_from_internal'])} from internal"
                )
                if self.auto_save:
                    self._save()

            return result

    def get_entry(self, ip: str) -> Optional[BlacklistEntry]:
        entry = self._entries.get(ip)
        if entry and entry.is_expired:
            self.unblock_ip(ip)
            return None
        return entry

    def list_entries(self) -> list[BlacklistEntry]:
        self._cleanup_expired()
        if self.auto_sync and (time.time() - self._last_sync) > self.sync_interval:
            self.sync_with_system(save=True)
        return list(self._entries.values())

    def list_ips(self) -> list[str]:
        self._cleanup_expired()
        if self.auto_sync and (time.time() - self._last_sync) > self.sync_interval:
            self.sync_with_system(save=True)
        return list(self._entries.keys())

    def cleanup_expired(self) -> int:
        return self._cleanup_expired()

    def _cleanup_expired(self) -> int:
        expired = [ip for ip, entry in self._entries.items() if entry.is_expired]
        removed = 0
        for ip in expired:
            if self.unblock_ip(ip):
                removed += 1
        return removed

    def get_stats(self) -> dict:
        return {
            **self._stats,
            'internal_entries': len(self._entries),
            'last_sync': datetime.fromtimestamp(self._last_sync).isoformat() if self._last_sync else None,
        }

    def _save(self):
        if not self.storage_path:
            return
        try:
            data = {
                'saved_at': datetime.now().isoformat(),
                'entries': [entry.to_dict() for entry in self._entries.values()],
                'stats': self._stats,
            }
            dir_path = os.path.dirname(self.storage_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            tmp_path = f"{self.storage_path}.tmp"
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self.storage_path)
            logger.debug(f"Blacklist saved to {self.storage_path} ({len(self._entries)} entries)")
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
            verified = 0

            for ed in entries_data:
                try:
                    entry = BlacklistEntry.from_dict(ed)
                    if entry.is_expired:
                        continue

                    if self.strict_consistency:
                        if not self._check_in_blacklist(entry.ip_address):
                            logger.warning(
                                f"[LOAD-VERIFY] IP {entry.ip_address} in storage but not blocked "
                                f"at system level. Attempting to re-block..."
                            )
                            success = self.firewall.block_ip(
                                entry.ip_address,
                                comment=f"{entry.rule_id}: {entry.reason}".strip(": ")
                            )
                            if not success:
                                logger.warning(
                                    f"[LOAD-VERIFY] Failed to re-block {entry.ip_address}. "
                                    f"Skipping this entry."
                                )
                                continue

                    self._entries[entry.ip_address] = entry
                    loaded += 1
                    verified += 1
                except Exception:
                    continue

            if 'stats' in data:
                for k, v in data['stats'].items():
                    if k in self._stats and isinstance(v, (int, float)):
                        self._stats[k] = v

            logger.info(
                f"Loaded {loaded} blacklist entries from {self.storage_path} "
                f"({verified} verified at system level)"
            )
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
