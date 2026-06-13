import re
import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Union, Any

from .log_parser import LogEntry

logger = logging.getLogger(__name__)


@dataclass
class WhitelistMatch:
    matched: bool
    rule_name: str
    rule_id: str
    reason: str = ""
    match_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class WhitelistRule:
    id: str
    name: str
    description: str = ""
    enabled: bool = True
    priority: int = 100
    ip_addresses: list[str] = field(default_factory=list)
    ip_networks: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    port_ranges: list[tuple[int, int]] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    match_type: str = "any"
    exclude_from_blocking: bool = True
    log_hits: bool = True
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "WhitelistRule":
        port_ranges = []
        for pr in data.get('port_ranges', []):
            if isinstance(pr, (list, tuple)) and len(pr) == 2:
                port_ranges.append((int(pr[0]), int(pr[1])))
            elif isinstance(pr, str) and '-' in pr:
                start, end = pr.split('-', 1)
                port_ranges.append((int(start.strip()), int(end.strip())))

        return cls(
            id=data.get('id', ''),
            name=data.get('name', data.get('id', 'Unnamed Whitelist')),
            description=data.get('description', ''),
            enabled=data.get('enabled', True),
            priority=int(data.get('priority', 100)),
            ip_addresses=[str(x) for x in data.get('ip_addresses', data.get('ips', []))],
            ip_networks=[str(x) for x in data.get('ip_networks', data.get('cidrs', []))],
            ports=[int(x) for x in data.get('ports', [])],
            port_ranges=port_ranges,
            protocols=[str(x).upper() for x in data.get('protocols', [])],
            match_type=data.get('match_type', 'any').lower(),
            exclude_from_blocking=data.get('exclude_from_blocking', True),
            log_hits=data.get('log_hits', True),
            extra=data.get('extra', {}),
        )

    def parse_cidr(self, cidr: str) -> Optional[ipaddress._BaseNetwork]:
        try:
            return ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning(f"Invalid CIDR in whitelist rule {self.id}: {cidr}")
            return None

    def _ip_matches(self, ip: Optional[str]) -> bool:
        if not ip:
            return False

        if ip in self.ip_addresses:
            return True

        for cidr in self.ip_networks:
            network = self.parse_cidr(cidr)
            if network:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj in network:
                        return True
                except ValueError:
                    continue

        return False

    def _port_matches(self, port: Optional[int]) -> bool:
        if port is None:
            return False

        if port in self.ports:
            return True

        for start, end in self.port_ranges:
            if start <= port <= end:
                return True

        return False

    def _protocol_matches(self, protocol: Optional[str]) -> bool:
        if not protocol:
            return False
        return protocol.upper() in [p.upper() for p in self.protocols]

    def matches(self, entry: LogEntry) -> WhitelistMatch:
        if not self.enabled:
            return WhitelistMatch(matched=False, rule_id=self.id, rule_name=self.name)

        match_fields: dict[str, Any] = {}
        checks_passed = 0
        checks_total = 0

        if self.ip_addresses or self.ip_networks:
            checks_total += 2
            src_match = self._ip_matches(entry.source_ip)
            dst_match = self._ip_matches(entry.dest_ip)
            if src_match:
                match_fields['source_ip'] = entry.source_ip
                checks_passed += 1
            if dst_match:
                match_fields['dest_ip'] = entry.dest_ip
                checks_passed += 1

        if self.ports or self.port_ranges:
            checks_total += 2
            src_port_match = self._port_matches(entry.source_port)
            dst_port_match = self._port_matches(entry.dest_port)
            if src_port_match:
                match_fields['source_port'] = entry.source_port
                checks_passed += 1
            if dst_port_match:
                match_fields['dest_port'] = entry.dest_port
                checks_passed += 1

        if self.protocols:
            checks_total += 1
            proto_match = self._protocol_matches(entry.protocol)
            if proto_match:
                match_fields['protocol'] = entry.protocol
                checks_passed += 1

        if checks_total == 0:
            return WhitelistMatch(matched=False, rule_id=self.id, rule_name=self.name)

        if self.match_type == 'all':
            matched = checks_passed == checks_total
        else:
            matched = checks_passed > 0

        reason_parts = []
        if 'source_ip' in match_fields:
            reason_parts.append(f"source IP {match_fields['source_ip']}")
        if 'dest_ip' in match_fields:
            reason_parts.append(f"dest IP {match_fields['dest_ip']}")
        if 'source_port' in match_fields:
            reason_parts.append(f"source port {match_fields['source_port']}")
        if 'dest_port' in match_fields:
            reason_parts.append(f"dest port {match_fields['dest_port']}")
        if 'protocol' in match_fields:
            reason_parts.append(f"protocol {match_fields['protocol']}")

        return WhitelistMatch(
            matched=matched,
            rule_id=self.id,
            rule_name=self.name,
            reason=', '.join(reason_parts),
            match_fields=match_fields,
        )


class WhitelistManager:
    def __init__(self, rules: Optional[list[WhitelistRule]] = None):
        self._rules: list[WhitelistRule] = []
        self._hit_count: dict[str, int] = {}
        self._last_hit: dict[str, datetime] = {}

        if rules:
            for rule in rules:
                self.add_rule(rule)

    def add_rule(self, rule: WhitelistRule):
        if not rule.id:
            rule.id = f"whitelist_{len(self._rules) + 1}"
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)
        self._hit_count[rule.id] = 0
        logger.info(f"Added whitelist rule: {rule.id} - {rule.name} (priority={rule.priority})")

    def add_rule_from_dict(self, data: dict):
        self.add_rule(WhitelistRule.from_dict(data))

    def remove_rule(self, rule_id: str):
        self._rules = [r for r in self._rules if r.id != rule_id]
        self._hit_count.pop(rule_id, None)
        self._last_hit.pop(rule_id, None)
        logger.info(f"Removed whitelist rule: {rule_id}")

    def get_rule(self, rule_id: str) -> Optional[WhitelistRule]:
        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        return None

    def list_rules(self) -> list[WhitelistRule]:
        return list(self._rules)

    def check(self, entry: LogEntry) -> Optional[WhitelistMatch]:
        for rule in self._rules:
            match = rule.matches(entry)
            if match.matched:
                self._hit_count[rule.id] = self._hit_count.get(rule.id, 0) + 1
                self._last_hit[rule.id] = datetime.now()

                if rule.log_hits:
                    logger.info(
                        f"[WHITELIST-HIT] Rule: {rule.name} ({rule.id}) | "
                        f"Reason: {match.reason} | "
                        f"Source: {entry.source_ip}:{entry.source_port or '-'} | "
                        f"Dest: {entry.dest_ip}:{entry.dest_port or '-'} | "
                        f"Total hits: {self._hit_count[rule.id]}"
                    )

                return match

        return None

    def is_whitelisted(self, entry: LogEntry) -> bool:
        return self.check(entry) is not None

    def should_exclude_from_blocking(self, entry: LogEntry) -> Optional[WhitelistMatch]:
        match = self.check(entry)
        if match and match.matched:
            rule = self.get_rule(match.rule_id)
            if rule and rule.exclude_from_blocking:
                return match
        return None

    def get_hit_stats(self) -> dict[str, dict]:
        stats = {}
        for rule in self._rules:
            stats[rule.id] = {
                'name': rule.name,
                'hits': self._hit_count.get(rule.id, 0),
                'last_hit': self._last_hit.get(rule.id),
            }
        return stats

    def reset_stats(self, rule_id: Optional[str] = None):
        if rule_id:
            self._hit_count[rule_id] = 0
            self._last_hit.pop(rule_id, None)
        else:
            for rid in self._hit_count:
                self._hit_count[rid] = 0
            self._last_hit.clear()
