import re
import os
import json
import time
import ipaddress
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
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
class WhitelistHit:
    id: str
    timestamp: datetime
    rule_id: str
    rule_name: str
    source_ip: Optional[str]
    dest_ip: Optional[str]
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: Optional[str]
    skipped_block: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "WhitelistHit":
        d = dict(data)
        d['timestamp'] = datetime.fromisoformat(d['timestamp'])
        return cls(**d)


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
    def __init__(self, rules: Optional[list[WhitelistRule]] = None,
                 storage_path: Optional[str] = None,
                 max_history_days: int = 30):
        self._rules: list[WhitelistRule] = []
        self._hit_count: dict[str, int] = {}
        self._last_hit: dict[str, datetime] = {}
        self._skipped_blocks: dict[str, int] = {}
        self._hit_history: list[WhitelistHit] = []
        self._storage_path = storage_path
        self._max_history_days = max_history_days
        self._lock = threading.Lock()
        self._last_save = 0.0
        self._auto_save_interval = 30

        if rules:
            for rule in rules:
                self.add_rule(rule)

        if self._storage_path:
            self._load()

    def add_rule(self, rule: WhitelistRule):
        if not rule.id:
            rule.id = f"whitelist_{len(self._rules) + 1}"
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)
        self._hit_count[rule.id] = self._hit_count.get(rule.id, 0)
        self._skipped_blocks[rule.id] = self._skipped_blocks.get(rule.id, 0)
        logger.info(f"Added whitelist rule: {rule.id} - {rule.name} (priority={rule.priority})")

    def add_rule_from_dict(self, data: dict):
        self.add_rule(WhitelistRule.from_dict(data))

    def remove_rule(self, rule_id: str):
        self._rules = [r for r in self._rules if r.id != rule_id]
        self._hit_count.pop(rule_id, None)
        self._last_hit.pop(rule_id, None)
        self._skipped_blocks.pop(rule_id, None)
        logger.info(f"Removed whitelist rule: {rule_id}")

    def get_rule(self, rule_id: str) -> Optional[WhitelistRule]:
        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        return None

    def list_rules(self) -> list[WhitelistRule]:
        return list(self._rules)

    def check(self, entry: LogEntry, would_block: bool = False) -> Optional[WhitelistMatch]:
        for rule in self._rules:
            if not rule.enabled:
                continue
            match = rule.matches(entry)
            if match.matched:
                with self._lock:
                    hit_marker = f"_wl_hit_{rule.id}"
                    skip_marker = f"_wl_skip_{rule.id}"
                    hist_marker = f"_wl_hist_{rule.id}"

                    hit_added_now = False
                    skip_added_now = False

                    if not entry.extra.get(hit_marker):
                        self._hit_count[rule.id] = self._hit_count.get(rule.id, 0) + 1
                        self._last_hit[rule.id] = datetime.now()
                        entry.extra[hit_marker] = True
                        hit_added_now = True

                    skip_now = False
                    if would_block and rule.exclude_from_blocking:
                        if not entry.extra.get(skip_marker):
                            self._skipped_blocks[rule.id] = self._skipped_blocks.get(rule.id, 0) + 1
                            entry.extra[skip_marker] = True
                            skip_added_now = True
                        skip_now = True

                    if not entry.extra.get(hist_marker):
                        hit = WhitelistHit(
                            id=f"wl_hit_{int(time.time()*1000)}_{id(self)}",
                            timestamp=datetime.now(),
                            rule_id=rule.id,
                            rule_name=rule.name,
                            source_ip=entry.source_ip,
                            dest_ip=entry.dest_ip,
                            source_port=entry.source_port,
                            dest_port=entry.dest_port,
                            protocol=entry.protocol,
                            skipped_block=skip_now,
                            reason=match.reason,
                        )
                        self._hit_history.append(hit)
                        entry.extra[hist_marker] = id(hit)
                        hit_added_now = True
                    elif skip_added_now:
                        # Update the existing history entry's skipped_block flag
                        existing_hit_id = entry.extra.get(hist_marker)
                        for h in reversed(self._hit_history):
                            if id(h) == existing_hit_id:
                                h.skipped_block = True
                                break

                    if hit_added_now or skip_added_now:
                        self._save()

                if rule.log_hits:
                    skip_msg = " [BLOCK-SKIPPED]" if (would_block and rule.exclude_from_blocking and skip_now) else ""
                    logger.info(
                        f"[WHITELIST-HIT] Rule: {rule.name} ({rule.id}) | "
                        f"Reason: {match.reason} | "
                        f"Source: {entry.source_ip}:{entry.source_port or '-'} | "
                        f"Dest: {entry.dest_ip}:{entry.dest_port or '-'} | "
                        f"Total hits: {self._hit_count[rule.id]}{skip_msg}"
                    )

                return match

        return None

    def is_whitelisted(self, entry: LogEntry) -> bool:
        return self.check(entry) is not None

    def should_exclude_from_blocking(self, entry: LogEntry) -> Optional[WhitelistMatch]:
        match = self.check(entry, would_block=True)
        if match and match.matched:
            rule = self.get_rule(match.rule_id)
            if rule and rule.exclude_from_blocking:
                return match
        return None

    def get_hit_stats(self, hours: Optional[int] = None) -> dict[str, dict]:
        stats = {}
        cutoff = datetime.now() - timedelta(hours=hours) if hours else None

        for rule in self._rules:
            history = self._hit_history
            if cutoff is not None:
                history = [h for h in history if h.timestamp >= cutoff]

            rule_hits = [h for h in history if h.rule_id == rule.id]
            total = len(rule_hits)
            skipped = sum(1 for h in rule_hits if h.skipped_block)
            ips = set(h.source_ip for h in rule_hits if h.source_ip)
            last = max((h.timestamp for h in rule_hits), default=None)
            stats[rule.id] = {
                'name': rule.name,
                'description': rule.description,
                'priority': rule.priority,
                'enabled': rule.enabled,
                'hits': total,
                'last_hit': last,
                'skipped_blocks': skipped,
                'ip_count': len(ips),
            }
        return stats

    def get_top_rules(self, limit: int = 20, sort_by: str = 'hits',
                      hours: Optional[int] = None) -> list[dict]:
        stats = self.get_hit_stats(hours=hours)
        sorted_stats = sorted(
            stats.values(),
            key=lambda s: s.get(sort_by, 0) or 0,
            reverse=True,
        )[:limit]
        return sorted_stats

    def get_hits(self, hours: Optional[int] = None, rule_id: Optional[str] = None,
                 skipped_only: bool = False) -> list[WhitelistHit]:
        result = list(self._hit_history)
        if hours:
            cutoff = datetime.now() - timedelta(hours=hours)
            result = [h for h in result if h.timestamp >= cutoff]
        if rule_id:
            result = [h for h in result if h.rule_id == rule_id]
        if skipped_only:
            result = [h for h in result if h.skipped_block]
        result.sort(key=lambda h: h.timestamp, reverse=True)
        return result

    def reset_stats(self, rule_id: Optional[str] = None):
        with self._lock:
            if rule_id:
                self._hit_count[rule_id] = 0
                self._last_hit.pop(rule_id, None)
                self._skipped_blocks[rule_id] = 0
            else:
                for rid in self._hit_count:
                    self._hit_count[rid] = 0
                    self._skipped_blocks[rid] = 0
                self._last_hit.clear()

    def _save(self, force: bool = False):
        if not self._storage_path:
            return
        now = time.time()
        if not force and (now - self._last_save) < self._auto_save_interval:
            return
        try:
            self._cleanup_old()
            data = {
                'saved_at': datetime.now().isoformat(),
                'hit_count': self._hit_count,
                'skipped_blocks': self._skipped_blocks,
                'last_hit': {k: v.isoformat() for k, v in self._last_hit.items()},
                'hit_history': [h.to_dict() for h in self._hit_history],
            }
            dir_path = os.path.dirname(self._storage_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            tmp_path = f"{self._storage_path}.tmp"
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self._storage_path)
            self._last_save = now
            logger.debug(
                f"Whitelist stats saved: {sum(self._hit_count.values())} total hits"
            )
        except Exception as e:
            logger.error(f"Failed to save whitelist stats: {e}")

    def _load(self):
        if not self._storage_path or not os.path.exists(self._storage_path):
            return
        try:
            with open(self._storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self._hit_count = data.get('hit_count', {})
            self._skipped_blocks = data.get('skipped_blocks', {})
            for k, v in data.get('last_hit', {}).items():
                try:
                    self._last_hit[k] = datetime.fromisoformat(v)
                except (ValueError, TypeError):
                    continue
            for hd in data.get('hit_history', []):
                try:
                    self._hit_history.append(WhitelistHit.from_dict(hd))
                except Exception:
                    continue
            self._cleanup_old()
            logger.info(
                f"Loaded whitelist stats: {sum(self._hit_count.values())} hits, "
                f"{len(self._hit_history)} history records from {self._storage_path}"
            )
        except Exception as e:
            logger.error(f"Failed to load whitelist stats: {e}")

    def _cleanup_old(self):
        if self._max_history_days <= 0:
            return
        cutoff = datetime.now() - timedelta(days=self._max_history_days)
        old_count = len(self._hit_history)
        self._hit_history = [h for h in self._hit_history if h.timestamp >= cutoff]
        removed = old_count - len(self._hit_history)
        if removed > 0:
            logger.debug(f"Cleaned up {removed} old whitelist hit records")

    def flush(self):
        self._save(force=True)

    def print_whitelist_report(self, hours: Optional[int] = None, limit: int = 20):
        if hours:
            print(f"\n{'=' * 80}")
            print(f"  白名单统计报告 / Whitelist Report - 最近 {hours} 小时")
            print(f"{'=' * 80}")
        else:
            print(f"\n{'=' * 80}")
            print(f"  白名单统计报告 / Whitelist Report - 全部历史")
            print(f"{'=' * 80}")

        print(f"\n📊 命中排行榜 / Top Hit Rules")
        print(f"{'-' * 80}")
        top_rules = self.get_top_rules(limit=limit, sort_by='hits', hours=hours)
        if top_rules:
            print(
                f"  {'#':<3} {'规则ID':<18} {'名称':<22} {'命中':<6} "
                f"{'跳过封禁':<8} {'IP数':<6} {'最近命中'}"
            )
            for i, s in enumerate(top_rules, 1):
                last_hit = s['last_hit'].strftime('%m-%d %H:%M') if s['last_hit'] else 'never'
                enabled = "✓" if s['enabled'] else "✗"
                print(
                    f"  {i:<3} [{enabled}] {s['name'][:20]:<20} "
                    f"{s['hits']:<6} {s['skipped_blocks']:<8} "
                    f"{s['ip_count']:<6} {last_hit}"
                )
                if s.get('description'):
                    print(f"      说明: {s['description'][:60]}")
        else:
            print("  暂无命中数据")

        recent_skips = self.get_hits(hours=hours, skipped_only=True)[:10]
        if recent_skips:
            print(f"\n⚠ 最近跳过的封禁 / Recently Skipped Blocks (Top 10)")
            print(f"{'-' * 80}")
            print(f"  {'时间':<18} {'规则':<18} {'源IP':<18} {'目标':<20} {'原因'}")
            for h in recent_skips:
                ts = h.timestamp.strftime('%m-%d %H:%M:%S')
                dest = f"{h.dest_ip or '-'}:{h.dest_port or '-'}"
                print(
                    f"  {ts:<18} {h.rule_name[:16]:<18} "
                    f"{h.source_ip or '-':<18} {dest[:19]:<20} {h.reason[:30]}"
                )

        if hours:
            window_hits = self.get_hits(hours=hours)
            total_hits = len(window_hits)
            total_skipped = sum(1 for h in window_hits if h.skipped_block)
            unique_ips = len(set(h.source_ip for h in window_hits if h.source_ip))
        else:
            total_hits = sum(self._hit_count.values())
            total_skipped = sum(self._skipped_blocks.values())
            unique_ips = len(set(h.source_ip for h in self._hit_history if h.source_ip))

        print(f"\n📈 概览统计 / Overview")
        print(f"{'-' * 80}")
        print(f"  白名单规则总数: {len(self._rules)}")
        print(f"  总命中次数: {total_hits}")
        print(f"  跳过封禁次数: {total_skipped}")
        print(f"  命中唯一IP数: {unique_ips}")
        if hours:
            print(f"  时间范围: 最近 {hours} 小时")
        else:
            print(f"  时间范围: 全部历史")
        print(f"{'=' * 80}\n")

    def print_trend_report(self, limit: int = 20):
        print(f"\n{'=' * 100}")
        print(f"  白名单趋势对比 / Whitelist Trend Report - 1h vs 24h vs 全部历史")
        print(f"{'=' * 100}")

        s1 = self.get_hit_stats(hours=1)
        s24 = self.get_hit_stats(hours=24)
        s_all = self.get_hit_stats(hours=None)

        # 按 24h 命中数排序
        sorted_rids = sorted(
            s_all.keys(),
            key=lambda r: (
                s24.get(r, {}).get('hits', 0),
                s1.get(r, {}).get('hits', 0),
                s_all.get(r, {}).get('hits', 0),
            ),
            reverse=True,
        )[:limit]

        if sorted_rids:
            print(
                f"\n  {'#':<3} {'规则':<24} {'1h命中':>8} {'24h命中':>9} "
                f"{'全部命中':>9} {'1h跳过':>8} {'24h跳过':>9} {'全部跳过':>9} {'最近命中':<18}"
            )
            print(f"  {'-' * 96}")
            for i, rid in enumerate(sorted_rids, 1):
                a1, a24, aa = s1.get(rid, {}), s24.get(rid, {}), s_all.get(rid, {})
                h1, h24, ha = a1.get('hits', 0), a24.get('hits', 0), aa.get('hits', 0)
                k1, k24, ka = a1.get('skipped_blocks', 0), a24.get('skipped_blocks', 0), aa.get('skipped_blocks', 0)
                last_hit = aa.get('last_hit')
                last_str = last_hit.strftime('%Y-%m-%d %H:%M') if last_hit else 'never'
                name = aa.get('name', rid)[:22]

                # 异常标记：1h命中占24h的比例偏高（短时间爆量）
                flag = ''
                if h24 >= 5 and h1 >= h24 * 0.5:
                    flag = ' ⚠ SPIKE'
                elif h24 == 0 and h1 > 0:
                    flag = ' ⚡ NEW'
                elif ha > 0 and h24 == 0 and h1 == 0:
                    flag = ' 💤 IDLE'

                print(
                    f"  {i:<3} {name:<24} {h1:>8} {h24:>9} {ha:>9} "
                    f"{k1:>8} {k24:>9} {ka:>9} {last_str:<18}{flag}"
                )
        else:
            print("  暂无白名单命中数据")

        # 概览
        tot1 = sum(v.get('hits', 0) for v in s1.values())
        tot24 = sum(v.get('hits', 0) for v in s24.values())
        tot_all = sum(v.get('hits', 0) for v in s_all.values())
        skip1 = sum(v.get('skipped_blocks', 0) for v in s1.values())
        skip24 = sum(v.get('skipped_blocks', 0) for v in s24.values())
        skip_all = sum(v.get('skipped_blocks', 0) for v in s_all.values())

        print(f"\n📈 总览 / Totals")
        print(f"{'-' * 100}")
        print(f"  {'':<27} {'1小时':>10} {'24小时':>10} {'全部历史':>10}")
        print(f"  总命中次数:                {tot1:>10} {tot24:>10} {tot_all:>10}")
        print(f"  跳过封禁次数:              {skip1:>10} {skip24:>10} {skip_all:>10}")
        print(f"  命中规则数:                {sum(1 for v in s1.values() if v.get('hits',0)>0):>10} "
              f"{sum(1 for v in s24.values() if v.get('hits',0)>0):>10} "
              f"{sum(1 for v in s_all.values() if v.get('hits',0)>0):>10}")
        print(f"{'=' * 100}\n")
