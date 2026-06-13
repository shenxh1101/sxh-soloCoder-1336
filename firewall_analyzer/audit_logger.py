import os
import json
import time
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Optional, Union

logger = logging.getLogger(__name__)


@dataclass
class AlertEvent:
    id: str
    timestamp: datetime
    rule_id: str
    rule_name: str
    ip_address: Optional[str]
    count: int
    time_window: int
    action: str
    action_result: str = ""
    stage: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "AlertEvent":
        d = dict(data)
        d['timestamp'] = datetime.fromisoformat(d['timestamp'])
        if 'extra' not in d:
            d['extra'] = {}
        return cls(**d)


@dataclass
class BlockEvent:
    id: str
    timestamp: datetime
    ip_address: str
    reason: str
    rule_id: str
    stage: str = ""
    expire_at: Optional[datetime] = None
    unblocked_at: Optional[datetime] = None
    unblock_reason: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        if self.expire_at:
            d['expire_at'] = self.expire_at.isoformat()
        if self.unblocked_at:
            d['unblocked_at'] = self.unblocked_at.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "BlockEvent":
        d = dict(data)
        d['timestamp'] = datetime.fromisoformat(d['timestamp'])
        if d.get('expire_at'):
            d['expire_at'] = datetime.fromisoformat(d['expire_at'])
        if d.get('unblocked_at'):
            d['unblocked_at'] = datetime.fromisoformat(d['unblocked_at'])
        if 'extra' not in d:
            d['extra'] = {}
        return cls(**d)


class AuditLogger:
    def __init__(self, storage_path: Optional[str] = None, max_history_days: int = 30):
        self.storage_path = storage_path
        self.max_history_days = max_history_days
        self._alerts: list[AlertEvent] = []
        self._blocks: list[BlockEvent] = []
        self._lock = threading.Lock()
        self._last_save = 0.0
        self._auto_save_interval = 30

        if self.storage_path:
            self._load()

    def _load(self):
        if not self.storage_path or not os.path.exists(self.storage_path):
            return
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for a in data.get('alerts', []):
                try:
                    self._alerts.append(AlertEvent.from_dict(a))
                except Exception:
                    continue
            for b in data.get('blocks', []):
                try:
                    self._blocks.append(BlockEvent.from_dict(b))
                except Exception:
                    continue
            self._cleanup_old()
            logger.info(
                f"Loaded {len(self._alerts)} alert events and {len(self._blocks)} block events "
                f"from audit log"
            )
        except Exception as e:
            logger.error(f"Failed to load audit log: {e}")

    def _save(self, force: bool = False):
        if not self.storage_path:
            return
        now = time.time()
        if not force and (now - self._last_save) < self._auto_save_interval:
            return
        try:
            self._cleanup_old()
            data = {
                'saved_at': datetime.now().isoformat(),
                'alerts': [a.to_dict() for a in self._alerts],
                'blocks': [b.to_dict() for b in self._blocks],
            }
            dir_path = os.path.dirname(self.storage_path)
            if dir_path and not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            tmp_path = f"{self.storage_path}.tmp"
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self.storage_path)
            self._last_save = now
            logger.debug(
                f"Audit log saved: {len(self._alerts)} alerts, {len(self._blocks)} blocks"
            )
        except Exception as e:
            logger.error(f"Failed to save audit log: {e}")

    def _cleanup_old(self):
        if self.max_history_days <= 0:
            return
        cutoff = datetime.now() - timedelta(days=self.max_history_days)
        old_alert_count = len(self._alerts)
        old_block_count = len(self._blocks)
        self._alerts = [a for a in self._alerts if a.timestamp >= cutoff]
        self._blocks = [b for b in self._blocks if b.timestamp >= cutoff]
        removed_alerts = old_alert_count - len(self._alerts)
        removed_blocks = old_block_count - len(self._blocks)
        if removed_alerts or removed_blocks:
            logger.debug(
                f"Cleaned up {removed_alerts} old alerts and {removed_blocks} old blocks "
                f"(older than {self.max_history_days} days)"
            )

    def log_alert(self, rule_id: str, rule_name: str, ip_address: Optional[str],
                  count: int, time_window: int, action: str, action_result: str = "",
                  stage: str = "", extra: Optional[dict] = None) -> AlertEvent:
        event = AlertEvent(
            id=f"alert_{int(time.time()*1000)}_{id(self)}",
            timestamp=datetime.now(),
            rule_id=rule_id,
            rule_name=rule_name,
            ip_address=ip_address,
            count=count,
            time_window=time_window,
            action=action,
            action_result=action_result,
            stage=stage,
            extra=extra or {},
        )
        with self._lock:
            self._alerts.append(event)
            self._save()
        logger.debug(
            f"[AUDIT-ALERT] {rule_id} {rule_name} | IP={ip_address} | "
            f"count={count} | stage={stage} | action={action}"
        )
        return event

    def log_block(self, ip_address: str, reason: str, rule_id: str, stage: str = "",
                  expire_at: Optional[datetime] = None, extra: Optional[dict] = None) -> BlockEvent:
        event = BlockEvent(
            id=f"block_{int(time.time()*1000)}_{id(self)}",
            timestamp=datetime.now(),
            ip_address=ip_address,
            reason=reason,
            rule_id=rule_id,
            stage=stage,
            expire_at=expire_at,
            extra=extra or {},
        )
        with self._lock:
            self._blocks.append(event)
            self._save()
        logger.debug(
            f"[AUDIT-BLOCK] {ip_address} | reason={reason} | rule={rule_id} | "
            f"stage={stage} | expire={expire_at}"
        )
        return event

    def log_unblock(self, ip_address: str, reason: str = ""):
        with self._lock:
            for event in reversed(self._blocks):
                if event.ip_address == ip_address and event.unblocked_at is None:
                    event.unblocked_at = datetime.now()
                    event.unblock_reason = reason
                    self._save()
                    logger.debug(f"[AUDIT-UNBLOCK] {ip_address} | reason={reason}")
                    return

    def flush(self):
        with self._lock:
            self._save(force=True)
            logger.info(f"Audit log flushed: {len(self._alerts)} alerts, {len(self._blocks)} blocks")

    def get_alerts(self, hours: Optional[int] = None, rule_id: Optional[str] = None,
                   ip_address: Optional[str] = None) -> list[AlertEvent]:
        result = list(self._alerts)
        if hours:
            cutoff = datetime.now() - timedelta(hours=hours)
            result = [a for a in result if a.timestamp >= cutoff]
        if rule_id:
            result = [a for a in result if a.rule_id == rule_id]
        if ip_address:
            result = [a for a in result if a.ip_address == ip_address]
        result.sort(key=lambda a: a.timestamp, reverse=True)
        return result

    def get_blocks(self, hours: Optional[int] = None, active_only: bool = False,
                   ip_address: Optional[str] = None) -> list[BlockEvent]:
        result = list(self._blocks)
        if hours:
            cutoff = datetime.now() - timedelta(hours=hours)
            result = [b for b in result if b.timestamp >= cutoff]
        if active_only:
            now = datetime.now()
            result = [b for b in result if b.unblocked_at is None and (b.expire_at is None or b.expire_at > now)]
        if ip_address:
            result = [b for b in result if b.ip_address == ip_address]
        result.sort(key=lambda b: b.timestamp, reverse=True)
        return result

    def get_expiring_soon(self, within_hours: int = 24) -> list[BlockEvent]:
        now = datetime.now()
        cutoff = now + timedelta(hours=within_hours)
        result = [
            b for b in self._blocks
            if b.unblocked_at is None and b.expire_at is not None and now < b.expire_at <= cutoff
        ]
        result.sort(key=lambda b: b.expire_at or datetime.max)
        return result

    def get_top_rules(self, hours: Optional[int] = None, limit: int = 10) -> list[dict]:
        alerts = self.get_alerts(hours=hours)
        rule_stats: dict[str, dict] = {}
        for a in alerts:
            if a.rule_id not in rule_stats:
                rule_stats[a.rule_id] = {
                    'rule_id': a.rule_id,
                    'rule_name': a.rule_name,
                    'trigger_count': 0,
                    'unique_ips': set(),
                    'total_events': 0,
                }
            rule_stats[a.rule_id]['trigger_count'] += 1
            if a.ip_address:
                rule_stats[a.rule_id]['unique_ips'].add(a.ip_address)
            rule_stats[a.rule_id]['total_events'] += a.count

        for s in rule_stats.values():
            s['unique_ips'] = len(s['unique_ips'])

        result = sorted(rule_stats.values(), key=lambda s: s['trigger_count'], reverse=True)[:limit]
        return result

    def get_top_blocked_ips(self, hours: Optional[int] = None, limit: int = 10) -> list[dict]:
        blocks = self.get_blocks(hours=hours)
        ip_stats: dict[str, dict] = {}
        for b in blocks:
            if b.ip_address not in ip_stats:
                ip_stats[b.ip_address] = {
                    'ip_address': b.ip_address,
                    'block_count': 0,
                    'last_block': b.timestamp,
                    'reasons': set(),
                    'rules': set(),
                    'active': False,
                    'expire_at': None,
                }
            ip_stats[b.ip_address]['block_count'] += 1
            if b.timestamp > ip_stats[b.ip_address]['last_block']:
                ip_stats[b.ip_address]['last_block'] = b.timestamp
            if b.reason:
                ip_stats[b.ip_address]['reasons'].add(b.reason)
            if b.rule_id:
                ip_stats[b.ip_address]['rules'].add(b.rule_id)
            if b.unblocked_at is None and (b.expire_at is None or b.expire_at > datetime.now()):
                ip_stats[b.ip_address]['active'] = True
                if b.expire_at:
                    ip_stats[b.ip_address]['expire_at'] = b.expire_at

        for s in ip_stats.values():
            s['reasons'] = list(s['reasons'])[:3]
            s['rules'] = list(s['rules'])[:3]

        result = sorted(ip_stats.values(), key=lambda s: s['block_count'], reverse=True)[:limit]
        return result

    def get_stage_distribution(self, hours: Optional[int] = None) -> dict[str, int]:
        alerts = self.get_alerts(hours=hours)
        stages: dict[str, int] = {}
        for a in alerts:
            stage = a.stage or 'unknown'
            stages[stage] = stages.get(stage, 0) + 1
        return stages

    def flush(self):
        self._save(force=True)

    def print_audit_report(self, hours: Optional[int] = None):
        if hours:
            print(f"\n{'=' * 70}")
            print(f"  告警审计报告 / Audit Report - 最近 {hours} 小时")
            print(f"{'=' * 70}")
        else:
            print(f"\n{'=' * 70}")
            print(f"  告警审计报告 / Audit Report - 全部历史")
            print(f"{'=' * 70}")

        print(f"\n📊 触发最多的规则 / Top Triggered Rules")
        print(f"{'-' * 70}")
        top_rules = self.get_top_rules(hours=hours)
        if top_rules:
            print(f"  {'#':<3} {'规则ID':<20} {'名称':<22} {'触发':<6} {'IP数':<6} {'总事件':<8}")
            for i, s in enumerate(top_rules, 1):
                print(
                    f"  {i:<3} {s['rule_id']:<20} {s['rule_name'][:20]:<22} "
                    f"{s['trigger_count']:<6} {s['unique_ips']:<6} {s['total_events']:<8}"
                )
        else:
            print("  暂无数据")

        print(f"\n🔒 被封最多的IP / Top Blocked IPs")
        print(f"{'-' * 70}")
        top_ips = self.get_top_blocked_ips(hours=hours)
        if top_ips:
            print(f"  {'#':<3} {'IP地址':<20} {'封禁次数':<8} {'状态':<8} {'最近封禁'}")
            for i, s in enumerate(top_ips, 1):
                status = "ACTIVE" if s['active'] else "released"
                last = s['last_block'].strftime('%m-%d %H:%M')
                print(
                    f"  {i:<3} {s['ip_address']:<20} {s['block_count']:<8} "
                    f"{status:<8} {last}"
                )
                if s['reasons']:
                    print(f"      原因: {', '.join(s['reasons'])}")
        else:
            print("  暂无数据")

        print(f"\n⏰ 即将到期的封禁 / Expiring Soon (within 24h)")
        print(f"{'-' * 70}")
        expiring = self.get_expiring_soon(within_hours=24)
        if expiring:
            print(f"  {'IP地址':<20} {'规则':<18} {'到期时间':<20} {'原因'}")
            for b in expiring:
                exp_str = b.expire_at.strftime('%Y-%m-%d %H:%M') if b.expire_at else '-'
                print(f"  {b.ip_address:<20} {b.rule_id[:16]:<18} {exp_str:<20} {b.reason[:30]}")
        else:
            print("  暂无即将到期的封禁")

        stages = self.get_stage_distribution(hours=hours)
        if stages:
            print(f"\n🎚  风险阶段分布 / Stage Distribution")
            print(f"{'-' * 70}")
            for stage, count in sorted(stages.items()):
                print(f"  {stage:<20} {count} 次")

        alerts_1h = len(self.get_alerts(hours=1))
        alerts_24h = len(self.get_alerts(hours=24))
        blocks_1h = len(self.get_blocks(hours=1))
        blocks_24h = len(self.get_blocks(hours=24))
        active_blocks = len(self.get_blocks(active_only=True))

        print(f"\n📈 概览统计 / Overview")
        print(f"{'-' * 70}")
        print(f"  最近1小时:  {alerts_1h} 次告警, {blocks_1h} 次封禁")
        print(f"  最近24小时: {alerts_24h} 次告警, {blocks_24h} 次封禁")
        print(f"  当前活跃封禁: {active_blocks} 个IP")
        print(f"  历史总记录: {len(self._alerts)} 次告警, {len(self._blocks)} 次封禁")
        print(f"{'=' * 70}\n")
