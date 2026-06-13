import re
import time
import json
import logging
import ipaddress
import threading
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Optional, Union
from abc import ABC, abstractmethod

try:
    import urllib.request
    import urllib.parse
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

from .log_parser import LogEntry

logger = logging.getLogger(__name__)


@dataclass
class RuleMatchResult:
    matched: bool
    rule_id: str
    triggered: bool = False
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleActionContext:
    rule_id: str
    rule_name: str
    ip_address: Optional[str]
    entries: list[LogEntry]
    count: int
    time_window: int
    extra: dict[str, Any] = field(default_factory=dict)


def _is_private_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def _is_public_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return False


def _in_cidr(ip_str: str, cidr: str) -> bool:
    if not ip_str or not cidr:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr, strict=False)
        return ip in network
    except ValueError:
        return False


def _in_cidr_list(ip_str: str, cidr_list: Union[str, list]) -> bool:
    if not ip_str or not cidr_list:
        return False
    if isinstance(cidr_list, str):
        cidr_list = [c.strip() for c in cidr_list.split(',') if c.strip()]
    for cidr in cidr_list:
        if _in_cidr(ip_str, cidr):
            return True
    return False


def _in_port_range(port: Union[int, str, None], range_spec: Union[str, list, tuple]) -> bool:
    if port is None:
        return False
    try:
        port = int(port)
    except (ValueError, TypeError):
        return False

    if isinstance(range_spec, str):
        if '-' in range_spec:
            start, end = range_spec.split('-', 1)
            try:
                return int(start.strip()) <= port <= int(end.strip())
            except (ValueError, TypeError):
                return False
        else:
            try:
                return port == int(range_spec)
            except (ValueError, TypeError):
                return False
    elif isinstance(range_spec, (list, tuple)):
        if len(range_spec) == 2 and all(isinstance(x, (int, str)) for x in range_spec):
            try:
                return int(range_spec[0]) <= port <= int(range_spec[1])
            except (ValueError, TypeError):
                return False
        else:
            return any(_in_port_range(port, r) for r in range_spec)

    return False


def _in_time_range(_, time_spec: Union[str, list]) -> bool:
    now = datetime.now()

    if isinstance(time_spec, str):
        time_specs = [time_spec]
    else:
        time_specs = list(time_spec)

    for spec in time_specs:
        try:
            if '-' in spec:
                start_str, end_str = spec.split('-', 1)
                start_h, start_m = _parse_hhmm(start_str.strip())
                end_h, end_m = _parse_hhmm(end_str.strip())

                current_minutes = now.hour * 60 + now.minute
                start_minutes = start_h * 60 + start_m
                end_minutes = end_h * 60 + end_m

                if start_minutes <= end_minutes:
                    if start_minutes <= current_minutes <= end_minutes:
                        return True
                else:
                    if current_minutes >= start_minutes or current_minutes <= end_minutes:
                        return True
        except (ValueError, TypeError):
            continue

    return False


def _is_day_of_week(_, days: Union[int, str, list]) -> bool:
    now = datetime.now()
    today = now.weekday()

    if isinstance(days, (int, str)):
        days_list = [int(d) for d in str(days).split(',') if d.strip().isdigit()]
    else:
        days_list = [int(d) for d in days if str(d).strip().isdigit()]

    return today in days_list


def _is_hour_of_day(_, hours: Union[int, str, list]) -> bool:
    now = datetime.now()
    current_hour = now.hour

    if isinstance(hours, (int, str)):
        hours_list = [int(h) for h in str(hours).split(',') if h.strip().isdigit()]
    else:
        hours_list = [int(h) for h in hours if str(h).strip().isdigit()]

    return current_hour in hours_list


def _parse_hhmm(s: str) -> tuple[int, int]:
    s = s.strip()
    if ':' in s:
        h, m = s.split(':', 1)
        return int(h.strip()), int(m.strip())
    else:
        return int(s), 0


class ConditionEvaluator:
    OPERATORS = {
        'eq': lambda a, b: a == b,
        'ne': lambda a, b: a != b,
        'gt': lambda a, b: a is not None and b is not None and a > b,
        'gte': lambda a, b: a is not None and b is not None and a >= b,
        'lt': lambda a, b: a is not None and b is not None and a < b,
        'lte': lambda a, b: a is not None and b is not None and a <= b,
        'in': lambda a, b: a in b if b is not None else False,
        'not_in': lambda a, b: a not in b if b is not None else True,
        'contains': lambda a, b: b in a if a and b else False,
        'icontains': lambda a, b: str(b).lower() in str(a).lower() if a and b else False,
        'regex': lambda a, b: bool(re.search(str(b), str(a))) if a and b else False,
        'startswith': lambda a, b: str(a).startswith(str(b)) if a and b else False,
        'endswith': lambda a, b: str(a).endswith(str(b)) if a and b else False,
        'is_private_ip': lambda a, b: _is_private_ip(a),
        'is_public_ip': lambda a, b: _is_public_ip(a),
        'in_cidr': lambda a, b: _in_cidr_list(a, b),
        'not_in_cidr': lambda a, b: not _in_cidr_list(a, b),
        'in_port_range': lambda a, b: _in_port_range(a, b),
        'not_in_port_range': lambda a, b: not _in_port_range(a, b),
        'in_time_range': _in_time_range,
        'not_in_time_range': lambda a, b: not _in_time_range(a, b),
        'is_day_of_week': _is_day_of_week,
        'is_hour_of_day': _is_hour_of_day,
    }

    def __init__(self, conditions: list[dict]):
        self.conditions = conditions or []

    def evaluate(self, entry: LogEntry) -> bool:
        if not self.conditions:
            return True

        for cond in self.conditions:
            if not self._evaluate_single(cond, entry):
                return False
        return True

    def _evaluate_single(self, condition: dict, entry: LogEntry) -> bool:
        field_name = condition.get('field', '')
        operator = condition.get('operator', 'eq').lower()
        value = condition.get('value')

        field_value = self._get_field_value(entry, field_name)
        op_func = self.OPERATORS.get(operator)

        if op_func is None:
            logger.warning(f"Unknown operator: {operator}")
            return False

        try:
            return op_func(field_value, value)
        except Exception as e:
            logger.debug(f"Error evaluating condition {condition}: {e}")
            return False

    def _get_field_value(self, entry: LogEntry, field_path: str) -> Any:
        if not field_path:
            return None

        parts = field_path.split('.')
        obj: Any = entry
        for part in parts:
            if obj is None:
                return None
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                obj = getattr(obj, part, None)
        return obj


class EventTracker:
    def __init__(self, time_window_seconds: int, max_history: int = 100000):
        self.time_window = time_window_seconds
        self.max_history = max_history
        self._events: dict[str, deque[tuple[datetime, LogEntry]]] = defaultdict(
            lambda: deque(maxlen=max_history)
        )
        self._last_cleanup = time.time()
        self._cleanup_interval = 60

    def track(self, key: str, entry: LogEntry) -> int:
        now = datetime.now()
        queue = self._events[key]
        queue.append((now, entry))
        self._cleanup_expired(key, now)
        self._maybe_global_cleanup()
        return len(queue)

    def get_count(self, key: str) -> int:
        self._cleanup_expired(key, datetime.now())
        return len(self._events.get(key, []))

    def get_entries(self, key: str) -> list[LogEntry]:
        self._cleanup_expired(key, datetime.now())
        return [e for _, e in self._events.get(key, [])]

    def _cleanup_expired(self, key: str, now: datetime):
        queue = self._events.get(key)
        if not queue:
            return
        cutoff = now - timedelta(seconds=self.time_window)
        while queue and queue[0][0] < cutoff:
            queue.popleft()

    def _maybe_global_cleanup(self):
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        current_time = datetime.now()
        cutoff = current_time - timedelta(seconds=self.time_window)
        empty_keys = []
        for key, queue in self._events.items():
            while queue and queue[0][0] < cutoff:
                queue.popleft()
            if not queue:
                empty_keys.append(key)
        for key in empty_keys:
            del self._events[key]

    def reset(self, key: Optional[str] = None):
        if key:
            self._events.pop(key, None)
        else:
            self._events.clear()

    def all_keys(self) -> list[str]:
        return list(self._events.keys())


class ThresholdTrigger:
    def __init__(
        self,
        threshold: int,
        time_window_seconds: int,
        group_by: str = "source_ip",
        cooldown_seconds: int = 0,
        burst_threshold: Optional[int] = None,
        burst_window_seconds: int = 10,
    ):
        self.threshold = threshold
        self.time_window = time_window_seconds
        self.group_by = group_by
        self.cooldown = cooldown_seconds
        self.burst_threshold = burst_threshold
        self.burst_window = burst_window_seconds

        self._tracker = EventTracker(time_window_seconds)
        self._burst_tracker = EventTracker(burst_window_seconds)
        self._last_triggered: dict[str, datetime] = {}

    def check(self, entry: LogEntry) -> tuple[bool, list[LogEntry], int]:
        key = self._extract_key(entry)
        if key is None:
            return False, [], 0

        count = self._tracker.track(key, entry)
        entries = self._tracker.get_entries(key)

        if self._is_in_cooldown(key):
            return False, entries, count

        is_triggered = False
        if count >= self.threshold:
            is_triggered = True

        if self.burst_threshold:
            burst_count = self._burst_tracker.track(key, entry)
            if burst_count >= self.burst_threshold:
                is_triggered = True
                entries = self._burst_tracker.get_entries(key)
                count = burst_count

        if is_triggered:
            self._mark_triggered(key)
            self._tracker.reset(key)
            self._burst_tracker.reset(key)

        return is_triggered, entries, count

    def _extract_key(self, entry: LogEntry) -> Optional[str]:
        if self.group_by == 'source_ip':
            return entry.source_ip
        elif self.group_by == 'dest_ip':
            return entry.dest_ip
        elif self.group_by == 'dest_port':
            return str(entry.dest_port) if entry.dest_port else None
        elif self.group_by == 'protocol':
            return entry.protocol
        elif self.group_by == 'source_ip+dest_port':
            if entry.source_ip and entry.dest_port:
                return f"{entry.source_ip}:{entry.dest_port}"
            return None
        else:
            parts = self.group_by.split('+')
            values = []
            for p in parts:
                val = getattr(entry, p.strip(), None)
                if val is None:
                    return None
                values.append(str(val))
            return '+'.join(values) if values else None

    def _is_in_cooldown(self, key: str) -> bool:
        if self.cooldown <= 0:
            return False
        last = self._last_triggered.get(key)
        if last is None:
            return False
        return (datetime.now() - last).total_seconds() < self.cooldown

    def _mark_triggered(self, key: str):
        if self.cooldown > 0:
            self._last_triggered[key] = datetime.now()


@dataclass
class Rule:
    id: str
    name: str
    description: str = ""
    enabled: bool = True
    conditions: list[dict] = field(default_factory=list)
    threshold: int = 10
    time_window: int = 3600
    group_by: str = "source_ip"
    cooldown: int = 0
    burst_threshold: Optional[int] = None
    burst_window: int = 10
    auto_unblock_hours: Optional[float] = None
    actions: list[dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        return cls(
            id=data.get('id', ''),
            name=data.get('name', data.get('id', 'Unnamed Rule')),
            description=data.get('description', ''),
            enabled=data.get('enabled', True),
            conditions=data.get('conditions', []),
            threshold=data.get('threshold', 10),
            time_window=data.get('time_window', 3600),
            group_by=data.get('group_by', 'source_ip'),
            cooldown=data.get('cooldown', 0),
            burst_threshold=data.get('burst_threshold'),
            burst_window=data.get('burst_window', 10),
            auto_unblock_hours=data.get('auto_unblock_hours'),
            actions=data.get('actions', []),
        )


class RuleEngine:
    def __init__(self, rules: Optional[list[Rule]] = None):
        self._rules: dict[str, Rule] = {}
        self._evaluators: dict[str, ConditionEvaluator] = {}
        self._triggers: dict[str, ThresholdTrigger] = {}
        self._action_handlers: dict[str, Callable[[RuleActionContext], None]] = {}
        self._on_trigger_callbacks: list[Callable[[Rule, RuleActionContext], None]] = []

        if rules:
            for rule in rules:
                self.add_rule(rule)

        self._register_default_handlers()

    def _register_default_handlers(self):
        self.register_action_handler('log', self._default_log_action)
        self.register_action_handler('webhook', send_webhook_action)

    def add_rule(self, rule: Rule):
        if not rule.id:
            rule.id = f"rule_{int(time.time())}_{len(self._rules)}"
        self._rules[rule.id] = rule
        self._evaluators[rule.id] = ConditionEvaluator(rule.conditions)
        self._trigger = ThresholdTrigger(
            threshold=rule.threshold,
            time_window_seconds=rule.time_window,
            group_by=rule.group_by,
            cooldown_seconds=rule.cooldown,
            burst_threshold=rule.burst_threshold,
            burst_window_seconds=rule.burst_window,
        )
        self._triggers[rule.id] = self._trigger
        logger.info(f"Added rule: {rule.id} - {rule.name}")

    def add_rule_from_dict(self, data: dict):
        self.add_rule(Rule.from_dict(data))

    def remove_rule(self, rule_id: str):
        self._rules.pop(rule_id, None)
        self._evaluators.pop(rule_id, None)
        self._triggers.pop(rule_id, None)
        logger.info(f"Removed rule: {rule_id}")

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        return self._rules.get(rule_id)

    def list_rules(self) -> list[Rule]:
        return list(self._rules.values())

    def register_action_handler(self, action_type: str, handler: Callable[[RuleActionContext], None]):
        self._action_handlers[action_type] = handler

    def on_trigger(self, callback: Callable[[Rule, RuleActionContext], None]):
        self._on_trigger_callbacks.append(callback)

    def process_entry(self, entry: LogEntry) -> list[RuleMatchResult]:
        results: list[RuleMatchResult] = []

        for rule_id, rule in self._rules.items():
            if not rule.enabled:
                continue

            try:
                evaluator = self._evaluators.get(rule_id)
                if evaluator and not evaluator.evaluate(entry):
                    continue

                trigger = self._triggers.get(rule_id)
                if not trigger:
                    continue

                is_triggered, entries, count = trigger.check(entry)
                key = trigger._extract_key(entry)

                result = RuleMatchResult(
                    matched=True,
                    rule_id=rule_id,
                    triggered=is_triggered,
                    context={
                        'key': key,
                        'count': count,
                        'threshold': rule.threshold,
                        'time_window': rule.time_window,
                    },
                )
                results.append(result)

                if is_triggered:
                    self._handle_trigger(rule, key, entries, count)

            except Exception as e:
                logger.error(f"Error processing rule {rule_id}: {e}", exc_info=True)

        return results

    def _handle_trigger(self, rule: Rule, key: Optional[str], entries: list[LogEntry], count: int):
        logger.warning(
            f"Rule triggered: [{rule.id}] {rule.name} | "
            f"key={key} | count={count} | threshold={rule.threshold}"
        )

        ip_address = None
        if key:
            if ':' in key:
                ip_address = key.split(':')[0]
            else:
                ip_address = key

        context = RuleActionContext(
            rule_id=rule.id,
            rule_name=rule.name,
            ip_address=ip_address,
            entries=entries,
            count=count,
            time_window=rule.time_window,
            extra={
                'key': key,
                'threshold': rule.threshold,
                'auto_unblock_hours': rule.auto_unblock_hours,
            },
        )

        for action_def in rule.actions:
            action_type = action_def.get('type', action_def.get('action', ''))
            params = {k: v for k, v in action_def.items() if k not in ('type', 'action')}
            context.extra.update(params)

            handler = self._action_handlers.get(action_type)
            if handler:
                try:
                    handler(context)
                except Exception as e:
                    logger.error(f"Error in action handler {action_type}: {e}", exc_info=True)
            else:
                logger.debug(f"No handler registered for action type: {action_type}")

        for callback in self._on_trigger_callbacks:
            try:
                callback(rule, context)
            except Exception as e:
                logger.error(f"Error in trigger callback: {e}", exc_info=True)

    def _default_log_action(self, context: RuleActionContext):
        level = context.extra.get('level', 'WARNING')
        message = context.extra.get('message', f"Rule {context.rule_name} triggered for IP {context.ip_address}")
        log_func = getattr(logger, level.lower(), logger.warning)
        log_func(
            f"[ACTION:LOG] {message} | "
            f"count={context.count} | "
            f"window={context.time_window}s | "
            f"entries={len(context.entries)}"
        )


def send_webhook(url: str, payload: dict, method: str = "POST",
                headers: Optional[dict] = None, timeout: int = 10) -> tuple[int, str]:
    if not HAS_URLLIB:
        return -1, "urllib not available"

    try:
        json_data = json.dumps(payload).encode('utf-8')
        req_headers = {
            'Content-Type': 'application/json',
            **(headers or {}),
        }
        req = urllib.request.Request(
            url=url,
            data=json_data,
            headers=req_headers,
            method=method.upper(),
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            response_body = response.read().decode('utf-8', errors='replace')
            return response.status, response_body
    except Exception as e:
        logger.error(f"Webhook request failed to {url}: {e}")
        return -1, str(e)


def send_webhook_action(context: RuleActionContext):
    url = context.extra.get('url')
    if not url:
        logger.warning("[ACTION:WEBHOOK] Missing 'url' parameter in webhook action")
        return

    method = context.extra.get('method', 'POST')
    headers = context.extra.get('headers', {})
    timeout = context.extra.get('timeout', 10)
    template = context.extra.get('payload')

    if template:
        payload = dict(template)
        for k, v in payload.items():
            if isinstance(v, str):
                v = v.replace('{IP}', context.ip_address or '')
                v = v.replace('{RULE_ID}', context.rule_id)
                v = v.replace('{RULE_NAME}', context.rule_name)
                v = v.replace('{COUNT}', str(context.count))
                v = v.replace('{TIME_WINDOW}', str(context.time_window))
                payload[k] = v
    else:
        payload = {
            'event': 'firewall_rule_triggered',
            'rule_id': context.rule_id,
            'rule_name': context.rule_name,
            'ip_address': context.ip_address,
            'count': context.count,
            'time_window': context.time_window,
            'timestamp': datetime.now().isoformat(),
            'source_ips': list(set(e.source_ip for e in context.entries if e.source_ip))[:20],
            'sample_logs': [e.raw_line for e in context.entries[:5]],
        }

    status, response = send_webhook(url, payload, method=method, headers=headers, timeout=timeout)

    if status >= 200 and status < 300:
        logger.info(
            f"[ACTION:WEBHOOK] Successfully sent to {url} | "
            f"status={status} | ip={context.ip_address}"
        )
    else:
        logger.warning(
            f"[ACTION:WEBHOOK] Failed to send to {url} | "
            f"status={status} | response={response[:200]}"
        )

