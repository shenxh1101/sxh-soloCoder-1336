import re
import time
import logging
import ipaddress
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Optional, Union
from abc import ABC, abstractmethod

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

        context = RuleActionContext(
            rule_id=rule.id,
            rule_name=rule.name,
            ip_address=key if key and ':' not in key else (key.split(':')[0] if key else None),
            entries=entries,
            count=count,
            time_window=rule.time_window,
            extra={
                'key': key,
                'threshold': rule.threshold,
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
