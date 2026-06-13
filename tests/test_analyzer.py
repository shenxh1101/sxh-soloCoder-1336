"""
测试脚本 - 用于验证动态防火墙日志分析器的功能
在测试环境中模拟日志生成并验证规则触发
"""
import os
import sys
import time
import tempfile
import threading
import json
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from firewall_analyzer.config_loader import AppConfig, LogSourceConfig, BlacklistConfig, WhitelistConfig
from firewall_analyzer.main import setup_logging, FirewallAnalyzer
from firewall_analyzer.log_parser import LogParserRegistry, IPTablesParser, WindowsSecurityParser


def test_log_parsers():
    print("\n" + "=" * 60)
    print("测试1: 日志解析器 / Testing Log Parsers")
    print("=" * 60)

    registry = LogParserRegistry()

    iptables_lines = [
        'Jun 14 10:23:45 firewall kernel: [123456.789012] DROP IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=192.168.1.100 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=54321 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0',
        '2024-06-14T10:25:30.123456 firewall iptables: action=DROP src=203.0.113.50 dst=198.51.100.1 proto=TCP spt=33333 dpt=3389',
        'Jun 14 10:27:00 kernel: ACCEPT IN=eth0 SRC=10.0.0.5 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=80',
    ]

    print("\n--- iptables 日志解析 ---")
    for line in iptables_lines:
        entry = registry.parse(line)
        if entry:
            print(f"  ✓ 解析成功:")
            print(f"    时间: {entry.timestamp}")
            print(f"    源IP: {entry.source_ip} -> 目标IP: {entry.dest_ip}")
            print(f"    端口: {entry.source_port or '-'} -> {entry.dest_port or '-'}")
            print(f"    协议: {entry.protocol} | 动作: {entry.action}")
        else:
            print(f"  ✗ 解析失败: {line[:80]}...")

    windows_lines = [
        '2024-06-14T10:30:00.000Z EventID=4625 Source Network Address=185.220.101.42 IpAddress=185.220.101.42 Destination Port=3389 Protocol=6',
        'EventID=5157 2024-06-14 10:31:15 SourceAddress=45.33.32.156 DestPort=22 Protocol=TCP',
        '2024-06-14 10:32:00 EventID=4625 Remote IP=103.144.82.120 WorkstationName=ATTACKER-PC Status=0xC000006D',
        'EventID=5152 Timestamp=2024-06-14T10:33:00 Source=200.100.50.25 Destination Port=445 Protocol=17',
        'EventID=4771 2024-06-14 10:34:00 Client Address=::ffff:192.168.1.200 Service Name=krbtgt Status=0x6',
    ]

    print("\n--- Windows 安全日志解析 (多字段变体) ---")
    for line in windows_lines:
        entry = registry.parse(line)
        if entry:
            print(f"  ✓ 解析成功:")
            print(f"    时间: {entry.timestamp}")
            print(f"    源IP: {entry.source_ip}")
            print(f"    目标端口: {entry.dest_port} | 协议: {entry.protocol} | 动作: {entry.action}")
            if entry.extra.get('event_id'):
                print(f"    Event ID: {entry.extra['event_id']}")
            if entry.extra.get('failure_reason'):
                print(f"    失败原因: {entry.extra['failure_reason']}")
        else:
            print(f"  ✗ 解析失败: {line[:80]}...")

    print("\n--- Windows 4625 连续失败登录 ---")
    login_lines = [
        f'2024-06-14 10:40:{i:02d} EventID=4625 Source Network Address=172.100.50.10 IpAddress=172.100.50.10 Destination Port=3389 Protocol=6 Status=0xC000006D'
        for i in range(10)
    ]
    parsed = [registry.parse(line) for line in login_lines]
    success_count = sum(1 for e in parsed if e and e.source_ip == '172.100.50.10' and e.action == 'DENY')
    print(f"  解析成功 {success_count}/{len(login_lines)} 条失败登录记录")
    assert success_count == len(login_lines), "所有4625事件应该被正确解析"

    print("\n日志解析器测试完成 ✓")
    return True


def test_rule_engine():
    print("\n" + "=" * 60)
    print("测试2: 规则引擎 / Testing Rule Engine")
    print("=" * 60)

    from firewall_analyzer.rule_engine import RuleEngine, Rule, RuleActionContext, ConditionEvaluator

    print("\n--- 新条件运算符测试 ---")
    from datetime import datetime
    from firewall_analyzer.log_parser import LogEntry

    test_entry = LogEntry(
        timestamp=datetime.now(),
        source_ip='203.0.113.100',
        dest_ip='10.0.0.1',
        source_port=54321,
        dest_port=22,
        protocol='TCP',
        action='DENY',
    )

    test_cases = [
        ('in_cidr - 命中', {'field': 'source_ip', 'operator': 'in_cidr', 'value': '203.0.113.0/24'}, True),
        ('in_cidr - 未命中', {'field': 'source_ip', 'operator': 'in_cidr', 'value': '192.168.0.0/16'}, False),
        ('not_in_cidr - 命中', {'field': 'source_ip', 'operator': 'not_in_cidr', 'value': '192.168.0.0/16'}, True),
        ('in_port_range - 命中', {'field': 'dest_port', 'operator': 'in_port_range', 'value': '1-1024'}, True),
        ('in_port_range - 未命中', {'field': 'dest_port', 'operator': 'in_port_range', 'value': '1024-65535'}, False),
        ('not_in_port_range - 命中', {'field': 'dest_port', 'operator': 'not_in_port_range', 'value': '80-443'}, True),
        ('in_cidr - 多网段', {'field': 'source_ip', 'operator': 'in_cidr', 'value': ['10.0.0.0/8', '203.0.113.0/24']}, True),
        ('in_time_range', {'field': '', 'operator': 'in_time_range', 'value': '00:00-23:59'}, True),
        ('is_hour_of_day', {'field': '', 'operator': 'is_hour_of_day', 'value': '0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23'}, True),
    ]

    for name, condition, expected in test_cases:
        evaluator = ConditionEvaluator([condition])
        result = evaluator.evaluate(test_entry)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {name}: 预期={expected}, 实际={result}")
        assert result == expected, f"测试失败: {name}"

    print("\n--- 规则触发测试 (含auto_unblock_hours) ---")

    triggered_rules = []

    def on_trigger(rule: Rule, ctx: RuleActionContext):
        triggered_rules.append({
            'rule_id': rule.id,
            'ip': ctx.ip_address,
            'count': ctx.count,
            'auto_unblock': ctx.extra.get('auto_unblock_hours'),
        })
        print(f"  ⚠ 规则触发: {rule.id} - IP={ctx.ip_address} - 次数={ctx.count} - 自动解封={ctx.extra.get('auto_unblock_hours')}h")

    rules_config = [
        {
            'id': 'test_ssh_brute',
            'name': 'SSH暴力破解测试',
            'conditions': [
                {'field': 'dest_port', 'operator': 'eq', 'value': 22},
                {'field': 'action', 'operator': 'eq', 'value': 'DENY'},
                {'field': 'source_ip', 'operator': 'not_in_cidr', 'value': '192.168.0.0/16'},
            ],
            'threshold': 3,
            'time_window': 3600,
            'group_by': 'source_ip',
            'cooldown': 0,
            'auto_unblock_hours': 24,
            'actions': [{'type': 'log', 'level': 'WARNING', 'message': 'SSH brute force'}],
        },
        {
            'id': 'test_port_range',
            'name': '高危端口访问',
            'conditions': [
                {'field': 'dest_port', 'operator': 'in_port_range', 'value': '1-1024'},
                {'field': 'action', 'operator': 'eq', 'value': 'DENY'},
            ],
            'threshold': 2,
            'time_window': 60,
            'group_by': 'source_ip',
            'cooldown': 0,
            'auto_unblock_hours': 12,
            'actions': [],
        },
    ]

    engine = RuleEngine()
    for rc in rules_config:
        engine.add_rule_from_dict(rc)
    engine.on_trigger(on_trigger)

    print(f"\n已加载 {len(engine.list_rules())} 条规则")
    for rule in engine.list_rules():
        print(f"  - {rule.id}: auto_unblock_hours={rule.auto_unblock_hours}")

    test_entries = [
        LogEntry(timestamp=datetime.now(), source_ip='10.0.0.50', dest_port=22, protocol='TCP', action='DENY'),
        LogEntry(timestamp=datetime.now(), source_ip='10.0.0.50', dest_port=22, protocol='TCP', action='DENY'),
        LogEntry(timestamp=datetime.now(), source_ip='10.0.0.51', dest_port=80, protocol='TCP', action='ALLOW'),
        LogEntry(timestamp=datetime.now(), source_ip='10.0.0.50', dest_port=22, protocol='TCP', action='DENY'),
        LogEntry(timestamp=datetime.now(), source_ip='10.0.0.52', dest_port=23, protocol='TCP', action='DENY'),
        LogEntry(timestamp=datetime.now(), source_ip='10.0.0.50', dest_port=22, protocol='TCP', action='DENY'),
    ]

    print(f"\n模拟处理 {len(test_entries)} 条日志...")
    for i, entry in enumerate(test_entries):
        results = engine.process_entry(entry)
        triggered = sum(1 for r in results if r.triggered)
        print(f"  条目{i+1}: {entry.source_ip}:{entry.dest_port} [{entry.action}] -> {len(results)}条规则匹配, {triggered}条触发")

    print(f"\n总共触发了 {len(triggered_rules)} 次规则")
    for t in triggered_rules:
        print(f"  - {t}")

    print("\n规则引擎测试完成 ✓")
    return True


def test_blacklist_manager():
    print("\n" + "=" * 60)
    print("测试3: 黑名单管理器 / Testing Blacklist Manager")
    print("=" * 60)

    from firewall_analyzer.blacklist_manager import BlacklistManager, NullFirewallManager

    with tempfile.TemporaryDirectory() as tmpdir:
        storage = os.path.join(tmpdir, "blacklist_test.json")

        print("\n--- 严格一致性模式测试 ---")
        bl = BlacklistManager(
            storage_path=storage,
            auto_save=True,
            default_expire_hours=None,
            auto_sync=True,
            sync_interval_seconds=60,
            strict_consistency=True,
        )
        bl.firewall = NullFirewallManager()

        print(f"  auto_sync: {bl.auto_sync}")
        print(f"  strict_consistency: {bl.strict_consistency}")

        blocked_events = []
        unblocked_events = []

        def on_block(entry):
            blocked_events.append(entry.ip_address)
            print(f"  ↓ 拉黑事件: {entry.ip_address} - {entry.reason}")

        def on_unblock(entry):
            unblocked_events.append(entry.ip_address)
            print(f"  ↑ 取消拉黑: {entry.ip_address}")

        bl.on_block(on_block)
        bl.on_unblock(on_unblock)

        test_ips = [
            ('192.168.1.100', 'SSH暴力破解', 'rule_ssh', 24),
            ('10.0.0.50', '端口扫描', 'rule_scan', 1),
            ('172.16.0.1', '可疑访问', 'rule_sus', None),
        ]

        print("\n--- 添加黑名单（一致性验证） ---")
        for ip, reason, rule_id, expire in test_ips:
            result = bl.block_ip(ip, reason=reason, rule_id=rule_id, expire_hours=expire)
            print(f"  拉黑 {ip}: {'成功' if result else '失败'}")
            in_system = bl._check_in_blacklist(ip)
            in_internal = ip in bl._entries
            print(f"    系统层: {'✓' if in_system else '✗'}, 内部层: {'✓' if in_internal else '✗'}")
            assert bl.is_blocked(ip), f"IP {ip} 应该已被拉黑"

        print(f"\n当前黑名单: {len(bl.list_ips())} 个IP")
        for entry in bl.list_entries():
            print(f"  - {entry.ip_address}: hits={entry.hits}, reason={entry.reason}, expire={entry.expire_at}")

        stats = bl.get_stats()
        print(f"\n统计信息: {stats}")
        assert stats.get('block_success', 0) == len(test_ips), "拉黑成功计数应该正确"

        print("\n--- 持久化测试（含统计信息） ---")
        assert os.path.exists(storage), "黑名单文件未创建"
        with open(storage, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"  存储文件包含 {len(data.get('entries', []))} 条记录")
        print(f"  统计信息已保存: {'stats' in data}")

        bl2 = BlacklistManager(
            storage_path=storage,
            auto_save=True,
            strict_consistency=True,
        )
        bl2.firewall = NullFirewallManager()
        loaded_count = len(bl2.list_ips())
        print(f"  重新加载后有 {loaded_count} 个IP")
        assert loaded_count == len(test_ips), f"应该加载到 {len(test_ips)} 个IP, 实际 {loaded_count}"

        print("\n--- 取消拉黑（一致性验证） ---")
        result = bl.unblock_ip('10.0.0.50')
        print(f"  取消拉黑 10.0.0.50: {'成功' if result else '失败'}")
        assert not bl.is_blocked('10.0.0.50'), "IP 应该已被取消拉黑"
        print(f"  剩余黑名单: {len(bl.list_ips())} 个IP")

        print("\n--- 系统同步测试 ---")
        sync_result = bl.sync_with_system(save=True)
        print(f"  同步结果: {sync_result}")
        print(f"  系统层面IP: {len(sync_result['system_blocked'])} 个")
        print(f"  内部层面IP: {len(sync_result['internal_blocked'])} 个")

        print("\n黑名单管理器测试完成 ✓")
        return True


def test_whitelist_manager():
    print("\n" + "=" * 60)
    print("测试4: 白名单管理器 / Testing Whitelist Manager")
    print("=" * 60)

    from firewall_analyzer.whitelist_manager import WhitelistManager, WhitelistRule
    from firewall_analyzer.log_parser import LogEntry
    from datetime import datetime

    whitelist = WhitelistManager()

    whitelist_rules = [
        {
            'id': 'wl_internal',
            'name': '内网网段',
            'priority': 10,
            'ip_networks': ['192.168.0.0/16', '10.0.0.0/8'],
            'log_hits': True,
            'exclude_from_blocking': True,
        },
        {
            'id': 'wl_trusted_ports',
            'name': '可信端口',
            'priority': 20,
            'ports': [80, 443],
            'port_ranges': ['1024-5000'],
            'protocols': ['TCP'],
            'match_type': 'any',
        },
        {
            'id': 'wl_specific_ip',
            'name': '公司出口IP',
            'priority': 5,
            'ip_addresses': ['203.0.113.42', '198.51.100.15'],
        },
    ]

    for rule_data in whitelist_rules:
        whitelist.add_rule_from_dict(rule_data)

    print(f"已加载 {len(whitelist.list_rules())} 条白名单规则")
    for rule in sorted(whitelist.list_rules(), key=lambda r: r.priority):
        print(f"  [{rule.priority}] {rule.id}: {rule.name}")

    test_cases = [
        (
            '内网IP 192.168.1.100:22',
            LogEntry(timestamp=datetime.now(), source_ip='192.168.1.100', dest_port=22, protocol='TCP', action='DENY'),
            True, 'wl_internal'
        ),
        (
            '公司出口IP 203.0.113.42:22',
            LogEntry(timestamp=datetime.now(), source_ip='203.0.113.42', dest_port=22, protocol='TCP', action='DENY'),
            True, 'wl_specific_ip'
        ),
        (
            '公网IP访问443端口',
            LogEntry(timestamp=datetime.now(), source_ip='8.8.8.8', dest_port=443, protocol='TCP', action='DENY'),
            True, 'wl_trusted_ports'
        ),
        (
            '公网IP访问22端口',
            LogEntry(timestamp=datetime.now(), source_ip='8.8.8.8', dest_port=22, protocol='UDP', action='DENY'),
            False, None
        ),
        (
            '公网IP 10.0.0.5:1500',
            LogEntry(timestamp=datetime.now(), source_ip='8.8.8.8', dest_port=1500, protocol='TCP', action='DENY'),
            True, 'wl_trusted_ports'
        ),
    ]

    print("\n--- 白名单匹配测试 ---")
    for name, entry, should_match, expected_rule in test_cases:
        match = whitelist.check(entry)
        matched = match is not None
        status = "✓" if matched == should_match else "✗"
        matched_rule = match.rule_id if match else None
        print(f"  {status} {name}: 预期={'白名单' if should_match else '不匹配'}, 实际={matched_rule or '不匹配'}")
        assert matched == should_match, f"测试失败: {name}"
        if should_match and expected_rule:
            assert matched_rule == expected_rule, f"应该命中规则 {expected_rule}, 实际 {matched_rule}"

    print("\n--- 白名单命中统计 ---")
    stats = whitelist.get_hit_stats()
    for rid, s in stats.items():
        print(f"  {s['name']}: {s['hits']} 次命中")

    assert stats['wl_internal']['hits'] >= 1, "内网规则应该有命中"
    assert stats['wl_specific_ip']['hits'] >= 1, "特定IP规则应该有命中"

    print("\n--- 排除封禁测试 ---")
    entry = LogEntry(timestamp=datetime.now(), source_ip='192.168.1.200', dest_port=22, protocol='TCP', action='DENY')
    match = whitelist.should_exclude_from_blocking(entry)
    assert match is not None, "内网IP应该排除封禁"
    print(f"  ✓ 192.168.1.200 排除封禁，匹配规则: {match.rule_name}")

    print("\n白名单管理器测试完成 ✓")
    return True


def test_webhook_action():
    print("\n" + "=" * 60)
    print("测试5: Webhook动作 / Testing Webhook Action")
    print("=" * 60)

    from firewall_analyzer.rule_engine import send_webhook_action, RuleActionContext, send_webhook
    from firewall_analyzer.log_parser import LogEntry
    from datetime import datetime

    webhook_calls = []

    class MockURLOpen:
        def __init__(self, status=200, response=b'{"status": "ok"}'):
            self.status = status
            self._response = response

        def read(self):
            return self._response

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    try:
        import urllib.request
        original_urlopen = urllib.request.urlopen

        def mock_urlopen(req, timeout=None):
            webhook_calls.append({
                'url': req.full_url,
                'method': req.method,
                'headers': dict(req.headers),
                'data': req.data.decode('utf-8') if req.data else None,
            })
            return MockURLOpen(status=200, response=b'{"status": "success"}')

        urllib.request.urlopen = mock_urlopen

        entries = [
            LogEntry(timestamp=datetime.now(), source_ip='203.0.113.99', dest_port=22, protocol='TCP', action='DENY', raw_line='TEST LOG'),
        ]

        context = RuleActionContext(
            rule_id='test_ssh',
            rule_name='SSH Brute Force',
            ip_address='203.0.113.99',
            entries=entries,
            count=10,
            time_window=3600,
            extra={
                'url': 'https://api.example.com/alerts',
                'method': 'POST',
                'headers': {'Authorization': 'Bearer test-token'},
                'timeout': 10,
            },
        )

        print("\n--- 发送Webhook（自定义payload） ---")
        context.extra['payload'] = {
            'event': 'block',
            'ip': '{IP}',
            'rule': '{RULE_ID}',
            'count': '{COUNT}',
        }

        send_webhook_action(context)

        assert len(webhook_calls) == 1, "应该发送1次Webhook"
        call = webhook_calls[0]
        print(f"  ✓ URL: {call['url']}")
        print(f"  ✓ Method: {call['method']}")
        print(f"  ✓ Auth header: {call['headers'].get('Authorization')}")

        import json
        payload = json.loads(call['data'])
        print(f"  ✓ Payload: {payload}")
        assert payload['ip'] == '203.0.113.99', "IP应该被替换"
        assert payload['rule'] == 'test_ssh', "规则ID应该被替换"
        assert payload['count'] == '10', "次数应该被替换"

        print("\n--- 发送Webhook（默认payload） ---")
        webhook_calls.clear()
        context.extra.pop('payload', None)
        send_webhook_action(context)

        assert len(webhook_calls) == 1, "应该发送1次Webhook"
        payload = json.loads(webhook_calls[0]['data'])
        print(f"  ✓ 默认payload包含字段: {list(payload.keys())}")
        assert payload['event'] == 'firewall_rule_triggered'
        assert payload['ip_address'] == '203.0.113.99'
        assert payload['sample_logs']

    finally:
        import urllib.request
        urllib.request.urlopen = original_urlopen

    print("\nWebhook动作测试完成 ✓")
    return True


def test_log_monitor():
    print("\n" + "=" * 60)
    print("测试6: 实时日志监控 / Testing Log Monitor")
    print("=" * 60)

    from firewall_analyzer.log_monitor import LogMonitor

    with tempfile.TemporaryDirectory() as tmpdir:
        logfile = os.path.join(tmpdir, "test.log")

        collected_lines = []
        stop_event = threading.Event()

        def callback(line: str):
            collected_lines.append(line)
            print(f"  ← 收到新行: {line[:60]}")

        with open(logfile, 'w', encoding='utf-8') as f:
            f.write("初始行1\n初始行2\n初始行3\n")

        print("\n从开头读取模式...")
        collected_lines.clear()
        monitor = LogMonitor(logfile, callback, from_beginning=True, poll_interval=0.2)
        monitor.start()
        time.sleep(0.5)

        print(f"  读取了 {len(collected_lines)} 行初始内容")
        assert len(collected_lines) >= 3, f"应该至少读取3行, 实际 {len(collected_lines)}"

        print("\n追加新行测试实时监控...")
        new_lines = [
            '新行1: 测试日志',
            '新行2: SRC=1.2.3.4 DST=5.6.7.8 DROP',
            '新行3: 更多测试数据',
        ]

        for line in new_lines:
            with open(logfile, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
            time.sleep(0.3)

        time.sleep(0.5)
        monitor.stop()

        print(f"  总共收集到 {len(collected_lines)} 行")
        last_three = collected_lines[-3:] if len(collected_lines) >= 3 else collected_lines
        for line in last_three:
            print(f"    {line}")

        assert any('新行1' in l for l in collected_lines), "新行1应该被收集"
        assert any('SRC=1.2.3.4' in l for l in collected_lines), "新行2应该被收集"

        print("\n日志监控测试完成 ✓")
        return True


def _close_all_logging_handlers():
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        try:
            handler.close()
            root_logger.removeHandler(handler)
        except Exception:
            pass
    fw_logger = logging.getLogger('firewall_analyzer')
    for handler in fw_logger.handlers[:]:
        try:
            handler.close()
            fw_logger.removeHandler(handler)
        except Exception:
            pass
    logging.shutdown()


def test_end_to_end():
    print("\n" + "=" * 60)
    print("测试7: 端到端集成测试（含白名单+自动解封+Webhook） / End-to-End Integration Test")
    print("=" * 60)

    tmpdir = tempfile.mkdtemp()
    success = False
    try:
        logfile = os.path.join(tmpdir, "fw.log")
        bl_storage = os.path.join(tmpdir, "bl.json")

        with open(logfile, 'w', encoding='utf-8') as f:
            f.write("")

        config = AppConfig(
            log_level="WARNING",
            log_file=None,
            log_sources=[
                LogSourceConfig(
                    path=logfile,
                    parser="iptables",
                    from_beginning=False,
                    poll_interval=0.2,
                )
            ],
            rules=[
                {
                    'id': 'int_test_ssh',
                    'name': 'SSH暴力破解-集成测试',
                    'conditions': [
                        {'field': 'dest_port', 'operator': 'eq', 'value': 22},
                        {'field': 'action', 'operator': 'eq', 'value': 'DENY'},
                        {'field': 'source_ip', 'operator': 'not_in_cidr', 'value': '192.168.0.0/16'},
                    ],
                    'threshold': 3,
                    'time_window': 3600,
                    'group_by': 'source_ip',
                    'cooldown': 0,
                    'auto_unblock_hours': 24,
                    'actions': [
                        {'type': 'block', 'reason': '集成测试-SSH暴力破解'},
                        {'type': 'log', 'level': 'WARNING', 'message': 'Test alert from {IP}'},
                    ],
                },
            ],
            blacklist=BlacklistConfig(
                enabled=True,
                storage_path=bl_storage,
                auto_save=True,
                auto_sync=True,
                sync_interval_seconds=60,
                strict_consistency=True,
            ),
            whitelist=WhitelistConfig(
                enabled=True,
                rules=[
                    {
                        'id': 'wl_int_test',
                        'name': '测试白名单',
                        'ip_addresses': ['10.0.0.100'],
                    },
                ],
            ),
        )

        setup_logging(config)

        analyzer = FirewallAnalyzer(config)

        from firewall_analyzer.blacklist_manager import NullFirewallManager
        analyzer.blacklist.firewall = NullFirewallManager()

        print(f"\n配置的日志源: {logfile}")
        print(f"黑名单存储: {bl_storage}")
        print(f"规则数量: {len(analyzer.rule_engine.list_rules())}")
        print(f"白名单规则: {len(analyzer.whitelist.list_rules())}")

        print("\n启动分析器...")
        analyzer.start()
        time.sleep(0.5)

        print("\n--- 测试白名单IP（不应该被拉黑） ---")
        whitelist_ip = "10.0.0.100"
        print(f"  模拟白名单IP {whitelist_ip} 连续访问...")
        for i in range(5):
            line = (
                f"Jun 14 13:0{i}:00 kernel: DROP IN=eth0 "
                f"SRC={whitelist_ip} DST=10.0.0.1 PROTO=TCP SPT={50000+i} DPT=22 SYN"
            )
            with open(logfile, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
            time.sleep(0.3)

        time.sleep(1.0)
        whitelist_blocked = analyzer.blacklist.is_blocked(whitelist_ip)
        print(f"  白名单IP {whitelist_ip} 是否已拉黑: {'是' if whitelist_blocked else '否'}")
        assert not whitelist_blocked, "白名单IP不应该被拉黑"
        whitelist_stats = analyzer.whitelist.get_hit_stats()
        print(f"  白名单命中统计: {whitelist_stats.get('wl_int_test', {}).get('hits', 0)} 次")

        print("\n--- 测试攻击IP（应该被拉黑） ---")
        attacker_ip = "203.0.113.99"
        print(f"  模拟攻击 IP: {attacker_ip} 连续访问SSH端口...")

        attack_lines = []
        for i in range(5):
            line = (
                f"Jun 14 13:{10+i:02d}:00 kernel: DROP IN=eth0 "
                f"SRC={attacker_ip} DST=10.0.0.1 PROTO=TCP SPT={50000+i} DPT=22 SYN"
            )
            attack_lines.append(line)

        for i, line in enumerate(attack_lines):
            with open(logfile, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
            print(f"  写入攻击行 {i+1}/5")
            time.sleep(0.4)

        print("\n等待规则触发...")
        time.sleep(1.5)

        blocked = analyzer.blacklist.is_blocked(attacker_ip)
        stats = analyzer.stats

        print(f"\n结果:")
        print(f"  处理行数: {stats['lines_processed']}")
        print(f"  解析条目: {stats['entries_parsed']}")
        print(f"  白名单命中: {stats['whitelist_hits']}")
        print(f"  触发规则: {stats['rules_triggered']}")
        print(f"  拉黑IP数: {stats['ips_blocked']}")
        print(f"  攻击者 {attacker_ip} {'已被拉黑 ✓' if blocked else '未被拉黑 ✗'}")
        print(f"  当前黑名单: {analyzer.blacklist.list_ips()}")

        entry = analyzer.blacklist.get_entry(attacker_ip)
        if entry:
            print(f"  自动解封时间: {entry.expire_at}")
            assert entry.expire_at is not None, "应该有自动解封时间"

        print("\n写入正常流量（不应触发）...")
        normal_lines = [
            f"Jun 14 13:20:00 kernel: ACCEPT IN=eth0 SRC=10.0.0.200 DST=10.0.0.1 PROTO=TCP SPT=44444 DPT=80",
            f"Jun 14 13:20:01 kernel: ACCEPT IN=eth0 SRC=10.0.0.201 DST=10.0.0.1 PROTO=TCP SPT=44444 DPT=443",
        ]
        for line in normal_lines:
            with open(logfile, 'a', encoding='utf-8') as f:
                f.write(line + '\n')

        time.sleep(0.5)

        normal_ok = not analyzer.blacklist.is_blocked('10.0.0.200')
        print(f"  正常流量未被拉黑: {'✓' if normal_ok else '✗'}")

        print("\n停止分析器...")
        analyzer.stop()
        time.sleep(0.3)

        _close_all_logging_handlers()
        time.sleep(0.2)

        assert blocked, f"攻击者IP {attacker_ip} 应该被拉黑"
        assert stats['rules_triggered'] >= 1, "应该至少触发一次规则"
        assert stats['ips_blocked'] >= 1, "应该至少拉黑一个IP"
        assert stats['whitelist_hits'] >= 5, "白名单应该至少命中5次"

        success = True
        print("\n端到端集成测试通过 ✓")
        return True
    except AssertionError as ae:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise
    finally:
        _close_all_logging_handlers()
        time.sleep(0.1)
        import shutil
        for _ in range(5):
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
                break
            except Exception:
                time.sleep(0.2)


def main():
    print("╔" + "═" * 58 + "╗")
    print("║" + " 动态防火墙日志分析器 - 功能测试套件 (增强版)".center(58) + "║")
    print("╚" + "═" * 58 + "╝")

    tests = [
        ("日志解析器", test_log_parsers),
        ("规则引擎", test_rule_engine),
        ("黑名单管理器", test_blacklist_manager),
        ("白名单管理器", test_whitelist_manager),
        ("Webhook动作", test_webhook_action),
        ("实时日志监控", test_log_monitor),
        ("端到端集成", test_end_to_end),
    ]

    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result, None))
        except Exception as e:
            import traceback
            print(f"\n✗ 测试 [{name}] 抛出异常: {e}")
            traceback.print_exc()
            results.append((name, False, str(e)))

    print("\n" + "=" * 60)
    print("测试结果汇总 / Test Summary")
    print("=" * 60)

    passed = 0
    failed = 0
    for name, result, error in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status}  {name}")
        if error:
            print(f"          错误: {error}")
        if result:
            passed += 1
        else:
            failed += 1

    print("-" * 60)
    print(f"  总计: {len(results)} 个测试 | 通过: {passed} | 失败: {failed}")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
