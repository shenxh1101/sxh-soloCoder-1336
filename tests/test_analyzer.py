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

from firewall_analyzer.config_loader import AppConfig, LogSourceConfig, BlacklistConfig
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
    ]

    print("\n--- Windows 安全日志解析 ---")
    for line in windows_lines:
        entry = registry.parse(line)
        if entry:
            print(f"  ✓ 解析成功:")
            print(f"    时间: {entry.timestamp}")
            print(f"    源IP: {entry.source_ip}")
            print(f"    目标端口: {entry.dest_port} | 协议: {entry.protocol} | 动作: {entry.action}")
            if entry.extra.get('event_id'):
                print(f"    Event ID: {entry.extra['event_id']}")
        else:
            print(f"  ✗ 解析失败: {line[:80]}...")

    print("\n日志解析器测试完成 ✓")
    return True


def test_rule_engine():
    print("\n" + "=" * 60)
    print("测试2: 规则引擎 / Testing Rule Engine")
    print("=" * 60)

    from firewall_analyzer.rule_engine import RuleEngine, Rule, RuleActionContext

    triggered_rules = []

    def on_trigger(rule: Rule, ctx: RuleActionContext):
        triggered_rules.append({
            'rule_id': rule.id,
            'ip': ctx.ip_address,
            'count': ctx.count,
        })
        print(f"  ⚠ 规则触发: {rule.id} - IP={ctx.ip_address} - 次数={ctx.count}")

    rules_config = [
        {
            'id': 'test_ssh_brute',
            'name': 'SSH暴力破解测试',
            'conditions': [
                {'field': 'dest_port', 'operator': 'eq', 'value': 22},
                {'field': 'action', 'operator': 'eq', 'value': 'DENY'},
            ],
            'threshold': 3,
            'time_window': 3600,
            'group_by': 'source_ip',
            'cooldown': 0,
            'actions': [{'type': 'log', 'level': 'WARNING', 'message': 'SSH brute force'}],
        },
        {
            'id': 'test_single_deny',
            'name': '单次拒绝即报警',
            'conditions': [
                {'field': 'action', 'operator': 'eq', 'value': 'DENY'},
            ],
            'threshold': 1,
            'time_window': 60,
            'group_by': 'source_ip+dest_port',
            'cooldown': 0,
            'actions': [],
        },
    ]

    engine = RuleEngine()
    for rc in rules_config:
        engine.add_rule_from_dict(rc)
    engine.on_trigger(on_trigger)

    print(f"\n已加载 {len(engine.list_rules())} 条规则")

    from firewall_analyzer.log_parser import LogEntry
    from datetime import datetime

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
        bl = BlacklistManager(
            storage_path=storage,
            auto_save=True,
            default_expire_hours=None,
        )
        bl.firewall = NullFirewallManager()

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

        print("\n--- 添加黑名单 ---")
        for ip, reason, rule_id, expire in test_ips:
            result = bl.block_ip(ip, reason=reason, rule_id=rule_id, expire_hours=expire)
            print(f"  拉黑 {ip}: {'成功' if result else '失败'}")
            assert bl.is_blocked(ip), f"IP {ip} 应该已被拉黑"

        print(f"\n当前黑名单: {len(bl.list_ips())} 个IP")
        for entry in bl.list_entries():
            print(f"  - {entry.ip_address}: hits={entry.hits}, reason={entry.reason}, expire={entry.expire_at}")

        print("\n--- 持久化测试 ---")
        assert os.path.exists(storage), "黑名单文件未创建"
        with open(storage, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"  存储文件包含 {len(data.get('entries', []))} 条记录")

        bl2 = BlacklistManager(storage_path=storage, auto_save=True)
        bl2.firewall = NullFirewallManager()
        loaded_count = len(bl2.list_ips())
        print(f"  重新加载后有 {loaded_count} 个IP")
        assert loaded_count == len(test_ips), f"应该加载到 {len(test_ips)} 个IP, 实际 {loaded_count}"

        print("\n--- 取消拉黑 ---")
        result = bl.unblock_ip('10.0.0.50')
        print(f"  取消拉黑 10.0.0.50: {'成功' if result else '失败'}")
        assert not bl.is_blocked('10.0.0.50'), "IP 应该已被取消拉黑"
        print(f"  剩余黑名单: {len(bl.list_ips())} 个IP")

        print("\n黑名单管理器测试完成 ✓")
        return True


def test_log_monitor():
    print("\n" + "=" * 60)
    print("测试4: 实时日志监控 / Testing Log Monitor")
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
    print("测试5: 端到端集成测试 / End-to-End Integration Test")
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
                    ],
                    'threshold': 3,
                    'time_window': 3600,
                    'group_by': 'source_ip',
                    'cooldown': 0,
                    'actions': [
                        {'type': 'block', 'reason': '集成测试-SSH暴力破解', 'expire_hours': 1},
                        {'type': 'log', 'level': 'WARNING', 'message': 'Test alert from {IP}'},
                    ],
                },
            ],
            blacklist=BlacklistConfig(
                enabled=True,
                storage_path=bl_storage,
                auto_save=True,
            ),
        )

        setup_logging(config)

        analyzer = FirewallAnalyzer(config)

        from firewall_analyzer.blacklist_manager import NullFirewallManager
        analyzer.blacklist.firewall = NullFirewallManager()

        print(f"\n配置的日志源: {logfile}")
        print(f"黑名单存储: {bl_storage}")
        print(f"规则数量: {len(analyzer.rule_engine.list_rules())}")

        print("\n启动分析器...")
        analyzer.start()
        time.sleep(0.5)

        attacker_ip = "203.0.113.99"
        print(f"\n模拟攻击 IP: {attacker_ip} 连续访问SSH端口...")

        attack_lines = []
        for i in range(5):
            line = (
                f"Jun 14 12:{30+i:02d}:00 kernel: [100000.{i:06d}] DROP IN=eth0 "
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
        print(f"  触发规则: {stats['rules_triggered']}")
        print(f"  拉黑IP数: {stats['ips_blocked']}")
        print(f"  攻击者 {attacker_ip} {'已被拉黑 ✓' if blocked else '未被拉黑 ✗'}")
        print(f"  当前黑名单: {analyzer.blacklist.list_ips()}")

        print("\n写入正常流量（不应触发）...")
        normal_lines = [
            f"Jun 14 12:40:00 kernel: ACCEPT IN=eth0 SRC=10.0.0.200 DST=10.0.0.1 PROTO=TCP SPT=44444 DPT=80",
            f"Jun 14 12:40:01 kernel: ACCEPT IN=eth0 SRC=10.0.0.201 DST=10.0.0.1 PROTO=TCP SPT=44444 DPT=443",
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
    print("║" + " 动态防火墙日志分析器 - 功能测试套件".center(58) + "║")
    print("╚" + "═" * 58 + "╝")

    tests = [
        ("日志解析器", test_log_parsers),
        ("规则引擎", test_rule_engine),
        ("黑名单管理器", test_blacklist_manager),
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
