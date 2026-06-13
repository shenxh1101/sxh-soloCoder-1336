import re
import logging
import logging.handlers
import signal
import sys
import time
import threading
from typing import Optional

from .config_loader import AppConfig, load_config
from .log_parser import LogParserRegistry, LogEntry
from .log_monitor import MultiLogMonitor, LogMonitor
from .rule_engine import RuleEngine, Rule, RuleActionContext
from .blacklist_manager import BlacklistManager, BlacklistEntry
from .whitelist_manager import WhitelistManager, WhitelistMatch

logger = logging.getLogger("firewall_analyzer")


def setup_logging(config: AppConfig):
    log_level = getattr(logging, config.log_level.upper(), logging.INFO)

    handlers: list[logging.Handler] = []

    console_handler = logging.StreamHandler(sys.stdout)
    console_format = logging.Formatter(
        '[%(asctime)s] %(levelname)-8s %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    console_handler.setFormatter(console_format)
    handlers.append(console_handler)

    if config.log_file:
        import os
        log_dir = os.path.dirname(config.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            config.log_file,
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding='utf-8',
        )
        file_format = logging.Formatter(
            '[%(asctime)s] %(levelname)-8s %(name)s [%(process)d:%(threadName)s]: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
        )
        file_handler.setFormatter(file_format)
        handlers.append(file_handler)

    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True,
    )

    logging.getLogger('firewall_analyzer').setLevel(log_level)


class FirewallAnalyzer:
    def __init__(self, config: AppConfig):
        self.config = config
        self.parser_registry = LogParserRegistry()
        self.blacklist = BlacklistManager(
            storage_path=config.blacklist.storage_path,
            auto_save=config.blacklist.auto_save,
            default_expire_hours=config.blacklist.default_expire_hours,
            auto_sync=config.blacklist.auto_sync,
            sync_interval_seconds=config.blacklist.sync_interval_seconds,
            strict_consistency=config.blacklist.strict_consistency,
        )
        self.whitelist = WhitelistManager()
        self.rule_engine = RuleEngine()
        self._monitor: Optional[MultiLogMonitor] = None
        self._stop_event = threading.Event()
        self._stats_lock = threading.Lock()
        self._stats = {
            'lines_processed': 0,
            'entries_parsed': 0,
            'rules_triggered': 0,
            'ips_blocked': 0,
            'whitelist_hits': 0,
            'start_time': time.time(),
        }

        self._setup_blacklist_callbacks()
        self._setup_rule_actions()
        self._load_whitelist_rules()
        self._load_rules()
        self._setup_cleanup_thread()

    def _setup_blacklist_callbacks(self):
        def on_block(entry: BlacklistEntry):
            with self._stats_lock:
                self._stats['ips_blocked'] += 1
            logger.warning(
                f"[BLACKLIST] + {entry.ip_address} "
                f"| reason: {entry.reason or 'N/A'} "
                f"| rule: {entry.rule_id or 'N/A'} "
                f"| expire: {entry.expire_at.isoformat() if entry.expire_at else 'never'}"
            )

        def on_unblock(entry: BlacklistEntry):
            logger.info(
                f"[BLACKLIST] - {entry.ip_address} "
                f"| was blocked for {entry.reason or 'N/A'}"
            )

        self.blacklist.on_block(on_block)
        self.blacklist.on_unblock(on_unblock)

    def _load_whitelist_rules(self):
        if not self.config.whitelist.enabled:
            logger.info("Whitelist disabled in config")
            return

        rules = self.config.whitelist.rules
        if not rules:
            logger.warning("Whitelist enabled but no rules configured")
            return

        for rule_data in rules:
            try:
                self.whitelist.add_rule_from_dict(rule_data)
            except Exception as e:
                logger.error(f"Failed to load whitelist rule: {rule_data.get('id', 'unknown')}: {e}")

        logger.info(f"Loaded {len(self.whitelist.list_rules())} whitelist rules")

    def _setup_rule_actions(self):
        def block_action(context: RuleActionContext):
            if not context.ip_address:
                logger.warning(f"Cannot block: no IP address in context for rule {context.rule_id}")
                return

            latest_entry = context.entries[-1] if context.entries else None
            if latest_entry:
                whitelist_match = self.whitelist.should_exclude_from_blocking(latest_entry)
                if whitelist_match:
                    logger.info(
                        f"[WHITELIST-EXCLUDE] Skipping block for {context.ip_address} | "
                        f"matched rule: {whitelist_match.rule_name} | "
                        f"reason: {whitelist_match.reason}"
                    )
                    return

            if self.blacklist.is_blocked(context.ip_address):
                return

            reason = context.extra.get('reason', context.rule_name)
            expire_hours = context.extra.get('expire_hours', context.extra.get('auto_unblock_hours'))
            self.blacklist.block_ip(
                ip=context.ip_address,
                reason=reason,
                rule_id=context.rule_id,
                expire_hours=expire_hours,
                extra={
                    'trigger_count': context.count,
                    'time_window': context.time_window,
                },
            )

        def unblock_action(context: RuleActionContext):
            if not context.ip_address:
                return
            self.blacklist.unblock_ip(context.ip_address)

        def command_action(context: RuleActionContext):
            command = context.extra.get('command', '')
            if not command:
                return
            ip = context.ip_address or ''
            command = command.replace('{IP}', ip)
            command = command.replace('{RULE_ID}', context.rule_id)
            command = command.replace('{RULE_NAME}', context.rule_name)
            command = command.replace('{COUNT}', str(context.count))
            command = re.sub(r'\$IP\b', ip, command)
            shell = context.extra.get('shell', True)
            rc, stdout, stderr = self.blacklist.execute_custom_command(
                command, ip=None,
            )
            if rc == 0:
                logger.info(f"[ACTION:COMMAND] Executed: {command}")
                if stdout:
                    logger.debug(f"  stdout: {stdout[:500]}")
            else:
                logger.error(f"[ACTION:COMMAND] Failed (rc={rc}): {command}")
                if stderr:
                    logger.error(f"  stderr: {stderr[:500]}")

        def email_action(context: RuleActionContext):
            import os
            recipient = context.extra.get('to', os.environ.get('FW_ALERT_EMAIL'))
            if not recipient:
                logger.warning("Email action skipped: no recipient configured")
                return
            subject = context.extra.get(
                'subject',
                f"[FW Alert] {context.rule_name} - {context.ip_address}",
            )
            body = context.extra.get('body', '')
            if not body:
                body = (
                    f"Firewall rule triggered:\n\n"
                    f"Rule: {context.rule_name} ({context.rule_id})\n"
                    f"IP: {context.ip_address}\n"
                    f"Count: {context.count} in {context.time_window}s\n"
                    f"Reason: {context.extra.get('reason', context.rule_name)}\n"
                    f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                )
            try:
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart

                sender = os.environ.get('FW_SMTP_FROM', 'firewall@localhost')
                smtp_host = os.environ.get('FW_SMTP_HOST', 'localhost')
                smtp_port = int(os.environ.get('FW_SMTP_PORT', '25'))
                smtp_user = os.environ.get('FW_SMTP_USER')
                smtp_pass = os.environ.get('FW_SMTP_PASS')
                use_tls = os.environ.get('FW_SMTP_TLS', '').lower() in ('1', 'true', 'yes')

                msg = MIMEMultipart()
                msg['From'] = sender
                msg['To'] = recipient
                msg['Subject'] = subject
                msg.attach(MIMEText(body, 'plain'))

                with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as smtp:
                    if use_tls:
                        smtp.starttls()
                    if smtp_user and smtp_pass:
                        smtp.login(smtp_user, smtp_pass)
                    smtp.sendmail(sender, [recipient], msg.as_string())

                logger.info(f"[ACTION:EMAIL] Alert sent to {recipient}")
            except Exception as e:
                logger.error(f"[ACTION:EMAIL] Failed to send email: {e}")

        self.rule_engine.register_action_handler('block', block_action)
        self.rule_engine.register_action_handler('deny', block_action)
        self.rule_engine.register_action_handler('drop', block_action)
        self.rule_engine.register_action_handler('unblock', unblock_action)
        self.rule_engine.register_action_handler('allow', unblock_action)
        self.rule_engine.register_action_handler('command', command_action)
        self.rule_engine.register_action_handler('exec', command_action)
        self.rule_engine.register_action_handler('email', email_action)
        self.rule_engine.register_action_handler('mail', email_action)

    def _load_rules(self):
        for rule_data in self.config.rules:
            try:
                self.rule_engine.add_rule_from_dict(rule_data)
            except Exception as e:
                logger.error(f"Failed to load rule: {rule_data.get('id', 'unknown')}: {e}")

        def on_rule_triggered(rule: Rule, context: RuleActionContext):
            with self._stats_lock:
                self._stats['rules_triggered'] += 1
            logger.info(
                f"[RULE TRIGGER] {rule.id} ({rule.name}) "
                f"| IP: {context.ip_address} "
                f"| Count: {context.count}/{rule.threshold} "
                f"| Window: {rule.time_window}s"
            )

        self.rule_engine.on_trigger(on_rule_triggered)

    def _setup_cleanup_thread(self):
        def cleanup_loop():
            while not self._stop_event.is_set():
                try:
                    time.sleep(300)
                    if self._stop_event.is_set():
                        break
                    removed = self.blacklist.cleanup_expired()
                    if removed > 0:
                        logger.info(f"Cleanup: removed {removed} expired blacklist entries")
                except Exception as e:
                    logger.error(f"Error in cleanup thread: {e}")

        t = threading.Thread(target=cleanup_loop, name="CleanupThread", daemon=True)
        t.start()

    def _on_log_line(self, file_path: str, line: str):
        with self._stats_lock:
            self._stats['lines_processed'] += 1

        entry = self.parser_registry.parse(line)
        if entry is None:
            logger.debug(f"Unparseable line from {file_path}: {line[:200]}")
            return

        with self._stats_lock:
            self._stats['entries_parsed'] += 1

        whitelist_match = self.whitelist.check(entry)
        if whitelist_match:
            with self._stats_lock:
                self._stats['whitelist_hits'] += 1
            logger.debug(
                f"Whitelist match: {whitelist_match.rule_name} | "
                f"source: {entry.source_ip}:{entry.source_port or '-'} | "
                f"dest: {entry.dest_ip}:{entry.dest_port or '-'}"
            )

        if self.blacklist.is_blocked(entry.source_ip):
            logger.debug(f"Skipping entry from already-blocked IP: {entry.source_ip}")
            return

        self.rule_engine.process_entry(entry)

    def start(self):
        logger.info("=" * 60)
        logger.info("动态防火墙日志分析器启动 / Firewall Analyzer Starting")
        logger.info("=" * 60)

        if not self.config.log_sources:
            logger.error("No log sources configured!")
            return

        logger.info(f"Loaded {len(self.rule_engine.list_rules())} rules")
        logger.info(f"Monitoring {len(self.config.log_sources)} log source(s)")

        for src in self.config.log_sources:
            logger.info(f"  - {src.path} [parser={src.parser or 'auto'}]")

        if self.config.whitelist.enabled:
            whitelist_rules = self.whitelist.list_rules()
            logger.info(f"Whitelist: {len(whitelist_rules)} rule(s) loaded")

        if self.config.blacklist.enabled:
            existing_ips = self.blacklist.list_ips()
            logger.info(f"Blacklist storage: {self.config.blacklist.storage_path or 'memory only'}")
            logger.info(f"Existing blocked IPs: {len(existing_ips)}")
            if self.config.blacklist.strict_consistency:
                logger.info("Blacklist strict consistency mode: ENABLED")
            if self.config.blacklist.auto_sync:
                logger.info(f"Blacklist auto-sync: every {self.config.blacklist.sync_interval_seconds}s")

        self._monitor = MultiLogMonitor(
            log_paths=[src.path for src in self.config.log_sources],
            line_callback=self._on_log_line,
            from_beginning=any(src.from_beginning for src in self.config.log_sources),
            poll_interval=min(src.poll_interval for src in self.config.log_sources),
        )

        self._monitor.start()
        logger.info("Analyzer is now running. Press Ctrl+C to stop.")

    def stop(self):
        logger.info("Shutting down firewall analyzer...")
        self._stop_event.set()
        if self._monitor:
            self._monitor.stop()
        if self.blacklist:
            self.blacklist.cleanup_expired()
        self._print_stats()
        logger.info("Shutdown complete.")

    def _print_stats(self):
        elapsed = time.time() - self._stats['start_time']
        with self._stats_lock:
            stats = dict(self._stats)
        logger.info("=" * 40)
        logger.info("运行统计 / Statistics")
        logger.info("=" * 40)
        logger.info(f"  运行时长: {elapsed:.1f}s ({elapsed/3600:.2f}h)")
        logger.info(f"  处理行数: {stats['lines_processed']}")
        logger.info(f"  解析条目: {stats['entries_parsed']}")
        logger.info(f"  白名单命中: {stats['whitelist_hits']}")
        logger.info(f"  触发规则: {stats['rules_triggered']}")
        logger.info(f"  拉黑IP数: {stats['ips_blocked']}")
        logger.info(f"  当前黑名单: {len(self.blacklist.list_ips())}")
        bl_stats = self.blacklist.get_stats()
        if bl_stats.get('inconsistencies_found', 0) > 0:
            logger.info(f"  检测不一致: {bl_stats['inconsistencies_found']}")
        logger.info("=" * 40)

        whitelist_stats = self.whitelist.get_hit_stats()
        if any(s['hits'] > 0 for s in whitelist_stats.values()):
            logger.info("白名单命中统计 / Whitelist Hit Stats")
            logger.info("-" * 40)
            for rid, s in sorted(whitelist_stats.items(), key=lambda x: x[1]['hits'], reverse=True):
                if s['hits'] > 0:
                    last_hit = s['last_hit'].strftime('%Y-%m-%d %H:%M:%S') if s['last_hit'] else 'N/A'
                    logger.info(f"  {s['name']:<30} hits: {s['hits']:<6} last: {last_hit}")
            logger.info("=" * 40)

    def wait(self):
        try:
            while not self._stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")
            self.stop()

    def run(self):
        self.start()
        self.wait()

    @property
    def stats(self) -> dict:
        with self._stats_lock:
            return dict(self._stats)


def _register_signal_handlers(analyzer: FirewallAnalyzer):
    def _signal_handler(signum, frame):
        sig_name = signal.Signals(signum).name
        logger.info(f"Received signal {sig_name}, initiating shutdown...")
        analyzer.stop()
        sys.exit(0)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal_handler)
        except (ValueError, OSError):
            pass


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="动态防火墙日志分析器 / Dynamic Firewall Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例 / Examples:
  python -m firewall_analyzer -c config.yaml
  python -m firewall_analyzer --config config.yaml --dry-run
  python -m firewall_analyzer --list-rules -c config.yaml
  python -m firewall_analyzer --show-blacklist -c config.yaml
  python -m firewall_analyzer --unblock 192.168.1.100 -c config.yaml
        """,
    )

    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='配置文件路径 (YAML或JSON) / Path to config file',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='测试模式，不实际执行拉黑 / Dry run mode, no actual blocking',
    )
    parser.add_argument(
        '--list-rules',
        action='store_true',
        help='列出所有规则并退出 / List all rules and exit',
    )
    parser.add_argument(
        '--show-blacklist',
        action='store_true',
        help='显示当前黑名单并退出 / Show current blacklist and exit',
    )
    parser.add_argument(
        '--block',
        metavar='IP',
        help='手动拉黑指定IP / Manually block an IP',
    )
    parser.add_argument(
        '--unblock',
        metavar='IP',
        help='手动取消拉黑指定IP / Manually unblock an IP',
    )
    parser.add_argument(
        '--block-reason',
        default='Manual block',
        help='手动拉黑的原因 / Reason for manual block',
    )
    parser.add_argument(
        '--block-expire-hours',
        type=int,
        default=None,
        help='手动拉黑的过期时间(小时) / Expire hours for manual block',
    )

    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except FileNotFoundError as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"加载配置文件失败: {e}", file=sys.stderr)
        sys.exit(1)

    setup_logging(config)

    analyzer = FirewallAnalyzer(config)

    if args.dry_run:
        from .blacklist_manager import NullFirewallManager
        analyzer.blacklist.firewall = NullFirewallManager()
        logger.info("DRY RUN MODE - No actual blocking will occur")

    if args.list_rules:
        rules = analyzer.rule_engine.list_rules()
        print(f"\n已加载规则 / Loaded Rules ({len(rules)} total):")
        print("-" * 80)
        for rule in rules:
            status = "ON" if rule.enabled else "OFF"
            print(f"  [{status}] {rule.id} - {rule.name}")
            print(f"        阈值: {rule.threshold}次 / {rule.time_window}s | 分组: {rule.group_by}")
            if rule.burst_threshold:
                print(f"        突发: {rule.burst_threshold}次 / {rule.burst_window}s")
            if rule.auto_unblock_hours:
                print(f"        自动解封: {rule.auto_unblock_hours}小时")
            if rule.description:
                print(f"        说明: {rule.description}")
            if rule.conditions:
                print(f"        条件: {len(rule.conditions)} condition(s)")
            if rule.actions:
                print(f"        动作: {', '.join(a.get('type', a.get('action', '?')) for a in rule.actions)}")
            print()
        sys.exit(0)

    if args.show_blacklist:
        entries = analyzer.blacklist.list_entries()
        print(f"\n当前黑名单 / Current Blacklist ({len(entries)} entries):")
        print("-" * 100)
        print(f"  {'IP Address':<18} {'Added At':<22} {'Reason':<25} {'Expires':<22} {'Hits'}")
        print("-" * 100)
        for entry in entries:
            exp_str = entry.expire_at.strftime('%Y-%m-%d %H:%M:%S') if entry.expire_at else 'Never'
            print(
                f"  {entry.ip_address:<18} "
                f"{entry.added_at.strftime('%Y-%m-%d %H:%M:%S'):<22} "
                f"{(entry.reason or '')[:24]:<25} "
                f"{exp_str:<22} "
                f"{entry.hits}"
            )
        print()
        sys.exit(0)

    if args.block:
        print(f"正在拉黑 IP: {args.block} ...")
        ok = analyzer.blacklist.block_ip(
            args.block,
            reason=args.block_reason,
            rule_id='manual',
            expire_hours=args.block_expire_hours,
        )
        if ok:
            print(f"成功拉黑: {args.block}")
        else:
            print(f"拉黑失败: {args.block}", file=sys.stderr)
        sys.exit(0 if ok else 1)

    if args.unblock:
        print(f"正在取消拉黑 IP: {args.unblock} ...")
        ok = analyzer.blacklist.unblock_ip(args.unblock)
        if ok:
            print(f"成功取消拉黑: {args.unblock}")
        else:
            print(f"取消拉黑失败或IP不在黑名单: {args.unblock}")
        sys.exit(0 if ok else 1)

    _register_signal_handlers(analyzer)

    try:
        analyzer.run()
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        analyzer.stop()
        sys.exit(1)


if __name__ == "__main__":
    main()
