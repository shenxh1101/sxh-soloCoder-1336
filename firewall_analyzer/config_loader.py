import os
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logger.warning("PyYAML not installed. YAML config support disabled. Install with: pip install pyyaml")


@dataclass
class LogSourceConfig:
    path: str
    parser: Optional[str] = None
    encoding: str = "utf-8"
    from_beginning: bool = False
    poll_interval: float = 1.0


@dataclass
class BlacklistConfig:
    enabled: bool = True
    storage_path: Optional[str] = None
    default_expire_hours: Optional[int] = None
    auto_save: bool = True
    auto_sync: bool = True
    sync_interval_seconds: int = 300
    strict_consistency: bool = True


@dataclass
class WhitelistConfig:
    enabled: bool = True
    rules: list[dict] = field(default_factory=list)


@dataclass
class AppConfig:
    log_level: str = "INFO"
    log_file: Optional[str] = None
    log_sources: list[LogSourceConfig] = field(default_factory=list)
    rules: list[dict] = field(default_factory=list)
    blacklist: BlacklistConfig = field(default_factory=BlacklistConfig)
    whitelist: WhitelistConfig = field(default_factory=WhitelistConfig)
    extra: dict[str, Any] = field(default_factory=dict)


def _load_yaml(file_path: str) -> dict:
    if not HAS_YAML:
        raise ImportError("PyYAML is required to load YAML configuration files. Install with: pip install pyyaml")
    with open(file_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def _load_json(file_path: str) -> dict:
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_config(file_path: str) -> AppConfig:
    file_path = os.path.abspath(file_path)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Config file not found: {file_path}")

    ext = os.path.splitext(file_path)[1].lower()

    if ext in ('.yaml', '.yml'):
        raw = _load_yaml(file_path)
    elif ext == '.json':
        raw = _load_json(file_path)
    else:
        raise ValueError(f"Unsupported config format: {ext}. Use .yaml, .yml, or .json")

    return _parse_config(raw, file_path)


def _parse_config(raw: dict, source_path: str) -> AppConfig:
    base_dir = os.path.dirname(source_path)

    log_sources_raw = raw.get('log_sources', raw.get('logs', []))
    log_sources: list[LogSourceConfig] = []
    for src in log_sources_raw:
        if isinstance(src, str):
            log_sources.append(LogSourceConfig(path=_resolve_path(src, base_dir)))
        elif isinstance(src, dict):
            path = src.get('path', src.get('file', ''))
            log_sources.append(LogSourceConfig(
                path=_resolve_path(path, base_dir),
                parser=src.get('parser', src.get('type')),
                encoding=src.get('encoding', 'utf-8'),
                from_beginning=src.get('from_beginning', src.get('tail_from_start', False)),
                poll_interval=float(src.get('poll_interval', src.get('interval', 1.0))),
            ))

    blacklist_raw = raw.get('blacklist', raw.get('blocklist', {}))
    bl_storage = blacklist_raw.get('storage_path', blacklist_raw.get('file'))
    if bl_storage:
        bl_storage = _resolve_path(bl_storage, base_dir)

    blacklist_config = BlacklistConfig(
        enabled=blacklist_raw.get('enabled', True),
        storage_path=bl_storage,
        default_expire_hours=blacklist_raw.get('default_expire_hours', blacklist_raw.get('ttl_hours')),
        auto_save=blacklist_raw.get('auto_save', True),
        auto_sync=blacklist_raw.get('auto_sync', True),
        sync_interval_seconds=int(blacklist_raw.get('sync_interval_seconds', 300)),
        strict_consistency=blacklist_raw.get('strict_consistency', True),
    )

    whitelist_raw = raw.get('whitelist', {})
    whitelist_config = WhitelistConfig(
        enabled=whitelist_raw.get('enabled', True),
        rules=whitelist_raw.get('rules', []),
    )

    rules = raw.get('rules', [])

    log_file = raw.get('log_file')
    if log_file:
        log_file = _resolve_path(log_file, base_dir)

    app_log_level = str(raw.get('log_level', raw.get('logging_level', 'INFO'))).upper()

    extra = {k: v for k, v in raw.items() if k not in (
        'log_sources', 'logs', 'blacklist', 'blocklist', 'whitelist', 'rules',
        'log_level', 'logging_level', 'log_file',
    )}

    return AppConfig(
        log_level=app_log_level,
        log_file=log_file,
        log_sources=log_sources,
        rules=rules,
        blacklist=blacklist_config,
        whitelist=whitelist_config,
        extra=extra,
    )


def _resolve_path(path: str, base_dir: str) -> str:
    if not path:
        return path
    if os.path.isabs(path):
        return path
    return os.path.abspath(os.path.join(base_dir, path))
