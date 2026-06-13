import re
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    timestamp: datetime
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    raw_line: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "action": self.action,
            "extra": self.extra,
        }


class BaseLogParser(ABC):
    @abstractmethod
    def parse(self, line: str) -> Optional[LogEntry]:
        pass

    @abstractmethod
    def can_parse(self, line: str) -> bool:
        pass

    @staticmethod
    def _search_field(line: str, patterns: list[str]) -> Optional[str]:
        for p in patterns:
            m = re.search(p, line, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    @staticmethod
    def _search_int(line: str, patterns: list[str]) -> Optional[int]:
        val = BaseLogParser._search_field(line, patterns)
        if val:
            try:
                return int(val)
            except (ValueError, TypeError):
                return None
        return None


class IPTablesParser(BaseLogParser):
    TIMESTAMP_PATTERNS = [
        re.compile(r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
        re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)'),
    ]

    ACTION_PATTERNS = [
        r'\b(ACCEPT|DROP|REJECT|LOG|ALLOW|DENY|BLOCK|PERMIT)\b',
        r'action\s*[=:]\s*"?(ACCEPT|DROP|REJECT|ALLOW|DENY|BLOCK|PERMIT)"?',
    ]

    SRC_PATTERNS = [
        r'\bSRC\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})\b',
        r'\bsrc\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'source(?:\s+ip)?\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
    ]

    DST_PATTERNS = [
        r'\bDST\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})\b',
        r'\bdst\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'destination(?:\s+ip)?\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
    ]

    SPT_PATTERNS = [
        r'\bSPT\s*=\s*(\d+)\b',
        r'\bspt\s*[=:]\s*"?(\d+)"?',
        r'src(?:_|\s+)?port\s*[=:]\s*"?(\d+)"?',
        r'sport\s*[=:]\s*"?(\d+)"?',
    ]

    DPT_PATTERNS = [
        r'\bDPT\s*=\s*(\d+)\b',
        r'\bdpt\s*[=:]\s*"?(\d+)"?',
        r'dst(?:_|\s+)?port\s*[=:]\s*"?(\d+)"?',
        r'dport\s*[=:]\s*"?(\d+)"?',
    ]

    PROTO_PATTERNS = [
        r'\bPROTO\s*=\s*(\w+)\b',
        r'\bproto\s*[=:]\s*"?(\w+)"?',
        r'protocol\s*[=:]\s*"?(\w+)"?',
    ]

    def can_parse(self, line: str) -> bool:
        if 'kernel:' in line and re.search(r'\b(ACCEPT|DROP|REJECT|LOG|ALLOW|DENY|BLOCK)\b', line):
            return True
        if re.search(r'\bSRC\s*=', line) and re.search(r'\bDST\s*=', line):
            return True
        if re.search(r'src\s*[=:]\s*\d', line, re.IGNORECASE) and re.search(r'(ACCEPT|DROP|REJECT)', line, re.IGNORECASE):
            return True
        return False

    def parse(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None

        entry = LogEntry(
            timestamp=self._extract_timestamp(line),
            raw_line=line,
        )

        entry.source_ip = self._search_field(line, self.SRC_PATTERNS)
        entry.dest_ip = self._search_field(line, self.DST_PATTERNS)
        entry.source_port = self._search_int(line, self.SPT_PATTERNS)
        entry.dest_port = self._search_int(line, self.DPT_PATTERNS)

        proto = self._search_field(line, self.PROTO_PATTERNS)
        if proto:
            proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '132': 'SCTP'}
            entry.protocol = proto_map.get(proto, proto.upper())

        action = self._search_field(line, self.ACTION_PATTERNS)
        if action:
            action_upper = action.upper()
            if action_upper in ('ACCEPT', 'ALLOW', 'PERMIT'):
                entry.action = 'ALLOW'
            elif action_upper in ('DROP', 'REJECT', 'DENY', 'BLOCK'):
                entry.action = 'DENY'
            elif action_upper != 'LOG':
                entry.action = action_upper

        if entry.source_ip or entry.dest_ip or entry.action:
            return entry
        return None

    def _extract_timestamp(self, line: str) -> datetime:
        for pattern in self.TIMESTAMP_PATTERNS:
            m = pattern.search(line)
            if m:
                ts = m.group('ts')
                try:
                    if 'T' in ts or ts.count('-') >= 2:
                        ts = ts.replace(',', '.').replace('Z', '')
                        if 'T' in ts:
                            return datetime.fromisoformat(ts)
                        else:
                            return datetime.strptime(ts.split('.')[0], '%Y-%m-%d %H:%M:%S')
                    else:
                        current_year = datetime.now().year
                        return datetime.strptime(f"{current_year} {ts}", '%Y %b %d %H:%M:%S')
                except (ValueError, TypeError):
                    continue
        return datetime.now()


class WindowsSecurityParser(BaseLogParser):
    TIMESTAMP_PATTERNS = [
        re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)'),
        re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)'),
        re.compile(r'<TimeCreated\s+SystemTime=["\'](?P<ts>[^"\']+)["\']'),
    ]

    EVENT_ID_PATTERNS = [
        r'EventID\s*[=:]\s*"?(\d+)"?',
        r'<EventID>(\d+)</EventID>',
    ]

    SRC_PATTERNS = [
        r'Source\s*Network\s*Address\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'IpAddress\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'Remote(?:\s*Machine)?\s*Address\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'<Data\s+Name=["\']SourceNetworkAddress["\']>(\d{1,3}(?:\.\d{1,3}){3})</Data>',
        r'<Data\s+Name=["\']IpAddress["\']>(\d{1,3}(?:\.\d{1,3}){3})</Data>',
        r'<Data\s+Name=["\']RemoteAddress["\']>(\d{1,3}(?:\.\d{1,3}){3})</Data>',
        r'客户端地址\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
    ]

    DST_PATTERNS = [
        r'Destination\s*Network\s*Address\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'Dest(?:ination)?\s*Address\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'<Data\s+Name=["\']DestAddress["\']>(\d{1,3}(?:\.\d{1,3}){3})</Data>',
    ]

    DPT_PATTERNS = [
        r'Destination\s*Port\s*[=:]\s*"?(\d+)"?',
        r'Dest(?:ination)?\s*Port\s*[=:]\s*"?(\d+)"?',
        r'<Data\s+Name=["\']DestPort["\']>(\d+)</Data>',
    ]

    PROTO_PATTERNS = [
        r'Protocol\s*[=:]\s*"?(\w+)"?',
        r'<Data\s+Name=["\']Protocol["\']>(\w+)</Data>',
    ]

    BLOCK_EVENT_IDS = {'4625', '5152', '5155', '5157', '5159', '4624', '4776', '4771', '4768', '4769'}
    DENY_EVENT_IDS = {'4625', '5152', '5155', '5157', '5159'}

    def can_parse(self, line: str) -> bool:
        if re.search(r'EventID\s*[=:]\s*"?(4625|5152|5155|5157|5159)"?', line, re.IGNORECASE):
            return True
        if '<Event' in line and ('4625' in line or '5152' in line or '5157' in line):
            return True
        if re.search(r'(Source\s*Network\s*Address|IpAddress|SourceAddress)', line, re.IGNORECASE):
            if re.search(r'(EventID|Event\s*ID)', line, re.IGNORECASE):
                return True
        return False

    def parse(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None

        entry = LogEntry(
            timestamp=self._extract_timestamp(line),
            raw_line=line,
        )

        event_id = self._search_field(line, self.EVENT_ID_PATTERNS)
        entry.extra['event_id'] = event_id

        if event_id in self.DENY_EVENT_IDS:
            entry.action = 'DENY'
            if event_id == '4625':
                entry.extra['description'] = 'Account failed to log on (RDP/SSH brute force suspect)'
            else:
                entry.extra['description'] = 'Windows Filtering Platform blocked packet/connection'

        entry.source_ip = self._search_field(line, self.SRC_PATTERNS)
        entry.dest_ip = self._search_field(line, self.DST_PATTERNS)
        entry.dest_port = self._search_int(line, self.DPT_PATTERNS)

        proto = self._search_field(line, self.PROTO_PATTERNS)
        if proto:
            proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP'}
            entry.protocol = proto_map.get(proto, proto.upper())

        if entry.source_ip or entry.dest_ip:
            return entry
        return None

    def _extract_timestamp(self, line: str) -> datetime:
        for pattern in self.TIMESTAMP_PATTERNS:
            m = pattern.search(line)
            if m:
                ts = m.group('ts')
                try:
                    ts = ts.replace('Z', '+00:00')
                    if 'T' in ts:
                        return datetime.fromisoformat(ts).replace(tzinfo=None)
                    else:
                        return datetime.strptime(ts.split(',')[0].split('.')[0], '%Y-%m-%d %H:%M:%S')
                except (ValueError, TypeError):
                    continue
        return datetime.now()


class GenericSyslogParser(BaseLogParser):
    TIMESTAMP_PATTERNS = [
        re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)'),
        re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)'),
        re.compile(r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
    ]

    ACTION_PATTERNS = [
        r'\b(ACCEPT|DROP|REJECT|ALLOW|DENY|BLOCK|PERMIT)\b',
        r'(?:action|act|verdict|policy)\s*[=:]\s*"?(ACCEPT|DROP|REJECT|ALLOW|DENY|BLOCK|PERMIT)"?',
    ]

    SRC_PATTERNS = [
        r'\bsrc(?:_ip)?\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'source(?:\s*ip)?\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'from\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'(\d{1,3}(?:\.\d{1,3}){3}):\d+\s',
    ]

    DST_PATTERNS = [
        r'\bdst(?:_ip)?\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'destination(?:\s*ip)?\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'to\s*[=:]\s*"?(\d{1,3}(?:\.\d{1,3}){3})"?',
        r'->\s*(\d{1,3}(?:\.\d{1,3}){3})',
    ]

    SPT_PATTERNS = [
        r'\bsrc(?:_|\s*)?port\s*[=:]\s*"?(\d+)"?',
        r'\bspt\s*[=:]\s*"?(\d+)"?',
        r':(\d+)\s*->',
    ]

    DPT_PATTERNS = [
        r'\bdst(?:_|\s*)?port\s*[=:]\s*"?(\d+)"?',
        r'\bdpt\s*[=:]\s*"?(\d+)"?',
        r'->\s*\S+:(\d+)',
        r'port\s*[=:]\s*"?(\d+)"?',
    ]

    PROTO_PATTERNS = [
        r'\bproto(?:col)?\s*[=:]\s*"?(\w+)"?',
        r'\b(TCP|UDP|ICMP|GRE|ESP|AH|SCTP)\b',
    ]

    def can_parse(self, line: str) -> bool:
        has_ip = bool(re.search(r'\d{1,3}(?:\.\d{1,3}){3}', line))
        has_action = bool(re.search(r'\b(ACCEPT|DROP|REJECT|ALLOW|DENY|BLOCK|PERMIT)\b', line, re.IGNORECASE))
        has_port_keyword = bool(re.search(r'(src|dst|dest|dpt|spt|port)\s*[=:]', line, re.IGNORECASE))
        return has_ip and (has_action or has_port_keyword)

    def parse(self, line: str) -> Optional[LogEntry]:
        line = line.strip()
        if not line:
            return None

        entry = LogEntry(
            timestamp=self._extract_timestamp(line),
            raw_line=line,
        )

        entry.source_ip = self._search_field(line, self.SRC_PATTERNS)
        entry.dest_ip = self._search_field(line, self.DST_PATTERNS)
        entry.source_port = self._search_int(line, self.SPT_PATTERNS)
        entry.dest_port = self._search_int(line, self.DPT_PATTERNS)

        proto = self._search_field(line, self.PROTO_PATTERNS)
        if proto:
            entry.protocol = proto.upper()

        action = self._search_field(line, self.ACTION_PATTERNS)
        if action:
            action_upper = action.upper()
            if action_upper in ('ACCEPT', 'ALLOW', 'PERMIT'):
                entry.action = 'ALLOW'
            elif action_upper in ('DROP', 'REJECT', 'DENY', 'BLOCK'):
                entry.action = 'DENY'

        if entry.source_ip or entry.dest_ip:
            return entry
        return None

    def _extract_timestamp(self, line: str) -> datetime:
        for pattern in self.TIMESTAMP_PATTERNS:
            m = pattern.search(line)
            if m:
                ts = m.group('ts')
                try:
                    if 'T' in ts or ts.count('-') >= 2:
                        ts = ts.replace(',', '.').replace('Z', '')
                        if 'T' in ts:
                            return datetime.fromisoformat(ts)
                        else:
                            return datetime.strptime(ts.split('.')[0], '%Y-%m-%d %H:%M:%S')
                    else:
                        current_year = datetime.now().year
                        return datetime.strptime(f"{current_year} {ts}", '%Y %b %d %H:%M:%S')
                except (ValueError, TypeError):
                    continue
        return datetime.now()


class LogParserRegistry:
    def __init__(self):
        self._parsers: list[BaseLogParser] = []
        self._register_defaults()

    def _register_defaults(self):
        self.register(IPTablesParser())
        self.register(WindowsSecurityParser())
        self.register(GenericSyslogParser())

    def register(self, parser: BaseLogParser):
        self._parsers.append(parser)

    def parse(self, line: str) -> Optional[LogEntry]:
        for parser in self._parsers:
            try:
                if parser.can_parse(line):
                    entry = parser.parse(line)
                    if entry:
                        return entry
            except Exception as e:
                logger.debug(f"Parser {parser.__class__.__name__} error: {e}")
                continue
        return None

    def get_parser(self, parser_type: str) -> Optional[BaseLogParser]:
        parser_map = {
            'iptables': IPTablesParser,
            'windows': WindowsSecurityParser,
            'syslog': GenericSyslogParser,
        }
        cls = parser_map.get(parser_type.lower())
        if cls:
            return cls()
        return None
