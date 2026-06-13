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
        re.compile(r'^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
    ]

    EVENT_ID_PATTERNS = [
        r'EventID\s*[=:]\s*"?(\d+)"?',
        r'Event\s+ID\s*[=:]\s*"?(\d+)"?',
        r'<EventID>(\d+)</EventID>',
        r'Microsoft-Windows-Security-Auditing[^>]*EventID=(\d+)',
    ]

    SRC_PATTERNS = [
        r'Source\s*Network\s*Address\s*[=:]\s*"?([^"\s,]+)"?',
        r'SourceAddress\s*[=:]\s*"?([^"\s,]+)"?',
        r'Source\s*Address\s*[=:]\s*"?([^"\s,]+)"?',
        r'Src(?:Addr)?\s*[=:]\s*"?([^"\s,]+)"?',
        r'IpAddress\s*[=:]\s*"?([^"\s,]+)"?',
        r'IP\s*Address\s*[=:]\s*"?([^"\s,]+)"?',
        r'IP\s*[=:]\s*"?([^"\s,]+)"?',
        r'Addr\s*[=:]\s*"?([^"\s,]+)"?',
        r'Remote(?:\s*Machine)?\s*Address\s*[=:]\s*"?([^"\s,]+)"?',
        r'Remote\s*IP\s*[=:]\s*"?([^"\s,]+)"?',
        r'Client\s*Address\s*[=:]\s*"?([^"\s,]+)"?',
        r'<Data\s+Name=["\']SourceNetworkAddress["\']>([^<]+)</Data>',
        r'<Data\s+Name=["\']SourceAddress["\']>([^<]+)</Data>',
        r'<Data\s+Name=["\']IpAddress["\']>([^<]+)</Data>',
        r'<Data\s+Name=["\']RemoteAddress["\']>([^<]+)</Data>',
        r'<Data\s+Name=["\']ClientAddress["\']>([^<]+)</Data>',
        r'客户端地址\s*[=:]\s*"?([^"\s,]+)"?',
        r'远程地址\s*[=:]\s*"?([^"\s,]+)"?',
        r'来源地址\s*[=:]\s*"?([^"\s,]+)"?',
        r'Src\s*[=:]\s*"?([^"\s,]+)"?',
    ]

    DST_PATTERNS = [
        r'Destination\s*Network\s*Address\s*[=:]\s*"?([^"\s,]+)"?',
        r'DestAddress\s*[=:]\s*"?([^"\s,]+)"?',
        r'Destination\s*Address\s*[=:]\s*"?([^"\s,]+)"?',
        r'Dest(?:Addr)?\s*[=:]\s*"?([^"\s,]+)"?',
        r'Dest(?:ination)?\s*IP\s*[=:]\s*"?([^"\s,]+)"?',
        r'Local\s*Address\s*[=:]\s*"?([^"\s,]+)"?',
        r'Dst\s*[=:]\s*"?([^"\s,]+)"?',
        r'Target\s*Address\s*[=:]\s*"?([^"\s,]+)"?',
        r'<Data\s+Name=["\']DestAddress["\']>([^<]+)</Data>',
        r'<Data\s+Name=["\']DestinationAddress["\']>([^<]+)</Data>',
        r'<Data\s+Name=["\']LocalAddress["\']>([^<]+)</Data>',
        r'目标地址\s*[=:]\s*"?([^"\s,]+)"?',
        r'本地地址\s*[=:]\s*"?([^"\s,]+)"?',
    ]

    DPT_PATTERNS = [
        r'Destination\s*Port\s*[=:]\s*"?(\d+)"?',
        r'DestPort\s*[=:]\s*"?(\d+)"?',
        r'Dest(?:ination)?\s*Port\s*[=:]\s*"?(\d+)"?',
        r'Local\s*Port\s*[=:]\s*"?(\d+)"?',
        r'Target\s*Port\s*[=:]\s*"?(\d+)"?',
        r'<Data\s+Name=["\']DestPort["\']>(\d+)</Data>',
        r'<Data\s+Name=["\']DestinationPort["\']>(\d+)</Data>',
        r'<Data\s+Name=["\']LocalPort["\']>(\d+)</Data>',
        r'目标端口\s*[=:]\s*"?(\d+)"?',
        r'本地端口\s*[=:]\s*"?(\d+)"?',
    ]

    SPT_PATTERNS = [
        r'Source\s*Port\s*[=:]\s*"?(\d+)"?',
        r'SrcPort\s*[=:]\s*"?(\d+)"?',
        r'Remote\s*Port\s*[=:]\s*"?(\d+)"?',
        r'<Data\s+Name=["\']SourcePort["\']>(\d+)</Data>',
        r'<Data\s+Name=["\']RemotePort["\']>(\d+)</Data>',
        r'源端口\s*[=:]\s*"?(\d+)"?',
        r'远程端口\s*[=:]\s*"?(\d+)"?',
    ]

    PROTO_PATTERNS = [
        r'Protocol\s*[=:]\s*"?(\w+)"?',
        r'Protocol\s*Type\s*[=:]\s*"?(\w+)"?',
        r'<Data\s+Name=["\']Protocol["\']>(\w+)</Data>',
        r'<Data\s+Name=["\']ProtocolType["\']>(\w+)</Data>',
        r'协议\s*[=:]\s*"?(\w+)"?',
    ]

    LOGON_TYPE_PATTERNS = [
        r'Logon\s*Type\s*[=:]\s*"?(\w+)"?',
        r'<Data\s+Name=["\']LogonType["\']>(\w+)</Data>',
        r'登录类型\s*[=:]\s*"?(\w+)"?',
    ]

    FAILURE_REASON_PATTERNS = [
        r'Failure\s*Reason\s*[=:]\s*"([^"]+)"?',
        r'<Data\s+Name=["\']FailureReason["\']>([^<]+)</Data>',
        r'失败原因\s*[=:]\s*"([^"]+)"?',
    ]

    KEYWORD_PATTERNS = [
        r'Keywords\s*[=:]\s*"([^"]+)"?',
        r'<Keywords>([^<]+)</Keywords>',
        r'关键字\s*[=:]\s*"([^"]+)"?',
    ]

    DENY_EVENT_IDS = {
        '4625': 'DENY',
        '4771': 'DENY',
        '4772': 'DENY',
        '4776': 'DENY',
        '4768': 'DENY',
        '4769': 'DENY',
        '5152': 'DENY',
        '5155': 'DENY',
        '5157': 'DENY',
        '5159': 'DENY',
        '5151': 'DENY',
        '5153': 'DENY',
        '5154': 'DENY',
        '4634': 'ALLOW',
        '4624': 'ALLOW',
        '4647': 'ALLOW',
        '4672': 'ALLOW',
    }

    EVENT_DESCRIPTIONS = {
        '4624': '账户登录成功',
        '4625': '账户登录失败',
        '4634': '账户注销',
        '4771': 'Kerberos预身份验证失败',
        '4772': 'Kerberos身份验证票证请求失败',
        '4776': '域控制器尝试验证账户凭据失败',
        '4768': 'Kerberos身份验证票证(TGT)请求',
        '4769': 'Kerberos服务票证请求',
        '5152': 'Windows过滤平台阻止数据包',
        '5155': 'Windows过滤平台阻止应用或服务监听端口',
        '5157': 'Windows过滤平台阻止连接',
        '5159': 'Windows过滤平台阻止绑定到本地端口',
        '5151': 'Windows过滤平台允许数据包',
        '5153': 'Windows过滤平台允许应用或服务监听端口',
        '5154': 'Windows过滤平台允许连接',
        '4647': '用户发起注销',
        '4672': '管理员登录',
    }

    LOGON_TYPE_MAP = {
        '2': '交互式登录',
        '3': '网络登录',
        '4': '批处理登录',
        '5': '服务登录',
        '7': '解锁',
        '8': '网络明文登录',
        '9': '新凭据登录',
        '10': '远程交互登录(RDP)',
        '11': '缓存交互登录',
    }

    def can_parse(self, line: str) -> bool:
        line_upper = line.upper()
        has_event_id = bool(re.search(
            r'EventID\s*[=:]\s*"?(4625|4771|4772|4776|4768|4769|5152|5155|5157|5159|5151|5153|5154|4624)\b',
            line, re.IGNORECASE
        ))
        if has_event_id:
            return True

        if '<Event' in line and re.search(r'<EventID>(4625|477[126]|476[89]|515[2-9]|515[134]|4624)</EventID>', line, re.IGNORECASE):
            return True

        has_ip_field = bool(re.search(
            r'(Source\s*Network\s*Address|SourceAddress|IpAddress|Remote\s*Address|Client\s*Address)\s*[=:]',
            line, re.IGNORECASE
        ))
        has_event_id_field = bool(re.search(r'(EventID|Event\s*ID)\s*[=:]', line, re.IGNORECASE))
        if has_ip_field and has_event_id_field:
            return True

        if 'Security-Auditing' in line_upper and re.search(r'\d{1,3}(?:\.\d{1,3}){3}', line):
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

        if event_id:
            if event_id in self.DENY_EVENT_IDS:
                entry.action = self.DENY_EVENT_IDS[event_id]
                entry.extra['description'] = self.EVENT_DESCRIPTIONS.get(event_id, '')

        logon_type = self._search_field(line, self.LOGON_TYPE_PATTERNS)
        if logon_type:
            entry.extra['logon_type'] = self.LOGON_TYPE_MAP.get(logon_type, logon_type)
            entry.extra['logon_type_id'] = logon_type

        failure_reason = self._search_field(line, self.FAILURE_REASON_PATTERNS)
        if failure_reason:
            entry.extra['failure_reason'] = failure_reason.strip()

        keywords = self._search_field(line, self.KEYWORD_PATTERNS)
        if keywords:
            entry.extra['keywords'] = keywords.strip()

        entry.source_ip = self._normalize_ip(self._search_field(line, self.SRC_PATTERNS))
        entry.dest_ip = self._normalize_ip(self._search_field(line, self.DST_PATTERNS))
        entry.source_port = self._search_int(line, self.SPT_PATTERNS)
        entry.dest_port = self._search_int(line, self.DPT_PATTERNS)

        if not entry.source_ip or not entry.dest_ip:
            ip_candidates = self._extract_all_ips(line)
            if len(ip_candidates) >= 2:
                if not entry.source_ip:
                    entry.source_ip = self._normalize_ip(ip_candidates[0])
                if not entry.dest_ip:
                    entry.dest_ip = self._normalize_ip(ip_candidates[-1])
            elif len(ip_candidates) == 1 and not entry.source_ip and not entry.dest_ip:
                entry.source_ip = self._normalize_ip(ip_candidates[0])

        if entry.source_ip:
            entry.extra['source_ip_raw'] = entry.source_ip
        if entry.dest_ip:
            entry.extra['dest_ip_raw'] = entry.dest_ip

        proto = self._search_field(line, self.PROTO_PATTERNS)
        if proto:
            proto_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '2': 'IGMP', '41': 'IPv6', '47': 'GRE', '50': 'ESP', '51': 'AH', '89': 'OSPF', '132': 'SCTP'}
            entry.protocol = proto_map.get(proto, proto.upper())

        if event_id == '4625' and not entry.dest_port:
            logon_type_id = entry.extra.get('logon_type_id', '')
            if logon_type_id == '10':
                entry.dest_port = 3389
            elif logon_type_id in ('2', '3', '7', '8', '9', '11'):
                entry.extra['potential_ports'] = [22, 3389, 445, 135, 139, 5985, 5986]

        if event_id in ('5152', '5157') and entry.dest_port and not entry.protocol:
            entry.protocol = 'TCP'

        if entry.source_ip or entry.dest_ip or entry.action:
            return entry
        return None

    @staticmethod
    def _normalize_ip(ip_str: Optional[str]) -> Optional[str]:
        if not ip_str:
            return None
        ip_str = ip_str.strip()
        if not ip_str:
            return None

        if ip_str.startswith('::ffff:') or ip_str.startswith('::FFFF:'):
            mapped = ip_str.split(':', 1)[1].lstrip(':fF')
            mapped = mapped.lstrip('fF:')
            if mapped and re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', mapped):
                return mapped

        ipv4_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', ip_str)
        if ipv4_match:
            return ipv4_match.group(1)

        if ':' in ip_str:
            if re.match(r'^[0-9a-fA-F:]+$', ip_str):
                if '.' in ip_str:
                    last_part = ip_str.rsplit(':', 1)[-1]
                    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', last_part):
                        return last_part
                return ip_str

        return ip_str if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', ip_str) else None

    @staticmethod
    def _extract_all_ips(line: str) -> list[str]:
        ips = []
        pattern = r'(?:::f{4}:)?(\d{1,3}(?:\.\d{1,3}){3})'
        for m in re.finditer(pattern, line):
            ip = m.group(1)
            parts = ip.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                if ip not in ips:
                    ips.append(ip)
        return ips

    def _extract_timestamp(self, line: str) -> datetime:
        for pattern in self.TIMESTAMP_PATTERNS:
            m = pattern.search(line)
            if m:
                ts = m.group('ts')
                try:
                    ts = ts.replace('Z', '+00:00')
                    if 'T' in ts:
                        return datetime.fromisoformat(ts).replace(tzinfo=None)
                    elif ts.count('-') >= 2:
                        return datetime.strptime(ts.split(',')[0].split('.')[0], '%Y-%m-%d %H:%M:%S')
                    else:
                        current_year = datetime.now().year
                        return datetime.strptime(f"{current_year} {ts}", '%Y %b %d %H:%M:%S')
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
