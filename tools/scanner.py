import ipaddress
import re
import socket
import struct
import subprocess
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed


MAX_PREFIX   = 16   # Refuse anything larger than /16
MAX_NETWORKS = 20   # Bulk scan cap

# NetBIOS Node Status Request (RFC 1002).
# Queries the wildcard name '*' to retrieve the full name table from a host.
_NBSTAT_REQUEST = (
    b'\x00\x01'  # Transaction ID
    b'\x00\x00'  # Flags: standard query, non-recursive
    b'\x00\x01'  # QDCOUNT = 1
    b'\x00\x00'  # ANCOUNT = 0
    b'\x00\x00'  # NSCOUNT = 0
    b'\x00\x00'  # ARCOUNT = 0
    b'\x20'      # QNAME length = 32
    b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    b'\x00'      # end of name
    b'\x00\x21'  # QTYPE  = NBSTAT (33)
    b'\x00\x01'  # QCLASS = IN
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_network(raw: str) -> str:
    raw = raw.strip()
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        raise ValueError(f"'{raw}' is not a valid network address (e.g. 10.10.83.0/24).")

    if network.version != 4:
        raise ValueError("Only IPv4 networks are supported.")

    if network.prefixlen < MAX_PREFIX:
        raise ValueError(
            f"Prefix /{network.prefixlen} is too large. "
            f"Maximum supported range is /{MAX_PREFIX} ({2**(32-MAX_PREFIX):,} hosts)."
        )

    return str(network)


def validate_networks(raw: str) -> list:
    """
    Parse a newline-or-comma-separated list of CIDR networks.
    Returns a deduplicated, validated list of canonical network strings.
    Raises ValueError on any problem.
    """
    entries = [s.strip() for s in re.split(r'[\n,]+', raw) if s.strip()]
    if not entries:
        raise ValueError("No networks provided.")
    if len(entries) > MAX_NETWORKS:
        raise ValueError(
            f"Too many networks ({len(entries)}). Maximum is {MAX_NETWORKS} per bulk scan."
        )
    seen = set()
    result = []
    for entry in entries:
        canonical = validate_network(entry)
        if canonical not in seen:
            seen.add(canonical)
            result.append(canonical)
    return result


def _nmap_timeout(prefix_len: int) -> int:
    """
    Scale the nmap subprocess timeout to the size of the target network.
      /24 (256)     →  120s
      /20 (4096)    →  180s
      /18 (16384)   →  300s
      /16 (65536)   →  600s  (cap)
    """
    host_count = 2 ** (32 - prefix_len)
    return max(120, min(600, host_count // 20))


def run_icmp_scan(network: str, resolve_dns: bool, resolve_netbios: bool) -> dict:
    """
    Ping-sweep *network* with nmap.  DNS and NetBIOS resolution are always
    performed in parallel *after* the sweep — nmap always runs with -n so it
    never blocks on sequential DNS lookups during the scan itself.
    """
    prefix_len   = int(network.split('/')[1])
    nmap_timeout = _nmap_timeout(prefix_len)

    # -n: skip DNS inside nmap — we resolve in parallel afterwards
    cmd = ['nmap', '-sn', '-T4', '-n', '--oX', '-', network]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=nmap_timeout)
    except subprocess.TimeoutExpired:
        return _error(f'ICMP scan timed out after {nmap_timeout}s.')
    except FileNotFoundError:
        return _error('nmap is not installed or not on PATH.')

    if proc.returncode != 0 and not proc.stdout.strip():
        return _error(f'nmap exited with code {proc.returncode}: {proc.stderr.strip()}')

    hosts = _parse_ping_sweep(proc.stdout)
    up_ips = [h['ip'] for h in hosts if h['status'] == 'up']

    if up_ips and (resolve_dns or resolve_netbios):
        # Fire DNS and NetBIOS lookups concurrently
        with ThreadPoolExecutor(max_workers=2) as outer:
            dns_future = outer.submit(_resolve_dns_all, up_ips) if resolve_dns     else None
            nb_future  = outer.submit(_query_netbios_all, up_ips) if resolve_netbios else None

        dns_map = dns_future.result() if dns_future else {}
        nb_map  = nb_future.result()  if nb_future  else {}

        # For NetBIOS: fall back to rDNS for hosts that didn't answer UDP 137.
        # If DNS was already fetched, reuse those results.  Otherwise do a
        # quick parallel rDNS pass for only the missing IPs.
        if resolve_netbios:
            missing = [ip for ip in up_ips if not nb_map.get(ip)]
            if missing:
                if dns_map:
                    # Reuse already-fetched DNS results
                    rdns = {ip: dns_map[ip] for ip in missing if ip in dns_map}
                else:
                    # Short parallel rDNS sweep just for the missing hosts
                    rdns = _resolve_dns_all(missing, per_host_timeout=2.0)

                for ip, fqdn in rdns.items():
                    short = fqdn.split('.')[0]
                    if short:
                        nb_map[ip] = {'name': short, 'source': 'rdns'}

        for h in hosts:
            ip = h['ip']
            if resolve_dns:
                h['dns_name'] = dns_map.get(ip, '')
            if resolve_netbios:
                result = nb_map.get(ip) or {}
                h['netbios_name']   = result.get('name', '')
                h['netbios_source'] = result.get('source', '')

    up_count = sum(1 for h in hosts if h['status'] == 'up')
    return {'hosts': hosts, 'up_count': up_count, 'total_count': len(hosts), 'error': None}


# ---------------------------------------------------------------------------
# ICMP sweep parsing
# ---------------------------------------------------------------------------

def _error(msg: str) -> dict:
    return {'hosts': [], 'up_count': 0, 'total_count': 0, 'error': msg}


def _parse_ping_sweep(xml_text: str) -> list:
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts

    for host_el in root.findall('host'):
        status_el = host_el.find('status')
        addr_el   = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None or status_el is None:
            continue

        hosts.append({
            'ip':             addr_el.get('addr', ''),
            'status':         status_el.get('state', 'unknown'),
            'dns_name':       '',
            'netbios_name':   '',
            'netbios_source': '',
        })

    hosts.sort(key=lambda h: ipaddress.ip_address(h['ip']))
    return hosts


# ---------------------------------------------------------------------------
# Parallel reverse DNS
# ---------------------------------------------------------------------------

def _resolve_dns_all(ips: list, per_host_timeout: float = 3.0) -> dict:
    """Parallel reverse DNS lookups. Returns {ip: fqdn}."""
    results = {}
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(_resolve_dns_one, ip, per_host_timeout): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                name = future.result()
                if name:
                    results[ip] = name
            except Exception:
                pass
    return results


def _resolve_dns_one(ip: str, timeout: float = 3.0) -> str:
    """
    Reverse DNS lookup with a hard timeout.
    socket.gethostbyaddr() has no built-in timeout so we run it in a
    daemon thread and abandon it if it exceeds *timeout* seconds.
    """
    result: list = []

    def _lookup():
        try:
            result.append(socket.gethostbyaddr(ip)[0])
        except Exception:
            pass

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(timeout)
    return result[0] if result else ''


# ---------------------------------------------------------------------------
# NetBIOS Node Status — pure Python UDP implementation
# ---------------------------------------------------------------------------

def _query_netbios_all(ips: list, timeout: float = 2.0) -> dict:
    """
    Query NetBIOS for all IPs in parallel.
    Returns {ip: {'name': str, 'source': 'netbios'}} for responding hosts.
    Non-responding hosts are absent from the dict (rDNS fallback is handled
    by the caller in run_icmp_scan).
    """
    results = {}
    with ThreadPoolExecutor(max_workers=50) as pool:
        futures = {pool.submit(_query_netbios_one, ip, timeout): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                name = future.result()
                if name:
                    results[ip] = {'name': name, 'source': 'netbios'}
            except Exception:
                pass
    return results


def _query_netbios_one(ip: str, timeout: float = 2.0) -> str:
    """Send a NetBIOS Node Status Request to ip:137. Returns name or ''."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(_NBSTAT_REQUEST, (ip, 137))
        data, _ = sock.recvfrom(1024)
        return _parse_nbstat_response(data)
    except (socket.timeout, OSError):
        return ''
    finally:
        sock.close()


def _parse_nbstat_response(data: bytes) -> str:
    """
    Parse a raw NetBIOS Node Status Response and return the workstation name.

    The RFC says responses have QDCOUNT=0 (no question section), but Windows
    inconsistently echoes the question back (QDCOUNT=1).  We read QDCOUNT from
    the header and conditionally skip the question section so the parse lands
    at the right offset in both cases.
    """
    if len(data) < 12:
        return ''

    qdcount = struct.unpack('>H', data[4:6])[0]
    ancount = struct.unpack('>H', data[6:8])[0]
    if ancount == 0:
        return ''

    offset = 12

    # Skip question section only if actually present
    if qdcount > 0:
        if offset >= len(data):
            return ''
        offset += 2 if data[offset] == 0xC0 else 34  # QNAME
        offset += 4                                    # QTYPE + QCLASS

    # Answer RR_NAME
    if offset >= len(data):
        return ''
    offset += 2 if data[offset] == 0xC0 else 34

    # Skip RTYPE + RCLASS + TTL + RDLENGTH
    offset += 10

    if offset >= len(data):
        return ''

    num_names = data[offset]
    offset += 1

    for _ in range(num_names):
        if offset + 18 > len(data):
            break

        raw_name = data[offset:offset + 15]
        suffix   = data[offset + 15]
        flags    = struct.unpack('>H', data[offset + 16:offset + 18])[0]
        offset  += 18

        is_group = bool(flags & 0x8000)

        if suffix == 0x00 and not is_group:
            name = ''.join(chr(b) for b in raw_name if 0x20 <= b <= 0x7E).strip()
            if name:
                return name

    return ''
