#!/usr/bin/env python3
"""Linux IPv4 multicast discovery, with no preconfigured UDP ports."""
import argparse
import ctypes
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import socket
import struct
import sys
import time
from services import ServiceNames


def ranges(values):
    result = []
    for value in values:
        if '-' in value:
            a, b = value.split('-', 1)
            lo, hi = int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b))
        else:
            net = ipaddress.IPv4Network(value, strict=False)
            lo, hi = int(net.network_address), int(net.broadcast_address)
        if not (0xE0000000 <= lo <= hi <= 0xEFFFFFFF):
            raise ValueError('range must be within IPv4 multicast 224.0.0.0/4')
        result.append((lo, hi))
    merged = []
    for lo, hi in sorted(result):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
        else:
            merged.append((lo, hi))
    return merged


def addresses(blocks):
    for lo, hi in blocks:
        for value in range(lo, hi + 1):
            yield socket.inet_ntoa(struct.pack('!I', value))


def payload_kind(data):
    def ts(buf):
        return len(buf) >= 188 and buf[0] == 0x47 and (len(buf) < 376 or buf[188] == 0x47)
    if ts(data):
        return 'mpeg-ts'
    if len(data) >= 12 and data[0] >> 6 == 2:
        offset = 12 + 4 * (data[0] & 15)
        if data[0] & 16:
            if len(data) < offset + 4:
                return 'udp'
            offset += 4 + 4 * struct.unpack_from('!H', data, offset + 2)[0]
        if ts(data[offset:]):
            return 'rtp-mpeg-ts'
    return 'udp'


def parse_packet(data):
    """Parse an AF_PACKET/SOCK_DGRAM IPv4 snapshot; reject fragmented packets."""
    if len(data) < 20 or data[0] >> 4 != 4 or data[9] != 17:
        return None
    ihl = (data[0] & 15) * 4
    total = struct.unpack_from('!H', data, 2)[0]
    if ihl < 20 or len(data) < ihl + 8 or total < ihl + 8:
        return None
    if struct.unpack_from('!H', data, 6)[0] & 0x3FFF:
        return None
    if data[16] & 0xF0 != 0xE0:
        return None
    port, length = struct.unpack_from('!HH', data, ihl + 2)
    if not port or length < 8 or length > total - ihl:
        return None
    group = socket.inet_ntoa(data[16:20])
    source = socket.inet_ntoa(data[12:16])
    payload = data[ihl + 8:min(len(data), ihl + length)]
    return group, port, source, length - 8, payload_kind(payload)


def interface_info(name):
    index = socket.if_nametoindex(name)
    if len(name.encode()) > 15:
        raise ValueError('interface name is too long')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        address = fcntl.ioctl(s, 0x8915, struct.pack('256s', name.encode()))[20:24]
    return index, socket.inet_ntoa(address)


def attach_filter(sock):
    # Full datagrams are required: SDT may follow the first TS packet in UDP.
    class Insn(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]
    class Program(ctypes.Structure):
        _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Insn))]
    code = (Insn * 8)(Insn(0x30, 0, 0, 9), Insn(0x15, 0, 5, 17),
                      Insn(0x20, 0, 0, 16), Insn(0x54, 0, 0, 0xF0000000),
                      Insn(0x15, 0, 2, 0xE0000000), Insn(0x06, 0, 0, 65535),
                      Insn(0x06, 0, 0, 0), Insn(0x06, 0, 0, 0))
    program = Program(len(code), code)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setsockopt(sock.fileno(), socket.SOL_SOCKET, 26,
                       ctypes.byref(program), ctypes.sizeof(program)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


class Capture:
    def __init__(self, interface):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800))
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            self.sock.bind((interface, 0))
            attach_filter(self.sock)
            self.sock.setblocking(False)
        except BaseException:
            self.sock.close()
            raise

    def fileno(self):
        return self.sock.fileno()

    def recv(self):
        data, address = self.sock.recvfrom(65535)
        # Do not mistake locally transmitted packets for ISP reception.
        return b'' if address[2] == socket.PACKET_OUTGOING else data

    def drops(self):
        # Reading PACKET_STATISTICS resets its counters. Call only once at end.
        return struct.unpack('II', self.sock.getsockopt(263, 6, 8))[1]

    def close(self):
        self.sock.close()


def join(group, index):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # ip_mreqn: explicit interface, independent of the default route.
        request = struct.pack('=4s4si', socket.inet_aton(group), b'\0' * 4, index)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, request)
        return sock
    except BaseException:
        sock.close()
        raise


def write_results(prefix, records, summary):
    base = Path(prefix)
    rows = sorted(records.values(), key=lambda r: (int(ipaddress.IPv4Address(r['group'])), r['port']))
    document = json.dumps({'summary': summary, 'streams': rows}, indent=2, ensure_ascii=False) + '\n'
    playlist = ['#EXTM3U']
    for row in rows:
        scheme = 'rtp' if row['kind'] == 'rtp-mpeg-ts' else 'udp'
        for service in row.get('services') or [None]:
            label = service['name'] if service else f"{row['group']}:{row['port']}"
            label = ''.join(c for c in label if c.isprintable())
            playlist.append(f'#EXTINF:-1,{label}')
            if service:
                playlist.append(f"#EXTVLCOPT:program={service['service_id']}")
            playlist.append(f"{scheme}://@{row['group']}:{row['port']}")
    for suffix, content in (('.json', document), ('.m3u', '\n'.join(playlist) + '\n')):
        dest = Path(str(base) + suffix)
        temporary = Path(str(dest) + '.tmp')
        with temporary.open('x', encoding='utf-8') as stream:
            stream.write(content)
        os.replace(temporary, dest)


def scan(args, blocks, index, capture, joiner=join, stopped=lambda: False):
    total = sum(hi - lo + 1 for lo, hi in blocks) * args.passes
    active, records = {}, {}
    decoders = {}
    attempted = joined = expired = errors = 0
    started = time.monotonic()
    next_join = started
    last_report = last_save = started
    exhausted = False
    iterator = (group for _ in range(args.passes) for group in addresses(blocks))
    summary = {}
    selector = selectors.DefaultSelector()
    selector.register(capture, selectors.EVENT_READ)
    try:
        while (not exhausted or active) and not stopped():
            now = time.monotonic()
            for group, (sock, deadline) in list(active.items()):
                if now >= deadline:
                    sock.close()
                    del active[group]
                    expired += 1
                    next_join = max(next_join, now + args.cooldown)
                    for key in [key for key in decoders if key[0] == group]:
                        del decoders[key]
            if not exhausted and len(active) < args.concurrency and now >= next_join:
                # Avoid overlapping membership windows across passes on tiny ranges.
                if attempted and attempted % (total // args.passes) == 0 and active:
                    pass
                else:
                    group = next(iterator, None)
                    if group is None:
                        exhausted = True
                    else:
                        attempted += 1
                        try:
                            sock = joiner(group, index)
                            active[group] = (sock, time.monotonic() + args.wait)
                            joined += 1
                        except OSError as exc:
                            errors += 1
                            if errors <= 5:
                                print(f'join {group}: {exc}', file=sys.stderr)
                        next_join = time.monotonic() + 1 / args.rate
            now = time.monotonic()
            timeout = 0.1
            if active:
                timeout = min(timeout, max(0, min(d for _, d in active.values()) - now))
            if not exhausted and len(active) < args.concurrency:
                timeout = min(timeout, max(0, next_join - now))
                # Pass boundary: wait for remaining windows rather than busy spinning.
                if attempted and attempted % (total // args.passes) == 0 and active:
                    timeout = min(0.1, max(0, min(d for _, d in active.values()) - now))
            if selector.select(timeout):
                for _ in range(256):
                    try:
                        data = capture.recv()
                        packet = parse_packet(data)
                    except BlockingIOError:
                        break
                    if packet is None or packet[0] not in active:
                        continue
                    group, port, source, size, kind = packet
                    key = (group, port)
                    if key not in records:
                        records[key] = {'group': group, 'port': port, 'source': source,
                                        'kind': kind, 'packets': 0, 'payload_bytes': 0}
                        print(f'found {group}:{port} ({kind})', file=sys.stderr)
                    record = records[key]
                    record['packets'] += 1
                    record['payload_bytes'] += size
                    if kind != 'udp':
                        record['kind'] = kind
                        decoder = decoders.setdefault(key, ServiceNames())
                        ihl = (data[0] & 15) * 4
                        services = decoder.feed(data[ihl + 8:ihl + 8 + size])
                        if services:
                            previous = {s['service_id']: s for s in record.get('services', [])}
                            previous.update({s['service_id']: s for s in services})
                            record['services'] = [previous[k] for k in sorted(previous)]
            now = time.monotonic()
            summary = {'planned_windows': total, 'attempted_windows': attempted,
                       'joined_windows': joined, 'completed_windows': expired,
                       'join_errors': errors, 'elapsed_seconds': round(now - started, 3),
                       'stream_count': len(records), 'interrupted': bool(stopped()),
                       'ranges': args.ranges, 'interface': args.interface,
                       'wait_seconds': args.wait, 'concurrency': args.concurrency,
                       'joins_per_second': args.rate, 'passes': args.passes,
                       'leave_cooldown_seconds': args.cooldown}
            if now - last_report >= 2:
                speed = expired / max(now - started, .001)
                eta = (total - expired) / speed if speed else None
                print(f'{expired}/{total} windows; {len(records)} streams; '
                      f'{speed:.1f} groups/s; ETA {eta:.0f}s' if eta is not None else
                      f'{expired}/{total} windows; waiting for first completed window', file=sys.stderr)
                last_report = now
            if now - last_save >= 10:
                write_results(args.output, records, summary)
                last_save = now
    finally:
        for sock, _ in active.values():
            sock.close()
        selector.close()
    summary['interrupted'] = bool(stopped())
    summary['capture_drops'] = capture.drops()
    summary['scan_complete'] = (expired == total and errors == 0
                                and summary['capture_drops'] == 0 and not stopped())
    write_results(args.output, records, summary)
    print(json.dumps(summary, ensure_ascii=False), file=sys.stderr)
    return 130 if stopped() else 2 if errors or summary['capture_drops'] else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-i', '--interface', required=True, help='IPTV interface (including VLAN interface if applicable)')
    parser.add_argument('-r', '--range', dest='ranges', action='append',
                        help='CIDR or inclusive FIRST-LAST; repeatable; default: full 224.0.0.0/4')
    parser.add_argument('-c', '--concurrency', type=int, default=4, help='simultaneous groups, 1-4 (NOWTV limit)')
    parser.add_argument('--wait', type=float, default=5, help='seconds per joined group (default: 5; includes SDT observation)')
    parser.add_argument('--rate', type=float, default=4, help='maximum group joins/second (default: 4)')
    parser.add_argument('--cooldown', type=float, default=2, help='pause new joins after leaving a group (seconds; default: 2)')
    parser.add_argument('--passes', type=int, default=1)
    parser.add_argument('-o', '--output', default='channels', help='output prefix; .json and .m3u will be replaced')
    parser.add_argument('--dry-run', action='store_true', help='show range size and ideal timing without joining or capturing')
    args = parser.parse_args(argv)
    args.ranges = args.ranges or ['224.0.0.0/4']
    try:
        import math
        if (args.concurrency < 1 or args.passes < 1 or not math.isfinite(args.wait)
                or not math.isfinite(args.rate) or args.wait <= 0 or args.rate <= 0):
            raise ValueError('concurrency/passes must be positive integers; wait/rate must be finite and positive')
        if args.concurrency > 4:
            raise ValueError('NOWTV permits at most 4 concurrent groups; use -c 1 through -c 4')
        if not math.isfinite(args.cooldown) or args.cooldown < 0:
            raise ValueError('cooldown must be finite and nonnegative')
        blocks = ranges(args.ranges)
        count = sum(hi - lo + 1 for lo, hi in blocks)
        ideal = max(count / args.rate, count * args.wait / args.concurrency) * args.passes
        print(f'{count:,} distinct groups, {args.passes} pass(es); ideal lower estimate '
              f'{ideal:.1f}s ({ideal / 3600:.2f}h), excluding leave cooldown, ISP delays and retries', file=sys.stderr)
        if args.dry_run:
            return 0
        if sys.platform != 'linux':
            raise ValueError('Linux is required')
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft != resource.RLIM_INFINITY and args.concurrency + 32 > soft:
            raise ValueError(f'concurrency exceeds file descriptor budget (soft limit {soft}); lower -c or raise ulimit -n')
        index, address = interface_info(args.interface)
        print(f'interface {args.interface}: {address}, index {index}', file=sys.stderr)
        parent = Path(args.output).parent
        if not parent.is_dir() or not os.access(parent, os.W_OK):
            raise ValueError(f'output directory is not writable: {parent}')
        interrupted = [False]
        def stop(_signal, _frame):
            interrupted[0] = True
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        capture = Capture(args.interface)
        try:
            return scan(args, blocks, index, capture, stopped=lambda: interrupted[0])
        finally:
            capture.close()
    except (OSError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        if isinstance(exc, PermissionError):
            print('Live capture requires root or CAP_NET_RAW (for example: sudo python3 scanner.py ...).', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
