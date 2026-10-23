import argparse
import contextlib
import io
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

import scanner


def packet(group='239.1.2.3', port=54321, payload=b'hello', options=b''):
    ihl = 20 + len(options)
    header = struct.pack('!BBHHHBBH4s4s', 0x40 + ihl // 4, 0, ihl + 8 + len(payload),
                         0, 0, 64, 17, 0, socket.inet_aton('192.0.2.1'), socket.inet_aton(group))
    return header + options + struct.pack('!HHHH', 1234, port, 8 + len(payload), 0) + payload


class FakeCapture:
    def __init__(self):
        self.reader, self.writer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.reader.setblocking(False)

    def fileno(self):
        return self.reader.fileno()

    def recv(self):
        return self.reader.recv(65535)

    def drops(self):
        return 0

    def close(self):
        self.reader.close()
        self.writer.close()


class ScannerTests(unittest.TestCase):
    def test_ranges_merge_and_full_space_is_lazy(self):
        self.assertEqual(scanner.ranges(['239.0.0.0/30', '239.0.0.2-239.0.0.5']),
                         [(0xEF000000, 0xEF000005)])
        full = scanner.ranges(['224.0.0.0/4'])
        self.assertEqual(sum(b - a + 1 for a, b in full), 268435456)
        self.assertEqual(next(scanner.addresses(full)), '224.0.0.0')
        for value in ['192.168.1.0/24', '239.0.0.2-239.0.0.1', '::/0']:
            with self.assertRaises(ValueError):
                scanner.ranges([value])

    def test_unknown_port_and_ipv4_options(self):
        result = scanner.parse_packet(packet(options=b'\x01' * 4))
        self.assertEqual(result, ('239.1.2.3', 54321, '192.0.2.1', 5, 'udp'))

    def test_payload_types(self):
        ts = b'\x47' + bytes(187)
        self.assertEqual(scanner.parse_packet(packet(payload=ts * 2))[4], 'mpeg-ts')
        rtp = bytes([0x91, 33]) + bytes(10) + bytes(4) + struct.pack('!HH', 0, 1) + bytes(4)
        self.assertEqual(scanner.parse_packet(packet(payload=rtp + ts * 2))[4], 'rtp-mpeg-ts')
        self.assertEqual(scanner.payload_kind(b'\x90' + bytes(11)), 'udp')

    def test_reject_bad_packets(self):
        valid = packet()
        variants = [b'', valid[:24], packet(group='192.0.2.1'), packet(port=0)]
        for offset, replacement in [(6, b'\x20\x00'), (6, b'\x00\x01'),
                                    (9, b'\x06'), (0, b'\x44'), (24, b'\x00\x07')]:
            variants.append(valid[:offset] + replacement + valid[offset + len(replacement):])
        for data in variants:
            self.assertIsNone(scanner.parse_packet(data))

    def test_kernel_bpf_program(self):
        # Linux can attach cBPF to an unprivileged UDP socket too. This checks
        # the real kernel verifier and executes the same filter on crafted data.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(('127.0.0.1', 0))
            receiver.settimeout(.05)
            scanner.attach_filter(receiver)
            # UDP socket filter offset 0 is the UDP header. Prefix 8 bytes in
            # the BPF's apparent IP header by removing them from our payload.
            crafted = bytearray(packet())
            sender.sendto(bytes(crafted[8:]), receiver.getsockname())
            self.assertTrue(receiver.recv(512))
            large = packet(payload=bytes(1300))[8:]
            sender.sendto(large, receiver.getsockname())
            self.assertEqual(receiver.recv(65535), large)
            crafted[9] = 6
            sender.sendto(bytes(crafted[8:]), receiver.getsockname())
            with self.assertRaises(socket.timeout):
                receiver.recv(512)
            crafted = bytearray(packet(group='192.0.2.1'))
            sender.sendto(bytes(crafted[8:]), receiver.getsockname())
            with self.assertRaises(socket.timeout):
                receiver.recv(512)

    def test_real_linux_multicast_membership_and_receive(self):
        index = socket.if_nametoindex('lo')
        group = '239.255.254.123'
        member = scanner.join(group, index)
        try:
            member.bind(('', 0))
            member.settimeout(1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('127.0.0.1'))
                sender.sendto(b'iptv-test', (group, member.getsockname()[1]))
                self.assertEqual(member.recv(100), b'iptv-test')
        finally:
            member.close()

    def run_scan(self, fail=False, interrupt=False, drops=0):
        capture = FakeCapture()
        capture.drops = lambda: drops
        memberships = []
        state = {'active': 0, 'peak': 0, 'stopped': False}
        class Member:
            def __init__(self):
                self.closed = False
                state['active'] += 1
                state['peak'] = max(state['peak'], state['active'])
                memberships.append(self)
            def close(self):
                if not self.closed:
                    state['active'] -= 1
                    self.closed = True
        def joiner(group, _index):
            if fail and group.endswith('.2'):
                raise OSError('simulated membership limit')
            member = Member()
            capture.writer.send(packet(group, 45678, b'\x47' + bytes(187)))
            capture.writer.send(packet('239.99.99.99', 9999))
            if interrupt:
                state['stopped'] = True
            return member
        try:
            with tempfile.TemporaryDirectory() as directory:
                args = argparse.Namespace(passes=2, concurrency=2, wait=.03, rate=1000, cooldown=.01,
                                          output=directory + '/channels', interface='fake0',
                                          ranges=['239.1.2.1-239.1.2.3'])
                with contextlib.redirect_stderr(io.StringIO()):
                    code = scanner.scan(args, scanner.ranges(args.ranges), 1, capture,
                                        joiner, lambda: state['stopped'])
                doc = json.loads(Path(args.output + '.json').read_text())
                playlist = Path(args.output + '.m3u').read_text()
                self.assertTrue(all(m.closed for m in memberships))
                self.assertLessEqual(state['peak'], 2)
                if not interrupt:
                    self.assertEqual(doc['summary']['attempted_windows'], 6)
                    self.assertEqual(doc['summary']['completed_windows'], 4 if fail else 6)
                    self.assertEqual(len(doc['streams']), 2 if fail else 3)
                    self.assertIn('udp://@239.1.2.1:45678', playlist)
                    self.assertNotIn('239.99.99.99', playlist)
                    self.assertTrue(all(s['packets'] == 2 for s in doc['streams']))
                return code, doc
        finally:
            capture.close()

    def test_scan_unknown_ports_two_passes_output_and_cleanup(self):
        code, doc = self.run_scan()
        self.assertEqual(code, 0)
        self.assertTrue(doc['summary']['scan_complete'])

    def test_membership_errors_report_incomplete(self):
        code, doc = self.run_scan(fail=True)
        self.assertEqual(code, 2)
        self.assertEqual(doc['summary']['join_errors'], 2)
        self.assertFalse(doc['summary']['scan_complete'])

    def test_interrupt_saves_results_and_closes_memberships(self):
        code, doc = self.run_scan(interrupt=True)
        self.assertEqual(code, 130)
        self.assertTrue(doc['summary']['interrupted'])
        self.assertFalse(doc['summary']['scan_complete'])

    def test_capture_drops_report_incomplete(self):
        code, doc = self.run_scan(drops=7)
        self.assertEqual(code, 2)
        self.assertEqual(doc['summary']['capture_drops'], 7)
        self.assertFalse(doc['summary']['scan_complete'])


if __name__ == '__main__':
    unittest.main()
