import argparse
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import time
import unittest

import scanner
from services import ServiceNames, crc32_mpeg, dvb_text
from test_scanner import FakeCapture, packet


def section(name='NOW News', sid=332):
    provider = b'NOWTV'
    name = b'\x15' + name.encode('utf-8')
    value = b'\x01' + bytes([len(provider)]) + provider + bytes([len(name)]) + name
    descriptor = bytes([0x48, len(value)]) + value
    entry = struct.pack('!HBH', sid, 0xFC, 0x8000 | len(descriptor)) + descriptor
    body = b'\x00\x01\xc1\x00\x00\x00\x01\xff' + entry
    result = b'\x42' + struct.pack('!H', 0xF000 | (len(body) + 4)) + body
    return result + struct.pack('!I', crc32_mpeg(result))


def ts(payload, start=True, cc=0):
    content = (b'\0' if start else b'') + payload
    # Adaptation padding keeps trailing stuffing outside the section payload.
    adaptation_length = 183 - len(content)
    assert adaptation_length >= 0
    adaptation = bytes([adaptation_length])
    if adaptation_length:
        adaptation += b'\0' + b'\xff' * (adaptation_length - 1)
    return bytes([0x47, 0x40 if start else 0, 0x11, 0x30 | cc]) + adaptation + content


class ServiceTests(unittest.TestCase):
    def test_name_and_provider(self):
        names = ServiceNames().feed(ts(section('NOW 新聞')))
        self.assertEqual(names, [{'service_id': 332, 'name': 'NOW 新聞', 'provider': 'NOWTV'}])

    def test_sdt_after_first_512_bytes_and_rtp(self):
        null = b'\x47\x1f\xff\x10' + b'\xff' * 184
        udp = null * 5 + ts(section())
        self.assertGreater(len(udp), 512)
        rtp = b'\x80\x21' + bytes(10)
        self.assertEqual(ServiceNames().feed(rtp + udp)[0]['name'], 'NOW News')

    def test_section_reassembly_and_packet_loss(self):
        data = section()
        first, second = ts(data[:20]), ts(data[20:], start=False, cc=1)
        decoder = ServiceNames()
        self.assertEqual(decoder.feed(first), [])
        self.assertEqual(decoder.feed(second)[0]['name'], 'NOW News')
        decoder = ServiceNames()
        decoder.feed(first)
        self.assertEqual(decoder.feed(ts(data[20:], start=False, cc=2)), [])

    def test_crc_and_other_transport_stream_rejected(self):
        data = bytearray(section())
        data[-1] ^= 1
        self.assertEqual(ServiceNames().feed(ts(data)), [])
        data = bytearray(section())
        data[0] = 0x46
        data[-4:] = struct.pack('!I', crc32_mpeg(data[:-4]))
        self.assertEqual(ServiceNames().feed(ts(data)), [])

    def test_text_encodings_and_control_characters(self):
        self.assertEqual(dvb_text(b'\x11' + '新聞'.encode('utf-16-be')), '新聞')
        self.assertEqual(dvb_text(b'NOW\r\nNews'), 'NOWNews')
        self.assertEqual(dvb_text(b'\x15' + '新聞'.encode()), '新聞')

    def test_real_scan_path_names_and_cooldown(self):
        capture = FakeCapture()
        events = []
        class Member:
            def close(self):
                events.append(('leave', time.monotonic()))
        def joiner(group, _index):
            events.append(('join', time.monotonic()))
            capture.writer.send(packet(group, payload=ts(section())))
            return Member()
        try:
            with tempfile.TemporaryDirectory() as directory:
                args = argparse.Namespace(passes=1, concurrency=1, wait=.02, rate=1000,
                                          cooldown=.03, output=directory + '/named',
                                          ranges=['239.1.1.1-239.1.1.2'], interface='fake0')
                with contextlib.redirect_stderr(io.StringIO()):
                    code = scanner.scan(args, scanner.ranges(args.ranges), 1, capture, joiner)
                self.assertEqual(code, 0)
                self.assertGreaterEqual(events[2][1] - events[1][1], .029)
                playlist = Path(args.output + '.m3u').read_text()
                self.assertIn('#EXTINF:-1,NOW News\n#EXTVLCOPT:program=332', playlist)
                streams = json.loads(Path(args.output + '.json').read_text())['streams']
                self.assertEqual(streams[0]['services'][0]['name'], 'NOW News')
        finally:
            capture.close()

    def test_reject_more_than_four_before_opening_capture(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scanner.main(['-i', 'ens256', '-c', '5', '--dry-run']), 1)


if __name__ == '__main__':
    unittest.main()
