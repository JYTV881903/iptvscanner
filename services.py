"""DVB SDT service names from UDP or RTP MPEG transport streams."""
import struct


def crc32_mpeg(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            crc = ((crc << 1) ^ (0x04C11DB7 if crc & 0x80000000 else 0)) & 0xFFFFFFFF
    return crc


def dvb_text(data):
    if not data:
        return ''
    encoding = 'utf-8'
    if data[0] == 0x15:
        data = data[1:]
    elif data[0] == 0x11:
        encoding, data = 'utf-16-be', data[1:]
    elif data[0] == 0x12:
        encoding, data = 'euc-kr', data[1:]
    elif data[0] == 0x13:
        encoding, data = 'gb2312', data[1:]
    elif data[0] == 0x14:
        encoding, data = 'big5', data[1:]
    elif data[0] == 0x10 and len(data) >= 3 and data[1] == 0:
        encoding, data = f'iso8859-{data[2]}', data[3:]
    elif 1 <= data[0] <= 11:
        encoding, data = f'iso8859-{data[0] + 4}', data[1:]
    try:
        text = data.decode(encoding)
    except (UnicodeError, LookupError):
        # ASCII/default English names work directly. ISO-6937 non-ASCII is
        # not fully implemented; replacement avoids inventing decoded names.
        text = data.decode('utf-8', errors='replace')
    return ''.join(c for c in text if c.isprintable()).strip()


def transport_payload(data):
    if data[:1] == b'\x47':
        return data
    if len(data) < 12 or data[0] >> 6 != 2:
        return b''
    offset = 12 + 4 * (data[0] & 15)
    if data[0] & 16:
        if len(data) < offset + 4:
            return b''
        offset += 4 + 4 * struct.unpack_from('!H', data, offset + 2)[0]
    end = len(data)
    if data[0] & 32:
        padding = data[-1]
        if not padding or padding > end - offset:
            return b''
        end -= padding
    payload = data[offset:end]
    return payload if payload[:1] == b'\x47' else b''


class ServiceNames:
    def __init__(self):
        self.buffer = bytearray()
        self.continuity = None
        self.services = {}

    def _sections(self):
        while len(self.buffer) >= 3:
            if self.buffer[0] == 0xFF:
                self.buffer.clear()
                return
            size = 3 + ((self.buffer[1] & 15) << 8 | self.buffer[2])
            if size < 15 or size > 1024:
                self.buffer.clear()
                return
            if len(self.buffer) < size:
                return
            section = bytes(self.buffer[:size])
            del self.buffer[:size]
            # Actual transport stream, current table, valid MPEG CRC only.
            if section[0] != 0x42 or not section[5] & 1 or crc32_mpeg(section):
                continue
            pos, end = 11, size - 4
            found = {}
            while pos + 5 <= end:
                sid = int.from_bytes(section[pos:pos + 2], 'big')
                limit = pos + 5 + ((section[pos + 3] & 15) << 8 | section[pos + 4])
                if limit > end:
                    break
                desc = pos + 5
                while desc + 2 <= limit:
                    tag, length = section[desc:desc + 2]
                    start, stop = desc + 2, desc + 2 + length
                    if stop > limit:
                        break
                    value = section[start:stop]
                    if tag == 0x48 and len(value) >= 3:
                        provider_len = value[1]
                        name_pos = 2 + provider_len
                        if name_pos < len(value):
                            name_len = value[name_pos]
                            if name_pos + 1 + name_len <= len(value):
                                name = dvb_text(value[name_pos + 1:name_pos + 1 + name_len])
                                if name:
                                    found[sid] = {'service_id': sid, 'name': name,
                                                  'provider': dvb_text(value[2:name_pos])}
                    desc = stop
                pos = limit
            self.services.update(found)

    def feed(self, data):
        data = transport_payload(data)
        for offset in range(0, len(data) - 187, 188):
            ts = data[offset:offset + 188]
            if ts[0] != 0x47 or ((ts[1] & 31) << 8 | ts[2]) != 0x11:
                continue
            control, cc = ts[3] >> 4, ts[3] & 15
            if ts[1] & 0x80 or ts[3] & 0xC0 or not control & 1:
                continue
            pos = 4
            if control & 2:
                pos += 1 + ts[4]
                if ts[4] and ts[5] & 0x80:
                    self.buffer.clear()
                    self.continuity = None
            if pos >= 188:
                continue
            if self.continuity == cc:
                continue  # duplicate TS packet
            if self.continuity is not None and cc != (self.continuity + 1) % 16:
                self.buffer.clear()
            self.continuity = cc
            payload = ts[pos:]
            if ts[1] & 0x40:
                pointer = payload[0]
                if pointer + 1 > len(payload):
                    self.buffer.clear()
                    continue
                if self.buffer:
                    self.buffer.extend(payload[1:1 + pointer])
                    self._sections()
                self.buffer = bytearray(payload[1 + pointer:])
            elif self.buffer:
                self.buffer.extend(payload)
            self._sections()
        return [self.services[k] for k in sorted(self.services)]
