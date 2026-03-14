#!/usr/local/bin/python3
"""
Pure-Python MaxMind MMDB reader — no external dependencies.

Implements enough of the MMDB binary format to read GeoLite2-Country databases.
Reference: https://maxmind.github.io/MaxMind-DB/
"""

import struct
import socket
import os

# MMDB data section type constants
_POINTER = 1
_UTF8 = 2
_DOUBLE = 3
_BYTES = 4
_UINT16 = 5
_UINT32 = 6
_MAP = 7
_INT32 = 8
_UINT64 = 9
_UINT128 = 10
_ARRAY = 11
_BOOLEAN = 14
_FLOAT = 15


class MMDBReader:
    """Minimal pure-Python reader for MaxMind MMDB files."""

    def __init__(self, filepath):
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"MMDB file not found: {filepath}")
        with open(filepath, 'rb') as f:
            self._buf = f.read()
        self._parse_metadata()

    def _parse_metadata(self):
        """Find and parse the metadata section at the end of the file."""
        marker = b'\xab\xcd\xefMaxMind.com'
        pos = self._buf.rfind(marker)
        if pos < 0:
            raise ValueError("Not a valid MMDB file (metadata marker not found)")
        meta_start = pos + len(marker)
        meta, _ = self._decode(meta_start)
        self._meta = meta
        self._node_count = meta['node_count']
        self._record_size = meta['record_size']
        self._node_byte_size = self._record_size * 2 // 8
        self._search_tree_size = self._node_count * self._node_byte_size
        self._data_start = self._search_tree_size + 16  # 16-byte null separator
        self._ip_version = meta.get('ip_version', 4)

    def get(self, ip_str):
        """Look up an IP address string. Returns dict or None."""
        try:
            packed = socket.inet_pton(socket.AF_INET6 if ':' in ip_str else socket.AF_INET, ip_str)
        except (socket.error, OSError):
            return None

        # Convert IPv4 to IPv4-mapped IPv6 for IPv6 databases
        if len(packed) == 4 and self._ip_version == 6:
            packed = b'\x00' * 12 + packed

        bits = []
        for byte in packed:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)

        node = 0
        for bit in bits:
            if node >= self._node_count:
                break
            record = self._read_record(node, bit)
            if record == self._node_count:
                # Empty/not found
                return None
            if record > self._node_count:
                # Data pointer
                offset = record - self._node_count - 16
                data, _ = self._decode(self._search_tree_size + 16 + offset)
                return data
            node = record

        return None

    def _read_record(self, node, side):
        """Read left (side=0) or right (side=1) record from a node."""
        rs = self._record_size
        offset = node * self._node_byte_size

        if rs == 24:
            if side == 0:
                return (self._buf[offset] << 16) | (self._buf[offset + 1] << 8) | self._buf[offset + 2]
            else:
                return (self._buf[offset + 3] << 16) | (self._buf[offset + 4] << 8) | self._buf[offset + 5]
        elif rs == 28:
            if side == 0:
                middle = self._buf[offset + 3]
                return ((middle >> 4) << 24) | (self._buf[offset] << 16) | (self._buf[offset + 1] << 8) | self._buf[offset + 2]
            else:
                middle = self._buf[offset + 3]
                return ((middle & 0x0f) << 24) | (self._buf[offset + 4] << 16) | (self._buf[offset + 5] << 8) | self._buf[offset + 6]
        elif rs == 32:
            if side == 0:
                return struct.unpack('>I', self._buf[offset:offset + 4])[0]
            else:
                return struct.unpack('>I', self._buf[offset + 4:offset + 8])[0]
        else:
            raise ValueError(f"Unsupported record size: {rs}")

    def _decode(self, offset):
        """Decode a data value at the given offset. Returns (value, new_offset)."""
        ctrl = self._buf[offset]
        offset += 1

        dtype = ctrl >> 5
        if dtype == 0:
            # Extended type
            dtype = self._buf[offset] + 7
            offset += 1

        if dtype == _POINTER:
            psize = (ctrl >> 3) & 0x03
            if psize == 0:
                ptr = ((ctrl & 0x07) << 8) | self._buf[offset]
                offset += 1
            elif psize == 1:
                ptr = ((ctrl & 0x07) << 16) | (self._buf[offset] << 8) | self._buf[offset + 1]
                ptr += 2048
                offset += 2
            elif psize == 2:
                ptr = ((ctrl & 0x07) << 24) | (self._buf[offset] << 16) | (self._buf[offset + 1] << 8) | self._buf[offset + 2]
                ptr += 526336
                offset += 3
            else:
                ptr = struct.unpack('>I', self._buf[offset:offset + 4])[0]
                offset += 4
            val, _ = self._decode(self._data_start + ptr)
            return val, offset

        # Determine payload size
        size = ctrl & 0x1f
        if size == 29:
            size = 29 + self._buf[offset]
            offset += 1
        elif size == 30:
            size = 285 + (self._buf[offset] << 8) | self._buf[offset + 1]
            offset += 2
        elif size == 31:
            size = 65821 + (self._buf[offset] << 16) | (self._buf[offset + 1] << 8) | self._buf[offset + 2]
            offset += 3

        if dtype == _MAP:
            result = {}
            for _ in range(size):
                key, offset = self._decode(offset)
                val, offset = self._decode(offset)
                result[key] = val
            return result, offset
        elif dtype == _ARRAY:
            result = []
            for _ in range(size):
                val, offset = self._decode(offset)
                result.append(val)
            return result, offset
        elif dtype == _UTF8:
            val = self._buf[offset:offset + size].decode('utf-8', errors='replace')
            return val, offset + size
        elif dtype == _BYTES:
            return self._buf[offset:offset + size], offset + size
        elif dtype == _UINT16:
            return int.from_bytes(self._buf[offset:offset + size], 'big') if size else 0, offset + size
        elif dtype == _UINT32:
            return int.from_bytes(self._buf[offset:offset + size], 'big') if size else 0, offset + size
        elif dtype == _UINT64:
            return int.from_bytes(self._buf[offset:offset + size], 'big') if size else 0, offset + size
        elif dtype == _UINT128:
            return int.from_bytes(self._buf[offset:offset + size], 'big') if size else 0, offset + size
        elif dtype == _INT32:
            if size == 0:
                return 0, offset
            return int.from_bytes(self._buf[offset:offset + size], 'big', signed=True), offset + size
        elif dtype == _DOUBLE:
            return struct.unpack('>d', self._buf[offset:offset + 8])[0], offset + 8
        elif dtype == _FLOAT:
            return struct.unpack('>f', self._buf[offset:offset + 4])[0], offset + 4
        elif dtype == _BOOLEAN:
            return size != 0, offset
        else:
            # Unknown type — skip
            return None, offset + size

    def close(self):
        self._buf = None

    @property
    def metadata(self):
        return self._meta
