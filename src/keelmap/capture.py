"""Read classic pcap and pcapng files without third-party dependencies.

Frame numbers match Wireshark: every packet block counts, in file order,
starting at 1, across all sections and interfaces. Packets the reader cannot
timestamp (pcapng Simple Packet Blocks) still use up a frame number, so the
numbers KeelMap cites always point at the same packet Wireshark shows.
"""

from __future__ import annotations

import hashlib
import struct
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import BinaryIO, Iterator

from keelmap.decoders.base import Frame

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


class CaptureError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _ts(ticks: int, units_per_sec: int, offset_sec: int = 0) -> datetime:
    """Round to the nearest microsecond, the finest unit datetime holds."""
    sec, frac = divmod(ticks, units_per_sec)
    usec = (frac * 1_000_000 + units_per_sec // 2) // units_per_sec
    return _EPOCH + timedelta(seconds=sec + offset_sec, microseconds=usec)


@dataclass
class _Iface:
    linktype: int
    snaplen: int
    units: int = 1_000_000
    offset: int = 0


class CaptureReader:
    """Iterate frames. Counters describe anything that was not yielded."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.sha256 = sha256_file(self.path)
        self.frame_count = 0
        self.first_ts: datetime | None = None
        self.last_ts: datetime | None = None
        self.stats: Counter[str] = Counter()

    def __iter__(self) -> Iterator[Frame]:
        with open(self.path, "rb") as f:
            magic = f.read(4)
            if magic in _PCAP_MAGICS:
                yield from self._pcap(f, magic)
            elif magic == _PCAPNG_SHB:
                f.seek(0)
                yield from self._pcapng(f)
            else:
                raise CaptureError(f"{self.path.name}: not a pcap or pcapng file")

    def _emit(self, number: int, ts: datetime, data: bytes, linktype: int) -> Frame:
        self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
        self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        return Frame(number, ts, data, linktype, self.sha256)

    # classic pcap -------------------------------------------------------------

    def _pcap(self, f: BinaryIO, magic: bytes) -> Iterator[Frame]:
        endian, units = _PCAP_MAGICS[magic]
        hdr = f.read(20)
        if len(hdr) < 20:
            raise CaptureError(f"{self.path.name}: truncated pcap header")
        _vmaj, _vmin, _zone, _sig, _snap, network = struct.unpack(endian + "HHiIII", hdr)
        linktype = network & 0xFFFF
        rec = struct.Struct(endian + "IIII")
        while True:
            h = f.read(16)
            if not h:
                return
            if len(h) < 16:
                self.stats["capture_truncated"] += 1
                return
            sec, frac, incl, _orig = rec.unpack(h)
            data = f.read(incl)
            if len(data) < incl:
                self.stats["capture_truncated"] += 1
                return
            self.frame_count += 1
            yield self._emit(self.frame_count, _ts(sec * units + frac, units), data, linktype)

    # pcapng -------------------------------------------------------------------

    def _pcapng(self, f: BinaryIO) -> Iterator[Frame]:
        endian = "<"
        ifaces: list[_Iface] = []
        while True:
            head = f.read(8)
            if not head:
                return
            if len(head) < 8:
                self.stats["capture_truncated"] += 1
                return
            if head[:4] == _PCAPNG_SHB:
                bom = f.read(4)
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise CaptureError(f"{self.path.name}: bad pcapng byte-order magic")
                btype = 0x0A0D0D0A
                total = struct.unpack(endian + "I", head[4:])[0]
                body = bom + f.read(total - 12)
                ifaces = []
            else:
                btype, total = struct.unpack(endian + "II", head)
                body = f.read(total - 8)
            if total < 12 or len(body) < total - 8:
                self.stats["capture_truncated"] += 1
                return
            body = body[:-4]  # trailing block length

            if btype == 1:  # Interface Description Block
                linktype, _res, snaplen = struct.unpack(endian + "HHI", body[:8])
                ifaces.append(self._idb_options(endian, linktype, snaplen, body[8:]))
            elif btype == 6:  # Enhanced Packet Block
                iid, hi, lo, cap, _orig = struct.unpack(endian + "IIIII", body[:20])
                self.frame_count += 1
                if iid >= len(ifaces):
                    self.stats["frame_unknown_interface"] += 1
                    continue
                i = ifaces[iid]
                yield self._emit(self.frame_count, _ts((hi << 32) | lo, i.units, i.offset),
                                 body[20:20 + cap], i.linktype)
            elif btype == 2:  # Packet Block (obsolete)
                iid, _drops, hi, lo, cap, _orig = struct.unpack(endian + "HHIIII", body[:20])
                self.frame_count += 1
                if iid >= len(ifaces):
                    self.stats["frame_unknown_interface"] += 1
                    continue
                i = ifaces[iid]
                yield self._emit(self.frame_count, _ts((hi << 32) | lo, i.units, i.offset),
                                 body[20:20 + cap], i.linktype)
            elif btype == 3:  # Simple Packet Block: no timestamp, so no evidence possible
                self.frame_count += 1
                self.stats["frame_without_timestamp"] += 1

    @staticmethod
    def _idb_options(endian: str, linktype: int, snaplen: int, opts: bytes) -> _Iface:
        iface = _Iface(linktype, snaplen)
        pos = 0
        while pos + 4 <= len(opts):
            code, length = struct.unpack(endian + "HH", opts[pos:pos + 4])
            val = opts[pos + 4:pos + 4 + length]
            if code == 0:
                break
            if code == 9 and length >= 1:  # if_tsresol
                r = val[0]
                iface.units = 2 ** (r & 0x7F) if r & 0x80 else 10 ** r
            elif code == 14 and length >= 8:  # if_tsoffset, seconds
                iface.offset = struct.unpack(endian + "q", val[:8])[0]
            pos += 4 + length + (-length % 4)
        return iface
