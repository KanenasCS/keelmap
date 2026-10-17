"""Build test frames and captures by hand, independent of the code under test."""

from __future__ import annotations

import ipaddress
import struct
from datetime import datetime, timezone

BCAST = "ff:ff:ff:ff:ff:ff"


def mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def ip4(s: str) -> bytes:
    return ipaddress.IPv4Address(s).packed


def ether(dst: str, src: str, etype: int, payload: bytes, vlan: int | None = None) -> bytes:
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    return mac(dst) + mac(src) + tag + struct.pack("!H", etype) + payload


def arp(op: int, sha: str, spa: str, tha: str, tpa: str) -> bytes:
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac(sha) + ip4(spa) + mac(tha) + ip4(tpa)


def ipv4_udp(src: str, dst: str, sport: int, dport: int, payload: bytes, frag: int = 0) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, frag, 64, 17, 0, ip4(src), ip4(dst))
    return hdr + udp


def dhcp(op: int, mtype: int, chaddr: str, ciaddr="0.0.0.0", yiaddr="0.0.0.0",
         giaddr="0.0.0.0", options: dict[int, bytes] | None = None) -> bytes:
    body = struct.pack("!BBBBIHH", op, 1, 6, 0, 0x1234, 0, 0)
    body += ip4(ciaddr) + ip4(yiaddr) + ip4("0.0.0.0") + ip4(giaddr)
    body += mac(chaddr) + b"\x00" * 10 + b"\x00" * 192 + b"\x63\x82\x53\x63"
    opts = bytes([53, 1, mtype])
    for code, val in (options or {}).items():
        opts += bytes([code, len(val)]) + val
    return body + opts + b"\xff"


def ts(sec: int, usec: int = 0) -> datetime:
    return datetime.fromtimestamp(sec, timezone.utc).replace(microsecond=usec)


def write_pcap(path, frames: list[tuple[datetime, bytes]], linktype: int = 1,
               nanos: bool = False, big_endian: bool = False) -> None:
    e = ">" if big_endian else "<"
    magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
    out = struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)
    for t, data in frames:
        sec = int(t.timestamp())
        frac = t.microsecond * (1000 if nanos else 1)
        out += struct.pack(e + "IIII", sec, frac, len(data), len(data)) + data
    with open(path, "wb") as f:
        f.write(out)


def _block(btype: int, body: bytes) -> bytes:
    body += b"\x00" * (-len(body) % 4)
    total = 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def write_pcapng(path, frames: list[tuple[datetime | None, bytes]], tsresol: int | None = None) -> None:
    """Frames with timestamp None are written as Simple Packet Blocks."""
    shb = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    opts = b""
    if tsresol is not None:
        opts = struct.pack("<HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3 + struct.pack("<HH", 0, 0)
    idb = _block(1, struct.pack("<HHI", 1, 0, 65535) + opts)
    units = 10 ** 6 if tsresol is None else (2 ** (tsresol & 0x7F) if tsresol & 0x80 else 10 ** tsresol)
    out = shb + idb
    for t, data in frames:
        if t is None:
            out += _block(3, struct.pack("<I", len(data)) + data)
            continue
        ticks = int(t.timestamp()) * units + t.microsecond * units // 1_000_000
        out += _block(6, struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data)) + data)
    with open(path, "wb") as f:
        f.write(out)


def ipv4_tcp(src: str, dst: str, sport: int, dport: int, payload: bytes, seq: int = 1000) -> bytes:
    tcp = struct.pack("!HHIIHHHH", sport, dport, seq, 1, (5 << 12) | 0x18, 8192, 0, 0) + payload
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, ip4(src), ip4(dst))
    return hdr + tcp


def mbap(tid: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def devid_request() -> bytes:
    return bytes([0x2B, 0x0E, 0x01, 0x00])


def devid_response(objects: dict[int, bytes]) -> bytes:
    body = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, len(objects)])
    for oid, val in objects.items():
        body += bytes([oid, len(val)]) + val
    return body


LLDP_DST = "01:80:c2:00:00:0e"


def tlv(ttype: int, value: bytes) -> bytes:
    return struct.pack("!H", (ttype << 9) | len(value)) + value


def lldp_frame(src: str, tlvs: list[bytes], end: bool = True) -> bytes:
    body = b"".join(tlvs) + (tlv(0, b"") if end else b"")
    return ether(LLDP_DST, src, 0x88CC, body)


def lldp_basic(src: str) -> list[bytes]:
    return [tlv(1, b"\x04" + mac(src)), tlv(2, b"\x07" + b"1"), tlv(3, b"\x00\x78")]
