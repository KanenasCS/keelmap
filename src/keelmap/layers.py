"""Lower-layer parsing shared by decoders. Returns None rather than guessing on bad input."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

LINKTYPE_ETHERNET = 1
ETH_ARP = 0x0806
ETH_IPV4 = 0x0800
ETH_LLDP = 0x88CC
_VLAN_TPIDS = {0x8100, 0x88A8, 0x9100}


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def is_unicast_mac(b: bytes) -> bool:
    return len(b) == 6 and not (b[0] & 0x01) and b != b"\x00" * 6


def is_host_ip(ip: str) -> bool:
    """True for an address a single device can own. Excludes unspecified, broadcast, multicast, loopback."""
    a = ipaddress.IPv4Address(ip)
    return not (a.is_unspecified or a.is_multicast or a.is_loopback or ip == "255.255.255.255")


@dataclass(frozen=True)
class Ethernet:
    dst: bytes
    src: bytes
    ethertype: int | None      # None for 802.3 length-field frames
    vlans: tuple[int, ...]
    payload: bytes


def parse_ethernet(data: bytes) -> Ethernet | None:
    if len(data) < 14:
        return None
    dst, src = data[0:6], data[6:12]
    pos, vlans = 12, []
    (etype,) = struct.unpack("!H", data[pos:pos + 2])
    while etype in _VLAN_TPIDS:
        if len(data) < pos + 6:
            return None
        (tci, etype) = struct.unpack("!HH", data[pos + 2:pos + 6])
        vlans.append(tci & 0x0FFF)
        pos += 4
    pos += 2
    return Ethernet(dst, src, etype if etype > 1500 else None, tuple(vlans), data[pos:])


@dataclass(frozen=True)
class IPv4:
    src: str
    dst: str
    proto: int
    payload: bytes
    fragment: bool             # True if this is a fragment (any part)


def parse_ipv4(data: bytes) -> IPv4 | None:
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    (total,) = struct.unpack("!H", data[2:4])
    if ihl < 20 or total < ihl or len(data) < ihl:
        return None
    (flags_frag,) = struct.unpack("!H", data[6:8])
    fragment = bool(flags_frag & 0x2000) or bool(flags_frag & 0x1FFF)
    end = min(total, len(data))
    return IPv4(
        src=str(ipaddress.IPv4Address(data[12:16])),
        dst=str(ipaddress.IPv4Address(data[16:20])),
        proto=data[9],
        payload=data[ihl:end],
        fragment=fragment,
    )


@dataclass(frozen=True)
class UDP:
    sport: int
    dport: int
    payload: bytes


def parse_udp(data: bytes) -> UDP | None:
    if len(data) < 8:
        return None
    sport, dport, length, _csum = struct.unpack("!HHHH", data[:8])
    if length < 8:
        return None
    return UDP(sport, dport, data[8:min(length, len(data))])


@dataclass(frozen=True)
class TCP:
    sport: int
    dport: int
    seq: int
    flags: int
    payload: bytes


def parse_tcp(data: bytes) -> TCP | None:
    if len(data) < 20:
        return None
    sport, dport, seq, _ack, off_flags = struct.unpack("!HHIIH", data[:14])
    off = (off_flags >> 12) * 4
    if off < 20 or len(data) < off:
        return None
    return TCP(sport, dport, seq, off_flags & 0x01FF, data[off:])
