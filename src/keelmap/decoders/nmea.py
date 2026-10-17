"""NMEA 0183 over UDP, including IEC 61162-450 and AIS.

Detection is by content, not port: NMEA over UDP has no fixed port. A sentence
counts only when it is well formed AND its checksum is valid. Sentences without
a checksum are counted and ignored, because structure alone is weak evidence.

What a talker id means: "GP" in $GPGGA says the sentence came from a GNSS
receiver, not that the network device is one. One IP sending GP, HE and SD
sentences is usually a multiplexer or gateway. So roles record exactly what
was sent: nmea0183/talker:gp, nmea0183/sentence:gpgga, nmea0183/proprietary:grm.
Manufacturer codes in proprietary sentences are not turned into vendors.

IEC 61162-450: datagrams starting with "UdPbC\\0" give role iec61162_450/sender
and iec61162_450/group:<address>:<port> for multicast destinations. The tag
block source ("s:") is the sender's own identifier, stored in device_ids.

AIS: !--VDM sentences describe vessels heard over radio. They are not assets
and are not inventoried, only counted. !--VDO sentences describe own ship, so
its MMSI, IMO, call sign and name are stored as sensitive vessel_identifiers,
self-reported by the source that emitted them.

UDP is one-way, so a destination address is not evidence of a receiver. No
communications are created from NMEA traffic.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from keelmap.decoders.ais import AisError, FragmentBuffer, dearmor, decode_identity
from keelmap.decoders.base import Frame
from keelmap.layers import (
    ETH_IPV4,
    LINKTYPE_ETHERNET,
    is_host_ip,
    mac_str,
    parse_ethernet,
    parse_ipv4,
    parse_udp,
)
from keelmap.model import Asset, Evidence, EvidenceKind, Inventory
from keelmap.resolve import IpResolver

_IEC450 = b"UdPbC\x00"
_IEC450_BINARY = b"RaUdP"
_SENTENCE = re.compile(r"^([$!])([A-Z][A-Z0-9]{2,9})(,[^*]*)?\*([0-9A-Fa-f]{2})$")
_NO_CHECKSUM = re.compile(r"^[$!][A-Z][A-Z0-9]{2,9},[^*]*$")
_TAG_BLOCK = re.compile(r"^\\([^\\*]*)\*([0-9A-Fa-f]{2})\\(.*)$")
_TAG_SOURCE = re.compile(r"^[A-Za-z0-9]{1,15}$")


def _checksum(body: str) -> int:
    c = 0
    for ch in body:
        c ^= ord(ch)
    return c


@dataclass
class _Source:
    staging: Asset
    ip: str
    eth_src: str
    frames_seen: set[int] = field(default_factory=set)


class NmeaDecoder:
    name = "nmea0183"
    version = "0.1.0"

    def __init__(self) -> None:
        self.stats: Counter[str] = Counter()
        self._sources: dict[tuple[str, str], _Source] = {}
        self._ais = FragmentBuffer()

    @property
    def tag(self) -> str:
        return f"{self.name}@{self.version}"

    def _ev(self, kind: EvidenceKind, frames: list[tuple[int, datetime, str]], detail: str) -> Evidence:
        frames = sorted(set(frames))
        return Evidence(kind, frames[0][2], tuple(f[0] for f in frames), frames[0][1], self.tag, detail)

    def handle(self, frame: Frame, inventory: Inventory) -> None:
        if frame.linktype != LINKTYPE_ETHERNET:
            return
        eth = parse_ethernet(frame.data)
        if eth is None or eth.ethertype != ETH_IPV4:
            return
        ip = parse_ipv4(eth.payload)
        if ip is None or ip.proto != 17 or ip.fragment:
            return
        udp = parse_udp(ip.payload)
        if udp is None or not udp.payload:
            return
        payload = udp.payload
        iec450 = payload.startswith(_IEC450)
        if payload.startswith(_IEC450_BINARY):
            self.stats["iec61162_450_binary_not_supported"] += 1
            return
        if iec450:
            payload = payload[len(_IEC450):]
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError:
            if iec450:
                self.stats["iec61162_450_not_ascii"] += 1
            return
        lines = [ln.strip("\r\n\x00") for ln in text.split("\n")]
        candidates = [ln for ln in lines if ln[:1] in ("$", "!", "\\")]
        if not candidates:
            return
        if not is_host_ip(ip.src):
            self.stats["nmea_source_ip_not_host"] += 1
            return

        ref = (frame.number, frame.timestamp, frame.source_sha256)
        src = None
        for line in candidates:
            parsed = self._parse_line(line)
            if parsed is None:
                continue
            tags, start, address, fields = parsed
            if src is None:
                src = self._source(ip.src, mac_str(eth.src))
                self._record_datagram(src, ref, ip, udp, iec450)
            self._record_sentence(src, ref, start, address, fields, tags, iec450, udp.sport)

    # parsing ------------------------------------------------------------------

    def _parse_line(self, line: str):
        tags: dict[str, str] = {}
        m = _TAG_BLOCK.match(line)
        if line.startswith("\\"):
            if not m:
                self.stats["nmea_tag_block_malformed"] += 1
                return None
            content, cks, line = m.group(1), m.group(2), m.group(3)
            if _checksum(content) != int(cks, 16):
                self.stats["nmea_tag_block_checksum_invalid"] += 1
                return None
            for item in content.split(","):
                k, _, v = item.partition(":")
                if k and v:
                    tags[k] = v
            if not line:
                return None   # tag block only, as in some grouped messages
        s = _SENTENCE.match(line)
        if not s:
            if _NO_CHECKSUM.match(line):
                self.stats["nmea_checksum_missing"] += 1
            else:
                self.stats["nmea_malformed"] += 1
            return None
        start, address, rest, cks = s.groups()
        if _checksum(address + (rest or "")) != int(cks, 16):
            self.stats["nmea_checksum_invalid"] += 1
            return None
        fields = (rest or "")[1:].split(",") if rest else []
        return tags, start, address, fields

    # recording ----------------------------------------------------------------

    def _source(self, ip: str, eth_src: str) -> _Source:
        key = (ip, eth_src)
        if key not in self._sources:
            self._sources[key] = _Source(Asset(f"ip:{ip}"), ip, eth_src)
        return self._sources[key]

    def _record_datagram(self, src: _Source, ref, ip, udp, iec450: bool) -> None:
        if ref[0] in src.frames_seen:
            return
        src.frames_seen.add(ref[0])
        a = src.staging
        a.ips.add(src.ip, self._ev(EvidenceKind.OBSERVED, [ref], "IP source of NMEA 0183 datagram with valid checksum"))
        if iec450:
            ev = self._ev(EvidenceKind.OBSERVED, [ref], "IEC 61162-450 UdPbC datagram")
            a.roles.add("iec61162_450/sender", ev)
            if ipaddress.IPv4Address(ip.dst).is_multicast:
                a.roles.add(f"iec61162_450/group:{ip.dst}:{udp.dport}", ev)

    def _record_sentence(self, src: _Source, ref, start, address, fields, tags, iec450, sport) -> None:
        a = src.staging
        if address.startswith("P"):
            mfr = address[1:4].lower()
            a.roles.add(f"nmea0183/proprietary:{mfr}", self._ev(
                EvidenceKind.OBSERVED, [ref], f"proprietary sentence ${address} with valid checksum"))
        else:
            talker, stype = address[:2].lower(), address[2:].lower()
            ev = self._ev(EvidenceKind.OBSERVED, [ref], f"{start}{address} sentence with valid checksum")
            a.roles.add(f"nmea0183/talker:{talker}", ev)
            a.roles.add(f"nmea0183/sentence:{talker}{stype}", ev)

        source_id = tags.get("s")
        if source_id is not None:
            if _TAG_SOURCE.match(source_id):
                label = "iec61162_450_sfi" if iec450 else "nmea_tag_source"
                a.device_ids.add(f"{label}:{source_id}", self._ev(
                    EvidenceKind.SELF_REPORTED, [ref], f"tag block s: field on {start}{address}"))
            else:
                self.stats["nmea_tag_source_invalid"] += 1

        if not address.startswith("P") and address[2:] in ("VDM", "VDO"):
            self._ais_sentence(src, ref, address, fields, sport)

    def _ais_sentence(self, src: _Source, ref, address: str, fields: list[str], sport: int) -> None:
        kind = address[2:]
        if len(fields) < 6:
            self.stats["ais_sentence_malformed"] += 1
            return
        try:
            done = self._ais.add((src.ip, src.eth_src, sport), kind, int(fields[0]), int(fields[1]),
                                 fields[2], fields[3], fields[4], int(fields[5] or 0), ref)
        except (AisError, ValueError):
            self.stats["ais_sentence_malformed"] += 1
            return
        if done is None:
            return
        payload, fill, refs = done
        try:
            ident = decode_identity(dearmor(payload, fill))
        except AisError:
            self.stats["ais_payload_invalid"] += 1
            return
        for reason in ident.rejected:
            self.stats[f"ais_{reason}"] += 1
        a = src.staging
        role_ev = self._ev(EvidenceKind.OBSERVED, refs, f"AIS {kind} type {ident.msg_type} message")
        a.roles.add(f"ais/{kind.lower()}", role_ev)
        if kind == "VDM":
            self.stats["ais_vdm_other_vessels_not_inventoried"] += 1
            return
        detail = f"AIS VDO own-ship type {ident.msg_type}"
        for label, value in (("mmsi", f"{ident.mmsi:09d}" if ident.mmsi is not None else None),
                             ("imo", str(ident.imo) if ident.imo is not None else None),
                             ("callsign", ident.callsign), ("name", ident.name)):
            if value is not None:
                a.vessel_identifiers.add(f"{label}:{value}", self._ev(
                    EvidenceKind.SELF_REPORTED, refs, f"{detail} {label}"))

    def finish(self, inventory: Inventory) -> None:
        incomplete = self._ais.close()
        if incomplete:
            self.stats["ais_fragments_incomplete"] += incomplete
        resolve = IpResolver(inventory, self.stats, "nmea0183")
        for src in self._sources.values():
            resolve(src.ip, src.eth_src).merge_from(src.staging)
        self._sources.clear()
