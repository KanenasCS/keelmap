"""LLDP decoder (IEEE 802.1AB), including LLDP-MED inventory.

LLDP is a device describing itself, so almost everything here is self_reported.
The only observed facts are that the Ethernet source sent an LLDP frame.

Validation follows the 802.1AB receive rules: the first three TLVs must be
Chassis ID, Port ID and TTL, in that order, with sane lengths, or the whole
frame is discarded. A TLV that runs past the end of the frame discards it too.

Stored:
  * MAC (observed) and role lldp/advertiser (observed) for the Ethernet source.
  * System Name as hostname. System Description verbatim as description.
    The description is never parsed into vendor, model or version: free text
    like "Cisco IOS Software, C3560 Software ..., Version 12.2(44)SE" has no
    reliable structure, and a guess about which part is which is not evidence.
  * Enabled capabilities (bridge, router, ...) as capabilities. Capabilities the
    device merely supports but has not enabled are not stored.
  * Chassis ID (MAC or locally assigned) and management addresses as device_ids.
    A management address is a claim, so it is never used as evidence that the
    device owns that IP.
  * LLDP-MED inventory: manufacturer, model and firmware revision fill vendor,
    model and firmware. Serial number and asset id go to device_ids.
  * The RFC 8520 MUD URL, the maker's description of how the device should
    behave on a network, goes to device_ids.

Not stored: Port ID and Port Description (they describe the port facing the
sensor, not the device), LLDP-MED hardware and software revisions, and other
organisationally specific TLVs.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import Counter

from keelmap.decoders.base import Frame, evidence_for
from keelmap.layers import ETH_LLDP, LINKTYPE_ETHERNET, is_unicast_mac, mac_str, parse_ethernet
from keelmap.model import EvidenceKind, Inventory

_CAPABILITIES = ["other", "repeater", "bridge", "wlan_access_point", "router", "telephone",
                 "docsis_cable_device", "station_only", "cvlan_component", "svlan_component", "tpmr"]
_MED_OUI = b"\x00\x12\xbb"
_IANA_OUI = b"\x00\x00\x5e"
_MED_FIELDS = {6: ("firmware", "LLDP-MED Firmware Revision"), 9: ("device_vendor", "LLDP-MED Manufacturer Name"),
               10: ("device_model", "LLDP-MED Model Name")}
_MED_IDS = {8: ("serial", "LLDP-MED Serial Number"), 11: ("asset_id", "LLDP-MED Asset ID")}


def _text(raw: bytes, multiline: bool = False) -> str | None:
    try:
        s = raw.decode("utf-8").strip().rstrip("\x00").strip()
    except UnicodeDecodeError:
        return None
    if not s:
        return None
    check = s.replace("\r", "").replace("\n", "").replace("\t", "") if multiline else s
    return s if check.isprintable() else None


def parse_tlvs(payload: bytes) -> list[tuple[int, bytes]] | None:
    """Split an LLDPDU into TLVs. None if it breaks the 802.1AB structure rules."""
    tlvs, pos = [], 0
    while pos + 2 <= len(payload):
        (head,) = struct.unpack("!H", payload[pos:pos + 2])
        ttype, length = head >> 9, head & 0x1FF
        value = payload[pos + 2:pos + 2 + length]
        if len(value) < length:
            return None
        pos += 2 + length
        if ttype == 0:
            break
        tlvs.append((ttype, value))
    if len(tlvs) < 3 or [t for t, _ in tlvs[:3]] != [1, 2, 3]:
        return None
    if any(t in (1, 2, 3) for t, _ in tlvs[3:]):
        return None
    if not 2 <= len(tlvs[0][1]) <= 256 or not 2 <= len(tlvs[1][1]) <= 256 or len(tlvs[2][1]) != 2:
        return None
    return tlvs


class LldpDecoder:
    name = "lldp"
    version = "0.1.0"

    def __init__(self) -> None:
        self.stats: Counter[str] = Counter()

    @property
    def tag(self) -> str:
        return f"{self.name}@{self.version}"

    def handle(self, frame: Frame, inventory: Inventory) -> None:
        if frame.linktype != LINKTYPE_ETHERNET:
            return
        eth = parse_ethernet(frame.data)
        if eth is None or eth.ethertype != ETH_LLDP:
            return
        tlvs = parse_tlvs(eth.payload)
        if tlvs is None:
            self.stats["lldp_malformed_discarded"] += 1
            return
        if not is_unicast_mac(eth.src):
            self.stats["lldp_source_not_unicast"] += 1
            return

        mac = mac_str(eth.src)
        asset = inventory.asset(f"mac:{mac}")
        obs = evidence_for(frame, EvidenceKind.OBSERVED, self.tag, "LLDP frame Ethernet source")
        asset.macs.add(mac, obs)
        asset.roles.add("lldp/advertiser", obs)

        def said(what: str):
            return evidence_for(frame, EvidenceKind.SELF_REPORTED, self.tag, what)

        for ttype, value in tlvs:
            if ttype == 1:
                self._chassis(asset, value, said)
            elif ttype == 5:
                name = _text(value)
                if name:
                    asset.hostname.add(name, said("LLDP System Name TLV"))
                else:
                    self.stats["lldp_text_unreadable"] += 1
            elif ttype == 6:
                desc = _text(value, multiline=True)
                if desc:
                    asset.description.add(desc, said("LLDP System Description TLV, stored verbatim"))
                else:
                    self.stats["lldp_text_unreadable"] += 1
            elif ttype == 7:
                self._capabilities(asset, value, said)
            elif ttype == 8:
                self._management(asset, value, said)
            elif ttype == 127 and value[:3] == _MED_OUI and len(value) >= 4:
                self._med(asset, value[3], value[4:], said)
            elif ttype == 127 and value[:3] == _IANA_OUI and len(value) >= 5 and value[3] == 1:
                url = _text(value[4:])
                if url:
                    asset.device_ids.add(f"mud_url:{url}", said("LLDP IANA MUD URL TLV (RFC 8520)"))
                else:
                    self.stats["lldp_text_unreadable"] += 1

    def _chassis(self, asset, value: bytes, said) -> None:
        subtype, cid = value[0], value[1:]
        if subtype == 4 and len(cid) == 6:
            asset.device_ids.add(f"lldp_chassis_mac:{mac_str(cid)}", said("LLDP Chassis ID, MAC address subtype"))
        elif subtype == 7 and _text(cid):
            asset.device_ids.add(f"lldp_chassis_local:{_text(cid)}", said("LLDP Chassis ID, locally assigned subtype"))
        else:
            self.stats["lldp_chassis_id_subtype_not_stored"] += 1

    def _capabilities(self, asset, value: bytes, said) -> None:
        if len(value) != 4:
            self.stats["lldp_capabilities_malformed"] += 1
            return
        _supported, enabled = struct.unpack("!HH", value)
        for bit, name in enumerate(_CAPABILITIES):
            if enabled & (1 << bit):
                asset.capabilities.add(name, said(f"LLDP System Capabilities TLV, enabled bit {name}"))

    def _management(self, asset, value: bytes, said) -> None:
        if len(value) < 2:
            self.stats["lldp_management_address_malformed"] += 1
            return
        alen = value[0]                       # includes the subtype octet
        if not 2 <= alen <= 32 or len(value) < 1 + alen:
            self.stats["lldp_management_address_malformed"] += 1
            return
        family, addr = value[1], value[2:1 + alen]
        if family == 1 and len(addr) == 4:
            ip = str(ipaddress.IPv4Address(addr))
            asset.device_ids.add(f"lldp_management_ipv4:{ip}", said("LLDP Management Address TLV, IPv4"))
        elif family == 2 and len(addr) == 16:
            ip = str(ipaddress.IPv6Address(addr))
            asset.device_ids.add(f"lldp_management_ipv6:{ip}", said("LLDP Management Address TLV, IPv6"))
        else:
            self.stats["lldp_management_address_family_not_stored"] += 1

    def _med(self, asset, subtype: int, info: bytes, said) -> None:
        if subtype in _MED_FIELDS:
            field, what = _MED_FIELDS[subtype]
            text = _text(info)
            if text:
                getattr(asset, field).add(text, said(what))
            else:
                self.stats["lldp_text_unreadable"] += 1
        elif subtype in _MED_IDS:
            label, what = _MED_IDS[subtype]
            text = _text(info)
            if text:
                asset.device_ids.add(f"lldp_med_{label}:{text}", said(what))
            else:
                self.stats["lldp_text_unreadable"] += 1

    def finish(self, inventory: Inventory) -> None:
        return None
