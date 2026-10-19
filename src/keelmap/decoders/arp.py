"""ARP decoder: establishes which MAC owns which IPv4 address on the sensor's segment.

What counts as evidence:
  * The sender fields of a request, reply or announcement, but only when the
    ARP sender MAC equals the Ethernet source MAC. A mismatch means the frame
    was relayed, proxied or forged, so nothing is stored from it.
  * Sender IP 0.0.0.0 is an address-conflict probe (RFC 5227). The MAC is
    stored, the IP is not.

What is never evidence:
  * Target fields. A request asking "who has 10.0.0.5" proves nothing about
    10.0.0.5. The target becomes an asset only when it answers.

Known limitation: with proxy ARP, a router answers for addresses it does not
own. KeelMap then records that the router's MAC answered for those IPs, which
is literally what the traffic shows. A MAC holding many IPs is visible in the
output and should be reviewed.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import Counter

from keelmap.decoders.base import Frame, evidence_for
from keelmap.layers import ETH_ARP, is_host_ip, is_unicast_mac, mac_str, parse_link
from keelmap.model import EvidenceKind, Inventory

_OPS = {1: "request", 2: "reply"}


class ArpDecoder:
    name = "arp"
    version = "0.1.0"

    def __init__(self) -> None:
        self.stats: Counter[str] = Counter()

    @property
    def tag(self) -> str:
        return f"{self.name}@{self.version}"

    def handle(self, frame: Frame, inventory: Inventory) -> None:
        eth = parse_link(frame.linktype, frame.data)
        if eth is None or eth.ethertype != ETH_ARP:
            return
        p = eth.payload
        if len(p) < 28:
            self.stats["arp_malformed"] += 1
            return
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", p[:8])
        if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4):
            self.stats["arp_not_ethernet_ipv4"] += 1
            return
        if op not in _OPS:
            self.stats["arp_other_opcode"] += 1
            return
        sha, spa, tpa = p[8:14], p[14:18], p[24:28]
        if sha != eth.src:
            self.stats["arp_sender_mac_mismatch"] += 1
            return
        if not is_unicast_mac(sha):
            self.stats["arp_sender_not_unicast"] += 1
            return

        sender_mac = mac_str(sha)
        sender_ip = str(ipaddress.IPv4Address(spa))
        kind = "announcement" if spa == tpa else _OPS[op]
        asset = inventory.asset(f"mac:{sender_mac}")
        asset.macs.add(sender_mac, evidence_for(
            frame, EvidenceKind.OBSERVED, self.tag,
            f"ARP {kind} sender hardware address, equals Ethernet source"))

        if sender_ip == "0.0.0.0":
            self.stats["arp_probe_no_ip"] += 1
            return
        if not is_host_ip(sender_ip):
            self.stats["arp_sender_ip_not_host"] += 1
            return
        asset.ips.add(sender_ip, evidence_for(
            frame, EvidenceKind.OBSERVED, self.tag,
            f"ARP {kind} sender protocol address from {sender_mac}"))

    def finish(self, inventory: Inventory) -> None:
        return None
