"""DHCP decoder: client and server roles, hostnames, and bound client addresses.

Only messages with giaddr 0.0.0.0 are used. A relayed message means the
Ethernet addresses belong to the relay path, not to the client or server.

Client messages (DISCOVER, REQUEST, DECLINE, RELEASE, INFORM):
  * Require Ethernet source == chaddr, then store the MAC and role dhcp/client.
  * Option 12 hostname is the client describing itself: self_reported.
  * The client IP is stored only when the packet is sent FROM that IP and it
    equals ciaddr, which happens when a bound client renews or informs.

Server messages (OFFER, ACK, NAK):
  * The Ethernet source answered a client, so it gets role dhcp/server.
  * Its IP is stored only when IP source equals option 54 (server identifier).

Deliberately not stored:
  * yiaddr from an ACK. It proves a lease was granted, not that the client uses it.
  * Option 50 (requested IP). A request is not use.
  * Option 60 (vendor class). It names the DHCP client software, such as
    "MSFT 5.0" or "udhcp 1.30", not the device maker.
  * Hostnames from server messages. Only the client can name itself.
"""

from __future__ import annotations

import ipaddress
from collections import Counter

from keelmap.decoders.base import Frame, evidence_for
from keelmap.layers import (
    ETH_IPV4,
    is_host_ip,
    is_unicast_mac,
    mac_str,
    parse_ipv4,
    parse_link,
    parse_udp,
)
from keelmap.model import EvidenceKind, Inventory

_COOKIE = b"\x63\x82\x53\x63"
_CLIENT_TYPES = {1: "DISCOVER", 3: "REQUEST", 4: "DECLINE", 7: "RELEASE", 8: "INFORM"}
_SERVER_TYPES = {2: "OFFER", 5: "ACK", 6: "NAK"}


def _options(data: bytes) -> dict[int, bytes] | None:
    opts: dict[int, bytes] = {}
    pos = 0
    while pos < len(data):
        code = data[pos]
        if code == 0:
            pos += 1
            continue
        if code == 255:
            return opts
        if pos + 2 > len(data):
            return None
        length = data[pos + 1]
        val = data[pos + 2:pos + 2 + length]
        if len(val) < length:
            return None
        opts[code] = opts.get(code, b"") + val  # RFC 3396 concatenation
        pos += 2 + length
    return opts


def _hostname(raw: bytes) -> str | None:
    text = raw.rstrip(b"\x00")
    try:
        name = text.decode("ascii")
    except UnicodeDecodeError:
        return None
    return name if name and name.isprintable() and not name.isspace() else None


class DhcpDecoder:
    name = "dhcp"
    version = "0.1.0"

    def __init__(self) -> None:
        self.stats: Counter[str] = Counter()

    @property
    def tag(self) -> str:
        return f"{self.name}@{self.version}"

    def handle(self, frame: Frame, inventory: Inventory) -> None:
        eth = parse_link(frame.linktype, frame.data)
        if eth is None or eth.ethertype != ETH_IPV4:
            return
        ip = parse_ipv4(eth.payload)
        if ip is None or ip.proto != 17:
            return
        udp = parse_udp(ip.payload)
        if udp is None or {udp.sport, udp.dport} != {67, 68}:
            return
        if ip.fragment:
            self.stats["dhcp_fragmented"] += 1
            return
        b = udp.payload
        if len(b) < 240 or b[236:240] != _COOKIE:
            self.stats["dhcp_malformed"] += 1
            return
        op, htype, hlen = b[0], b[1], b[2]
        ciaddr = str(ipaddress.IPv4Address(b[12:16]))
        giaddr = b[24:28]
        chaddr = b[28:34]
        opts = _options(b[240:])
        if opts is None:
            self.stats["dhcp_malformed"] += 1
            return
        if 52 in opts:
            self.stats["dhcp_option_overload_not_supported"] += 1
        mtype_raw = opts.get(53)
        if not mtype_raw:
            self.stats["bootp_without_dhcp_type"] += 1
            return
        mtype = mtype_raw[0]
        if giaddr != b"\x00\x00\x00\x00":
            self.stats["dhcp_relayed_skipped"] += 1
            return
        if not is_unicast_mac(eth.src):
            self.stats["dhcp_source_not_unicast"] += 1
            return

        if op == 1 and mtype in _CLIENT_TYPES:
            self._client(frame, inventory, eth.src, ip.src, ciaddr, htype, hlen, chaddr, opts,
                         _CLIENT_TYPES[mtype])
        elif op == 2 and mtype in _SERVER_TYPES:
            self._server(frame, inventory, eth.src, ip.src, opts, _SERVER_TYPES[mtype])
        else:
            self.stats["dhcp_other_type"] += 1

    def _client(self, frame, inventory, eth_src, ip_src, ciaddr, htype, hlen, chaddr, opts, name):
        if htype != 1 or hlen != 6 or chaddr != eth_src:
            self.stats["dhcp_chaddr_mismatch"] += 1
            return
        mac = mac_str(chaddr)
        asset = inventory.asset(f"mac:{mac}")
        obs = evidence_for(frame, EvidenceKind.OBSERVED, self.tag,
                           f"DHCP {name} from {mac}, chaddr equals Ethernet source")
        asset.macs.add(mac, obs)
        asset.roles.add("dhcp/client", obs)

        if 12 in opts:
            hostname = _hostname(opts[12])
            if hostname is None:
                self.stats["dhcp_hostname_unreadable"] += 1
            else:
                asset.hostname.add(hostname, evidence_for(
                    frame, EvidenceKind.SELF_REPORTED, self.tag, f"DHCP {name} option 12 host name"))

        if ciaddr != "0.0.0.0" and ip_src == ciaddr and is_host_ip(ciaddr):
            asset.ips.add(ciaddr, evidence_for(
                frame, EvidenceKind.OBSERVED, self.tag,
                f"DHCP {name} sent from bound address, IP source equals ciaddr"))

    def _server(self, frame, inventory, eth_src, ip_src, opts, name):
        mac = mac_str(eth_src)
        asset = inventory.asset(f"mac:{mac}")
        obs = evidence_for(frame, EvidenceKind.OBSERVED, self.tag,
                           f"DHCP {name} sent by {mac}, giaddr 0.0.0.0")
        asset.macs.add(mac, obs)
        asset.roles.add("dhcp/server", obs)

        sid = opts.get(54)
        if sid and len(sid) == 4 and str(ipaddress.IPv4Address(sid)) == ip_src and is_host_ip(ip_src):
            asset.ips.add(ip_src, evidence_for(
                frame, EvidenceKind.OBSERVED, self.tag,
                f"DHCP {name} IP source equals option 54 server identifier"))
        else:
            self.stats["dhcp_server_id_mismatch"] += 1

    def finish(self, inventory: Inventory) -> None:
        return None
