"""Modbus/TCP decoder (port 502).

Pairing is the proof. A request alone, or a response alone, stores nothing.
Only a request and a response on the same TCP connection, with the same
transaction id and unit id and a matching function code, show that both
sides really speak Modbus. Port 502 alone proves nothing: other protocols use it.

Stored from each pair:
  * Client role modbus/client (its request was answered).
  * Server role modbus/server (it answered), plus modbus/unit_id:<n> for the
    unit id it answered as. This does not prove separate devices exist behind it.
  * Server role modbus/gateway when it returns exception 10 or 11. The
    specification reserves those codes for gateways.
  * A client to server communication with operations such as modbus/fc:03
    or modbus/fc:16:exception:02.
  * Device identification (FC 43, MEI 14) as self-reported vendor, model and
    firmware, but only when addressed to unit 0 or 255. Those address the TCP
    device itself. Any other unit id may be a serial device behind a gateway,
    so the identity is not attached to the TCP endpoint.

IP to asset: resolved after all frames are read. An IP joins an existing
MAC-identity asset only if exactly one such asset has ARP or DHCP evidence for
that IP AND the Modbus frame's Ethernet source is that same MAC. Otherwise
the endpoint becomes an ip:<address> asset.

Transaction ids: a repeated id with the same TCP sequence number is a
retransmission and the original frame is kept. A repeated id with a new
sequence number is a new request, and the older one counts as unanswered.

Not handled in 0.1, and counted: Modbus on other ports is not detected at all.
ADUs split across TCP segments are counted and skipped.
"""

from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from keelmap.decoders.base import Frame
from keelmap.layers import (
    ETH_IPV4,
    LINKTYPE_ETHERNET,
    mac_str,
    parse_ethernet,
    parse_ipv4,
    parse_tcp,
)
from keelmap.model import Asset, Evidence, EvidenceKind, Inventory
from keelmap.resolve import IpResolver

PORT = 502
_DEVICE_UNITS = {0, 255}
_GATEWAY_EXCEPTIONS = {10, 11}
_OBJ_VENDOR, _OBJ_PRODUCT_CODE, _OBJ_REVISION, _OBJ_MODEL = 0x00, 0x01, 0x02, 0x05
_OBJ_NAMES = {0x00: "VendorName", 0x01: "ProductCode", 0x02: "MajorMinorRevision", 0x05: "ModelName"}


@dataclass(frozen=True)
class _Seen:
    number: int
    ts: datetime
    sha: str
    eth_src: str


@dataclass(frozen=True)
class _Request:
    seen: _Seen
    tid: int
    unit: int
    fc: int
    pdu: bytes
    tcp_seq: int


@dataclass(frozen=True)
class _Pair:
    req: _Request
    resp: _Seen
    client_ip: str
    server_ip: str
    exception: int | None
    device_id: dict[int, str] | None


def _split_adus(payload: bytes) -> tuple[list[tuple[int, int, bytes]], str | None] | None:
    """Return (adus, problem). None if the segment does not start with a valid MBAP header."""
    adus: list[tuple[int, int, bytes]] = []
    pos = 0
    while pos < len(payload):
        if len(payload) - pos < 7:
            return (adus, "split") if adus else None
        tid, pid, length, unit = struct.unpack("!HHHB", payload[pos:pos + 7])
        if pid != 0 or not 2 <= length <= 254:
            return (adus, "trailing") if adus else None
        end = pos + 6 + length
        if end > len(payload):
            return adus, "split"
        adus.append((tid, unit, payload[pos + 7:end]))
        pos = end
    return adus, None


def _device_id(pdu: bytes) -> dict[int, str] | None:
    """Parse a Read Device Identification response. None if malformed."""
    if len(pdu) < 7 or pdu[0] != 0x2B or pdu[1] != 0x0E:
        return None
    count, pos, out = pdu[6], 7, {}
    for _ in range(count):
        if pos + 2 > len(pdu):
            return None
        oid, length = pdu[pos], pdu[pos + 1]
        raw = pdu[pos + 2:pos + 2 + length]
        if len(raw) < length:
            return None
        try:
            text = raw.decode("ascii").strip().rstrip("\x00")
        except UnicodeDecodeError:
            text = ""
        if text and text.isprintable():
            out[oid] = text
        pos += 2 + length
    return out


class ModbusDecoder:
    name = "modbus"
    version = "0.1.0"

    def __init__(self) -> None:
        self.stats: Counter[str] = Counter()
        self._pending: dict[tuple, _Request] = {}
        self._pairs: list[_Pair] = []

    @property
    def tag(self) -> str:
        return f"{self.name}@{self.version}"

    def handle(self, frame: Frame, inventory: Inventory) -> None:
        if frame.linktype != LINKTYPE_ETHERNET:
            return
        eth = parse_ethernet(frame.data)
        if eth is None or eth.ethertype != ETH_IPV4:
            return
        ip = parse_ipv4(eth.payload)
        if ip is None or ip.proto != 6:
            return
        tcp = parse_tcp(ip.payload)
        if tcp is None or PORT not in (tcp.sport, tcp.dport):
            return
        if ip.fragment:
            self.stats["modbus_ip_fragment_skipped"] += 1
            return
        if not tcp.payload:
            return
        if tcp.sport == tcp.dport:
            self.stats["modbus_both_ports_502_skipped"] += 1
            return
        is_request = tcp.dport == PORT
        parsed = _split_adus(tcp.payload)
        if parsed is None:
            self.stats["modbus_port_502_not_mbap"] += 1
            return
        adus, problem = parsed
        if problem == "split":
            self.stats["modbus_adu_split_across_segments"] += 1
        elif problem == "trailing":
            self.stats["modbus_trailing_bytes"] += 1

        seen = _Seen(frame.number, frame.timestamp, frame.source_sha256, mac_str(eth.src))
        if is_request:
            conn = (frame.source_sha256, ip.src, tcp.sport, ip.dst)
        else:
            conn = (frame.source_sha256, ip.dst, tcp.dport, ip.src)

        for tid, unit, pdu in adus:
            key = conn + (tid,)
            fc = pdu[0]
            if is_request:
                if fc & 0x80:
                    # Undefined codes such as 0 are kept: a correct "illegal function"
                    # exception reply still proves a real Modbus exchange.
                    self.stats["modbus_request_exception_bit_set"] += 1
                elif key in self._pending and self._pending[key].tcp_seq == tcp.seq:
                    # TCP retransmission of the same request: keep the original frame.
                    self.stats["modbus_request_retransmitted"] += 1
                else:
                    if key in self._pending:
                        # Same transaction id reused for a new request. Many simple clients
                        # always send id 0. The older request was never answered.
                        self.stats["modbus_request_unanswered"] += 1
                    self._pending[key] = _Request(seen, tid, unit, fc, pdu, tcp.seq)
                continue

            req = self._pending.get(key)
            if req is None:
                self.stats["modbus_response_unpaired"] += 1
                continue
            if unit != req.unit or (fc & 0x7F) != req.fc:
                self.stats["modbus_response_mismatch"] += 1
                continue
            del self._pending[key]
            exception = None
            if fc & 0x80:
                if len(pdu) < 2:
                    self.stats["modbus_exception_malformed"] += 1
                    continue
                exception = pdu[1]
            dev = None
            if req.fc == 0x2B and req.pdu[1:2] == b"\x0e" and exception is None:
                dev = _device_id(pdu)
                if dev is None:
                    self.stats["modbus_device_id_malformed"] += 1
                elif not dev:
                    self.stats["modbus_device_id_empty"] += 1
            self._pairs.append(_Pair(req, seen, conn[1], conn[3], exception, dev))

    # resolution -------------------------------------------------------------------

    def _endpoint(self, resolve: IpResolver, ip: str, seen: _Seen, what: str) -> Asset:
        asset = resolve(ip, seen.eth_src)
        if asset.identity_key.startswith("ip:"):
            asset.ips.add(ip, Evidence(EvidenceKind.OBSERVED, seen.sha, (seen.number,), seen.ts, self.tag,
                                       f"IP source of Modbus {what}"))
        return asset

    def finish(self, inventory: Inventory) -> None:
        if self._pending:
            self.stats["modbus_request_unanswered"] += len(self._pending)
        self._pending.clear()
        resolve = IpResolver(inventory, self.stats, "modbus")
        for p in self._pairs:
            r, s = p.req, p.resp
            fc = r.fc
            exc = f" exception {p.exception}" if p.exception is not None else ""
            tx = f"transaction {r.tid}, unit {r.unit}"
            client = self._endpoint(resolve, p.client_ip, r.seen, "request")
            server = self._endpoint(resolve, p.server_ip, s, "response")

            req_ev = Evidence(EvidenceKind.OBSERVED, s.sha, (r.seen.number,), r.seen.ts, self.tag,
                              f"Modbus FC{fc:02d} request, {tx}, answered in frame {s.number}")
            resp_ev = Evidence(EvidenceKind.OBSERVED, s.sha, (s.number,), s.ts, self.tag,
                               f"Modbus FC{fc:02d} response{exc}, {tx}, to request in frame {r.seen.number}")
            pair_ev = Evidence(EvidenceKind.OBSERVED, s.sha, (r.seen.number, s.number), r.seen.ts, self.tag,
                               f"Modbus FC{fc:02d} request and response{exc}, {tx}")

            client.roles.add("modbus/client", req_ev)
            server.roles.add("modbus/server", resp_ev)
            if p.exception in _GATEWAY_EXCEPTIONS:
                server.roles.add("modbus/gateway", resp_ev)
            else:
                server.roles.add(f"modbus/unit_id:{r.unit}", resp_ev)

            comm = inventory.communication(client, server, "tcp", "modbus", PORT)
            comm.record(pair_ev)
            op = f"modbus/fc:{fc:02d}" + (f":exception:{p.exception:02d}" if p.exception is not None else "")
            comm.operations.add(op, pair_ev)

            if p.device_id:
                if r.unit not in _DEVICE_UNITS:
                    self.stats["modbus_device_id_not_attributed_unit"] += 1
                else:
                    self._identity(server, p.device_id, s, r.unit)
        self._pairs.clear()

    def _identity(self, asset: Asset, objs: dict[int, str], s: _Seen, unit: int) -> None:
        def ev(oid: int) -> Evidence:
            return Evidence(EvidenceKind.SELF_REPORTED, s.sha, (s.number,), s.ts, self.tag,
                            f"Modbus FC43 MEI 14 object {oid:#04x} {_OBJ_NAMES[oid]}, unit {unit}")
        if _OBJ_VENDOR in objs:
            asset.device_vendor.add(objs[_OBJ_VENDOR], ev(_OBJ_VENDOR))
        model_oid = _OBJ_MODEL if _OBJ_MODEL in objs else _OBJ_PRODUCT_CODE if _OBJ_PRODUCT_CODE in objs else None
        if model_oid is not None:
            asset.device_model.add(objs[model_oid], ev(model_oid))
        if _OBJ_REVISION in objs:
            asset.firmware.add(objs[_OBJ_REVISION], ev(_OBJ_REVISION))
