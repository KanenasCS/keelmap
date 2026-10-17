"""Turn an exported inventory into what the map shows.

All wording lives here, in Python, so it is tested. The page script only
places this data on screen with textContent, never as markup, because every
string here may come from network traffic.

Nothing is added that the inventory does not contain. Plain-language labels
translate roles and codes, they never upgrade them: "Answered Modbus requests"
not "PLC", "Sent sentences with talker id GP" not "GPS receiver".
"""

from __future__ import annotations

from typing import Any

MODBUS_FUNCTIONS = {
    1: "Read coils", 2: "Read discrete inputs", 3: "Read holding registers", 4: "Read input registers",
    5: "Write single coil", 6: "Write single register", 7: "Read exception status", 8: "Diagnostics",
    11: "Get comm event counter", 12: "Get comm event log", 15: "Write multiple coils",
    16: "Write multiple registers", 17: "Report server id", 20: "Read file record", 21: "Write file record",
    22: "Mask write register", 23: "Read and write multiple registers", 24: "Read FIFO queue",
    43: "Encapsulated interface transport",
}
MODBUS_WRITES = {5, 6, 15, 16, 21, 22, 23}
MODBUS_EXCEPTIONS = {
    1: "illegal function", 2: "illegal data address", 3: "illegal data value", 4: "server device failure",
    5: "acknowledge", 6: "server device busy", 8: "memory parity error", 10: "gateway path unavailable",
    11: "gateway target device failed to respond",
}

PROTOCOL_LABELS = {"modbus": "Modbus", "nmea0183": "NMEA 0183", "dhcp": "DHCP", "arp": "ARP"}

EVIDENCE_KINDS = {
    "observed": "Seen in traffic",
    "self_reported": "Stated by the device",
    "registry": "Public registry lookup",
}

# role prefix -> (activity label, how to show the value part)
_ROLE_GROUPS: list[tuple[str, str, str | None]] = [
    ("modbus/server", "Answered Modbus requests", None),
    ("modbus/gateway", "Returned Modbus gateway exceptions", None),
    ("modbus/unit_id:", "Answered as Modbus unit", "raw"),
    ("modbus/client", "Sent Modbus requests that were answered", None),
    ("ais/vdo", "Reported own-ship AIS data", None),
    ("ais/vdm", "Relayed AIS reports about other vessels", None),
    ("iec61162_450/sender", "Sent IEC 61162-450 datagrams", None),
    ("iec61162_450/group:", "Published to multicast group", "group"),
    ("nmea0183/talker:", "Sent NMEA sentences with talker id", "upper"),
    ("nmea0183/sentence:", "NMEA sentence types sent", "upper"),
    ("nmea0183/proprietary:", "Sent proprietary sentences with maker code", "upper"),
    ("dhcp/server", "Answered DHCP requests", None),
    ("lldp/advertiser", "Sent LLDP announcements", None),
    ("dhcp/client", "Requested an address over DHCP", None),
]

# kind, label for the legend, roles that select it (first match wins)
NODE_KINDS: list[tuple[str, str, tuple[str, ...]]] = [
    ("gateway", "Modbus gateway", ("modbus/gateway",)),
    ("server", "Modbus server", ("modbus/server",)),
    ("ais", "AIS source", ("ais/vdo", "ais/vdm")),
    ("navigation", "NMEA or IEC 61162-450 source", ("nmea0183/", "iec61162_450/sender")),
    ("client", "Modbus client", ("modbus/client",)),
    ("infrastructure", "DHCP server", ("dhcp/server",)),
    ("network", "Says it is a switch or router (LLDP)", ()),
    ("device", "Other device", ()),
]

CAPABILITY_LABELS = {
    "bridge": "Bridge (switch)", "router": "Router", "wlan_access_point": "Wireless access point",
    "repeater": "Repeater", "telephone": "Telephone", "docsis_cable_device": "Cable modem",
    "station_only": "End station only", "cvlan_component": "Customer VLAN component",
    "svlan_component": "Service VLAN component", "tpmr": "Two-port MAC relay", "other": "Other",
}

STAT_EXPLANATIONS = {
    "frames_without_timestamp": "Packets without a timestamp cannot be cited as evidence",
    "capture_truncated": "The capture file ends mid-packet",
    "capture_duplicate_skipped": "The same capture file was given twice",
    "arp_sender_mac_mismatch": "ARP sender differs from the Ethernet source, possibly relayed or forged",
    "arp_probe_no_ip": "Address-conflict probes, the device has no address yet",
    "dhcp_relayed_skipped": "DHCP through a relay, addresses belong to the relay path",
    "modbus_request_unanswered": "Modbus requests with no reply in the capture",
    "modbus_response_unpaired": "Modbus replies whose request is not in the capture",
    "modbus_port_502_not_mbap": "Traffic on port 502 that is not Modbus",
    "modbus_device_id_not_attributed_unit": "Device identity for a unit that may sit behind a gateway",
    "modbus_adu_split_across_segments": "Modbus messages split across packets, not reassembled",
    "nmea_checksum_invalid": "NMEA sentences with a wrong checksum",
    "nmea_checksum_missing": "NMEA sentences without a checksum",
    "ais_vdm_other_vessels_not_inventoried": "AIS reports about other vessels, which are not assets here",
    "ais_payload_invalid": "AIS messages that could not be decoded",
    "ais_fragments_incomplete": "Multi-part AIS messages with parts missing or out of order",
    "ais_imo_check_digit_failed": "IMO numbers with a wrong check digit",
}


def _evidence(ev_list: list[dict], multi_source: bool) -> list[dict]:
    out = []
    for e in ev_list:
        item = {
            "frames": e["frames"],
            "kind": EVIDENCE_KINDS.get(e["kind"], e["kind"]),
            "detail": e["detail"],
            "decoder": e["decoder"],
            "time": e["timestamp"],
        }
        if multi_source:
            item["source"] = e["source_sha256"][:12]
        out.append(item)
    return out


def _item(value: Any, member: dict, multi: bool) -> dict:
    return {"value": value, "count": member["evidence_count"], "evidence": _evidence(member["evidence"], multi)}


def _role_activity(role: str) -> tuple[str, str | None]:
    """Map one role to (activity label, value shown under it)."""
    for prefix, label, how in _ROLE_GROUPS:
        if role == prefix or (prefix.endswith(":") and role.startswith(prefix)):
            rest = role[len(prefix):]
            if how == "upper":
                return label, rest.upper()
            if how == "group":
                addr, _, port = rest.rpartition(":")
                return label, f"{addr} port {port}"
            if how == "raw":
                return label, rest
            return label, None
    return "Other observed role", role


def _activities(roles: list[dict], multi: bool) -> list[dict]:
    groups: dict[str, dict] = {}
    order = {label: i for i, (_, label, _) in enumerate(_ROLE_GROUPS)}
    for m in roles:
        label, value = _role_activity(m["value"])
        groups.setdefault(label, {"label": label, "items": []})["items"].append(_item(value, m, multi))
    return sorted(groups.values(), key=lambda g: order.get(g["label"], len(order)))


def _kind(role_values: list[str], capabilities: list[str]) -> str:
    """Observed roles decide first. A self-stated switch or router only shapes the
    symbol when nothing was observed that says more."""
    for kind, _, selectors in NODE_KINDS:
        if selectors and any(r == s or r.startswith(s) for r in role_values for s in selectors):
            return kind
    if {"bridge", "router"} & set(capabilities):
        return "network"
    return "device"


def _field(label: str, inline: str, f: dict, multi: bool, single: bool) -> dict:
    if single:
        items = [_item(c["value"], c, multi) for c in f.get("claims", [])]
    else:
        items = [_item(m["value"], m, multi) for m in f.get("members", [])]
    return {"label": label, "inline": inline, "state": f["state"], "items": items}


def _label(a: dict) -> str:
    if a["hostname"]["state"] == "known":
        return str(a["hostname"]["value"])
    for field in ("ips", "macs"):
        if a[field]["members"]:
            return str(a[field]["members"][0]["value"])
    return a["identity_key"]


def _operation(value: str) -> dict:
    """modbus/fc:16:exception:02 -> readable parts."""
    proto, _, rest = value.partition("/")
    parts = rest.split(":")
    out = {"raw": value, "text": value, "write": False, "rejected": False}
    if proto == "modbus" and len(parts) >= 2 and parts[0] == "fc" and parts[1].isdigit():
        fc = int(parts[1])
        name = MODBUS_FUNCTIONS.get(fc, "Undefined function")
        text = f"FC{fc:02d} {name}"
        if len(parts) == 4 and parts[2] == "exception" and parts[3].isdigit():
            exc = int(parts[3])
            text += f", rejected with {MODBUS_EXCEPTIONS.get(exc, f'exception {exc}')}"
            out["rejected"] = True
        out.update(text=text, write=fc in MODBUS_WRITES)
    return out


def build_view(inv: dict) -> dict:
    multi = len(inv["sources"]) > 1
    nodes, edges, groups = [], [], {}
    for a in inv["assets"]:
        roles = a["roles"]["members"]
        role_values = [m["value"] for m in roles]
        empty_single = {"state": "unknown", "claims": []}
        empty_set = {"state": "unknown", "members": []}
        caps_field = a.get("capabilities", empty_set)
        cap_values = [m["value"] for m in caps_field["members"]]
        caps_view = dict(caps_field, members=[dict(m, value=CAPABILITY_LABELS.get(m["value"], m["value"]))
                                               for m in caps_field["members"]])
        nodes.append({
            "id": a["asset_id"],
            "label": _label(a),
            "kind": _kind(role_values, cap_values),
            "identity": a["identity_key"],
            "first_seen": a["first_seen"],
            "last_seen": a["last_seen"],
            "search": " ".join([_label(a), a["identity_key"]] + [str(m["value"]) for m in a["ips"]["members"]]
                               + [str(m["value"]) for m in a["macs"]["members"]] + role_values).lower(),
            "activities": _activities(roles, multi),
            "about": [
                _field("Hostname", "hostname", a["hostname"], multi, True),
                _field("Vendor", "vendor", a["device_vendor"], multi, True),
                _field("Model", "model", a["device_model"], multi, True),
                _field("Firmware", "firmware", a["firmware"], multi, True),
                _field("Description, as sent", "description", a.get("description", empty_single), multi, True),
                _field("Enabled capabilities", "capabilities", caps_view, multi, False),
                _field("Device identifiers", "device identifiers", a.get("device_ids", empty_set), multi, False),
                _field("Vessel identifiers", "vessel identifiers", a["vessel_identifiers"], multi, False),
            ],
            "addresses": [
                _field("IP addresses", "IP addresses", a["ips"], multi, False),
                _field("MAC addresses", "MAC addresses", a["macs"], multi, False),
                _field("Network card maker", "network card maker", a["nic_vendor"], multi, True),
            ],
        })
        for m in roles:
            if m["value"].startswith("iec61162_450/group:"):
                rest = m["value"][len("iec61162_450/group:"):]
                gid = "group:" + rest
                addr, _, port = rest.rpartition(":")
                groups.setdefault(gid, {"id": gid, "label": f"{addr} port {port}", "kind": "group", "width": 0,
                                        "publishers": []})["publishers"].append(a["asset_id"])
                edges.append({"id": f"{a['asset_id']}>{gid}", "source": a["asset_id"], "target": gid,
                              "kind": "publish", "count": m["evidence_count"],
                              "evidence": _evidence(m["evidence"], multi)})

    for c in inv["communications"]:
        ops = [dict(_operation(m["value"]), count=m["evidence_count"],
                    evidence=_evidence(m["evidence"], multi)) for m in c["operations"]["members"]]
        writes = sum(o["count"] for o in ops if o["write"] and not o["rejected"])
        rejected_writes = sum(o["count"] for o in ops if o["write"] and o["rejected"])
        edges.append({
            "id": f"{c['src_asset_id']}>{c['dst_asset_id']}/{c['protocol']}/{c['dst_port']}",
            "source": c["src_asset_id"], "target": c["dst_asset_id"], "kind": "communication",
            "protocol": PROTOCOL_LABELS.get(c["protocol"], c["protocol"]),
            "transport": c["transport"], "port": c["dst_port"],
            "count": c["exchange_count"], "packets": c["packet_count"],
            "first_seen": c["first_seen"], "last_seen": c["last_seen"],
            "writes": writes, "rejected_writes": rejected_writes,
            "operations": sorted(ops, key=lambda o: (-o["count"], o["raw"])),
            "evidence": _evidence(c["evidence_sample"], multi),
        })

    stats = inv.get("stats", {})
    gaps = [{"key": k, "count": v, "text": STAT_EXPLANATIONS.get(k)}
            for k, v in sorted(stats.items(), key=lambda kv: (-kv[1], kv[0])) if k != "frames_read"]
    return {
        "schema_version": inv["schema_version"],
        "tool_version": inv["tool_version"],
        "redacted": inv["redacted"],
        "frames_read": stats.get("frames_read", 0),
        "sources": inv["sources"],
        "nodes": nodes,
        "groups": list(groups.values()),
        "edges": edges,
        "gaps": gaps,
        "kinds": [{"kind": k, "label": label} for k, label, _ in NODE_KINDS],
    }
