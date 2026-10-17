"""Map tests: wording stays faithful to the inventory, and output is safe to open."""

import base64
import hashlib
import json
import re

import pytest
from pcapgen import BCAST, arp, ether, ipv4_tcp, mbap, ts, write_pcap

from keelmap.__main__ import main
from keelmap.report import render as render_mod
from keelmap.report.render import render_html, safe_json
from keelmap.report.view import _operation, build_view
from keelmap.scan import scan

EVIL = '<img src=x onerror=alert(1)></script><script>alert(2)</script>{{APP}}\u2028'


def modbus_capture(tmp_path, write=True):
    hmi, plc = "00:0e:8c:00:00:09", "00:1d:9c:00:00:05"
    fc = bytes([0x06, 0, 1, 0, 7]) if write else bytes([0x03, 0, 0, 0, 1])
    rsp = fc if write else bytes([0x03, 2, 0, 7])
    frames = [
        ether(plc, hmi, 0x0800, ipv4_tcp("10.0.0.9", "10.0.0.5", 40000, 502, mbap(1, 1, fc))),
        ether(hmi, plc, 0x0800, ipv4_tcp("10.0.0.5", "10.0.0.9", 502, 40000, mbap(1, 1, rsp))),
    ]
    p = tmp_path / "m.pcap"
    write_pcap(p, [(ts(1_700_000_000 + i), f) for i, f in enumerate(frames)])
    return scan([p]).to_dict()


def poison(inv):
    a = inv["assets"][0]
    ev = {"kind": "self_reported", "source_sha256": "a" * 64, "frames": [1], "timestamp": "2023-11-14T22:13:20+00:00",
          "decoder": "dhcp@0.1.0", "detail": EVIL}
    claim = {"value": EVIL, "evidence_count": 1, "evidence": [ev]}
    a["hostname"] = {"state": "known", "value": EVIL, "claims": [claim]}
    a["roles"]["members"].append({"value": "nmea0183/talker:" + EVIL, "evidence_count": 1, "evidence": [ev]})
    return inv


# --- wording ---------------------------------------------------------------------

def test_roles_become_plain_language_without_upgrades(tmp_path):
    view = build_view(modbus_capture(tmp_path))
    server = next(n for n in view["nodes"] if n["identity"] == "ip:10.0.0.5")
    labels = [a["label"] for a in server["activities"]]
    assert labels == ["Answered Modbus requests", "Answered as Modbus unit"]
    assert server["kind"] == "server"
    assert "PLC" not in json.dumps(view)


def test_unknown_fields_stay_unknown(tmp_path):
    view = build_view(modbus_capture(tmp_path))
    server = next(n for n in view["nodes"] if n["identity"] == "ip:10.0.0.5")
    assert all(f["items"] == [] for f in server["about"])


def test_write_classification(tmp_path):
    edge = build_view(modbus_capture(tmp_path))["edges"][0]
    assert edge["writes"] == 1 and edge["protocol"] == "Modbus"
    assert edge["operations"][0]["text"] == "FC06 Write single register"
    reads = build_view(modbus_capture(tmp_path, write=False))["edges"][0]
    assert reads["writes"] == 0 and reads["rejected_writes"] == 0


@pytest.mark.parametrize("raw,text,write,rejected", [
    ("modbus/fc:16", "FC16 Write multiple registers", True, False),
    ("modbus/fc:16:exception:02", "FC16 Write multiple registers, rejected with illegal data address", True, True),
    ("modbus/fc:03:exception:10", "FC03 Read holding registers, rejected with gateway path unavailable", False, True),
    ("modbus/fc:99", "FC99 Undefined function", False, False),
    ("other/thing", "other/thing", False, False),
])
def test_operation_text(raw, text, write, rejected):
    o = _operation(raw)
    assert (o["text"], o["write"], o["rejected"]) == (text, write, rejected)


SET_FIELDS = ("ips", "macs", "device_ids", "vessel_identifiers")
SINGLE_FIELDS = ("hostname", "device_vendor", "device_model", "firmware", "nic_vendor")
TALKER_GP = {"value": "nmea0183/talker:gp", "evidence_count": 1, "evidence": []}


def test_talker_ids_are_not_turned_into_device_types():
    inv = {"schema_version": "0.1.0", "tool_version": "0.1.0", "redacted": True, "sources": [], "stats": {},
           "communications": [], "assets": [{
               "asset_id": "x", "identity_key": "ip:10.0.1.20", "first_seen": None, "last_seen": None,
               **{k: {"state": "unknown", "members": []} for k in SET_FIELDS},
               **{k: {"state": "unknown", "claims": []} for k in SINGLE_FIELDS},
               "roles": {"state": "known", "members": [TALKER_GP]}}]}
    node = build_view(inv)["nodes"][0]
    assert node["kind"] == "navigation"
    assert node["activities"][0] == {"label": "Sent NMEA sentences with talker id",
                                     "items": [{"value": "GP", "count": 1, "evidence": []}]}
    assert "GPS" not in json.dumps(node)


# --- safety ----------------------------------------------------------------------

def test_hostile_strings_cannot_break_out(tmp_path):
    html = render_html(poison(modbus_capture(tmp_path)))
    data = html.split('<script id="keelmap-data" type="application/json">')[1].split("</script>")[0]
    assert "<" not in data and ">" not in data and "\u2028" not in data
    assert "</script><script>alert" not in html
    assert "{{APP}}" in data          # stayed literal, was never substituted
    assert html.count("<script") == 3
    assert json.loads(data)["nodes"][0]["label"] == EVIL   # round-trips exactly


def test_csp_hashes_match_scripts(tmp_path):
    html = render_html(modbus_capture(tmp_path))
    csp = re.search(r'Content-Security-Policy" content="([^"]+)"', html).group(1)
    assert "default-src 'none'" in csp and "connect-src 'none'" in csp
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert len(scripts) == 2
    for code in scripts:
        h = base64.b64encode(hashlib.sha256(code.encode()).digest()).decode()
        assert f"'sha256-{h}'" in csp
    assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]


def test_tampered_vendor_file_is_refused(tmp_path, monkeypatch):
    real = render_mod._read
    monkeypatch.setattr(render_mod, "_read", lambda n: real(n) + "/*x*/" if n.endswith("cytoscape.min.js") else real(n))
    with pytest.raises(RuntimeError):
        render_html(modbus_capture(tmp_path))


def test_safe_json_escapes():
    assert safe_json({"a": "</script>&\u2029"}) == '{"a":"\\u003c/script\\u003e\\u0026\\u2029"}'


def test_no_external_references(tmp_path):
    html = render_html(modbus_capture(tmp_path))
    assert not re.search(r'(src|href)="(https?:)?//', html)


# --- CLI -------------------------------------------------------------------------

def arp_frame():
    plc = "00:1d:9c:00:00:05"
    return ether(BCAST, plc, 0x0806, arp(1, plc, "10.0.0.5", "00:00:00:00:00:00", "10.0.0.1"))

def test_scan_with_map_and_map_command(tmp_path):
    p = tmp_path / "a.pcap"
    write_pcap(p, [(ts(1_700_000_000), arp_frame())])
    assert main(["scan", str(p), "-o", str(tmp_path / "i.json"), "--map", str(tmp_path / "m.html")]) == 0
    assert "Asset chart" in (tmp_path / "m.html").read_text()
    assert main(["map", str(tmp_path / "i.json"), "-o", str(tmp_path / "m2.html")]) == 0


def test_unredacted_map_needs_marked_name(tmp_path):
    p = tmp_path / "a.pcap"
    write_pcap(p, [(ts(1_700_000_000), arp_frame())])
    inv = tmp_path / "i.unredacted.json"
    assert main(["scan", str(p), "-o", str(inv), "--no-redact"]) == 0
    assert main(["map", str(inv), "-o", str(tmp_path / "m.html")]) == 2
    assert main(["map", str(inv), "-o", str(tmp_path / "m.unredacted.html")]) == 0
    assert main(["scan", str(p), "-o", str(inv), "--no-redact", "--map", str(tmp_path / "x.html")]) == 2
