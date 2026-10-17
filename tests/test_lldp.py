"""LLDP tests. Real captures in fixtures/public (see lldp.source.md) plus built frames."""

import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from pcapgen import ip4, lldp_basic, lldp_frame, tlv, ts, write_pcap

from keelmap.scan import scan

FIX = Path(__file__).parent / "fixtures/public"
SW = "00:1d:9c:00:00:30"


def run_file(path):
    out = scan([path]).to_dict()
    return {a["identity_key"]: a for a in out["assets"]}, out


def run(tmp_path, frames):
    p = tmp_path / "l.pcap"
    write_pcap(p, [(ts(1_700_000_000 + i), f) for i, f in enumerate(frames)])
    return run_file(p)


def vals(a, field):
    return sorted(m["value"] for m in a[field]["members"])


def med(subtype: int, text: bytes) -> bytes:
    return tlv(127, b"\x00\x12\xbb" + bytes([subtype]) + text)


# --- real captures ---------------------------------------------------------------

def test_real_smc_switch():
    assets, _ = run_file(FIX / "lldp_smc_switch.pcap")
    a = assets["mac:00:22:2d:81:db:10"]
    assert a["hostname"]["value"] == "SMCGS8P-Smart"
    assert a["description"]["value"] == "SMCGS8P-Smart - SMCGS8P-Smart v3.20"
    assert vals(a, "capabilities") == ["bridge"]
    assert vals(a, "device_ids") == ["lldp_chassis_mac:00:22:2d:81:db:10", "lldp_management_ipv4:192.168.2.10"]
    assert vals(a, "roles") == ["lldp/advertiser"]
    # free text is not parsed into structured fields
    assert a["device_vendor"]["state"] == "unknown" and a["firmware"]["state"] == "unknown"
    # a management address is a claim, not proof of owning the IP
    assert a["ips"]["state"] == "unknown"


def test_real_mud_url_and_ipv6_management():
    assets, _ = run_file(FIX / "lldp_mudurl.pcap")
    a = assets["mac:00:23:54:c2:57:02"]
    ids = vals(a, "device_ids")
    assert "mud_url:https://imright.mud.example.com/.well-known/mud/v1/vomitv2.0" in ids
    assert "lldp_management_ipv4:62.12.173.114" in ids
    assert "lldp_management_ipv6:2001:8a8:1006:4:223:54ff:fec2:5702" in ids
    assert vals(a, "capabilities") == ["wlan_access_point"]
    assert a["hostname"]["claims"][0]["evidence_count"] == 2


def test_real_malformed_frame_discarded():
    assets, out = run_file(FIX / "lldp_malformed_asan.pcap")
    assert assets == {} and out["stats"]["lldp_malformed_discarded"] == 1


# --- 802.1AB structure rules -----------------------------------------------------

def test_mandatory_tlvs_out_of_order_discarded(tmp_path):
    b = lldp_basic(SW)
    assets, out = run(tmp_path, [lldp_frame(SW, [b[1], b[0], b[2], tlv(5, b"sw1")])])
    assert assets == {} and out["stats"]["lldp_malformed_discarded"] == 1


def test_duplicate_mandatory_tlv_discarded(tmp_path):
    assets, out = run(tmp_path, [lldp_frame(SW, lldp_basic(SW) + [tlv(3, b"\x00\x78")])])
    assert assets == {} and out["stats"]["lldp_malformed_discarded"] == 1


def test_tlv_running_past_frame_discarded(tmp_path):
    frame = lldp_frame(SW, lldp_basic(SW), end=False) + struct.pack("!H", (5 << 9) | 40) + b"short"
    assets, out = run(tmp_path, [frame])
    assert assets == {} and out["stats"]["lldp_malformed_discarded"] == 1


def test_ttl_must_be_two_octets(tmp_path):
    b = lldp_basic(SW)
    assets, _ = run(tmp_path, [lldp_frame(SW, [b[0], b[1], tlv(3, b"\x00\x00\x78")])])
    assert assets == {}


def test_zero_source_mac_rejected(tmp_path):
    zero = "00:00:00:00:00:00"
    assets, out = run(tmp_path, [lldp_frame(zero, lldp_basic(SW) + [tlv(5, b"leaf0b")])])
    assert assets == {} and out["stats"]["lldp_source_not_unicast"] == 1


# --- content rules ---------------------------------------------------------------

def test_supported_but_not_enabled_capability_not_stored(tmp_path):
    caps = tlv(7, struct.pack("!HH", 0x0014, 0x0004))   # supports bridge and router, only bridge enabled
    assets, _ = run(tmp_path, [lldp_frame(SW, lldp_basic(SW) + [caps])])
    assert vals(assets[f"mac:{SW}"], "capabilities") == ["bridge"]


def test_multiline_description_kept_verbatim(tmp_path):
    desc = b"Cisco IOS Software, C3560 Software, Version 12.2(44)SE\nCopyright (c) 1986-2008"
    assets, _ = run(tmp_path, [lldp_frame(SW, lldp_basic(SW) + [tlv(6, desc)])])
    a = assets[f"mac:{SW}"]
    assert a["description"]["value"] == desc.decode()
    assert a["device_vendor"]["state"] == "unknown" and a["device_model"]["state"] == "unknown"


def test_unreadable_text_not_stored(tmp_path):
    assets, out = run(tmp_path, [lldp_frame(SW, lldp_basic(SW) + [tlv(5, b"\xff\xfe\x00")])])
    assert assets[f"mac:{SW}"]["hostname"]["state"] == "unknown"
    assert out["stats"]["lldp_text_unreadable"] == 1


def test_lldp_med_inventory_fills_structured_fields(tmp_path):
    extra = [med(9, b"Acme Marine"), med(10, b"BX-200"), med(6, b"4.1.7"), med(8, b"SN123"),
             med(11, b"BRIDGE-SW-02"), med(7, b"sw 9.9"), med(5, b"rev B")]
    assets, _ = run(tmp_path, [lldp_frame(SW, lldp_basic(SW) + extra)])
    a = assets[f"mac:{SW}"]
    got = (a["device_vendor"]["value"], a["device_model"]["value"], a["firmware"]["value"])
    assert got == ("Acme Marine", "BX-200", "4.1.7")
    assert a["device_vendor"]["claims"][0]["evidence"][0]["kind"] == "self_reported"
    assert {"lldp_med_serial:SN123", "lldp_med_asset_id:BRIDGE-SW-02"} <= set(vals(a, "device_ids"))
    assert "sw 9.9" not in json.dumps(a) and "rev B" not in json.dumps(a)


def test_management_address_never_becomes_an_ip(tmp_path):
    mgmt = tlv(8, bytes([5, 1]) + ip4("10.0.0.30") + b"\x02\x00\x00\x00\x01\x00")
    assets, _ = run(tmp_path, [lldp_frame(SW, lldp_basic(SW) + [mgmt])])
    a = assets[f"mac:{SW}"]
    assert "lldp_management_ipv4:10.0.0.30" in vals(a, "device_ids") and a["ips"]["state"] == "unknown"


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_tshark_reads_built_med_frame(tmp_path):
    p = tmp_path / "m.pcap"
    frame = lldp_frame(SW, lldp_basic(SW) + [med(9, b"Acme Marine"), med(10, b"BX-200")])
    write_pcap(p, [(ts(1_700_000_000), frame)])
    cmd = ["tshark", "-r", str(p), "-T", "fields", "-e", "lldp.media.manufacturer",
           "-e", "lldp.media.model", "-e", "_ws.malformed"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    assert out.strip().split("\t") == ["Acme Marine", "BX-200"]
