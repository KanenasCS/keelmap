"""Modbus/TCP decoder tests. Expected results are written by hand from the packet definitions."""

import shutil
import subprocess

import pytest
from pcapgen import (
    BCAST,
    arp,
    devid_request,
    devid_response,
    ether,
    ipv4_tcp,
    mbap,
    ts,
    write_pcap,
)

from keelmap.scan import scan

HMI_MAC, PLC_MAC, RTR_MAC = "00:0e:8c:00:00:09", "00:1d:9c:00:00:05", "00:aa:00:00:00:01"
HMI, PLC = "10.0.0.9", "10.0.0.5"
READ = bytes([0x03, 0x00, 0x00, 0x00, 0x02])
READ_OK = bytes([0x03, 0x04, 0, 1, 0, 2])


def req(pdu, tid=1, unit=1, seq=1000, src_mac=HMI_MAC, src=HMI, dst=PLC, sport=40000):
    return ether(PLC_MAC, src_mac, 0x0800, ipv4_tcp(src, dst, sport, 502, mbap(tid, unit, pdu), seq))


def resp(pdu, tid=1, unit=1, seq=5000, src_mac=PLC_MAC, src=PLC, dst=HMI, dport=40000):
    return ether(HMI_MAC, src_mac, 0x0800, ipv4_tcp(src, dst, 502, dport, mbap(tid, unit, pdu), seq))


def run(tmp_path, frames):
    p = tmp_path / "c.pcap"
    write_pcap(p, [(ts(1_790_000_000 + i), f) for i, f in enumerate(frames)])
    out = scan([p]).to_dict(redact=False)
    return {a["identity_key"]: a for a in out["assets"]}, out["communications"], out["stats"]


def vals(a, field):
    return [m["value"] for m in a[field]["members"]]


def test_pair_gives_roles_communication_and_operation(tmp_path):
    assets, comms, _ = run(tmp_path, [req(READ), resp(READ_OK)])
    assert vals(assets[f"ip:{HMI}"], "roles") == ["modbus/client"]
    assert vals(assets[f"ip:{PLC}"], "roles") == ["modbus/server", "modbus/unit_id:1"]
    (c,) = comms
    assert c["packet_count"] == 2 and c["exchange_count"] == 1 and c["dst_port"] == 502
    op = c["operations"]["members"][0]
    assert op["value"] == "modbus/fc:03" and op["evidence"][0]["frames"] == [1, 2]
    assert assets[f"ip:{PLC}"]["roles"]["members"][0]["evidence"][0]["frames"] == [2]


def test_request_alone_stores_nothing(tmp_path):
    assets, comms, stats = run(tmp_path, [req(READ)])
    assert assets == {} and comms == [] and stats["modbus_request_unanswered"] == 1


def test_response_alone_stores_nothing(tmp_path):
    assets, _, stats = run(tmp_path, [resp(READ_OK)])
    assert assets == {} and stats["modbus_response_unpaired"] == 1


def test_function_mismatch_stores_nothing(tmp_path):
    assets, _, stats = run(tmp_path, [req(READ), resp(bytes([0x04, 0x02, 0, 1]))])
    assert assets == {} and stats["modbus_response_mismatch"] == 1


def test_unit_mismatch_stores_nothing(tmp_path):
    assets, _, stats = run(tmp_path, [req(READ, unit=1), resp(READ_OK, unit=2)])
    assert assets == {} and stats["modbus_response_mismatch"] == 1


def test_gateway_exception_gives_gateway_role_not_unit(tmp_path):
    assets, comms, _ = run(tmp_path, [req(READ, unit=7), resp(bytes([0x83, 0x0A]), unit=7)])
    roles = vals(assets[f"ip:{PLC}"], "roles")
    assert "modbus/gateway" in roles and "modbus/unit_id:7" not in roles
    assert comms[0]["operations"]["members"][0]["value"] == "modbus/fc:03:exception:10"


def test_ordinary_exception_keeps_unit_role(tmp_path):
    assets, comms, _ = run(tmp_path, [req(READ), resp(bytes([0x83, 0x02]))])
    assert "modbus/unit_id:1" in vals(assets[f"ip:{PLC}"], "roles")
    assert comms[0]["operations"]["members"][0]["value"] == "modbus/fc:03:exception:02"


def test_undefined_function_zero_answered_with_exception_is_a_pair(tmp_path):
    _, comms, _ = run(tmp_path, [req(b"\x00"), resp(bytes([0x80, 0x01]))])
    assert comms[0]["operations"]["members"][0]["value"] == "modbus/fc:00:exception:01"


def test_retransmitted_request_keeps_original_frame(tmp_path):
    _, comms, stats = run(tmp_path, [req(READ, seq=1000), req(READ, seq=1000), resp(READ_OK)])
    assert comms[0]["operations"]["members"][0]["evidence"][0]["frames"] == [1, 3]
    assert stats["modbus_request_retransmitted"] == 1


def test_reused_transaction_id_new_request_supersedes(tmp_path):
    first = req(READ, tid=0, seq=1000)
    second = req(bytes([0x01, 0, 0, 0, 8]), tid=0, seq=1012)
    _, comms, stats = run(tmp_path, [first, second, resp(bytes([0x01, 0x01, 0xFF]), tid=0)])
    op = comms[0]["operations"]["members"][0]
    assert op["value"] == "modbus/fc:01" and op["evidence"][0]["frames"] == [2, 3]
    assert stats["modbus_request_unanswered"] == 1


def test_two_adus_in_one_segment(tmp_path):
    both_req = ether(PLC_MAC, HMI_MAC, 0x0800, ipv4_tcp(HMI, PLC, 40000, 502, mbap(1, 1, READ) + mbap(2, 1, READ)))
    two = mbap(1, 1, READ_OK) + mbap(2, 1, READ_OK)
    both_resp = ether(HMI_MAC, PLC_MAC, 0x0800, ipv4_tcp(PLC, HMI, 502, 40000, two))
    _, comms, _ = run(tmp_path, [both_req, both_resp])
    c = comms[0]
    assert c["operations"]["members"][0]["evidence_count"] == 2
    assert c["exchange_count"] == 2 and c["packet_count"] == 2


def test_split_adu_is_counted(tmp_path):
    whole = mbap(1, 1, READ)
    part = ether(PLC_MAC, HMI_MAC, 0x0800, ipv4_tcp(HMI, PLC, 40000, 502, whole[:9]))
    _, _, stats = run(tmp_path, [part])
    assert stats["modbus_adu_split_across_segments"] == 1


def test_other_protocol_on_502_stores_nothing(tmp_path):
    junk = ether(PLC_MAC, HMI_MAC, 0x0800, ipv4_tcp(HMI, PLC, 40000, 502, b"GET / HTTP/1.1\r\n\r\n"))
    back = ether(HMI_MAC, PLC_MAC, 0x0800, ipv4_tcp(PLC, HMI, 502, 40000, b"HTTP/1.1 200 OK\r\n\r\n"))
    assets, _, stats = run(tmp_path, [junk, back])
    assert assets == {} and stats["modbus_port_502_not_mbap"] == 2


# --- device identification ----------------------------------------------------

OBJS = {0x00: b"Acme Marine", 0x01: b"AC-100", 0x02: b"v2.4.1", 0x05: b"AC-100 Ballast Controller"}


def test_device_id_unit_255_is_self_reported(tmp_path):
    assets, _, _ = run(tmp_path, [req(devid_request(), unit=255), resp(devid_response(OBJS), unit=255)])
    a = assets[f"ip:{PLC}"]
    assert a["device_vendor"]["value"] == "Acme Marine"
    assert a["device_model"]["value"] == "AC-100 Ballast Controller"   # ModelName preferred
    assert a["firmware"]["value"] == "v2.4.1"
    ev = a["device_model"]["claims"][0]["evidence"][0]
    assert ev["kind"] == "self_reported" and "ModelName" in ev["detail"] and ev["frames"] == [2]


def test_device_id_falls_back_to_product_code(tmp_path):
    objs = {k: v for k, v in OBJS.items() if k != 0x05}
    assets, _, _ = run(tmp_path, [req(devid_request(), unit=0), resp(devid_response(objs), unit=0)])
    assert assets[f"ip:{PLC}"]["device_model"]["value"] == "AC-100"


def test_device_id_other_unit_not_attributed(tmp_path):
    assets, _, stats = run(tmp_path, [req(devid_request(), unit=3), resp(devid_response(OBJS), unit=3)])
    a = assets[f"ip:{PLC}"]
    assert a["device_vendor"]["state"] == "unknown" and "modbus/unit_id:3" in vals(a, "roles")
    assert stats["modbus_device_id_not_attributed_unit"] == 1


def test_device_id_malformed_object_count(tmp_path):
    bad = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 5, 0x00, 0x04]) + b"Acme"
    assets, _, stats = run(tmp_path, [req(devid_request(), unit=255), resp(bad, unit=255)])
    assert assets[f"ip:{PLC}"]["device_vendor"]["state"] == "unknown"
    assert stats["modbus_device_id_malformed"] == 1


# --- IP to asset resolution ------------------------------------------------------

def arp_reply(mac, ip):
    return ether(BCAST, mac, 0x0806, arp(2, mac, ip, "00:00:00:00:00:00", "10.0.0.1"))


def test_ip_joins_mac_asset_when_arp_and_ethernet_agree(tmp_path):
    assets, _, _ = run(tmp_path, [req(READ), resp(READ_OK), arp_reply(PLC_MAC, PLC)])
    assert f"ip:{PLC}" not in assets
    assert "modbus/server" in vals(assets[f"mac:{PLC_MAC}"], "roles")


def test_ip_stays_separate_when_ethernet_source_differs(tmp_path):
    routed = resp(READ_OK, src_mac=RTR_MAC)
    assets, _, stats = run(tmp_path, [arp_reply(PLC_MAC, PLC), req(READ), routed])
    assert "modbus/server" in vals(assets[f"ip:{PLC}"], "roles")
    assert assets[f"mac:{PLC_MAC}"]["roles"]["state"] == "unknown"
    assert stats["modbus_ip_owner_mac_differs"] == 1


def test_ip_claimed_by_two_macs_is_ambiguous(tmp_path):
    other = "00:1d:9c:00:00:99"
    assets, _, stats = run(tmp_path, [arp_reply(PLC_MAC, PLC), arp_reply(other, PLC), req(READ), resp(READ_OK)])
    assert "modbus/server" in vals(assets[f"ip:{PLC}"], "roles")
    assert stats["modbus_ip_owner_ambiguous"] == 1


# --- fixtures verified by tshark -------------------------------------------------

@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_tshark_reads_generated_device_id_exchange(tmp_path):
    p = tmp_path / "d.pcap"
    write_pcap(p, [(ts(1_790_000_000), req(devid_request(), unit=255)),
                   (ts(1_790_000_001), resp(devid_response(OBJS), unit=255))])
    out = subprocess.run(["tshark", "-r", str(p), "-Y", "frame.number==2", "-T", "fields", "-E", "occurrence=a",
                          "-E", "aggregator=|", "-e", "modbus.request_frame", "-e", "modbus.mei",
                          "-e", "modbus.object_str_value"], capture_output=True, text=True, check=True).stdout
    req_frame, mei, values = out.strip().split("\t")
    assert req_frame == "1" and mei == "14"
    assert values.split("|") == [v.decode() for v in OBJS.values()]
