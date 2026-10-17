"""DHCP decoder tests. Expected results are written by hand from the packet definitions."""

import json

from pcapgen import BCAST, dhcp, ether, ip4, ipv4_udp, ts, write_pcap

from keelmap.scan import scan

CLIENT = "00:1d:9c:00:00:05"
SERVER = "00:08:74:00:00:01"
SID = {54: ip4("192.168.0.1")}


def c2s(payload, src_ip="0.0.0.0", src_mac=CLIENT):
    return ether(BCAST, src_mac, 0x0800, ipv4_udp(src_ip, "255.255.255.255", 68, 67, payload))


def s2c(payload, src_ip="192.168.0.1", src_mac=SERVER):
    return ether(BCAST, src_mac, 0x0800, ipv4_udp(src_ip, "255.255.255.255", 67, 68, payload))


def run(tmp_path, frames):
    p = tmp_path / "c.pcap"
    write_pcap(p, [(ts(1_790_000_000 + i), f) for i, f in enumerate(frames)])
    out = scan([p]).to_dict()
    return {a["identity_key"]: a for a in out["assets"]}, out["stats"], out


def vals(a, field):
    return [m["value"] for m in a[field]["members"]]


def test_full_exchange_gives_roles_but_not_the_offered_ip(tmp_path):
    frames = [
        c2s(dhcp(1, 1, CLIENT)),
        s2c(dhcp(2, 2, CLIENT, yiaddr="192.168.0.10", options=SID)),
        c2s(dhcp(1, 3, CLIENT, options={50: ip4("192.168.0.10"), **SID})),
        s2c(dhcp(2, 5, CLIENT, yiaddr="192.168.0.10", options=SID)),
    ]
    assets, _, out = run(tmp_path, frames)
    c, s = assets[f"mac:{CLIENT}"], assets[f"mac:{SERVER}"]
    assert vals(c, "roles") == ["dhcp/client"] and c["ips"]["state"] == "unknown"
    assert vals(s, "roles") == ["dhcp/server"] and vals(s, "ips") == ["192.168.0.1"]
    assert "192.168.0.10" not in json.dumps(out)


def test_hostname_is_self_reported_and_nul_stripped(tmp_path):
    assets, _, _ = run(tmp_path, [c2s(dhcp(1, 3, CLIENT, options={12: b"ECDIS-1\x00"}))])
    h = assets[f"mac:{CLIENT}"]["hostname"]
    assert h["state"] == "known" and h["value"] == "ECDIS-1"
    assert h["claims"][0]["evidence"][0]["kind"] == "self_reported"


def test_hostname_in_server_message_ignored(tmp_path):
    assets, _, _ = run(tmp_path, [s2c(dhcp(2, 5, CLIENT, options={12: b"assigned", **SID}))])
    assert f"mac:{CLIENT}" not in assets
    assert assets[f"mac:{SERVER}"]["hostname"]["state"] == "unknown"


def test_hostname_change_is_a_conflict(tmp_path):
    frames = [c2s(dhcp(1, 3, CLIENT, options={12: b"OLD"})), c2s(dhcp(1, 3, CLIENT, options={12: b"NEW"}))]
    assets, _, _ = run(tmp_path, frames)
    assert assets[f"mac:{CLIENT}"]["hostname"]["state"] == "conflict"


def test_unreadable_hostname_not_stored(tmp_path):
    assets, stats, _ = run(tmp_path, [c2s(dhcp(1, 3, CLIENT, options={12: b"\xff\xfe"}))])
    assert assets[f"mac:{CLIENT}"]["hostname"]["state"] == "unknown"
    assert stats["dhcp_hostname_unreadable"] == 1


def test_bound_client_renewing_proves_its_ip(tmp_path):
    renew = c2s(dhcp(1, 3, CLIENT, ciaddr="192.168.0.10"), src_ip="192.168.0.10")
    assets, _, _ = run(tmp_path, [renew])
    assert vals(assets[f"mac:{CLIENT}"], "ips") == ["192.168.0.10"]


def test_ciaddr_without_matching_source_not_stored(tmp_path):
    odd = c2s(dhcp(1, 3, CLIENT, ciaddr="192.168.0.10"), src_ip="0.0.0.0")
    assets, _, _ = run(tmp_path, [odd])
    assert assets[f"mac:{CLIENT}"]["ips"]["state"] == "unknown"


def test_relayed_messages_skipped(tmp_path):
    relayed = c2s(dhcp(1, 1, CLIENT, giaddr="10.1.1.1"), src_ip="10.1.1.1", src_mac="00:aa:00:00:00:01")
    assets, stats, _ = run(tmp_path, [relayed])
    assert assets == {} and stats["dhcp_relayed_skipped"] == 1


def test_vendor_class_not_mapped_to_device_vendor(tmp_path):
    assets, _, out = run(tmp_path, [c2s(dhcp(1, 1, CLIENT, options={60: b"udhcp 1.30"}))])
    assert assets[f"mac:{CLIENT}"]["device_vendor"]["state"] == "unknown"
    assert "udhcp" not in json.dumps(out)


def test_chaddr_mismatch_skipped(tmp_path):
    assets, stats, _ = run(tmp_path, [c2s(dhcp(1, 1, CLIENT), src_mac="00:aa:00:00:00:02")])
    assert assets == {} and stats["dhcp_chaddr_mismatch"] == 1


def test_server_id_mismatch_keeps_role_not_ip(tmp_path):
    msg = s2c(dhcp(2, 5, CLIENT, options={54: ip4("192.168.0.2")}))
    assets, stats, _ = run(tmp_path, [msg])
    s = assets[f"mac:{SERVER}"]
    assert vals(s, "roles") == ["dhcp/server"] and s["ips"]["state"] == "unknown"
    assert stats["dhcp_server_id_mismatch"] == 1
