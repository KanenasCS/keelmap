"""ARP decoder tests. Expected results are written by hand from the packet definitions."""

import pytest
from pcapgen import BCAST, arp, ether, ts, write_pcap

from keelmap.scan import scan

PLC = "00:1d:9c:00:00:05"
HMI = "00:0e:8c:00:00:09"
T0 = ts(1_790_000_000)


def run(tmp_path, frames):
    p = tmp_path / "c.pcap"
    write_pcap(p, [(ts(1_790_000_000 + i), f) for i, f in enumerate(frames)])
    out = scan([p]).to_dict()
    return {a["identity_key"]: a for a in out["assets"]}, out["stats"]


def ips(a):
    return [m["value"] for m in a["ips"]["members"]]


def test_reply_binds_mac_and_ip_and_request_target_is_not_an_asset(tmp_path):
    req = ether(BCAST, HMI, 0x0806, arp(1, HMI, "10.0.0.9", "00:00:00:00:00:00", "10.0.0.77"))
    rep = ether(HMI, PLC, 0x0806, arp(2, PLC, "10.0.0.5", HMI, "10.0.0.9"))
    assets, _ = run(tmp_path, [req, rep])
    assert set(assets) == {f"mac:{HMI}", f"mac:{PLC}"}
    assert ips(assets[f"mac:{PLC}"]) == ["10.0.0.5"]
    assert ips(assets[f"mac:{HMI}"]) == ["10.0.0.9"]
    assert "10.0.0.77" not in str(assets)
    ev = assets[f"mac:{PLC}"]["ips"]["members"][0]["evidence"][0]
    assert ev["frames"] == [2] and ev["kind"] == "observed" and ev["decoder"] == "arp@0.1.0"


def test_announcement_is_labelled(tmp_path):
    g = ether(BCAST, PLC, 0x0806, arp(1, PLC, "10.0.0.5", "00:00:00:00:00:00", "10.0.0.5"))
    assets, _ = run(tmp_path, [g])
    assert "announcement" in assets[f"mac:{PLC}"]["ips"]["members"][0]["evidence"][0]["detail"]


def test_probe_stores_mac_but_no_ip(tmp_path):
    probe = ether(BCAST, PLC, 0x0806, arp(1, PLC, "0.0.0.0", "00:00:00:00:00:00", "10.0.0.5"))
    assets, stats = run(tmp_path, [probe])
    a = assets[f"mac:{PLC}"]
    assert a["ips"]["state"] == "unknown"
    assert [m["value"] for m in a["macs"]["members"]] == [PLC]
    assert stats["arp_probe_no_ip"] == 1


def test_sender_mac_mismatch_stores_nothing(tmp_path):
    forged = ether(HMI, "00:aa:bb:cc:dd:ee", 0x0806, arp(2, PLC, "10.0.0.5", HMI, "10.0.0.9"))
    assets, stats = run(tmp_path, [forged])
    assert assets == {}
    assert stats["arp_sender_mac_mismatch"] == 1


def test_vlan_tagged_arp(tmp_path):
    rep = ether(HMI, PLC, 0x0806, arp(2, PLC, "10.0.0.5", HMI, "10.0.0.9"), vlan=20)
    assets, _ = run(tmp_path, [rep])
    assert ips(assets[f"mac:{PLC}"]) == ["10.0.0.5"]


def test_one_mac_answering_for_many_ips_is_shown_as_is(tmp_path):
    frames = [ether(HMI, PLC, 0x0806, arp(2, PLC, f"10.0.0.{n}", HMI, "10.0.0.9")) for n in (5, 6, 7)]
    assets, _ = run(tmp_path, frames)
    assert ips(assets[f"mac:{PLC}"]) == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]


@pytest.mark.parametrize("bad_ip", ["255.255.255.255", "224.0.0.1", "127.0.0.1"])
def test_non_host_sender_ip_not_stored(tmp_path, bad_ip):
    rep = ether(HMI, PLC, 0x0806, arp(2, PLC, bad_ip, HMI, "10.0.0.9"))
    assets, stats = run(tmp_path, [rep])
    assert assets[f"mac:{PLC}"]["ips"]["state"] == "unknown"
    assert stats["arp_sender_ip_not_host"] == 1


def test_multicast_sender_mac_rejected(tmp_path):
    bad = "01:00:5e:00:00:01"
    rep = ether(HMI, bad, 0x0806, arp(2, bad, "10.0.0.5", HMI, "10.0.0.9"))
    assets, stats = run(tmp_path, [rep])
    assert assets == {} and stats["arp_sender_not_unicast"] == 1
