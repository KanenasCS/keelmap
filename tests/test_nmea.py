"""NMEA 0183 over UDP tests. Real sentences from fixtures/public/nmea_samples.txt where possible."""

import json
from pathlib import Path

from pcapgen import BCAST, arp, ether, ipv4_udp, ts, write_pcap

from keelmap.scan import scan

L = (Path(__file__).parent / "fixtures/public/nmea_samples.txt").read_text().splitlines()
MAC, OTHER_MAC = "00:a0:c8:00:00:10", "00:aa:00:00:00:01"
SRC = "10.0.1.10"


def cks(body: str) -> str:
    c = 0
    for ch in body:
        c ^= ord(ch)
    return f"{c:02X}"


def sentence(body: str, start="$") -> str:
    return f"{start}{body}*{cks(body)}"


def as_vdo(line: str) -> str:
    """Relabel a real VDM sentence as VDO (own ship) and recompute its checksum."""
    body = line[line.index("!") + 1:line.index("*")].replace("VDM", "VDO", 1)
    return sentence(body, "!")


def udp(text: str | bytes, src=SRC, dst="10.0.1.255", port=10110, mac=MAC):
    data = text.encode() if isinstance(text, str) else text
    return ether(BCAST, mac, 0x0800, ipv4_udp(src, dst, port, port, data))


def run(tmp_path, frames, redact=False):
    p = tmp_path / "c.pcap"
    write_pcap(p, [(ts(1_790_000_000 + i), f) for i, f in enumerate(frames)])
    out = scan([p]).to_dict(redact=redact)
    return {a["identity_key"]: a for a in out["assets"]}, out


def vals(a, field):
    return sorted(m["value"] for m in a[field]["members"])


def test_real_gpgga_gives_talker_and_sentence_roles(tmp_path):
    assets, out = run(tmp_path, [udp(L[5] + "\r\n")])
    a = assets[f"ip:{SRC}"]
    assert vals(a, "roles") == ["nmea0183/sentence:gpgga", "nmea0183/talker:gp"]
    assert vals(a, "ips") == [SRC]
    assert out["communications"] == []


def test_several_sentences_in_one_datagram(tmp_path):
    hdt = sentence("HEHDT,274.07,T")
    assets, _ = run(tmp_path, [udp(L[5] + "\r\n" + hdt + "\r\n")])
    assert "nmea0183/talker:he" in vals(assets[f"ip:{SRC}"], "roles")


def test_bad_checksum_rejected(tmp_path):
    bad = L[5][:-2] + "00"
    assets, out = run(tmp_path, [udp(bad)])
    assert assets == {} and out["stats"]["nmea_checksum_invalid"] == 1


def test_missing_checksum_rejected(tmp_path):
    assets, out = run(tmp_path, [udp(L[5].split("*")[0])])
    assert assets == {} and out["stats"]["nmea_checksum_missing"] == 1


def test_other_udp_text_ignored_without_stats(tmp_path):
    assets, out = run(tmp_path, [udp("hello from a syslog-ish thing")])
    assert assets == {} and set(out["stats"]) == {"frames_read"}


def test_proprietary_sentence_records_code_not_vendor(tmp_path):
    assets, _ = run(tmp_path, [udp(sentence("PGRME,15.0,M,45.0,M,25.0,M"))])
    a = assets[f"ip:{SRC}"]
    assert vals(a, "roles") == ["nmea0183/proprietary:grm"]
    assert a["device_vendor"]["state"] == "unknown"


def test_iec_61162_450_sender_group_and_sfi(tmp_path):
    tag = "s:GP0001,n:12"
    line = f"\\{tag}*{cks(tag)}\\{L[5]}\r\n"
    assets, _ = run(tmp_path, [udp(b"UdPbC\x00" + line.encode(), dst="239.192.0.4", port=60004)])
    a = assets[f"ip:{SRC}"]
    roles = vals(a, "roles")
    assert "iec61162_450/sender" in roles and "iec61162_450/group:239.192.0.4:60004" in roles
    assert vals(a, "device_ids") == ["iec61162_450_sfi:GP0001"]
    assert a["device_ids"]["members"][0]["evidence"][0]["kind"] == "self_reported"


def test_real_tag_block_source_outside_450(tmp_path):
    assets, _ = run(tmp_path, [udp(L[6] + "\r\n"), udp(L[7] + "\r\n")])
    assert vals(assets[f"ip:{SRC}"], "device_ids") == ["nmea_tag_source:b003669710"]


def test_tag_block_bad_checksum_drops_sentence(tmp_path):
    line = "\\s:GP0001*00\\" + L[5]
    assets, out = run(tmp_path, [udp(line)])
    assert assets == {} and out["stats"]["nmea_tag_block_checksum_invalid"] == 1


def test_iec_61162_450_binary_counted(tmp_path):
    _, out = run(tmp_path, [udp(b"RaUdP\x00\x01\x02")])
    assert out["stats"]["iec61162_450_binary_not_supported"] == 1


def test_vdm_other_vessels_counted_not_inventoried(tmp_path):
    assets, out = run(tmp_path, [udp(L[1] + "\r\n" + L[2] + "\r\n")])
    a = assets[f"ip:{SRC}"]
    assert "ais/vdm" in vals(a, "roles") and a["vessel_identifiers"]["state"] == "unknown"
    assert out["stats"]["ais_vdm_other_vessels_not_inventoried"] == 1
    assert "258315000" not in json.dumps(out)


def test_vdo_own_ship_across_two_datagrams(tmp_path):
    # Real type 5 payload relabelled as VDO to stand in for own ship.
    assets, out = run(tmp_path, [udp(as_vdo(L[1])), udp(as_vdo(L[2]))])
    a = assets[f"ip:{SRC}"]
    assert vals(a, "vessel_identifiers") == ["callsign:LFNA", "imo:6514895", "mmsi:258315000", "name:FALKVIK"]
    ev = a["vessel_identifiers"]["members"][0]["evidence"][0]
    assert ev["frames"] == [1, 2] and ev["kind"] == "self_reported"
    assert "ais/vdo" in vals(a, "roles")


def test_vdo_identifiers_redacted_by_default(tmp_path):
    _, out = run(tmp_path, [udp(as_vdo(L[1])), udp(as_vdo(L[2]))], redact=True)
    blob = json.dumps(out)
    for secret in ("258315000", "6514895", "LFNA", "FALKVIK"):
        assert secret not in blob


def test_ip_joins_mac_asset_when_arp_agrees(tmp_path):
    reply = ether(BCAST, MAC, 0x0806, arp(2, MAC, SRC, "00:00:00:00:00:00", "10.0.1.1"))
    assets, _ = run(tmp_path, [udp(L[5]), reply])
    assert f"ip:{SRC}" not in assets
    assert "nmea0183/talker:gp" in vals(assets[f"mac:{MAC}"], "roles")


def test_ip_stays_separate_when_ethernet_differs(tmp_path):
    reply = ether(BCAST, MAC, 0x0806, arp(2, MAC, SRC, "00:00:00:00:00:00", "10.0.1.1"))
    assets, out = run(tmp_path, [reply, udp(L[5], mac=OTHER_MAC)])
    assert "nmea0183/talker:gp" in vals(assets[f"ip:{SRC}"], "roles")
    assert out["stats"]["nmea0183_ip_owner_mac_differs"] == 1


def test_unspecified_source_ip_rejected(tmp_path):
    assets, out = run(tmp_path, [udp(L[5], src="0.0.0.0")])
    assert assets == {} and out["stats"]["nmea_source_ip_not_host"] == 1
