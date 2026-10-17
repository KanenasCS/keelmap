"""IEEE OUI registry tests with small files in the official CSV and TXT layouts."""

import json

import pytest
from pcapgen import BCAST, arp, ether, ts, write_pcap

from keelmap.__main__ import main
from keelmap.oui import OuiRegistry, RegistryError
from keelmap.scan import scan

CSV_L = """Registry,Assignment,Organization Name,Organization Address
MA-L,001D9C,Rockwell Automation,"1 Allen-Bradley Dr, Mayfield Heights OH US 44124"
MA-L,080030,NETWORK RESEARCH CORPORATION,somewhere
MA-L,080030,CERN,Geneva CH
MA-L,8C1F64,IEEE Registration Authority,445 Hoes Lane Piscataway NJ US 08554
MA-L,ACDE48,Private,
"""
CSV_M = """Registry,Assignment,Organization Name,Organization Address
MA-M,8C1F645,"Marine Sensors, Ltd.",Piraeus GR
"""
CSV_S = """Registry,Assignment,Organization Name,Organization Address
MA-S,8C1F6451A,Tiny Buoy Co,Oslo NO
"""
TXT = """OUI/MA-L\t\t\tOrganization
company_id\t\t\tOrganization
\t\t\t\tAddress

00-1D-9C   (hex)\t\tRockwell Automation
001D9C     (base 16)\t\tRockwell Automation
\t\t\t\t1 Allen-Bradley Dr
"""


@pytest.fixture
def files(tmp_path):
    out = {}
    for name, text in (("oui.csv", CSV_L), ("mam.csv", CSV_M), ("oui36.csv", CSV_S), ("oui.txt", TXT)):
        (tmp_path / name).write_text(text)
        out[name] = tmp_path / name
    return out


def reg(*paths):
    r = OuiRegistry()
    for p in paths:
        r.load(p)
    return r


def orgs(r, mac):
    entries, reason = r.lookup(mac)
    return sorted(e.org for e in entries), reason


def test_csv_and_txt_layouts(files):
    assert orgs(reg(files["oui.csv"]), "00:1d:9c:12:34:56") == (["Rockwell Automation"], None)
    assert orgs(reg(files["oui.txt"]), "00:1d:9c:12:34:56") == (["Rockwell Automation"], None)


def test_longest_prefix_wins(files):
    r = reg(files["oui.csv"], files["mam.csv"], files["oui36.csv"])
    assert orgs(r, "8c:1f:64:51:a0:01") == (["Tiny Buoy Co"], None)
    assert orgs(r, "8c:1f:64:5f:00:01") == (["Marine Sensors, Ltd."], None)


def test_registration_authority_block_needs_finer_file(files):
    assert orgs(reg(files["oui.csv"]), "8c:1f:64:51:a0:01") == ([], "registration_authority_block")


def test_private_local_and_multicast_not_looked_up(files):
    r = reg(files["oui.csv"])
    assert orgs(r, "ac:de:48:00:11:22") == ([], "private")
    assert orgs(r, "02:1d:9c:12:34:56") == ([], "locally_administered")
    assert orgs(r, "01:1d:9c:12:34:56") == ([], "multicast")
    assert orgs(r, "00:00:01:00:00:01") == ([], "not_found")


def test_prefix_with_several_holders_keeps_all(files):
    assert orgs(reg(files["oui.csv"]), "08:00:30:00:00:01")[0] == ["CERN", "NETWORK RESEARCH CORPORATION"]


def test_unrecognised_file_rejected(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("hello,world\n")
    with pytest.raises(RegistryError):
        OuiRegistry().load(p)


def capture(tmp_path, macs):
    frames = [ether(BCAST, m, 0x0806, arp(1, m, f"10.0.0.{i + 5}", "00:00:00:00:00:00", "10.0.0.1"))
              for i, m in enumerate(macs)]
    p = tmp_path / "c.pcap"
    write_pcap(p, [(ts(1_700_000_000 + i), f) for i, f in enumerate(frames)])
    return p


def test_scan_fills_nic_vendor_only_with_registry_evidence(tmp_path, files):
    p = capture(tmp_path, ["00:1d:9c:12:34:56", "08:00:30:00:00:01", "02:00:00:00:00:01"])
    out = scan([p], oui=reg(files["oui.csv"])).to_dict()
    A = {a["identity_key"]: a for a in out["assets"]}
    rock = A["mac:00:1d:9c:12:34:56"]
    assert rock["nic_vendor"]["value"] == "Rockwell Automation"
    assert rock["device_vendor"]["state"] == "unknown"
    ev = rock["nic_vendor"]["claims"][0]["evidence"][0]
    assert ev["kind"] == "registry" and ev["frames"] == [] and "MA-L 00-1D-9C" in ev["detail"]
    assert ev["source_sha256"] == out["registries"][0]["sha256"]
    assert A["mac:08:00:30:00:00:01"]["nic_vendor"]["state"] == "conflict"
    assert A["mac:02:00:00:00:00:01"]["nic_vendor"]["state"] == "unknown"
    assert out["stats"]["oui_locally_administered"] == 1
    assert out["stats"]["oui_prefix_listed_for_several_organisations"] == 1
    # registry lookups are not sightings
    assert rock["first_seen"] == rock["last_seen"]


def test_cli_oui_flag(tmp_path, files):
    p = capture(tmp_path, ["00:1d:9c:12:34:56"])
    o = tmp_path / "i.json"
    assert main(["scan", str(p), "-o", str(o), "--oui", str(files["oui.csv"])]) == 0
    assert json.loads(o.read_text())["assets"][0]["nic_vendor"]["value"] == "Rockwell Automation"
    bad = tmp_path / "bad.csv"
    bad.write_text("nope\n")
    assert main(["scan", str(p), "-o", str(o), "--oui", str(bad)]) == 1
