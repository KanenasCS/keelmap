import json

from pcapgen import BCAST, arp, ether, ts, write_pcap

from keelmap.__main__ import main
from keelmap.scan import scan

PLC = "00:1d:9c:00:00:05"
FRAME = ether(BCAST, PLC, 0x0806, arp(1, PLC, "10.0.0.5", "00:00:00:00:00:00", "10.0.0.1"))


def test_same_capture_twice_counted_once(tmp_path):
    p = tmp_path / "a.pcap"
    write_pcap(p, [(ts(1_790_000_000), FRAME)])
    q = tmp_path / "copy.pcap"
    q.write_bytes(p.read_bytes())
    out = scan([p, q]).to_dict()
    assert len(out["sources"]) == 1 and out["stats"]["capture_duplicate_skipped"] == 1


def test_unsupported_linktype_is_reported(tmp_path):
    p = tmp_path / "fr.pcap"
    write_pcap(p, [(ts(1_790_000_000), FRAME)], linktype=107)
    out = scan([p]).to_dict()
    assert out["assets"] == [] and out["stats"]["frames_unsupported_linktype_107"] == 1


def test_cli_end_to_end(tmp_path, capsys):
    p = tmp_path / "a.pcap"
    write_pcap(p, [(ts(1_790_000_000), FRAME)])
    o = tmp_path / "inv.json"
    assert main(["scan", str(p), "-o", str(o)]) == 0
    out = json.loads(o.read_text())
    assert out["redacted"] is True and out["assets"][0]["identity_key"] == f"mac:{PLC}"
    assert "1 assets" in capsys.readouterr().out


def test_cli_refuses_unredacted_output_with_normal_name(tmp_path):
    p = tmp_path / "a.pcap"
    write_pcap(p, [(ts(1_790_000_000), FRAME)])
    assert main(["scan", str(p), "-o", str(tmp_path / "inv.json"), "--no-redact"]) == 2
    assert main(["scan", str(p), "-o", str(tmp_path / "inv.unredacted.json"), "--no-redact"]) == 0
