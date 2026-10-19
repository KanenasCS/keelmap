"""One test per bug fixed in 0.1.1, named after the problem it guards against."""

import hashlib
import io
import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from pcapgen import (
    BCAST,
    arp,
    ether,
    ipv4_tcp,
    ipv4_udp,
    mbap,
    sll,
    sll2,
    ts,
    write_pcap,
)

import keelmap.decoders.ais as ais_mod
import keelmap.decoders.modbus as modbus_mod
from keelmap.__main__ import main
from keelmap.capture import CaptureReader
from keelmap.oui import OuiRegistry
from keelmap.report.render import render_html
from keelmap.report.view import build_view, explain_stat
from keelmap.scan import scan

FIX = Path(__file__).parent / "fixtures/public"
L = (FIX / "nmea_samples.txt").read_text().splitlines()
PLC = "00:1d:9c:00:00:05"
ARP = ether(BCAST, PLC, 0x0806, arp(1, PLC, "10.0.0.5", "00:00:00:00:00:00", "10.0.0.1"))


def cks(body: str) -> str:
    c = 0
    for ch in body:
        c ^= ord(ch)
    return f"{c:02X}"


def vdo_capture(tmp_path):
    vdo = [line[1:line.index("*")].replace("VDM", "VDO") for line in L[1:3]]
    frames = [ether(BCAST, "00:a0:c8:00:00:10", 0x0800,
                    ipv4_udp("10.0.1.10", "10.0.1.255", 10110, 10110, f"!{v}*{cks(v)}\r\n".encode())) for v in vdo]
    p = tmp_path / "own.pcap"
    write_pcap(p, [(ts(1_700_000_000 + i), f) for i, f in enumerate(frames)])
    return p


# --- 1. redaction could be reversed by trying every IMO or MMSI -------------------------

def test_redaction_tokens_are_not_plain_hashes(tmp_path):
    red = scan([vdo_capture(tmp_path)]).to_dict()
    tokens = {m["value"] for m in red["assets"][0]["vessel_identifiers"]["members"]}
    for plain in ("imo:6514895", "mmsi:258315000", "callsign:LFNA", "name:FALKVIK"):
        for n in (12, 16):
            assert "redacted:" + hashlib.sha256(plain.encode()).hexdigest()[:n] not in tokens
    assert red["redaction"]["method"] == "hmac-sha256"


def test_random_key_tokens_differ_between_exports(tmp_path):
    inv = scan([vdo_capture(tmp_path)])
    a = {m["value"] for m in inv.to_dict()["assets"][0]["vessel_identifiers"]["members"]}
    b = {m["value"] for m in inv.to_dict()["assets"][0]["vessel_identifiers"]["members"]}
    assert a.isdisjoint(b)


def test_key_file_gives_stable_tokens_and_keygen_protects_it(tmp_path):
    key = tmp_path / "k.key"
    assert main(["keygen", "-o", str(key)]) == 0
    assert main(["keygen", "-o", str(key)]) == 2          # never overwrites a key
    p = vdo_capture(tmp_path)
    outs = []
    for i in range(2):
        o = tmp_path / f"i{i}.json"
        assert main(["scan", str(p), "-o", str(o), "--redaction-key", str(key)]) == 0
        outs.append(json.loads(o.read_text()))
    tokens = [{m["value"] for m in o["assets"][0]["vessel_identifiers"]["members"]} for o in outs]
    assert tokens[0] == tokens[1]
    assert outs[0]["redaction"]["key"] == "supplied"
    assert outs[0]["redaction"]["key_id"] == outs[1]["redaction"]["key_id"]
    assert key.read_text().strip() not in json.dumps(outs[0])


def test_short_key_rejected(tmp_path):
    key = tmp_path / "k.key"
    key.write_text("abcd\n")
    assert main(["scan", str(vdo_capture(tmp_path)), "-o", str(tmp_path / "i.json"), "--redaction-key", str(key)]) == 1


# --- 2. crafted captures crashed the reader ----------------------------------------------

def pcap_header(linktype=1):
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)


def shb():
    return struct.pack("<II", 0x0A0D0D0A, 28) + struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + struct.pack("<I", 28)


def block(btype, body, total=None):
    body += b"\x00" * (-len(body) % 4)
    total = total if total is not None else 12 + len(body)
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def idb(opts=b""):
    return block(1, struct.pack("<HHI", 1, 0, 65535) + opts)


def read(tmp_path, data):
    p = tmp_path / "x.cap"
    p.write_bytes(data)
    r = CaptureReader(p)
    return list(r), r


@pytest.mark.parametrize("data,stat", [
    (pcap_header() + struct.pack("<IIII", 1, 0, 0xFFFFFFFF, 0xFFFFFFFF) + b"x" * 40, "capture_corrupt_record_length"),
    (shb() + idb() + struct.pack("<II", 6, 4), "capture_corrupt_block_length"),
    (struct.pack("<II", 0x0A0D0D0A, 12) + struct.pack("<I", 0x1A2B3C4D) + b"\x00" * 8, "capture_corrupt_block_length"),
    (shb() + idb() + block(6, b"\x00" * 8), "capture_corrupt_block"),
    (shb() + block(1, b"\x01\x00"), "capture_corrupt_block"),
    (shb() + idb() + block(6, struct.pack("<IIIII", 0, 0, 0, 500, 500) + b"ab"), "frame_capture_length_exceeds_block"),
])
def test_damaged_files_are_counted_not_crashing(tmp_path, data, stat):
    _, r = read(tmp_path, data)
    assert r.stats[stat] == 1


def test_truncated_tsresol_option_does_not_crash(tmp_path):
    opt = struct.pack("<HH", 9, 4) + b"\x06"          # claims 4 bytes, has 1, then the block ends
    frames, _ = read(tmp_path, shb() + idb(opt))
    assert frames == []


def test_impossible_timestamp_keeps_numbering(tmp_path):
    opt = struct.pack("<HH", 9, 1) + b"\x00\x00\x00\x00" + struct.pack("<HH", 0, 0)   # 1 tick per second
    epb = lambda hi: block(6, struct.pack("<IIIII", 0, hi, 0, 14, 14) + ARP[:14])  # noqa: E731
    frames, r = read(tmp_path, shb() + idb(opt) + epb(0xFFFFFFFF) + epb(0))
    assert [f.number for f in frames] == [2]
    assert r.stats["frame_timestamp_out_of_range"] == 1


def test_absurd_timestamp_resolution_ignored(tmp_path):
    opt = struct.pack("<HH", 9, 1) + bytes([0x80 | 100]) + b"\x00\x00\x00" + struct.pack("<HH", 0, 0)
    epb = block(6, struct.pack("<IIIII", 0, 0, 1_700_000_000, 14, 14) + ARP[:14])
    frames, _ = read(tmp_path, shb() + idb(opt) + epb)
    assert len(frames) == 1


# --- 3. memory grew with capture length --------------------------------------------------

def test_claims_do_not_remember_every_record(monkeypatch):
    import keelmap.model as m
    monkeypatch.setattr(m, "VERIFY_EVIDENCE", False)
    c = m._Claim()
    assert c._all is None


def test_shared_frames_counted_once_beyond_a_single_pair(tmp_path):
    hmi, plc = "00:0e:8c:00:00:09", "00:1d:9c:00:00:05"
    rd = bytes([3, 0, 0, 0, 1])
    rsp = bytes([3, 2, 0, 7])
    req = ether(plc, hmi, 0x0800, ipv4_tcp("10.0.0.9", "10.0.0.5", 40000, 502, mbap(1, 1, rd) + mbap(2, 1, rd)))
    r1 = ether(hmi, plc, 0x0800, ipv4_tcp("10.0.0.5", "10.0.0.9", 502, 40000, mbap(1, 1, rsp)))
    r2 = ether(hmi, plc, 0x0800, ipv4_tcp("10.0.0.5", "10.0.0.9", 502, 40000, mbap(2, 1, rsp), seq=5011))
    p = tmp_path / "p.pcap"
    write_pcap(p, [(ts(1_700_000_000 + i), f) for i, f in enumerate([req, r1, r2])])
    c = scan([p]).to_dict()["communications"][0]
    assert c["exchange_count"] == 2 and c["packet_count"] == 3


def test_pipelined_clients_on_two_connections_count_exactly(tmp_path):
    """Two connections from one client, responses interleaved. Each record must be unique."""
    hmi, plc = "00:0e:8c:00:00:09", "00:1d:9c:00:00:05"
    rd, rsp = bytes([3, 0, 0, 0, 1]), bytes([3, 2, 0, 7])
    a_req = ether(plc, hmi, 0x0800, ipv4_tcp("10.0.0.9", "10.0.0.5", 40000, 502, mbap(1, 1, rd) + mbap(2, 1, rd)))
    b_req = ether(plc, hmi, 0x0800, ipv4_tcp("10.0.0.9", "10.0.0.5", 40001, 502, mbap(1, 1, rd)))
    a1 = ether(hmi, plc, 0x0800, ipv4_tcp("10.0.0.5", "10.0.0.9", 502, 40000, mbap(1, 1, rsp)))
    b1 = ether(hmi, plc, 0x0800, ipv4_tcp("10.0.0.5", "10.0.0.9", 502, 40001, mbap(1, 1, rsp)))
    a2 = ether(hmi, plc, 0x0800, ipv4_tcp("10.0.0.5", "10.0.0.9", 502, 40000, mbap(2, 1, rsp), seq=5011))
    p = tmp_path / "p.pcap"
    write_pcap(p, [(ts(1_700_000_000 + i), f) for i, f in enumerate([a_req, b_req, a1, b1, a2])])
    out = scan([p]).to_dict()
    client = next(a for a in out["assets"] if a["identity_key"] == "ip:10.0.0.9")
    assert client["roles"]["members"][0]["evidence_count"] == 3
    assert out["communications"][0]["exchange_count"] == 3 and out["communications"][0]["packet_count"] == 5


def test_repeated_sentence_types_in_one_datagram_count_each_sentence(tmp_path):
    gga, rmc = L[5], f"$GPRMC,184353.07,A*{cks('GPRMC,184353.07,A')}"
    payload = "\r\n".join([gga, rmc, gga]).encode()
    p = tmp_path / "n.pcap"
    write_pcap(p, [(ts(1_700_000_000), ether(BCAST, "00:a0:c8:00:00:10", 0x0800,
                                              ipv4_udp("10.0.1.10", "10.0.1.255", 10110, 10110, payload)))])
    a = scan([p]).to_dict()["assets"][0]
    roles = {m["value"]: m["evidence_count"] for m in a["roles"]["members"]}
    assert roles["nmea0183/talker:gp"] == 3 and roles["nmea0183/sentence:gpgga"] == 2


def test_pending_modbus_requests_are_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(modbus_mod, "MAX_PENDING", 3)
    hmi, plc = "00:0e:8c:00:00:09", "00:1d:9c:00:00:05"
    reqs = [ether(plc, hmi, 0x0800, ipv4_tcp("10.0.0.9", "10.0.0.5", 40000, 502, mbap(t, 1, bytes([3, 0, 0, 0, 1])),
                                             seq=1000 + t)) for t in range(10)]
    p = tmp_path / "r.pcap"
    write_pcap(p, [(ts(1_700_000_000 + i), f) for i, f in enumerate(reqs)])
    d = modbus_mod.ModbusDecoder()
    scan([p], decoders=[d])
    assert d.stats["modbus_request_unanswered"] == 10 and not d._pending


def test_open_ais_fragments_are_capped(monkeypatch):
    monkeypatch.setattr(ais_mod.FragmentBuffer, "MAX_OPEN", 2)
    fb = ais_mod.FragmentBuffer()
    for seq in "1234":
        fb.add(("s",), "VDM", 2, 1, seq, "A", "AAA", 0, 1)
    assert len(fb._open) == 2 and fb.close() == 4


# --- 4. the IP resolver was quadratic ------------------------------------------------------

def test_resolver_index_gives_same_answers(tmp_path):
    frames = [ether(BCAST, f"00:1d:9c:00:00:{i:02x}", 0x0806,
                    arp(1, f"00:1d:9c:00:00:{i:02x}", f"10.0.0.{i}", "00:00:00:00:00:00", "10.0.0.254"))
              for i in range(1, 40)]
    body = "HEHDT,274.07,T"
    frames += [ether(BCAST, "00:1d:9c:00:00:07", 0x0800,
                     ipv4_udp("10.0.0.7", "10.0.0.255", 10110, 10110, f"${body}*{cks(body)}".encode()))]
    p = tmp_path / "x.pcap"
    write_pcap(p, [(ts(1_700_000_000 + i), f) for i, f in enumerate(frames)])
    A = {a["identity_key"]: a for a in scan([p]).to_dict()["assets"]}
    assert "nmea0183/talker:he" in [m["value"] for m in A["mac:00:1d:9c:00:00:07"]["roles"]["members"]]
    assert "ip:10.0.0.7" not in A


# --- 5. the chart showed "Frames and undefined" for registry evidence ----------------------

def test_registry_evidence_names_the_registry_file(tmp_path):
    csv = tmp_path / "oui.csv"
    csv.write_text("Registry,Assignment,Organization Name,Organization Address\nMA-L,001D9C,Rockwell Automation,x\n")
    reg = OuiRegistry()
    reg.load(csv)
    p = tmp_path / "a.pcap"
    write_pcap(p, [(ts(1_700_000_000), ARP)])
    p2 = tmp_path / "b.pcap"
    write_pcap(p2, [(ts(1_700_000_100), ARP)])
    view = build_view(scan([p, p2], oui=reg).to_dict())
    nic = next(f for f in view["nodes"][0]["addresses"] if f["label"] == "Network card maker")
    ev = nic["items"][0]["evidence"][0]
    assert ev["registry"].startswith("oui.csv, SHA-256 ") and "source" not in ev
    app = (Path(__file__).parents[1] / "src/keelmap/report/app.js").read_text()
    assert "if (e.registry)" in app and "No frame cited" in app


# --- 6. a closed console lost the chart -----------------------------------------------------

class ClosedConsole(io.StringIO):
    def write(self, s):
        raise BrokenPipeError()

    def fileno(self):
        return 1


def test_outputs_written_even_if_console_closes(tmp_path, monkeypatch):
    p = tmp_path / "a.pcap"
    write_pcap(p, [(ts(1_700_000_000), ARP)])
    monkeypatch.setattr("sys.stdout", ClosedConsole())
    monkeypatch.setattr("os.dup2", lambda a, b: None)
    rc = main(["scan", str(p), "-o", str(tmp_path / "i.json"), "--map", str(tmp_path / "m.html")])
    assert rc == 0 and (tmp_path / "i.json").exists() and (tmp_path / "m.html").exists()


# --- 7. map crashed on a damaged inventory ----------------------------------------------------

@pytest.mark.parametrize("content", [
    '{"schema_version": "0.1.0"}',
    '[1, 2, 3]',
    '{"schema_version": "0.1.0", "tool_version": "0.1.0", "redacted": true, "sources": [], '
    '"communications": [], "assets": [{"asset_id": "x"}]}',
    '{"schema_version": "9.0.0", "tool_version": "9", "redacted": true, '
    '"sources": [], "assets": [], "communications": []}',
    'not json',
])
def test_damaged_inventory_gives_clear_error(tmp_path, capsys, content):
    f = tmp_path / "bad.json"
    f.write_text(content)
    assert main(["map", str(f), "-o", str(tmp_path / "m.html")]) == 1
    assert "error:" in capsys.readouterr().err
    assert not (tmp_path / "m.html").exists()


# --- 9. tcpdump -i any captures produced nothing --------------------------------------------

@pytest.mark.parametrize("name", ["cooked_sll2_tcpdump.pcap", "cooked_sll_tcpdump.pcap"])
def test_real_cooked_captures(name):
    out = scan([FIX / name]).to_dict()
    (a,) = out["assets"]
    assert a["identity_key"] == "mac:02:fc:00:00:00:01"
    assert [m["value"] for m in a["ips"]["members"]] == ["192.0.2.2"]
    assert {m["value"] for m in a["roles"]["members"]} == {"nmea0183/talker:he", "nmea0183/sentence:hehdt"}
    assert out["stats"]["frames_cooked_not_ethernet"] == 3


def test_cooked_non_ethernet_and_unknown_linktypes_explained(tmp_path):
    p = tmp_path / "lo.pcap"
    write_pcap(p, [(ts(1_700_000_000), sll("00:00:00:00:00:00", 0x0800, b"\x45" + b"\x00" * 19, hatype=772))],
               linktype=113)
    assert scan([p]).to_dict()["stats"]["frames_cooked_not_ethernet"] == 1
    assert "link type 147" in explain_stat("frames_unsupported_linktype_147")


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
def test_tshark_reads_built_cooked_frames(tmp_path):
    p = tmp_path / "c.pcap"
    f = sll2("00:1d:9c:00:00:05", 0x0806, ARP[14:])
    write_pcap(p, [(ts(1_700_000_000), f)], linktype=276)
    out = subprocess.run(["tshark", "-r", str(p), "-T", "fields", "-e", "sll.src.eth", "-e", "arp.src.proto_ipv4"],
                         capture_output=True, text=True, check=True).stdout.split()
    assert out == ["00:1d:9c:00:00:05", "10.0.0.5"]
    assert scan([p]).to_dict()["assets"][0]["identity_key"] == "mac:00:1d:9c:00:00:05"


def test_render_still_safe_with_cooked_and_registry(tmp_path):
    html = render_html(scan([FIX / "cooked_sll2_tcpdump.pcap"]).to_dict())
    assert html.count("<script") == 3


# --- second review pass ----------------------------------------------------------------

def test_oui_successes_are_not_listed_as_gaps(tmp_path, capsys):
    csv = tmp_path / "oui.csv"
    csv.write_text("Registry,Assignment,Organization Name,Organization Address\nMA-L,001D9C,Rockwell Automation,x\n")
    p = tmp_path / "a.pcap"
    write_pcap(p, [(ts(1_700_000_000), ARP)])
    out = tmp_path / "i.json"
    assert main(["scan", str(p), "-o", str(out), "--oui", str(csv)]) == 0
    text = capsys.readouterr().out
    assert "card maker was found" in text and "not turned into evidence" not in text
    view = build_view(json.loads(out.read_text()))
    assert [g["key"] for g in view["gaps"]] == [] and view["lookups"][0]["key"] == "oui_matched"


def test_pcapng_trailing_length_mismatch_stops_reading(tmp_path):
    good = block(6, struct.pack("<IIIII", 0, 0, 1_700_000_000, 14, 14) + ARP[:14])
    bad = good[:-4] + struct.pack("<I", 999)
    frames, r = read(tmp_path, shb() + idb() + bad + good)
    assert frames == [] and r.stats["capture_corrupt_block_length"] == 1


def test_modbus_from_non_host_address_not_stored(tmp_path):
    hmi, plc = "00:0e:8c:00:00:09", "00:1d:9c:00:00:05"
    rd, rsp = bytes([3, 0, 0, 0, 1]), bytes([3, 2, 0, 7])
    req = ether(plc, hmi, 0x0800, ipv4_tcp("255.255.255.255", "10.0.0.5", 40000, 502, mbap(1, 1, rd)))
    resp = ether(hmi, plc, 0x0800, ipv4_tcp("10.0.0.5", "255.255.255.255", 502, 40000, mbap(1, 1, rsp)))
    p = tmp_path / "b.pcap"
    write_pcap(p, [(ts(1_700_000_000), req), (ts(1_700_000_001), resp)])
    out = scan([p]).to_dict()
    assert out["assets"] == [] and out["stats"]["modbus_endpoint_not_host_ip"] == 2


def test_modbus_device_id_text_is_trimmed():
    from keelmap.decoders.modbus import _device_id
    pdu = bytes([0x2B, 0x0E, 1, 1, 0, 0, 1, 0x00, 6]) + b"Acme \x00"
    assert _device_id(pdu) == {0: "Acme"}


def test_fragmented_nmea_counted(tmp_path):
    body = "HEHDT,274.07,T"
    frag = ether(BCAST, "00:a0:c8:00:00:10", 0x0800,
                 ipv4_udp("10.0.1.10", "10.0.1.255", 10110, 10110, f"${body}*{cks(body)}".encode(), frag=0x2000))
    p = tmp_path / "f.pcap"
    write_pcap(p, [(ts(1_700_000_000), frag)])
    out = scan([p]).to_dict()
    assert out["assets"] == [] and out["stats"]["nmea_ip_fragment_skipped"] == 1


def test_map_and_output_must_differ(tmp_path):
    p = tmp_path / "a.pcap"
    write_pcap(p, [(ts(1_700_000_000), ARP)])
    same = tmp_path / "x.json"
    assert main(["scan", str(p), "-o", str(same), "--map", str(same)]) == 2
    assert not same.exists()


def test_ais_type19_name_is_decoded():
    from keelmap.decoders.ais import dearmor, decode_identity
    # real class B extended report from the pyais test data, pyais reads MMSI 412432822, name ZHECANGYU4078
    bits = dearmor("C69DqeP0Ar8;JH3R6<4O7wWPl@:62L>jcaQgh0000000?104222P", 0)
    ident = decode_identity(bits)
    assert (ident.msg_type, ident.mmsi, ident.name) == (19, 412432822, "ZHECANGYU4078")
