"""Reader tests. Frame numbers and timestamps must match what Wireshark shows."""

import shutil
import subprocess

import pytest
from pcapgen import arp, ether, ts, write_pcap, write_pcapng

from keelmap.capture import CaptureError, CaptureReader

F = ether("ff:ff:ff:ff:ff:ff", "00:1d:9c:00:00:01", 0x0806,
          arp(1, "00:1d:9c:00:00:01", "10.0.0.5", "00:00:00:00:00:00", "10.0.0.1"))
T = [ts(1_790_000_000, 1), ts(1_790_000_001, 250_000), ts(1_790_000_002, 999_999)]


@pytest.mark.parametrize("nanos,big", [(False, False), (True, False), (False, True), (True, True)])
def test_classic_pcap_variants(tmp_path, nanos, big):
    p = tmp_path / "x.pcap"
    write_pcap(p, [(t, F) for t in T], nanos=nanos, big_endian=big)
    r = CaptureReader(p)
    frames = list(r)
    assert [f.number for f in frames] == [1, 2, 3]
    assert [f.timestamp for f in frames] == T
    assert all(f.linktype == 1 and f.data == F for f in frames)
    assert (r.first_ts, r.last_ts, r.frame_count) == (T[0], T[2], 3)


@pytest.mark.parametrize("tsresol", [None, 6, 9, 0x80 | 20])
def test_pcapng_resolutions(tmp_path, tsresol):
    p = tmp_path / "x.pcapng"
    write_pcapng(p, [(t, F) for t in T], tsresol=tsresol)
    frames = list(CaptureReader(p))
    if tsresol is not None and tsresol & 0x80:
        # Binary ticks do not land on microseconds, so allow one microsecond.
        assert all(abs((f.timestamp - t).total_seconds()) <= 1e-6 for f, t in zip(frames, T, strict=True))
    else:
        assert [f.timestamp for f in frames] == T


def test_simple_packet_block_keeps_numbering(tmp_path):
    p = tmp_path / "x.pcapng"
    write_pcapng(p, [(T[0], F), (None, F), (T[2], F)])
    r = CaptureReader(p)
    frames = list(r)
    assert [f.number for f in frames] == [1, 3]
    assert r.frame_count == 3
    assert r.stats["frame_without_timestamp"] == 1


def test_nanoseconds_round_to_nearest_microsecond(tmp_path):
    p = tmp_path / "x.pcapng"
    write_pcapng(p, [(T[2], F)], tsresol=9)
    raw = p.read_bytes()
    # add 600 ns to the stored ticks: 999_999 us + 600 ns rounds up into the next second
    import struct
    i = raw.index(struct.pack("<I", 6), 28)
    hi, lo = struct.unpack("<II", raw[i + 12:i + 20])
    ticks = ((hi << 32) | lo) + 600
    p.write_bytes(raw[:i + 12] + struct.pack("<II", ticks >> 32, ticks & 0xFFFFFFFF) + raw[i + 20:])
    (f,) = list(CaptureReader(p))
    assert f.timestamp == ts(1_790_000_003, 0)


def test_truncated_file_keeps_complete_frames(tmp_path):
    p = tmp_path / "x.pcap"
    write_pcap(p, [(t, F) for t in T])
    p.write_bytes(p.read_bytes()[:-10])
    r = CaptureReader(p)
    assert [f.number for f in r] == [1, 2]
    assert r.stats["capture_truncated"] == 1


def test_not_a_capture(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"hello world, not a capture")
    with pytest.raises(CaptureError):
        list(CaptureReader(p))


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")
@pytest.mark.parametrize("fmt", ["pcap", "pcapng"])
def test_frame_numbers_and_times_agree_with_tshark(tmp_path, fmt):
    p = tmp_path / f"x.{fmt}"
    if fmt == "pcap":
        write_pcap(p, [(t, F) for t in T], nanos=True)
    else:
        write_pcapng(p, [(T[0], F), (None, F), (T[2], F)], tsresol=9)
    out = subprocess.run(["tshark", "-r", str(p), "-T", "fields", "-e", "frame.number", "-e", "frame.time_epoch"],
                         capture_output=True, text=True, check=True).stdout.split("\n")
    truth = {int(n): e for n, e in (line.split("\t") for line in out if line.strip())}
    for f in CaptureReader(p):
        assert abs(f.timestamp.timestamp() - float(truth[f.number])) < 1e-6
