"""AIS payload tests. Reference values decoded by pyais, see fixtures/public/nmea_samples.source.md."""

from pathlib import Path

import pytest

from keelmap.decoders.ais import AisError, FragmentBuffer, dearmor, decode_identity, imo_valid

L = (Path(__file__).parent / "fixtures/public/nmea_samples.txt").read_text().splitlines()


def payload_of(*lines):
    fields = [ln[ln.index("!") + 1:ln.index("*")].split(",") for ln in lines]
    return "".join(f[5] for f in fields), int(fields[-1][6])


def test_dearmor_bounds():
    assert dearmor("0", 0) == "000000" and dearmor("w", 0) == "111111"
    assert dearmor("w", 2) == "1111"
    for bad in ("X", "_", "x", " "):
        with pytest.raises(AisError):
            dearmor(bad, 0)


def test_imo_check_digit():
    assert imo_valid(6514895) and imo_valid(8867052)
    assert not imo_valid(6514894) and not imo_valid(0) and not imo_valid(123456)


def test_type1_mmsi():
    ident = decode_identity(dearmor(*payload_of(L[0])))
    assert (ident.msg_type, ident.mmsi, ident.imo, ident.name) == (1, 247049900, None, None)


def test_type5_identity():
    ident = decode_identity(dearmor(*payload_of(L[1], L[2])))
    assert (ident.mmsi, ident.imo, ident.callsign, ident.name) == (258315000, 6514895, "LFNA", "FALKVIK")


def test_leading_padding_stripped():
    ident = decode_identity(dearmor(*payload_of(L[3], L[4])))
    assert ident.callsign == "UANX" and ident.name == "OMSKIY-140"


def test_truncated_type5_reads_only_complete_fields():
    bits = dearmor(*payload_of(L[1], L[2]))[:100]
    ident = decode_identity(bits)
    assert ident.mmsi == 258315000 and ident.imo == 6514895
    assert ident.name is None and "type5_truncated" in ident.rejected


def test_bad_imo_dropped_but_mmsi_kept():
    bits = list(dearmor(*payload_of(L[1], L[2])))
    bits[69] = "0" if bits[69] == "1" else "1"     # flip lowest IMO bit
    ident = decode_identity("".join(bits))
    assert ident.mmsi == 258315000 and ident.imo is None
    assert "imo_check_digit_failed" in ident.rejected


def test_fragments_in_order_complete():
    fb = FragmentBuffer()
    assert fb.add(("s",), "VDM", 2, 1, "9", "B", "AAA", 0, 1) is None
    assert fb.add(("s",), "VDM", 2, 2, "9", "B", "BBB", 2, 2) == ("AAABBB", 2, [1, 2])
    assert fb.close() == 0


def test_fragments_out_of_order_are_incomplete():
    fb = FragmentBuffer()
    assert fb.add(("s",), "VDM", 2, 2, "9", "B", "BBB", 2, 2) is None
    assert fb.add(("s",), "VDM", 2, 1, "9", "B", "AAA", 0, 1) is None
    assert fb.close() == 2


def test_fragments_from_different_sources_do_not_mix():
    fb = FragmentBuffer()
    fb.add(("a",), "VDM", 2, 1, "9", "B", "AAA", 0, 1)
    assert fb.add(("b",), "VDM", 2, 2, "9", "B", "BBB", 2, 2) is None
    assert fb.close() == 2
