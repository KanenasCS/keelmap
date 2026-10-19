"""Precision contract tests. If one of these fails, the contract was weakened."""

import json
from datetime import datetime, timezone

import pytest

from keelmap.model import (
    Asset,
    Communication,
    Evidence,
    EvidenceKind,
    FieldState,
    Inventory,
    PrecisionViolation,
)

SHA = "a" * 64
T0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc)


def ev(kind=EvidenceKind.OBSERVED, frames=(1,), ts=T0, decoder="modbus@0.1.0", detail="test frame"):
    return Evidence(kind, SHA, tuple(frames), ts, decoder, detail)


# --- Evidence is verifiable ---------------------------------------------------

def test_observed_evidence_must_cite_frames():
    with pytest.raises(PrecisionViolation):
        ev(frames=())


def test_registry_evidence_needs_no_frames():
    ev(kind=EvidenceKind.REGISTRY, frames=(), decoder="oui@0.1.0")


def test_naive_timestamp_rejected():
    with pytest.raises(PrecisionViolation):
        ev(ts=datetime(2026, 10, 1, 8, 0))


def test_decoder_must_be_versioned():
    with pytest.raises(PrecisionViolation):
        ev(decoder="modbus")


def test_detail_required():
    with pytest.raises(PrecisionViolation):
        ev(detail="  ")


# --- Fields start unknown and stay honest -------------------------------------

def test_new_asset_is_all_unknown():
    a = Asset("mac:00:1d:9c:00:00:01")
    for f in (a.hostname, a.device_vendor, a.device_model, a.firmware, a.nic_vendor):
        assert f.state is FieldState.UNKNOWN
        assert f.value is None
    assert a.ips.state is FieldState.UNKNOWN


def test_empty_value_rejected_instead_of_stored():
    a = Asset("ip:10.0.0.5")
    with pytest.raises(PrecisionViolation):
        a.hostname.add("", ev(kind=EvidenceKind.SELF_REPORTED, decoder="dhcp@0.1.0"))


def test_disagreeing_claims_become_conflict_not_a_pick():
    a = Asset("ip:10.0.0.5")
    a.device_model.add("Model-A", ev(kind=EvidenceKind.SELF_REPORTED, frames=(10,)))
    a.device_model.add("Model-B", ev(kind=EvidenceKind.SELF_REPORTED, frames=(20,)))
    assert a.device_model.state is FieldState.CONFLICT
    assert a.device_model.value is None
    d = a.to_dict()["device_model"]
    assert {c["value"] for c in d["claims"]} == {"Model-A", "Model-B"}


def test_repeat_claim_stays_known():
    a = Asset("ip:10.0.0.5")
    a.device_model.add("Model-A", ev(kind=EvidenceKind.SELF_REPORTED, frames=(10,)))
    a.device_model.add("Model-A", ev(kind=EvidenceKind.SELF_REPORTED, frames=(30,)))
    assert a.device_model.state is FieldState.KNOWN
    assert len(a.device_model.evidence()) == 2


# --- Fields only accept the right kind of evidence ----------------------------

def test_device_vendor_cannot_come_from_mac_prefix():
    a = Asset("mac:00:1d:9c:00:00:01")
    oui = ev(kind=EvidenceKind.REGISTRY, frames=(), decoder="oui@0.1.0", detail="IEEE OUI 00:1d:9c")
    with pytest.raises(PrecisionViolation):
        a.device_vendor.add("Rockwell", oui)
    a.nic_vendor.add("Rockwell", oui)   # allowed, and labelled as the NIC vendor only
    assert a.device_vendor.state is FieldState.UNKNOWN


def test_device_vendor_cannot_come_from_traffic_patterns():
    a = Asset("ip:10.0.0.5")
    with pytest.raises(PrecisionViolation):
        a.device_vendor.add("Siemens", ev(kind=EvidenceKind.OBSERVED, detail="talks S7 on 102"))


def test_roles_need_observed_evidence():
    a = Asset("ip:10.0.0.5")
    with pytest.raises(PrecisionViolation):
        a.roles.add("modbus/server", ev(kind=EvidenceKind.SELF_REPORTED))
    a.roles.add("modbus/server", ev(detail="response to FC03 from 10.0.0.9"))
    assert "modbus/server" in a.roles


def test_role_vocabulary_is_controlled():
    a = Asset("ip:10.0.0.5")
    with pytest.raises(PrecisionViolation):
        a.roles.add("PLC", ev())


def test_mac_format_enforced():
    with pytest.raises(PrecisionViolation):
        Asset("mac:00-1D-9C-00-00-01")
    a = Asset("ip:10.0.0.5")
    with pytest.raises(PrecisionViolation):
        a.macs.add("00:1D:9C:00:00:01", ev())


# --- Communications -----------------------------------------------------------

def test_communications_only_from_observed_traffic():
    inv = Inventory("0.1.0")
    c = inv.communication(inv.asset("ip:10.0.0.9"), inv.asset("ip:10.0.0.5"), "tcp", "modbus", 502)
    with pytest.raises(PrecisionViolation):
        c.record(ev(kind=EvidenceKind.SELF_REPORTED))


def test_l2_has_no_port():
    with pytest.raises(PrecisionViolation):
        Communication("a", "b", "l2", "arp", 0)


def test_evidence_sample_is_capped_but_counts_are_not():
    inv = Inventory("0.1.0")
    c = inv.communication(inv.asset("ip:10.0.0.9"), inv.asset("ip:10.0.0.5"), "tcp", "modbus", 502)
    for i in range(1, 51):
        c.record(ev(frames=(i,)))
    assert c.packet_count == 50
    assert len(c.evidence_sample) == Communication.SAMPLE_CAP


# --- Export -------------------------------------------------------------------

def test_unevidenced_assets_are_not_exported():
    inv = Inventory("0.1.0")
    inv.asset("ip:10.0.0.99")   # created, never seen
    seen = inv.asset("ip:10.0.0.5")
    seen.ips.add("10.0.0.5", ev())
    out = inv.to_dict()
    assert [a["identity_key"] for a in out["assets"]] == ["ip:10.0.0.5"]


def test_registry_lookup_alone_does_not_prove_existence():
    inv = Inventory("0.1.0")
    a = inv.asset("mac:00:1d:9c:00:00:01")
    a.nic_vendor.add("Rockwell", ev(kind=EvidenceKind.REGISTRY, frames=(), decoder="oui@0.1.0"))
    assert inv.to_dict()["assets"] == []


def test_communication_alone_proves_both_endpoints_exist():
    inv = Inventory("0.1.0")
    c = inv.communication(inv.asset("ip:10.0.0.9"), inv.asset("ip:10.0.0.5"), "tcp", "modbus", 502)
    c.record(ev(frames=(3,), ts=T0))
    c.record(ev(frames=(4,), ts=T1))
    assets = inv.to_dict()["assets"]
    assert len(assets) == 2
    assert all(a["first_seen"] == T0.isoformat() and a["last_seen"] == T1.isoformat() for a in assets)


def test_vessel_identifiers_redacted_by_default():
    inv = Inventory("0.1.0")
    a = inv.asset("ip:10.0.0.20")
    a.vessel_identifiers.add("mmsi:237000000", ev(decoder="nmea0183@0.1.0", detail="!AIVDO type 1"))
    blob = json.dumps(inv.to_dict())
    assert "237000000" not in blob
    assert "redacted:" in blob
    assert "237000000" in json.dumps(inv.to_dict(redact=False))


def test_capture_filename_redacted_by_default():
    from keelmap.model import SourceCapture
    inv = Inventory("0.1.0")
    inv.sources.append(SourceCapture("MV_Example_bridge.pcap", SHA, 100, T0, T1))
    assert "MV_Example" not in json.dumps(inv.to_dict())


def test_export_is_json_serialisable_and_versioned():
    inv = Inventory("0.1.0")
    a = inv.asset("mac:00:1d:9c:00:00:01")
    a.macs.add("00:1d:9c:00:00:01", ev(decoder="arp@0.1.0", detail="ARP reply sender"))
    a.ips.add("10.0.0.5", ev(decoder="arp@0.1.0", detail="ARP reply sender"))
    out = json.loads(json.dumps(inv.to_dict()))
    assert out["schema_version"] == "0.1.0"
    assert out["assets"][0]["device_vendor"]["state"] == "unknown"


def test_merge_keeps_exact_counts_and_times():
    a, b = Asset("ip:10.0.0.5"), Asset("ip:10.0.0.5")
    a.roles.add("modbus/server", ev(frames=(1,), ts=T0))
    b.roles.add("modbus/server", ev(frames=(2,), ts=T1))
    b.roles.add("modbus/server", ev(frames=(3,), ts=T1))
    a.merge_from(b)
    m = a.to_dict()["roles"]["members"][0]
    assert m["evidence_count"] == 3
    assert a.to_dict()["first_seen"] == T0.isoformat() and a.to_dict()["last_seen"] == T1.isoformat()


def test_repeated_record_counted_once():
    a = Asset("ip:10.0.0.5")
    a.roles.add("modbus/server", ev(frames=(1,)))
    a.roles.add("modbus/server", ev(frames=(1,)))   # same record twice in a row
    assert a.to_dict()["roles"]["members"][0]["evidence_count"] == 1


def test_verification_mode_catches_broken_assumptions(monkeypatch):
    import keelmap.model as m
    monkeypatch.setattr(m, "VERIFY_EVIDENCE", True)
    a, b = Asset("ip:10.0.0.5"), Asset("ip:10.0.0.5")
    a.roles.add("modbus/server", ev(frames=(1,)))
    a.roles.add("modbus/server", ev(frames=(2,)))
    with pytest.raises(PrecisionViolation):
        a.roles.add("modbus/server", ev(frames=(1,)))   # repeat, not straight after
    b.roles.add("modbus/server", ev(frames=(2,)))
    with pytest.raises(PrecisionViolation):
        a.merge_from(b)                                    # overlap would double count


def test_bad_field_pairing_refused():
    a, b = Asset("ip:10.0.0.5"), Asset("ip:10.0.0.6")
    b._fields = lambda: list(reversed(Asset._fields(b)))
    with pytest.raises(PrecisionViolation):
        a.merge_from(b)


def test_evidence_sample_capped_with_exact_count():
    a = Asset("ip:10.0.0.5")
    for i in range(1, 101):
        a.roles.add("modbus/server", ev(frames=(i,)))
    m = a.to_dict()["roles"]["members"][0]
    assert m["evidence_count"] == 100 and len(m["evidence"]) == 10
