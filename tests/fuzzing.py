"""Mutation fuzzing with invariant checks, shared by the CI smoke test and tools/fuzz.py.

Every run checks more than "no crash": each exported value must have evidence,
cite frames that exist in its capture, carry a timestamp inside the capture, be
filled only from evidence kinds its field allows, and redacted exports must not
contain raw vessel identifiers. Runs with evidence verification on.
"""

from __future__ import annotations

import json
import os
import random
import struct
from pathlib import Path

os.environ["KEELMAP_VERIFY_EVIDENCE"] = "1"

from keelmap.capture import CaptureError, CaptureReader  # noqa: E402
from keelmap.report.render import render_html  # noqa: E402
from keelmap.report.view import validate_inventory  # noqa: E402
from keelmap.scan import scan  # noqa: E402

INTERESTING = [0, 1, 2, 4, 6, 7, 12, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF]
ALLOWED = {"macs": {"observed"}, "ips": {"observed"}, "roles": {"observed"}, "nic_vendor": {"registry"},
           "hostname": {"self_reported"}, "device_vendor": {"self_reported"}, "device_model": {"self_reported"},
           "firmware": {"self_reported"}, "description": {"self_reported"}, "capabilities": {"self_reported"},
           "device_ids": {"self_reported"}, "vessel_identifiers": {"observed", "self_reported"}}


def mutate_bytes(data: bytes, rng: random.Random, others: list[bytes]) -> bytes:
    d = bytearray(data)
    for _ in range(rng.choice([1, 1, 2, 3, 8])):
        if not d:
            break
        lo = 24 if rng.random() < 0.8 and len(d) > 40 else 0
        i = rng.randrange(lo, len(d)) if len(d) > lo else 0
        op = rng.randrange(7)
        if op == 0:
            d[i] ^= 1 << rng.randrange(8)
        elif op == 1:
            d[i] = rng.choice([0, 0xFF, 0x7F, 0x80, rng.randrange(256)])
        elif op == 2 and i + 4 <= len(d):
            d[i:i + 4] = struct.pack(rng.choice("<>") + "I", rng.choice(INTERESTING))
        elif op == 3 and i + 2 <= len(d):
            d[i:i + 2] = struct.pack("!H", rng.choice(INTERESTING) & 0xFFFF)
        elif op == 4:
            d = d[:i]
        elif op == 5:
            j = rng.randrange(len(d))
            d[i:i] = d[j:j + rng.randrange(1, 64)]
        elif op == 6:
            other = rng.choice(others)
            j = rng.randrange(len(other))
            d = d[:i] + other[j:j + rng.randrange(1, 400)]
    return bytes(d)


def frames_of(path: Path) -> list[tuple[int, bytes]]:
    try:
        return [(f.linktype, f.data) for f in CaptureReader(path)]
    except CaptureError:
        return []


def mutate_frames(frames: list[tuple[int, bytes]], rng: random.Random) -> list[tuple[int, bytes]]:
    out = list(frames)
    for _ in range(rng.choice([1, 1, 2, 4])):
        i = rng.randrange(len(out))
        lt, d = out[i]
        b = bytearray(d)
        for _ in range(rng.choice([1, 2, 3, 6])):
            if not b:
                break
            j = rng.randrange(14 if len(b) > 20 and rng.random() < 0.7 else 0, len(b))
            op = rng.randrange(5)
            if op == 0:
                b[j] ^= 1 << rng.randrange(8)
            elif op == 1:
                b[j] = rng.choice([0, 1, 0xFF, 0x7F, 0x80, rng.randrange(256)])
            elif op == 2 and j + 2 <= len(b):
                b[j:j + 2] = struct.pack("!H", rng.choice(INTERESTING) & 0xFFFF)
            elif op == 3:
                b = b[:j]
            elif op == 4:
                b[j:j] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 30)))
        out[i] = (lt, bytes(b))
    if rng.random() < 0.2:
        rng.shuffle(out)
    return out


def write_frames(path: Path, frames: list[tuple[int, bytes]]) -> None:
    linktype = frames[0][0] if frames else 1
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for i, (_, d) in enumerate(frames):
        out += struct.pack("<IIII", 1_700_000_000 + i, 0, len(d), len(d)) + d
    path.write_bytes(out)


def check(path: Path) -> list[str]:
    """Scan, export and render. Return invariant violations. Exceptions propagate."""
    inv = scan([path])
    full = inv.to_dict(redact=False)
    red = inv.to_dict(redact=True)
    json.dumps(red)
    render_html(red)
    validate_inventory(red)
    problems = []
    # the same capture must always give the same inventory
    if scan([path]).to_dict(redact=False) != full:
        problems.append("scan is not deterministic")
    if len({a["asset_id"] for a in full["assets"]}) != len(full["assets"]):
        problems.append("duplicate asset ids")
    if len({a["identity_key"] for a in full["assets"]}) != len(full["assets"]):
        problems.append("duplicate identity keys")
    for s in full["sources"]:
        if s["start"] and s["end"] and s["start"] > s["end"]:
            problems.append("capture start after end")
    for k, v in full["stats"].items():
        if not isinstance(v, int) or v < 0:
            problems.append(f"stat {k} is not a count")
    for a in full["assets"]:
        if a["first_seen"] is None or a["first_seen"] > a["last_seen"]:
            problems.append("asset first_seen after last_seen or missing")
        counts = {m["value"]: m["evidence_count"] for m in a["roles"]["members"]}
        served = sum(v for k, v in counts.items() if k.startswith("modbus/unit_id:") or k == "modbus/gateway")
        if counts.get("modbus/server", 0) != served:
            problems.append("modbus server count differs from unit and gateway counts")
        answered = sum(c["exchange_count"] for c in full["communications"]
                       if c["dst_asset_id"] == a["asset_id"] and c["protocol"] == "modbus")
        if counts.get("modbus/server", 0) != answered:
            problems.append("modbus server count differs from exchanges answered")
        sent = sum(c["exchange_count"] for c in full["communications"]
                   if c["src_asset_id"] == a["asset_id"] and c["protocol"] == "modbus")
        if counts.get("modbus/client", 0) != sent:
            problems.append("modbus client count differs from exchanges sent")
        talkers = sum(v for k, v in counts.items() if k.startswith("nmea0183/talker:"))
        sentences = sum(v for k, v in counts.items() if k.startswith("nmea0183/sentence:"))
        if talkers != sentences:
            problems.append("nmea talker and sentence counts differ")
    for c in full["communications"]:
        if c["first_seen"] > c["last_seen"]:
            problems.append("communication first_seen after last_seen")
        ops = sum(m["evidence_count"] for m in c["operations"]["members"])
        if c["protocol"] == "modbus" and ops != c["exchange_count"]:
            problems.append("modbus operation counts differ from exchanges")
        if not 1 <= c["packet_count"] <= 2 * c["exchange_count"]:
            problems.append("communication packet count out of range")
        for e in c["evidence_sample"]:
            if len(set(e["frames"])) != len(e["frames"]):
                problems.append("evidence cites a frame twice")
    sources = {s["sha256"]: s for s in full["sources"]}
    ids = {a["asset_id"] for a in full["assets"]}
    for a in full["assets"]:
        for name, allowed in ALLOWED.items():
            f = a[name]
            entries = f.get("claims", f.get("members", []))
            if f["state"] == "unknown" and entries:
                problems.append(f"{name}: unknown with entries")
            if "claims" in f and f["state"] == "known" and len(entries) != 1:
                problems.append(f"{name}: known with {len(entries)} claims")
            if "claims" in f and f["state"] == "conflict" and len(entries) < 2:
                problems.append(f"{name}: conflict with {len(entries)} claims")
            for c in entries:
                if c["evidence_count"] < max(1, len(c["evidence"])):
                    problems.append(f"{name}: count below sample size")
                for e in c["evidence"]:
                    if e["kind"] not in allowed:
                        problems.append(f"{name}: filled from {e['kind']}")
                    if e["kind"] == "registry":
                        continue
                    s = sources.get(e["source_sha256"])
                    if s is None:
                        problems.append(f"{name}: cites an unknown capture")
                        continue
                    if any(not 1 <= fr <= s["frame_count"] for fr in e["frames"]):
                        problems.append(f"{name}: cites a frame outside the capture")
                    if s["start"] and not s["start"] <= e["timestamp"] <= s["end"]:
                        problems.append(f"{name}: timestamp outside the capture")
    for c in full["communications"]:
        if c["src_asset_id"] not in ids or c["dst_asset_id"] not in ids:
            problems.append("communication to an asset that is not exported")
    blob = json.dumps(red)
    for a in full["assets"]:
        for m in a["vessel_identifiers"]["members"]:
            raw = m["value"].split(":", 1)[1]
            if len(raw) >= 4 and raw in blob:
                problems.append("vessel identifier visible in redacted export")
    return problems


def run(seed_files: list[Path], iterations: int, seed: int, workdir: Path) -> dict:
    """Run both mutation modes. Returns failures keyed by kind, with the input that caused them."""
    rng = random.Random(seed)
    raw = [p.read_bytes() for p in seed_files]
    frame_sets = [f for f in (frames_of(p) for p in seed_files) if f]
    failures: dict[str, Path] = {}
    for n in range(iterations):
        path = workdir / f"case_{n}.pcap"
        if n % 2 == 0:
            path.write_bytes(mutate_bytes(rng.choice(raw), rng, raw))
        else:
            write_frames(path, mutate_frames(rng.choice(frame_sets), rng))
        try:
            problems = check(path)
        except CaptureError:
            problems = []
        except Exception as e:  # noqa: BLE001 - any escape is a finding
            problems = [f"{type(e).__name__}: {e}"]
        for p in problems:
            key = p[:90]
            if key not in failures:
                keep = workdir / f"failure_{len(failures)}.pcap"
                keep.write_bytes(path.read_bytes())
                failures[key] = keep
        path.unlink(missing_ok=True)
    return failures
