"""KeelMap asset data model.

The precision contract lives here, in code, so no decoder can bypass it.

Rules enforced by this module:
  1. Every value carries evidence. A value without evidence cannot be stored.
  2. There is no "inferred" evidence kind. Values come only from traffic that
     was observed, from a device describing itself, or from a public registry.
  3. Each field declares which evidence kinds may fill it. Device vendor can
     only come from the device itself, never from a MAC prefix lookup.
  4. Missing data reads as "unknown". Disagreeing data reads as "conflict"
     with every claim and its evidence kept, never silently resolved.
  5. Sensitive vessel identifiers are redacted on export unless the caller
     explicitly asks otherwise. Redaction uses a secret key (HMAC-SHA256), so a
     token cannot be reversed by trying every possible MMSI or IMO number.

Memory stays bounded however long the capture: each value keeps an exact count,
first and last time, and a small sample of citations, never every record.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import os
import re
import secrets
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Generic, Hashable, Iterable, TypeVar

SCHEMA_VERSION = "0.1.0"

# Verification mode for tests and fuzzing: remember every evidence record and
# fail loudly if the "each record arrives once" assumption is ever broken.
VERIFY_EVIDENCE = os.environ.get("KEELMAP_VERIFY_EVIDENCE") == "1"

T = TypeVar("T", bound=Hashable)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DECODER_RE = re.compile(r"^[a-z0-9_]+@\d+\.\d+\.\d+$")
_ROLE_RE = re.compile(r"^[a-z0-9_]+/[a-z0-9_:.\-]+$")
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


class PrecisionViolation(ValueError):
    """Raised when code tries to store something the contract forbids."""


class EvidenceKind(str, enum.Enum):
    OBSERVED = "observed"            # behaviour seen in traffic (sent, received, responded)
    SELF_REPORTED = "self_reported"  # the device said it about itself (LLDP, DHCP, Modbus device ID)
    REGISTRY = "registry"            # public registry lookup, e.g. IEEE OUI for a NIC vendor


class FieldState(str, enum.Enum):
    KNOWN = "known"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


@dataclass(frozen=True)
class Evidence:
    """Where a value came from, precise enough to verify in Wireshark."""

    kind: EvidenceKind
    source_sha256: str            # hash of the capture file
    frames: tuple[int, ...]       # 1-based frame numbers, as Wireshark shows them
    timestamp: datetime           # capture time of the first listed frame, timezone-aware
    decoder: str                  # "modbus@0.1.0"
    detail: str                   # short note, e.g. "MEI 0x0E object 0x01 ProductCode"

    def __post_init__(self) -> None:
        if not _SHA256_RE.match(self.source_sha256):
            raise PrecisionViolation("source_sha256 must be 64 lowercase hex characters")
        if self.kind is not EvidenceKind.REGISTRY:
            if not self.frames:
                raise PrecisionViolation(f"{self.kind.value} evidence must cite at least one frame")
            if any(f < 1 for f in self.frames):
                raise PrecisionViolation("frame numbers are 1-based")
        if self.timestamp.tzinfo is None:
            raise PrecisionViolation("timestamp must be timezone-aware")
        if not _DECODER_RE.match(self.decoder):
            raise PrecisionViolation("decoder must look like name@major.minor.patch")
        if not self.detail.strip():
            raise PrecisionViolation("detail must say what in the frame supports the value")

    def to_dict(self) -> dict:
        return {
            "kind": self.kind.value,
            "source_sha256": self.source_sha256,
            "frames": list(self.frames),
            "timestamp": self.timestamp.isoformat(),
            "decoder": self.decoder,
            "detail": self.detail,
        }


class _Claim:
    """Evidence for one value: exact count and time range, plus a capped sample of citations.

    Decoders emit each record once, and a repeat can only arrive straight after
    the original (two identical sentences in one datagram, for example), so
    comparing with the previous record keeps counts exact without remembering
    every record. merge() requires the two claims to share no records, which
    holds because every frame is decoded once and staged assets are keyed by source.
    """

    SAMPLE_CAP = 10
    __slots__ = ("sample", "count", "first", "last", "_last", "_all")

    def __init__(self) -> None:
        self.sample: list[Evidence] = []
        self.count = 0
        self.first: datetime | None = None
        self.last: datetime | None = None
        self._last: Evidence | None = None
        self._all: set[Evidence] | None = set() if VERIFY_EVIDENCE else None

    def add(self, e: Evidence) -> None:
        if e == self._last:
            return
        if self._all is not None:
            if e in self._all:
                raise PrecisionViolation(f"evidence repeated out of order: {e.detail}")
            self._all.add(e)
        self._last = e
        self.count += 1
        if len(self.sample) < self.SAMPLE_CAP:
            self.sample.append(e)
        if e.kind is not EvidenceKind.REGISTRY:
            self.first = e.timestamp if self.first is None else min(self.first, e.timestamp)
            self.last = e.timestamp if self.last is None else max(self.last, e.timestamp)

    def merge(self, other: "_Claim") -> None:
        if self._all is not None and other._all is not None:
            if self._all & other._all:
                raise PrecisionViolation("merged claims share evidence records")
            self._all |= other._all
        for e in other.sample:
            if len(self.sample) < self.SAMPLE_CAP and e not in self.sample:
                self.sample.append(e)
        self.count += other.count
        for t in (other.first, other.last):
            if t is not None:
                self.first = t if self.first is None else min(self.first, t)
                self.last = t if self.last is None else max(self.last, t)

    def to_dict(self, value: object) -> dict:
        return {"value": value, "evidence_count": self.count,
                "evidence": [e.to_dict() for e in self.sample]}


class Redactor:
    """Turns sensitive values into tokens with a secret key.

    With a random key (the default) tokens differ between exports and cannot be
    linked or reversed. With a key you keep, the same value always gets the same
    token, so exports can be compared, and only key holders can test a guess.
    """

    def __init__(self, key: bytes | None = None):
        self.from_file = key is not None
        self.key = key if key is not None else secrets.token_bytes(32)
        if len(self.key) < 16:
            raise ValueError("redaction key must be at least 16 bytes")

    def token(self, value: object) -> str:
        return "redacted:" + hmac.new(self.key, str(value).encode(), hashlib.sha256).hexdigest()[:16]

    def describe(self) -> dict:
        if self.from_file:
            return {"method": "hmac-sha256", "key": "supplied",
                    "key_id": hashlib.sha256(b"keelmap-key-id" + self.key).hexdigest()[:12]}
        return {"method": "hmac-sha256", "key": "random, discarded after export"}


def _as_redactor(redact: "Redactor | bool") -> "Redactor | None":
    if isinstance(redact, Redactor):
        return redact
    return Redactor() if redact else None


class Attested(Generic[T]):
    """A single-valued field. Unknown until evidenced, conflict if claims disagree."""

    def __init__(self, name: str, allowed: Iterable[EvidenceKind], sensitive: bool = False):
        self.name = name
        self.allowed = frozenset(allowed)
        self.sensitive = sensitive
        self._claims: dict[T, _Claim] = {}

    def add(self, value: T, evidence: Evidence) -> None:
        if value is None or (isinstance(value, str) and not value.strip()):
            raise PrecisionViolation(f"{self.name}: empty values are not stored, leave it unknown")
        if evidence.kind not in self.allowed:
            allowed = ", ".join(sorted(k.value for k in self.allowed))
            raise PrecisionViolation(
                f"{self.name} cannot be filled from {evidence.kind.value} evidence (allowed: {allowed})"
            )
        self._claims.setdefault(value, _Claim()).add(evidence)

    @property
    def state(self) -> FieldState:
        if not self._claims:
            return FieldState.UNKNOWN
        return FieldState.KNOWN if len(self._claims) == 1 else FieldState.CONFLICT

    @property
    def value(self) -> T | None:
        """Only returns a value when exactly one is evidenced."""
        if self.state is FieldState.KNOWN:
            return next(iter(self._claims))
        return None

    def evidence(self) -> list[Evidence]:
        """The sampled evidence. Use evidence_count for totals."""
        return [e for c in self._claims.values() for e in c.sample]

    def evidence_count(self) -> int:
        return sum(c.count for c in self._claims.values())

    def merge_from(self, other: "Attested[T]") -> None:
        """Merge claims from the same field of another asset. Kinds were checked when first added."""
        if other.allowed - self.allowed:
            raise PrecisionViolation(f"{self.name}: cannot merge a field with wider evidence rules")
        for v, c in other._claims.items():
            self._claims.setdefault(v, _Claim()).merge(c)

    def seen_range(self) -> list[datetime]:
        return [t for c in self._claims.values() for t in (c.first, c.last) if t is not None]

    def to_dict(self, redact: "Redactor | bool") -> dict:
        r = _as_redactor(redact) if self.sensitive else None
        out: dict = {"state": self.state.value}
        if self.state is FieldState.KNOWN:
            out["value"] = r.token(self.value) if r else self.value
        out["claims"] = [c.to_dict(r.token(v) if r else v) for v, c in self._claims.items()]
        return out


class AttestedSet(Generic[T]):
    """A multi-valued field (an asset can have several IPs). Each member has its own evidence."""

    def __init__(self, name: str, allowed: Iterable[EvidenceKind],
                 pattern: re.Pattern[str] | None = None, sensitive: bool = False):
        self.name = name
        self.allowed = frozenset(allowed)
        self.pattern = pattern
        self.sensitive = sensitive
        self._members: dict[T, _Claim] = {}

    def add(self, value: T, evidence: Evidence) -> None:
        if value is None or (isinstance(value, str) and not value.strip()):
            raise PrecisionViolation(f"{self.name}: empty values are not stored")
        if evidence.kind not in self.allowed:
            allowed = ", ".join(sorted(k.value for k in self.allowed))
            raise PrecisionViolation(
                f"{self.name} cannot be filled from {evidence.kind.value} evidence (allowed: {allowed})"
            )
        if self.pattern and not (isinstance(value, str) and self.pattern.match(value)):
            raise PrecisionViolation(f"{self.name}: {value!r} does not match {self.pattern.pattern}")
        self._members.setdefault(value, _Claim()).add(evidence)

    @property
    def state(self) -> FieldState:
        return FieldState.KNOWN if self._members else FieldState.UNKNOWN

    @property
    def values(self) -> list[T]:
        return list(self._members)

    def __contains__(self, value: object) -> bool:
        return value in self._members

    def evidence(self) -> list[Evidence]:
        """The sampled evidence. Use evidence_count for totals."""
        return [e for c in self._members.values() for e in c.sample]

    def evidence_count(self) -> int:
        return sum(c.count for c in self._members.values())

    def merge_from(self, other: "AttestedSet[T]") -> None:
        if other.allowed - self.allowed:
            raise PrecisionViolation(f"{self.name}: cannot merge a field with wider evidence rules")
        for v, c in other._members.items():
            self._members.setdefault(v, _Claim()).merge(c)

    def seen_range(self) -> list[datetime]:
        return [t for c in self._members.values() for t in (c.first, c.last) if t is not None]

    def to_dict(self, redact: "Redactor | bool") -> dict:
        r = _as_redactor(redact) if self.sensitive else None
        return {
            "state": self.state.value,
            "members": [c.to_dict(r.token(v) if r else v) for v, c in self._members.items()],
        }


_OBS = {EvidenceKind.OBSERVED}
_SELF = {EvidenceKind.SELF_REPORTED}
_REG = {EvidenceKind.REGISTRY}


class Asset:
    """A device seen on the network.

    Identity rule: identity_key is "mac:<mac>" when the device was seen on the
    same layer 2 segment as the sensor, otherwise "ip:<ip>". A MAC is never
    attached to an IP from routed traffic, because that MAC belongs to the router.
    Merging the two identities is a later-version feature and must be evidenced.
    """

    def __init__(self, identity_key: str):
        kind, _, val = identity_key.partition(":")
        if kind not in {"mac", "ip"} or not val:
            raise PrecisionViolation("identity_key must be 'mac:<mac>' or 'ip:<ip>'")
        if kind == "mac" and not _MAC_RE.match(val):
            raise PrecisionViolation("MAC identity must be lowercase colon-separated")
        self.identity_key = identity_key
        self.asset_id = hashlib.sha256(identity_key.encode()).hexdigest()[:16]

        self.macs: AttestedSet[str] = AttestedSet("macs", _OBS, pattern=_MAC_RE)
        self.ips: AttestedSet[str] = AttestedSet("ips", _OBS)
        self.nic_vendor: Attested[str] = Attested("nic_vendor", _REG)
        self.hostname: Attested[str] = Attested("hostname", _SELF)
        self.device_vendor: Attested[str] = Attested("device_vendor", _SELF)
        self.device_model: Attested[str] = Attested("device_model", _SELF)
        self.firmware: Attested[str] = Attested("firmware", _SELF)
        self.roles: AttestedSet[str] = AttestedSet("roles", _OBS, pattern=_ROLE_RE)
        self.description: Attested[str] = Attested("description", _SELF)
        self.capabilities: AttestedSet[str] = AttestedSet("capabilities", _SELF)
        self.device_ids: AttestedSet[str] = AttestedSet("device_ids", _SELF)
        self.vessel_identifiers: AttestedSet[str] = AttestedSet(
            "vessel_identifiers", _OBS | _SELF, sensitive=True
        )

    def _fields(self) -> list[Attested | AttestedSet]:
        return [self.macs, self.ips, self.nic_vendor, self.hostname, self.device_vendor,
                self.device_model, self.firmware, self.description, self.capabilities, self.roles,
                self.device_ids, self.vessel_identifiers]

    def merge_from(self, other: "Asset") -> None:
        """Fold another asset's evidence into this one. Used when a staged ip: asset
        turns out to belong to a MAC-identity asset."""
        for mine, theirs in zip(self._fields(), other._fields(), strict=True):
            if type(mine) is not type(theirs) or mine.name != theirs.name:
                raise PrecisionViolation(f"cannot merge field {theirs.name} into {mine.name}")
            mine.merge_from(theirs)  # type: ignore[arg-type]

    def traffic_times(self) -> list[datetime]:
        """First and last capture times per field value. Registry lookups are not sightings."""
        return [t for f in self._fields() for t in f.seen_range()]

    def to_dict(self, redact: "Redactor | bool" = True, extra_times: Iterable[datetime] = ()) -> dict:
        redact = _as_redactor(redact) or False
        times = self.traffic_times() + list(extra_times)
        fs, ls = (min(times), max(times)) if times else (None, None)
        return {
            "asset_id": self.asset_id,
            "identity_key": self.identity_key,
            "first_seen": fs.isoformat() if fs else None,
            "last_seen": ls.isoformat() if ls else None,
            **{f.name: f.to_dict(redact) for f in self._fields()},
        }


@dataclass
class Communication:
    """A directed relationship between two assets over one protocol and port."""

    src_asset_id: str
    dst_asset_id: str
    transport: str                 # "tcp", "udp" or "l2"
    protocol: str                  # "modbus", "nmea0183", "arp"
    dst_port: int | None
    exchange_count: int = 0        # recorded events, e.g. request/response pairs
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    operations: AttestedSet[str] = field(
        default_factory=lambda: AttestedSet("operations", _OBS, pattern=_ROLE_RE)
    )
    evidence_sample: list[Evidence] = field(default_factory=list)
    packet_count: int = 0          # distinct frames, several exchanges can share one
    _recent: deque = field(default_factory=lambda: deque(maxlen=Communication.FRAME_WINDOW), repr=False)

    SAMPLE_CAP = 20
    # Exchanges that share a frame (several Modbus messages in one TCP segment)
    # are recorded close together, so recent frames are enough to count each once.
    FRAME_WINDOW = 256

    def __post_init__(self) -> None:
        if self.transport not in {"tcp", "udp", "l2"}:
            raise PrecisionViolation("transport must be tcp, udp or l2")
        if self.transport == "l2" and self.dst_port is not None:
            raise PrecisionViolation("layer 2 communications have no port")

    @property
    def key(self) -> str:
        return f"{self.src_asset_id}>{self.dst_asset_id}/{self.transport}/{self.protocol}/{self.dst_port}"

    def record(self, evidence: Evidence) -> None:
        if evidence.kind is not EvidenceKind.OBSERVED:
            raise PrecisionViolation("communications are only recorded from observed traffic")
        self.exchange_count += 1
        for f in evidence.frames:
            ref = (evidence.source_sha256, f)
            if ref not in self._recent:
                self._recent.append(ref)
                self.packet_count += 1
        ts = evidence.timestamp
        self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)
        if len(self.evidence_sample) < self.SAMPLE_CAP:
            self.evidence_sample.append(evidence)

    def merge_from(self, other: "Communication") -> None:
        """Fold in a staged communication. The two never share frames, see _Claim."""
        self.exchange_count += other.exchange_count
        self.packet_count += other.packet_count
        for t in (other.first_seen, other.last_seen):
            if t is not None:
                self.first_seen = t if self.first_seen is None else min(self.first_seen, t)
                self.last_seen = t if self.last_seen is None else max(self.last_seen, t)
        self.operations.merge_from(other.operations)
        for e in other.evidence_sample:
            if len(self.evidence_sample) < self.SAMPLE_CAP:
                self.evidence_sample.append(e)

    def to_dict(self, redact: "Redactor | bool" = True) -> dict:
        return {
            "src_asset_id": self.src_asset_id,
            "dst_asset_id": self.dst_asset_id,
            "transport": self.transport,
            "protocol": self.protocol,
            "dst_port": self.dst_port,
            "packet_count": self.packet_count,
            "exchange_count": self.exchange_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "operations": self.operations.to_dict(redact),
            "evidence_sample": [e.to_dict() for e in self.evidence_sample],
        }


@dataclass(frozen=True)
class SourceCapture:
    filename: str
    sha256: str
    frame_count: int
    start: datetime | None
    end: datetime | None

    def to_dict(self, redact: bool = True) -> dict:
        return {
            "filename": "<redacted>" if redact else self.filename,
            "sha256": self.sha256,
            "frame_count": self.frame_count,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
        }


class Inventory:
    def __init__(self, tool_version: str):
        self.tool_version = tool_version
        self.sources: list[SourceCapture] = []
        self.assets: dict[str, Asset] = {}
        self.communications: dict[str, Communication] = {}
        # Everything that was seen but not turned into evidence, so coverage gaps are visible.
        self.stats: dict[str, int] = {}
        # Reference data used for registry evidence, e.g. IEEE OUI files, with their hashes.
        self.registries: list[dict] = []

    def asset(self, identity_key: str) -> Asset:
        """Get or create. Creation alone stores nothing, fields stay unknown until evidenced."""
        existing = self.assets.get(hashlib.sha256(identity_key.encode()).hexdigest()[:16])
        if existing is not None and existing.identity_key == identity_key:
            return existing
        a = Asset(identity_key)
        return self.assets.setdefault(a.asset_id, a)

    def mac_assets_with_ip(self, ip: str) -> list[Asset]:
        """Same-segment assets (MAC identity) that have evidence for owning this IP."""
        return [a for a in self.assets.values() if a.identity_key.startswith("mac:") and ip in a.ips]

    def communication(self, src: Asset, dst: Asset, transport: str,
                      protocol: str, dst_port: int | None) -> Communication:
        c = Communication(src.asset_id, dst.asset_id, transport, protocol, dst_port)
        return self.communications.setdefault(c.key, c)

    def to_dict(self, redact: bool = True, redaction_key: bytes | None = None) -> dict:
        """Export. With redact, sensitive values become keyed tokens: a fresh random
        key per export unless redaction_key is given."""
        r: Redactor | None = Redactor(redaction_key) if redact else None
        # An asset is exported only if traffic proves it exists: field evidence
        # or a recorded communication. Created-but-never-seen assets are dropped.
        comm_times: dict[str, list[datetime]] = {}
        for c in self.communications.values():
            if c.packet_count == 0:
                continue
            for aid in (c.src_asset_id, c.dst_asset_id):
                comm_times.setdefault(aid, []).extend(t for t in (c.first_seen, c.last_seen) if t is not None)
        exported = [a for a in self.assets.values() if a.traffic_times() or a.asset_id in comm_times]
        return {
            "schema_version": SCHEMA_VERSION,
            "tool_version": self.tool_version,
            "redacted": redact,
            "redaction": r.describe() if r else None,
            "sources": [s.to_dict(redact) for s in self.sources],
            "registries": list(self.registries),
            "assets": [a.to_dict(r or False, comm_times.get(a.asset_id, ()))
                       for a in sorted(exported, key=lambda a: a.asset_id)],
            "communications": [c.to_dict(r or False) for _, c in sorted(self.communications.items())
                               if c.packet_count > 0],
            "stats": dict(sorted(self.stats.items())),
        }
