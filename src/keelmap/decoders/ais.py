"""AIS payload decoding (ITU-R M.1371), limited to identity fields.

Only what an inventory needs: message type, MMSI, and the static identity in
types 5, 19 and 24 (IMO number, call sign, vessel name). Positions, speeds and
voyage data are deliberately not decoded.

Validation applied, because a wrong vessel identity is worse than none:
  * MMSI must be non-zero and fit nine digits.
  * IMO must be seven digits with a valid check digit. IMO 0 means "not available".
  * Text fields must be non-empty after removing '@' padding and surrounding spaces.
  * A field is read only when the payload is long enough to contain all of it.
"""

from __future__ import annotations

from dataclasses import dataclass

_SIXBIT_TEXT = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_ !\"#$%&'()*+,-./0123456789:;<=>?"


class AisError(ValueError):
    pass


def dearmor(payload: str, fill_bits: int) -> str:
    """Return the payload as a string of '0' and '1'."""
    if not 0 <= fill_bits <= 5:
        raise AisError("fill bits must be 0 to 5")
    out = []
    for ch in payload:
        v = ord(ch) - 48
        if v > 40:
            v -= 8
        if not 0 <= v <= 63 or ch in "XYZ[\\]^_" or not 48 <= ord(ch) <= 119:
            raise AisError(f"invalid armoring character {ch!r}")
        out.append(f"{v:06b}")
    bits = "".join(out)
    return bits[:len(bits) - fill_bits] if fill_bits else bits


def _uint(bits: str, start: int, length: int) -> int | None:
    if len(bits) < start + length:
        return None
    return int(bits[start:start + length], 2)


def _text(bits: str, start: int, chars: int) -> str | None:
    if len(bits) < start + chars * 6:
        return None
    s = "".join(_SIXBIT_TEXT[int(bits[start + i * 6:start + i * 6 + 6], 2)] for i in range(chars))
    s = s.split("@", 1)[0].strip()   # some transponders pad with leading spaces too
    return s or None


def imo_valid(imo: int) -> bool:
    if not 1_000_000 <= imo <= 9_999_999:
        return False
    d = [int(c) for c in str(imo)]
    return sum(x * w for x, w in zip(d[:6], range(7, 1, -1), strict=True)) % 10 == d[6]


@dataclass(frozen=True)
class AisIdentity:
    msg_type: int
    mmsi: int | None              # None when invalid
    imo: int | None = None
    callsign: str | None = None
    name: str | None = None
    rejected: tuple[str, ...] = ()  # reasons fields were dropped, for stats


def decode_identity(bits: str) -> AisIdentity:
    mtype = _uint(bits, 0, 6)
    if mtype is None or not 1 <= mtype <= 27:
        raise AisError("not a known AIS message type")
    rejected: list[str] = []
    mmsi = _uint(bits, 8, 30)
    if mmsi is None:
        raise AisError("payload too short for MMSI")
    if mmsi == 0 or mmsi > 999_999_999:
        rejected.append("mmsi_invalid")
        mmsi = None

    imo = callsign = name = None
    if mtype == 5:
        raw_imo = _uint(bits, 40, 30)
        if raw_imo not in (None, 0):
            if imo_valid(raw_imo):
                imo = raw_imo
            else:
                rejected.append("imo_check_digit_failed")
        callsign = _text(bits, 70, 7)
        name = _text(bits, 112, 20)
        if len(bits) < 232:
            rejected.append("type5_truncated")
    elif mtype == 19:
        name = _text(bits, 143, 20)
    elif mtype == 24:
        part = _uint(bits, 38, 2)
        if part == 0:
            name = _text(bits, 40, 20)
        elif part == 1:
            callsign = _text(bits, 90, 7)
    return AisIdentity(mtype, mmsi, imo, callsign, name, tuple(rejected))


class FragmentBuffer:
    """Reassemble multi-sentence AIS messages per source and sequential message id.

    Holds at most MAX_OPEN unfinished messages. Beyond that the oldest is dropped
    and counted as incomplete, so a lossy feed cannot grow memory without limit.
    """

    MAX_OPEN = 4096

    def __init__(self) -> None:
        self._open: dict[tuple, dict] = {}
        self.incomplete = 0

    def add(self, source: tuple, kind: str, count: int, num: int, seq: str, channel: str,
            payload: str, fill: int, ref: object) -> tuple[str, int, list] | None:
        """Return (payload, fill, refs) when a message is complete, else None."""
        if count == 1 and num == 1:
            return payload, fill, [ref]
        if not 1 <= num <= count <= 9:
            raise AisError("bad fragment numbering")
        key = (source, kind, seq, channel, count)
        entry = self._open.get(key)
        if num == 1:
            if entry is not None:
                self.incomplete += 1
                del self._open[key]
            elif len(self._open) >= self.MAX_OPEN:
                del self._open[next(iter(self._open))]
                self.incomplete += 1
            entry = self._open[key] = {"parts": {}, "fill": 0}
        elif entry is None or num in entry["parts"]:
            self.incomplete += 1
            self._open.pop(key, None)
            return None
        entry["parts"][num] = (payload, ref)
        if num == count:
            entry["fill"] = fill
        if len(entry["parts"]) == count:
            del self._open[key]
            parts = [entry["parts"][i] for i in range(1, count + 1)]
            return "".join(p for p, _ in parts), entry["fill"], [r for _, r in parts]
        return None

    def close(self) -> int:
        self.incomplete += len(self._open)
        self._open.clear()
        return self.incomplete
