"""NIC vendor from the IEEE registration authority files.

No registry data ships with KeelMap. Download the official files and pass them
with --oui (any combination, longest prefix wins):

  MA-L (24-bit):  https://standards-oui.ieee.org/oui/oui.csv  or  oui.txt
  MA-M (28-bit):  https://standards-oui.ieee.org/oui28/mam.csv
  MA-S (36-bit):  https://standards-oui.ieee.org/oui36/oui36.csv

What a match means: the IEEE assigned this address block to that organisation.
That names who made or registered the network card, often not who made the
device. So it fills only nic_vendor, as registry evidence citing the file's
SHA-256, and never device_vendor.

No lookup is stored for:
  * Locally administered addresses (second-lowest bit of the first octet set).
    These are assigned by software, virtual machines or phones that randomise
    MACs, and the registry says nothing about them.
  * Blocks the IEEE lists as "Private".
  * MA-L blocks held by the IEEE Registration Authority itself, when no MA-M or
    MA-S file was given to resolve the real holder.

A prefix the registry lists for several organisations (08-00-30 has three)
stores all of them, so nic_vendor shows a conflict instead of a silent pick.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from keelmap.model import Evidence, EvidenceKind, Inventory

VERSION = "0.1.0"
_TXT_LINE = re.compile(r"^([0-9A-Fa-f]{6})\s+\(base 16\)\s+(.*\S)\s*$")
_HEX = {6: "MA-L", 7: "MA-M", 9: "MA-S"}
_RA = "IEEE REGISTRATION AUTHORITY"


class RegistryError(ValueError):
    pass


@dataclass(frozen=True)
class _Entry:
    org: str
    registry: str
    prefix: str
    file_sha256: str
    file_name: str
    file_time: datetime


class OuiRegistry:
    def __init__(self) -> None:
        # A prefix can be listed for several organisations (08-00-30 has three), so keep them all.
        self._by_len: dict[int, dict[str, list[_Entry]]] = {6: {}, 7: {}, 9: {}}
        self.files: list[dict] = []

    def load(self, path: str | Path) -> int:
        path = Path(path)
        raw = path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        when = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        text = raw.decode("utf-8-sig", errors="replace")
        added = 0
        if text.lstrip().startswith("Registry,Assignment"):
            for row in csv.DictReader(io.StringIO(text)):
                prefix = (row.get("Assignment") or "").strip().upper()
                org = (row.get("Organization Name") or "").strip()
                reg = (row.get("Registry") or "").strip()
                if len(prefix) in _HEX and re.fullmatch(r"[0-9A-F]+", prefix) and org and reg == _HEX[len(prefix)]:
                    self._add(len(prefix), _Entry(org, reg, prefix, sha, path.name, when))
                    added += 1
        else:
            for line in text.splitlines():
                m = _TXT_LINE.match(line)
                if m:
                    prefix = m.group(1).upper()
                    self._add(6, _Entry(m.group(2), "MA-L", prefix, sha, path.name, when))
                    added += 1
        if not added:
            raise RegistryError(f"{path.name}: no IEEE registry entries recognised")
        self.files.append({"name": path.name, "sha256": sha, "entries": added,
                           "file_time": when.isoformat()})
        return added

    def _add(self, n: int, e: _Entry) -> None:
        bucket = self._by_len[n].setdefault(e.prefix, [])
        if all(x.org != e.org for x in bucket):
            bucket.append(e)

    def lookup(self, mac: str) -> tuple[list[_Entry], str | None]:
        """Return (entries, None) or ([], reason). Several entries mean the registry lists several holders."""
        octets = mac.split(":")
        first = int(octets[0], 16)
        if first & 0x01:
            return [], "multicast"
        if first & 0x02:
            return [], "locally_administered"
        hexmac = "".join(octets).upper()
        for n in (9, 7, 6):
            entries = self._by_len[n].get(hexmac[:n])
            if not entries:
                continue
            real = [e for e in entries if e.org.strip().upper() not in ("PRIVATE", _RA)]
            if real:
                return real, None
            if any(e.org.strip().upper() == _RA for e in entries):
                return [], "registration_authority_block"
            return [], "private"
        return [], "not_found"


def apply_oui(inventory: Inventory, registry: OuiRegistry) -> Counter:
    """Fill nic_vendor for every MAC with registry evidence. Returns per-MAC outcome counts."""
    stats: Counter[str] = Counter()
    tag = f"oui@{VERSION}"
    for asset in inventory.assets.values():
        for mac in asset.macs.values:
            entries, reason = registry.lookup(mac)
            if not entries:
                stats[f"oui_{reason}"] += 1
                continue
            for entry in entries:
                dashed = "-".join(entry.prefix[i:i + 2] for i in range(0, len(entry.prefix), 2))
                ev = Evidence(EvidenceKind.REGISTRY, entry.file_sha256, (), entry.file_time, tag,
                              f"IEEE {entry.registry} {dashed} in {entry.file_name}, assigned to the card maker")
                asset.nic_vendor.add(entry.org, ev)
            stats["oui_matched" if len(entries) == 1 else "oui_prefix_listed_for_several_organisations"] += 1
    inventory.registries.extend(registry.files)
    return stats
