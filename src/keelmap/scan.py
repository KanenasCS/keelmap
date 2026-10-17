"""Run decoders over one or more captures and return an Inventory."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable, Sequence

from keelmap import __version__
from keelmap.capture import CaptureReader
from keelmap.decoders.arp import ArpDecoder
from keelmap.decoders.base import Decoder
from keelmap.decoders.dhcp import DhcpDecoder
from keelmap.decoders.lldp import LldpDecoder
from keelmap.decoders.modbus import ModbusDecoder
from keelmap.decoders.nmea import NmeaDecoder
from keelmap.layers import LINKTYPE_ETHERNET
from keelmap.model import Inventory, SourceCapture
from keelmap.oui import OuiRegistry, apply_oui


def default_decoders() -> list[Decoder]:
    return [ArpDecoder(), DhcpDecoder(), LldpDecoder(), ModbusDecoder(), NmeaDecoder()]


def scan(paths: Iterable[str | Path], decoders: Sequence[Decoder] | None = None,
         oui: OuiRegistry | None = None) -> Inventory:
    decoders = list(decoders) if decoders is not None else default_decoders()
    inv = Inventory(__version__)
    stats: Counter[str] = Counter()
    seen: set[str] = set()

    for path in paths:
        reader = CaptureReader(path)
        if reader.sha256 in seen:
            stats["capture_duplicate_skipped"] += 1
            continue
        seen.add(reader.sha256)
        for frame in reader:
            stats["frames_read"] += 1
            if frame.linktype != LINKTYPE_ETHERNET:
                stats[f"frames_unsupported_linktype_{frame.linktype}"] += 1
                continue
            for d in decoders:
                d.handle(frame, inv)
        stats.update(reader.stats)
        inv.sources.append(SourceCapture(
            Path(path).name, reader.sha256, reader.frame_count, reader.first_ts, reader.last_ts))

    for d in decoders:
        d.finish(inv)
        stats.update(getattr(d, "stats", {}))
    if oui is not None:
        stats.update(apply_oui(inv, oui))
    inv.stats = dict(stats)
    return inv
