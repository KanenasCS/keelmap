"""Decoder interface.

A decoder reads frames and writes evidenced facts into the Inventory.
It never writes values directly: every write goes through Attested.add,
AttestedSet.add or Communication.record, which enforce the precision contract.

Decoder obligations the model cannot check, verified by fixture tests instead:
  * A role such as "modbus/server" needs a frame where the asset RESPONDED.
    A request sent to it proves nothing about what it is.
  * Never attach a MAC to an IP from routed traffic. Only same-segment
    evidence (ARP reply, DHCP exchange) links the two.
  * Cite the frame numbers that actually contain the value, not a nearby frame.
  * Bump the decoder version whenever what it extracts changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from keelmap.model import Evidence, EvidenceKind, Inventory


@dataclass(frozen=True)
class Frame:
    number: int                 # 1-based, matches Wireshark
    timestamp: datetime         # timezone-aware
    data: bytes                 # raw link-layer bytes
    linktype: int               # pcap link type, 1 = Ethernet
    source_sha256: str


class Decoder(Protocol):
    name: str
    version: str

    @property
    def tag(self) -> str:
        """Value for Evidence.decoder, e.g. 'modbus@0.1.0'."""
        ...

    def handle(self, frame: Frame, inventory: Inventory) -> None: ...

    def finish(self, inventory: Inventory) -> None:
        """Called once after the last frame, for request/response pairing that spans frames."""
        ...


def evidence_for(frame: Frame, kind: EvidenceKind, decoder_tag: str, detail: str) -> Evidence:
    """Evidence citing exactly this frame."""
    return Evidence(kind, frame.source_sha256, (frame.number,), frame.timestamp, decoder_tag, detail)
