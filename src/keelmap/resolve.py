"""Shared rule for attaching an IP endpoint to an asset.

An IP joins a MAC-identity asset only when exactly one such asset has ARP or
DHCP evidence for that IP AND the frame's Ethernet source is that same MAC.
Otherwise the endpoint is an ip:<address> asset. Call this from finish(),
after every frame has been seen, so ARP later in the capture still counts.
"""

from __future__ import annotations

from collections import Counter

from keelmap.model import Asset, Inventory


class IpResolver:
    """Built once per decoder finish(). The IP index is taken when it is first
    needed, so lookups cost the same however many assets the capture holds."""

    def __init__(self, inventory: Inventory, stats: Counter, prefix: str):
        self.inv = inventory
        self.stats = stats
        self.prefix = prefix
        self._cache: dict[tuple[str, str], Asset] = {}
        self._reported: set[tuple[str, str]] = set()
        self._index: dict[str, list[Asset]] | None = None

    def _owners(self, ip: str) -> list[Asset]:
        if self._index is None:
            self._index = {}
            for a in self.inv.assets.values():
                if a.identity_key.startswith("mac:"):
                    for owned in a.ips.values:
                        self._index.setdefault(owned, []).append(a)
        return self._index.get(ip, [])

    def __call__(self, ip: str, eth_src: str) -> Asset:
        key = (ip, eth_src)
        if key in self._cache:
            return self._cache[key]
        owners = self._owners(ip)
        if len(owners) == 1 and owners[0].identity_key == f"mac:{eth_src}":
            asset = owners[0]
        else:
            if len(owners) > 1:
                self._count("ip_owner_ambiguous", ip)
            elif len(owners) == 1:
                self._count("ip_owner_mac_differs", ip)
            asset = self.inv.asset(f"ip:{ip}")
        self._cache[key] = asset
        return asset

    def _count(self, what: str, ip: str) -> None:
        if (what, ip) not in self._reported:
            self._reported.add((what, ip))
            self.stats[f"{self.prefix}_{what}"] += 1
