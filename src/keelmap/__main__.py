"""Command line: python -m keelmap scan capture.pcap [more.pcapng] -o inventory.json"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from keelmap import __version__
from keelmap.capture import CaptureError
from keelmap.oui import OuiRegistry, RegistryError
from keelmap.report.render import render_html
from keelmap.scan import scan


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="keelmap", description="Passive OT and maritime asset discovery")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="build an inventory from capture files")
    s.add_argument("captures", nargs="+", type=Path)
    s.add_argument("-o", "--output", type=Path, required=True)
    s.add_argument("--no-redact", action="store_true",
                   help="keep vessel identifiers and filenames. "
                        "Outputs must end in .unredacted.json or .unredacted.html")
    s.add_argument("--map", type=Path, help="also write an offline HTML asset chart")
    s.add_argument("--oui", type=Path, action="append", default=[],
                   help="IEEE registry file (oui.csv, oui.txt, mam.csv, oui36.csv) for NIC vendor. Repeatable")
    g = sub.add_parser("map", help="draw an offline HTML asset chart from an inventory JSON file")
    g.add_argument("inventory", type=Path)
    g.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args(argv)

    if args.cmd == "map":
        return _map(args.inventory, args.output)

    if args.no_redact and not args.output.name.endswith(".unredacted.json"):
        print("error: --no-redact output must end in .unredacted.json so it is git-ignored", file=sys.stderr)
        return 2
    if args.no_redact and args.map and not args.map.name.endswith(".unredacted.html"):
        print("error: --no-redact map must end in .unredacted.html so it is git-ignored", file=sys.stderr)
        return 2
    registry = None
    if args.oui:
        registry = OuiRegistry()
        try:
            for f in args.oui:
                registry.load(f)
        except (RegistryError, OSError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    try:
        inv = scan(args.captures, oui=registry)
    except (CaptureError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    out = inv.to_dict(redact=not args.no_redact)
    args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    st = out["stats"]
    print(f"{len(out['assets'])} assets, {len(out['communications'])} communications "
          f"from {st.get('frames_read', 0)} frames in {len(out['sources'])} capture(s)")
    skipped = {k: v for k, v in st.items() if k != "frames_read"}
    if skipped:
        print("not turned into evidence:")
        for k, v in skipped.items():
            print(f"  {k}: {v}")
    print(f"written to {args.output}")
    if args.map:
        args.map.write_text(render_html(out), encoding="utf-8")
        print(f"map written to {args.map}")
    return 0


def _map(inventory: Path, output: Path) -> int:
    try:
        inv = json.loads(inventory.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: cannot read {inventory}: {e}", file=sys.stderr)
        return 1
    if not inv.get("redacted", True) and not output.name.endswith(".unredacted.html"):
        print("error: this inventory is unredacted, so the map must end in .unredacted.html", file=sys.stderr)
        return 2
    output.write_text(render_html(inv), encoding="utf-8")
    print(f"map written to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
