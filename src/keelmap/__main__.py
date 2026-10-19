"""Command line.

  keelmap scan capture.pcap [more.pcapng] -o inventory.json [--map chart.html]
  keelmap map inventory.json -o chart.html
  keelmap keygen -o redaction.key

Every output file is written before anything is printed, so a summary cut off
by a closed console (for example piped into head) never loses work.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from keelmap import __version__
from keelmap.capture import CaptureError
from keelmap.oui import OuiRegistry, RegistryError
from keelmap.report.render import render_html
from keelmap.report.view import EVIDENCE_STATS, InventoryError, explain_stat, validate_inventory
from keelmap.scan import scan


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def _read_key(path: Path) -> bytes:
    raw = path.read_bytes().strip()
    try:
        key = bytes.fromhex(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        key = raw
    if len(key) < 16:
        raise ValueError(f"{path.name}: a redaction key needs at least 16 bytes, create one with keelmap keygen")
    return key


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except BrokenPipeError:
        # The console went away mid-summary. Outputs are already written.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0


def _main(argv: list[str] | None) -> int:
    ap = argparse.ArgumentParser(prog="keelmap", description="Passive OT and maritime asset discovery")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="build an inventory from capture files")
    s.add_argument("captures", nargs="+", type=Path)
    s.add_argument("-o", "--output", type=Path, required=True)
    s.add_argument("--map", type=Path, help="also write an offline HTML asset chart")
    s.add_argument("--oui", type=Path, action="append", default=[],
                   help="IEEE registry file (oui.csv, oui.txt, mam.csv, oui36.csv) for NIC vendor. Repeatable")
    s.add_argument("--no-redact", action="store_true",
                   help="keep vessel identifiers and filenames. "
                        "Outputs must end in .unredacted.json or .unredacted.html")
    s.add_argument("--redaction-key", type=Path,
                   help="secret key file, so redacted values get the same token in every export. "
                        "Without it a random key is used and discarded")

    g = sub.add_parser("map", help="draw an offline HTML asset chart from an inventory JSON file")
    g.add_argument("inventory", type=Path)
    g.add_argument("-o", "--output", type=Path, required=True)

    k = sub.add_parser("keygen", help="create a redaction key file")
    k.add_argument("-o", "--output", type=Path, required=True)

    args = ap.parse_args(argv)
    if args.cmd == "map":
        return _map(args.inventory, args.output)
    if args.cmd == "keygen":
        return _keygen(args.output)
    return _scan(args)


def _scan(args: argparse.Namespace) -> int:
    if args.no_redact and not args.output.name.endswith(".unredacted.json"):
        print("error: --no-redact output must end in .unredacted.json so it is git-ignored", file=sys.stderr)
        return 2
    if args.no_redact and args.map and not args.map.name.endswith(".unredacted.html"):
        print("error: --no-redact map must end in .unredacted.html so it is git-ignored", file=sys.stderr)
        return 2
    if args.map and args.map.resolve() == args.output.resolve():
        print("error: --map and --output must be different files", file=sys.stderr)
        return 2
    if args.no_redact and args.redaction_key:
        print("error: --redaction-key has no effect with --no-redact", file=sys.stderr)
        return 2
    key = None
    if args.redaction_key:
        try:
            key = _read_key(args.redaction_key)
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
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

    out = inv.to_dict(redact=not args.no_redact, redaction_key=key)
    _write(args.output, json.dumps(out, indent=2) + "\n")
    if args.map:
        _write(args.map, render_html(out))

    st = out["stats"]
    print(f"{len(out['assets'])} assets, {len(out['communications'])} communications "
          f"from {st.get('frames_read', 0)} frames in {len(out['sources'])} capture(s)")
    found = {k: v for k, v in st.items() if k in EVIDENCE_STATS}
    for name, count in found.items():
        print(f"{count:>8}  {explain_stat(name)}")
    skipped = {k: v for k, v in st.items() if k != "frames_read" and k not in EVIDENCE_STATS}
    if skipped:
        print("seen but not turned into evidence:")
        for name, count in skipped.items():
            print(f"  {count:>8}  {explain_stat(name)}  [{name}]")
    print(f"inventory written to {args.output}")
    if args.map:
        print(f"chart written to {args.map}")
    return 0


def _map(inventory: Path, output: Path) -> int:
    try:
        inv = json.loads(inventory.read_text(encoding="utf-8"))
        validate_inventory(inv)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"error: cannot read {inventory}: {e}", file=sys.stderr)
        return 1
    except InventoryError as e:
        print(f"error: {inventory} is not a KeelMap inventory this version can draw: {e}", file=sys.stderr)
        return 1
    if inv.get("redacted") is not True and not output.name.endswith(".unredacted.html"):
        print("error: this inventory is unredacted, so the chart must end in .unredacted.html", file=sys.stderr)
        return 2
    _write(output, render_html(inv))
    print(f"chart written to {output}")
    return 0


def _keygen(output: Path) -> int:
    if output.exists():
        print(f"error: {output} exists, refusing to overwrite a key", file=sys.stderr)
        return 2
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(secrets.token_hex(32) + "\n")
    print(f"redaction key written to {output}. Keep it private, anyone holding it can test guesses.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
