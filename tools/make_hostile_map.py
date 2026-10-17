"""Write a map whose inventory is full of hostile strings, for tools/check_map_browser.js.

Usage: python tools/make_hostile_map.py inventory.json hostile.html
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keelmap.report.render import render_html  # noqa: E402

EVIL = ('<img src=x onerror="window.__pwned=1"></script><script>window.__pwned=2</script>'
        '{{APP}}"\'><svg onload="window.__pwned=3">\u2028')


def main(src: str, dst: str) -> None:
    inv = json.loads(Path(src).read_text(encoding="utf-8"))
    ev = {"kind": "self_reported", "source_sha256": "a" * 64, "frames": [1],
          "timestamp": "2024-01-01T00:00:00+00:00", "decoder": "dhcp@0.1.0", "detail": EVIL}
    for a in inv["assets"]:
        a["hostname"] = {"state": "known", "value": EVIL,
                         "claims": [{"value": EVIL, "evidence_count": 1, "evidence": [ev]}]}
        a["device_vendor"] = {"state": "conflict", "claims": [
            {"value": EVIL, "evidence_count": 1, "evidence": [ev]},
            {"value": EVIL + "2", "evidence_count": 1, "evidence": [ev]}]}
        a["roles"]["members"].append({"value": "nmea0183/talker:" + EVIL, "evidence_count": 1, "evidence": [ev]})
        a["description"] = {"state": "known", "value": EVIL + "\nsecond line",
                            "claims": [{"value": EVIL + "\nsecond line", "evidence_count": 1, "evidence": [ev]}]}
        a["capabilities"] = {"state": "known", "members": [{"value": EVIL, "evidence_count": 1, "evidence": [ev]}]}
        mud = {"value": "mud_url:" + EVIL, "evidence_count": 1, "evidence": [ev]}
        a["device_ids"] = {"state": "known", "members": [mud]}
    Path(dst).write_text(render_html(inv), encoding="utf-8")
    print(f"hostile map written to {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
