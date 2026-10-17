# Asset chart

`python -m keelmap scan capture.pcap -o inventory.json --map chart.html` or, from an existing inventory, `python -m keelmap map inventory.json -o chart.html`.

One HTML file, about 550 KB, that opens with no network access. It is drawn like a nautical chart: pale chart water, a graticule, a title block, and magenta reserved for what matters most, which here is Modbus writes.

## What it shows

| On the chart | Meaning |
|---|---|
| Diamond, buff | Modbus gateway, returned exception 10 or 11 |
| Rounded rectangle, buff | Modbus server, answered requests |
| Chevron, green | AIS source |
| Triangle, green | NMEA 0183 or IEC 61162-450 source |
| Circle | Modbus client |
| Hexagon | DHCP server |
| Square | Says it is a switch or router in LLDP. A claim, used only when no observed role says more |
| Small circle | Other device |
| Dashed outline | IEC 61162-450 multicast group. A destination, not a device |
| Grey line | Answered requests, thicker means more |
| Magenta line | Includes accepted Modbus writes |
| Dashed magenta | Modbus writes attempted, all rejected |
| Dotted green | Publishes to a multicast group |

Shapes come from roles in the inventory, in a fixed order. Labels translate roles, they never upgrade them. A source sending `$GPGGA` is shown as "Sent NMEA sentences with talker id GP", not as a GPS receiver, and nothing is ever called a PLC.

The side panel shows, for each asset, what it did, what it says about itself, its addresses and its connections. Every value opens to the frames behind it. Fields with no evidence are listed together as not stated. Conflicting claims are shown together, never resolved. The overview lists everything seen but not turned into evidence, so coverage gaps are visible.

## Safety

Every string in an inventory can come from network traffic, so the chart is built to be opened safely even when a capture was crafted by an attacker.

| Property | How |
|---|---|
| No network access | Content Security Policy `default-src 'none'`, `connect-src 'none'`. Nothing external is loaded |
| Only known scripts run | `script-src` lists the SHA-256 of the two scripts, computed at render time. No `unsafe-inline` for scripts |
| Captured text cannot become markup | Data sits in a non-executing JSON script element with `<`, `>`, `&` and line separators escaped. The page places it with `textContent` and canvas labels only |
| Template cannot be hijacked | Placeholders are filled in one pass over the template, so text in the data is never read as a placeholder |
| Vendored library is pinned | Cytoscape 3.30.2, SHA-256 checked on every render, audited for `eval` |
| Unredacted charts are marked | Need a `.unredacted.html` name, which git ignores, and show a magenta warning |

Styles allow `unsafe-inline` because Cytoscape injects one style element. No captured data is ever written as style.

## How it was tested

`tests/test_report.py` covers wording, escaping, CSP hashes, the vendor hash check and the CLI.

`tools/make_hostile_map.py` fills every asset with script, image, SVG and placeholder injection strings. `tools/check_map_browser.js` opens a chart in headless Chrome 131, in light and dark mode, visits every asset, opens every evidence list and fails on any CSP violation, error, dialog or injected element. The demo chart and the hostile chart both pass. The hostile strings are displayed as plain text.

Layout was reviewed from screenshots at 1440 by 900 and 390 by 844. The chart is fitted below the title block and above the mobile search bar.

## Limits

The layout is recomputed each time the file opens, so positions change between openings. Labels hide when zoomed far out, and the asset list remains the reliable way to reach every asset.
