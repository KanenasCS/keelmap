# Security policy

KeelMap reads untrusted network captures and renders what it finds, so parser
and rendering bugs can be security bugs. Reports are welcome.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(Security tab, "Report a vulnerability"). Please do not open a public issue.

Include the KeelMap version, the command you ran, and a capture that triggers
the problem. Build that capture from synthetic packets where you can.

## Never share real captures

Captures from vessels, ports and plants can contain vessel identities, internal
addressing and process data. Do not attach them to issues, pull requests or
vulnerability reports. If a bug only reproduces with real traffic, say so and
we will agree a way to reduce it to synthetic packets.

## In scope

- Crashes, hangs or excessive memory use on crafted captures
- A crafted capture making KeelMap store a value without evidence, or in the wrong field
- Script, markup or style injection into the HTML chart
- Redaction failures: vessel identifiers or filenames appearing in, or recoverable from, a redacted export
- Any network access from KeelMap or from a generated chart

## Design guarantees

KeelMap never transmits packets and makes no network connections. Charts load
nothing external and allow only scripts whose SHA-256 is pinned at render time.
See docs/map.md and docs/precision-contract.md.
