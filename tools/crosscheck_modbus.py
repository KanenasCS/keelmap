"""Compare KeelMap's Modbus results with tshark's own request/response matching.

Usage: python tools/crosscheck_modbus.py capture.pcap [--no-tcp-analysis]

--no-tcp-analysis stops tshark hiding segments it labels as retransmissions.
Use it when a capture missed the original segment: the retransmitted copy is
then the only record of that message, and KeelMap uses it.

tshark is the reference. For normal responses it reports the request frame
(modbus.request_frame). tshark 4.2 leaves that field empty for exception
responses, so those are paired here from tshark's own decoded fields: same TCP
stream, transaction id, unit id and function code, earliest unmatched request.
This script checks that:
  1. Per client, server and operation, KeelMap counts the same number of pairs.
  2. Every sampled evidence record cites a request and response frame that
     tshark also paired, with the same function code and exception.
Differences are printed, not hidden. Exit code 1 if any are found.
"""

from __future__ import annotations

import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from keelmap.decoders.arp import ArpDecoder  # noqa: E402
from keelmap.decoders.dhcp import DhcpDecoder  # noqa: E402
from keelmap.decoders.modbus import ModbusDecoder  # noqa: E402
from keelmap.scan import scan  # noqa: E402

FIELDS = ["frame.number", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport", "tcp.stream",
          "mbtcp.trans_id", "mbtcp.unit_id", "modbus.request_frame", "modbus.func_code",
          "modbus.exception_code"]

FALLBACK = 0


def tshark_pairs(path: str, tcp_analysis: bool = True) -> dict[tuple[int, int], tuple[str, str, str]]:
    global FALLBACK
    cmd = ["tshark", "-r", path, "-Y", "mbtcp", "-T", "fields", "-E", "occurrence=f"]
    if not tcp_analysis:
        cmd += ["-o", "tcp.analyze_sequence_numbers:FALSE"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    pairs, open_reqs = {}, {}
    for line in out.splitlines():
        num, src, dst, sport, dport, stream, tid, unit, req, fc, exc = (line.split("\t") + [""] * 11)[:11]
        if not fc:
            continue
        fc_i = int(fc) & 0x7F
        if dport == "502" and sport != "502":
            open_reqs.setdefault((stream, tid, unit, fc_i), []).append(int(num))
            continue
        if sport != "502":
            continue
        q = open_reqs.get((stream, tid, unit, fc_i))
        if req:
            req_n = int(req)
            if q and req_n in q:
                q.remove(req_n)
        elif exc and q:
            req_n = q.pop(0)
            FALLBACK += 1
        else:
            continue
        op = f"modbus/fc:{fc_i:02d}" + (f":exception:{int(exc):02d}" if exc else "")
        pairs[(req_n, int(num))] = (dst, src, op)   # client, server, op
    return pairs


def main(path: str, tcp_analysis: bool = True) -> int:
    truth = tshark_pairs(path, tcp_analysis)
    inv = scan([path], [ArpDecoder(), DhcpDecoder(), ModbusDecoder()])
    out = inv.to_dict(redact=False)
    ip_of = {a["asset_id"]: (a["ips"]["members"][0]["value"] if a["ips"]["members"] else a["identity_key"])
             for a in out["assets"]}

    ours: Counter = Counter()
    problems = []
    for c in out["communications"]:
        if c["protocol"] != "modbus":
            continue
        client, server = ip_of[c["src_asset_id"]], ip_of[c["dst_asset_id"]]
        for m in c["operations"]["members"]:
            ours[(client, server, m["value"])] += m["evidence_count"]
            for e in m["evidence"]:
                key = tuple(e["frames"])
                if truth.get(key) != (client, server, m["value"]):
                    problems.append(f"sample {key} {client}>{server} {m['value']}: tshark says {truth.get(key)}")

    theirs = Counter(truth.values())
    for k in sorted(set(ours) | set(theirs)):
        if ours[k] != theirs[k]:
            problems.append(f"count {k}: keelmap {ours[k]}, tshark {theirs[k]}")

    print(f"tshark pairs: {sum(theirs.values())}, keelmap pairs: {sum(ours.values())}, "
          f"operation groups: {len(theirs)}, exception pairs matched by fallback: {FALLBACK}")
    print("stats:", out["stats"])
    for p in problems[:50]:
        print("DIFF", p)
    print("MATCH" if not problems else f"{len(problems)} differences")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], "--no-tcp-analysis" not in sys.argv))
