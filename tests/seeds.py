"""Seed captures for fuzzing: every decoder and capture format, built here plus public fixtures."""

from __future__ import annotations

import shutil
from pathlib import Path

from pcapgen import (
    BCAST,
    arp,
    devid_request,
    devid_response,
    dhcp,
    ether,
    ip4,
    ipv4_tcp,
    ipv4_udp,
    lldp_basic,
    lldp_frame,
    mbap,
    sll2,
    tlv,
    ts,
    write_pcap,
    write_pcapng,
)

FIX = Path(__file__).parent / "fixtures/public"


def _cks(body: str) -> str:
    c = 0
    for ch in body:
        c ^= ord(ch)
    return f"{c:02X}"


def build(dest: Path) -> list[Path]:
    hmi, plc, ais, mux = "00:0e:8c:00:00:09", "00:1d:9c:00:00:05", "00:a0:c8:00:00:10", "00:a0:c8:00:00:20"
    lines = (FIX / "nmea_samples.txt").read_text().splitlines()
    vdo = [line[1:line.index("*")].replace("VDM", "VDO") for line in lines[1:3]]
    vdo = [f"!{v}*{_cks(v)}" for v in vdo]
    tag = "s:GP0001,n:1"
    modbus = [
        ether(plc, hmi, 0x0800, ipv4_tcp("10.0.0.9", "10.0.0.5", 40000, 502, mbap(1, 255, devid_request()))),
        ether(hmi, plc, 0x0800, ipv4_tcp("10.0.0.5", "10.0.0.9", 502, 40000,
                                         mbap(1, 255, devid_response({0: b"Acme", 1: b"X1", 2: b"v1", 5: b"M"})))),
        ether(plc, hmi, 0x0800, ipv4_tcp("10.0.0.9", "10.0.0.5", 40000, 502,
                                         mbap(2, 1, bytes([3, 0, 0, 0, 2])) + mbap(3, 1, bytes([6, 0, 1, 0, 7])),
                                         seq=1011)),
        ether(hmi, plc, 0x0800, ipv4_tcp("10.0.0.5", "10.0.0.9", 502, 40000,
                                         mbap(2, 1, bytes([0x83, 10])) + mbap(3, 1, bytes([6, 0, 1, 0, 7])),
                                         seq=5050)),
    ]
    l2 = [
        ether(BCAST, plc, 0x0806, arp(2, plc, "10.0.0.5", hmi, "10.0.0.9")),
        ether(BCAST, hmi, 0x0800, ipv4_udp("0.0.0.0", "255.255.255.255", 68, 67,
                                           dhcp(1, 3, hmi, options={12: b"HMI-1", 60: b"udhcp"}))),
        ether(BCAST, plc, 0x0800, ipv4_udp("10.0.0.1", "255.255.255.255", 67, 68,
                                           dhcp(2, 5, hmi, yiaddr="10.0.0.9", options={54: ip4("10.0.0.1")}))),
        lldp_frame(plc, lldp_basic(plc) + [tlv(5, b"sw1"), tlv(6, b"desc\nline2"), tlv(7, b"\x00\x14\x00\x04"),
                                           tlv(8, bytes([5, 1]) + ip4("10.0.0.30") + b"\x02\x00\x00\x00\x01\x00"),
                                           tlv(127, b"\x00\x12\xbb\x09Acme"),
                                           tlv(127, b"\x00\x00\x5e\x01https://x.example/mud")]),
    ]
    nmea = [
        ether(BCAST, ais, 0x0800, ipv4_udp("10.0.1.10", "10.0.1.255", 10110, 10110,
                                           ("\r\n".join(lines[:6]) + "\r\n").encode())),
        ether(BCAST, ais, 0x0800, ipv4_udp("10.0.1.10", "10.0.1.255", 10110, 10110, (vdo[0] + "\r\n").encode())),
        ether(BCAST, ais, 0x0800, ipv4_udp("10.0.1.10", "10.0.1.255", 10110, 10110, (vdo[1] + "\r\n").encode())),
        ether("01:00:5e:40:00:04", mux, 0x0800, ipv4_udp(
            "10.0.1.20", "239.192.0.4", 60004, 60004,
            b"UdPbC\x00" + f"\\{tag}*{_cks(tag)}\\{lines[5]}\r\n".encode() + lines[6].encode() + b"\r\n")),
    ]
    everything = modbus + l2 + nmea
    out = []
    for name, frames in (("modbus", modbus), ("l2", l2), ("nmea", nmea), ("all", everything)):
        p = dest / f"{name}.pcap"
        write_pcap(p, [(ts(1_700_000_000 + i, i * 1000), f) for i, f in enumerate(frames)])
        q = dest / f"{name}_ns_be.pcap"
        write_pcap(q, [(ts(1_700_000_000 + i), f) for i, f in enumerate(frames)], nanos=True, big_endian=True)
        r = dest / f"{name}.pcapng"
        write_pcapng(r, [(None if i == 1 else ts(1_700_000_000 + i), f) for i, f in enumerate(frames)], tsresol=9)
        out += [p, q, r]
    cooked = dest / "cooked.pcap"
    write_pcap(cooked, [(ts(1_700_000_000 + i), sll2(src, 0x0800 if f[12:14] == b"\x08\x00" else 0x0806, f[14:]))
                        for i, (src, f) in enumerate([(ais, nmea[0]), (plc, l2[0])])], linktype=276)
    out.append(cooked)
    for f in sorted(FIX.glob("*.pcap")):
        shutil.copy(f, dest / f.name)
        out.append(dest / f.name)
    return out
