# LLDP fixtures

| File | Source | Licence | SHA-256 | Reference values (tshark 4.2.2) |
|---|---|---|---|---|
| lldp_smc_switch.pcap | Zeek, `testing/btest/Traces/lldp.pcap` | BSD | c805ea9ed82b28d60432ed030e343e7f7de7a3e80df32a5a15f114e498996fc9 | Source 00:22:2d:81:db:10, chassis MAC same, System Name SMCGS8P-Smart, System Description "SMCGS8P-Smart - SMCGS8P-Smart v3.20", enabled capabilities 0x0004 (bridge), management address 192.168.2.10 |
| lldp_mudurl.pcap | tcpdump, `tests/lldp_mudurl.pcap` | BSD | a1265638677777d7f7f95b103d6293e1eab0b4a4f307c4e78e65a28cb107b03a | 2 frames from 00:23:54:c2:57:02, System Name upstairs.ofcourseimright.com, enabled capabilities 0x0008 (WLAN access point), management addresses 62.12.173.114 and 2001:8a8:1006:4:223:54ff:fec2:5702, MUD URL https://imright.mud.example.com/.well-known/mud/v1/vomitv2.0 |
| lldp_malformed_asan.pcap | tcpdump, `tests/lldp_asan.pcap` | BSD | ee7427958f947c5c2214b3fce0ce224b5bda911b978f8059b399be413a6f0cfe | tshark marks the frame malformed |
