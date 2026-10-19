# Decoders

Each decoder documents what it accepts as evidence and what it deliberately ignores. Every skip is counted in `stats`.

## Reader

| Topic | Behaviour |
|---|---|
| Formats | Classic pcap (microsecond and nanosecond, both byte orders) and pcapng |
| Frame numbers | Match Wireshark: every packet block counts, from 1, across sections |
| Timestamps | UTC, rounded to the nearest microsecond. Binary pcapng resolutions are accurate to within 1 microsecond |
| Simple Packet Blocks | Counted for numbering, not decoded, because they carry no timestamp (`frame_without_timestamp`) |
| Truncated files | Complete frames are kept, the rest is counted (`capture_truncated`) |
| Damaged files | A record or block with an impossible length, too short for its type, or whose leading and trailing pcapng lengths disagree, stops reading there and is counted (`capture_corrupt_record_length`, `capture_corrupt_block_length`, `capture_corrupt_block`). Records are capped at 1 MiB, so a crafted length cannot exhaust memory |
| Impossible timestamps | The frame keeps its number but is not decoded (`frame_timestamp_out_of_range`) |
| Link types | Ethernet (1), Linux cooked v1 (113) and v2 (276) from `tcpdump -i any`. Cooked frames carry the sender's address but no destination, which no decoder uses. Cooked frames from non-Ethernet interfaces such as loopback are counted (`frames_cooked_not_ethernet`). Others are counted per type (`frames_unsupported_linktype_<n>`) |
| VLAN tags | 802.1Q, 802.1ad and QinQ stripped before decoding |

## ARP (arp@0.1.0)

Ethernet II framing only. ARP inside 802.2 LLC/SNAP (legacy token ring and FDDI translation) is not decoded.

| Stored | From |
|---|---|
| MAC | Sender hardware address, only when it equals the Ethernet source |
| IP | Sender protocol address of a request, reply or announcement |

| Not stored | Why | Counter |
|---|---|---|
| Anything from target fields | Asking for an address does not prove it exists | none |
| Frames where sender MAC differs from Ethernet source | Relayed, proxied or forged | `arp_sender_mac_mismatch` |
| IP 0.0.0.0 | RFC 5227 probe, the MAC is still stored | `arp_probe_no_ip` |
| Broadcast, multicast, loopback IPs | No single device owns them | `arp_sender_ip_not_host` |

Proxy ARP makes a router answer for addresses it does not own. KeelMap records exactly that, so a MAC with many IPs is a signal to review.

## DHCP (dhcp@0.1.0)

| Stored | From | Evidence |
|---|---|---|
| Client MAC and role `dhcp/client` | Client message where chaddr equals Ethernet source | observed |
| Hostname | Option 12 in a client message | self_reported |
| Client IP | Client message sent from ciaddr (bound client renewing) | observed |
| Server MAC and role `dhcp/server` | OFFER, ACK or NAK | observed |
| Server IP | IP source when it equals option 54 | observed |

| Not stored | Why | Counter |
|---|---|---|
| yiaddr in OFFER or ACK | A granted lease is not proof of use. The client's own ARP or traffic proves it | none |
| Option 50 requested IP | A request is not use | none |
| Option 60 vendor class | Names the DHCP software, not the device maker | none |
| Hostname in server messages | Only the client can name itself | none |
| Relayed messages (giaddr set) | Ethernet addresses belong to the relay path | `dhcp_relayed_skipped` |
| Option overload (option 52) | Not supported in 0.1, other options still used | `dhcp_option_overload_not_supported` |

## LLDP (lldp@0.1.0)

LLDP is a device describing itself, so nearly everything is self_reported. Frames that break the IEEE 802.1AB structure are discarded whole, as the standard requires of receivers: the first three TLVs must be Chassis ID, Port ID and a two-octet TTL, none may repeat, and no TLV may run past the frame.

| Stored | From | Evidence |
|---|---|---|
| MAC, role `lldp/advertiser` | Ethernet source of a valid frame | observed |
| hostname | System Name TLV | self_reported |
| description | System Description TLV, verbatim | self_reported |
| capabilities | Enabled capabilities only | self_reported |
| vendor, model, firmware | LLDP-MED Manufacturer Name, Model Name, Firmware Revision | self_reported |
| device_ids `lldp_chassis_mac:`, `lldp_chassis_local:`, `lldp_management_ipv4:`, `lldp_management_ipv6:`, `lldp_med_serial:`, `lldp_med_asset_id:`, `mud_url:` | Chassis ID, Management Address, LLDP-MED inventory, RFC 8520 MUD URL | self_reported |

A switch sends LLDP from each port's own MAC, so a switch seen on several ports appears as several assets, each carrying the same chassis id in device_ids. Merging them would mean trusting a self-reported id, so it is left to the reader.

| Not stored | Why | Counter |
|---|---|---|
| Vendor, model or version parsed from the description | Free text has no reliable structure. "SMCGS8P-Smart - SMCGS8P-Smart v3.20" names no vendor at all | none |
| Management address as the device's IP | A claim, not observed use | none |
| Capabilities supported but not enabled | Not what the device is doing | none |
| Port ID, Port Description | Describe the port facing the sensor, not the device | none |
| LLDP-MED hardware and software revision | No matching field, kept out rather than squeezed into firmware | none |
| Malformed frames | 802.1AB receive rules | `lldp_malformed_discarded` |
| Source MAC not unicast | Cannot identify a device | `lldp_source_not_unicast` |

## IEEE OUI registry (oui@0.1.0)

Not a decoder: applied after decoding when `--oui` is given. No registry data ships with KeelMap. Download the official IEEE files (MA-L `oui.csv` or `oui.txt`, MA-M `mam.csv`, MA-S `oui36.csv`) and pass any of them. The longest matching prefix wins.

A match fills only `nic_vendor`, as registry evidence citing the file's SHA-256. The inventory lists every registry file used, with hash, entry count and file date. The card maker is often not the device maker: 08:00:27 resolves to PCS Systemtechnik, the block VirtualBox uses for virtual network cards.

| Not looked up | Why | Counter |
|---|---|---|
| Locally administered MACs | Assigned by software, virtual machines or phones that randomise MACs | `oui_locally_administered` |
| Multicast MACs | Group addresses, not a card | `oui_multicast` |
| Blocks listed as Private | No holder published | `oui_private` |
| MA-L blocks held by the IEEE Registration Authority | Real holder is in MA-M or MA-S, give those files too | `oui_registration_authority_block` |
| Prefix not in the files given | | `oui_not_found` |

A prefix the registry lists for several organisations stores all of them, so `nic_vendor` shows a conflict (`oui_prefix_listed_for_several_organisations`). The February 2024 MA-L file has two: 00-01-C8 and 08-00-30, which has three holders.

## Modbus/TCP (modbus@0.1.1)

Pairing is the proof. Only a request and a response on the same TCP connection, with the same transaction id, unit id and function code, store anything. Port 502 alone proves nothing.

| Stored | From | Evidence |
|---|---|---|
| Role `modbus/client` | Its request was answered | observed, request frame |
| Role `modbus/server` | It answered | observed, response frame |
| Role `modbus/unit_id:<n>` | It answered as unit n. Does not prove separate devices exist behind it | observed |
| Role `modbus/gateway` | It returned exception 10 or 11, which the specification reserves for gateways | observed |
| Communication client to server | Each pair, with operations such as `modbus/fc:03` or `modbus/fc:16:exception:02` | observed, both frames |
| Vendor, model, firmware | FC43 MEI 14 objects VendorName, ModelName (else ProductCode), MajorMinorRevision, only for unit 0 or 255 | self_reported |

| Not stored | Why | Counter |
|---|---|---|
| Unanswered requests | No proof the target speaks Modbus | `modbus_request_unanswered` |
| Responses without a matching request | Includes captures that start mid-exchange and duplicate copies | `modbus_response_unpaired` |
| Transaction, unit or function mismatch | Not provably the same exchange | `modbus_response_mismatch` |
| Non-Modbus data on port 502 | Other protocols use the port | `modbus_port_502_not_mbap` |
| Endpoints that are not host addresses | TCP from a broadcast or multicast address is not real traffic | `modbus_endpoint_not_host_ip` |
| Device identity for unit ids other than 0 and 255 | May describe a serial device behind a gateway, not the TCP endpoint | `modbus_device_id_not_attributed_unit` |
| ADUs split across TCP segments | No TCP reassembly in 0.1 | `modbus_adu_split_across_segments` |
| Modbus on ports other than 502 | Not detected in 0.1 | none, nothing is seen |

Transaction ids: a repeat with the same TCP sequence number is a retransmission and the original frame is cited. A repeat with a new sequence number is a new request and the older one counts as unanswered. Many simple clients always send transaction id 0, so keeping the oldest would wrongly reject every exchange after one lost response.

Memory: pairs are folded into per-source staging as soon as they are seen. Pending requests are capped at 65,536, the oldest counts as unanswered.

IP to asset: an IP joins a MAC-identity asset only when exactly one such asset has ARP or DHCP evidence for it and the Modbus frame's Ethernet source is that same MAC. Otherwise it becomes an `ip:<address>` asset (`modbus_ip_owner_mac_differs`, `modbus_ip_owner_ambiguous`).

Undefined function codes are kept when answered. A client sending code 0 and receiving "illegal function" is a real exchange.

## NMEA 0183 over UDP (nmea0183@0.1.1)

Detected by content on any UDP port, because NMEA over UDP has no fixed port. A sentence counts only when it is well formed and its checksum is valid.

| Stored | From | Evidence |
|---|---|---|
| Source IP | Datagram holding at least one valid sentence | observed |
| `nmea0183/talker:<id>` and `nmea0183/sentence:<id><type>` | Each valid sentence | observed |
| `nmea0183/proprietary:<code>` | `$P` sentences. The code is recorded, never mapped to a vendor | observed |
| `iec61162_450/sender`, `iec61162_450/group:<address>:<port>` | Datagrams starting `UdPbC\0`, group only for multicast destinations | observed |
| device_ids `iec61162_450_sfi:<id>` or `nmea_tag_source:<id>` | Tag block `s:` field with a valid tag checksum | self_reported |
| Roles `ais/vdm`, `ais/vdo` | Complete AIS messages | observed |
| vessel_identifiers `mmsi:`, `imo:`, `callsign:`, `name:` | Own-ship `VDO` messages only, types 5, 19 and 24 for the static identity. Redacted on export by default | self_reported |

A talker id describes the instrument behind a sentence, not the network device. One IP sending GP, HE and SD sentences is usually a multiplexer or gateway, so roles record what was sent, not what the device is.

| Not stored | Why | Counter |
|---|---|---|
| Vessels heard in `VDM` messages | Other ships are not assets on this network | `ais_vdm_other_vessels_not_inventoried` |
| Sentences with a bad or missing checksum | Structure alone is weak evidence | `nmea_checksum_invalid`, `nmea_checksum_missing` |
| Sentences behind a malformed or bad-checksum tag block | Tag and sentence travel together | `nmea_tag_block_malformed`, `nmea_tag_block_checksum_invalid` |
| IMO numbers failing the check digit | A wrong vessel identity is worse than none | `ais_imo_check_digit_failed` |
| MMSI 0 or above nine digits | Not a valid MMSI | `ais_mmsi_invalid` |
| AIS fragments out of order or missing | Not provably one message | `ais_fragments_incomplete` |
| IEC 61162-450 binary (`RaUdP`) datagrams | Not supported in 0.1 | `iec61162_450_binary_not_supported` |
| Fragmented UDP datagrams | Not reassembled | `nmea_ip_fragment_skipped` |
| Communications | UDP is one-way, a destination address is not evidence of a receiver | none |

IP to asset uses the same rule as Modbus, with counters prefixed `nmea0183_`.

## Validation log

| Capture | Source | Result |
|---|---|---|
| dhcp.pcap, dhcp.pcapng, dhcp-nanosecond.pcap | Wireshark repository, `test/captures` | 2 assets each. Every MAC, IP, frame number and timestamp matches tshark 4.2.2. Offered IP 192.168.0.10 correctly withheld |
| arp.pcap | Wireshark repository, `test/captures` | Frame Relay link type, correctly reported as unsupported |
| modbus.pcap (60,227 frames), modbusBig.pcap, modbusSmall.pcap, 4SICS-GeekLounge-151022-min.pcap, modbus-eit.pcap, modbus-and-non-modbus-p502.pcap, fuzz-72.pcap, fuzz-1011.pcap | Zeek repository, `testing/btest/Traces/modbus` | `tools/crosscheck_modbus.py --no-tcp-analysis`: every pair, function code and exception matches tshark on all 8 traces, 22,785 pairs in total. 60k frames scan in about 2 seconds |

Notes on the Modbus cross-check:

1. tshark 4.2 does not link exception responses to requests, so the cross-check pairs those itself from tshark's decoded fields (same stream, transaction, unit and function).
2. With its default TCP analysis, tshark hides segments it labels as retransmissions from the Modbus dissector. In modbusBig frame 3150 the capture missed the original response, so the retransmission is the only copy. KeelMap uses it, and tshark agrees once `--no-tcp-analysis` is set. fuzz-72 shows the same effect from fuzzed sequence numbers.
3. Two KeelMap bugs were found this way and fixed: answered function code 0 was discarded, and reused transaction ids kept the oldest request.
4. No public trace contains a successful device identification response. That path is covered by built packets only, and tshark confirms those packets decode with the intended objects.

Wireshark's captures are GPL licensed and are not committed. Fetch them from the Wireshark repository to repeat the check.

### NMEA and AIS

tshark 4.2 has no NMEA dissector, so two independent libraries are the references: pyais 3.3.1 for AIS and pynmea2 for NMEA sentence validity. The data is the real AIS and NMEA recordings in the pyais repository (MIT).

| Check | Data | Result |
|---|---|---|
| AIS identity decoding against pyais | 86,168 real sentences, 83,564 complete messages | 89,077 field values compared (MMSI 83,360, IMO 1,151, call sign 2,193, name 2,373), 0 differences after stripping leading space padding, which pyais also strips. Type 19 names added in 0.1.1: 109 compared, 0 differences |
| Rejections | Same data | 104 IMO numbers rejected for a failed check digit, all MMSIs rejected were genuinely out of range, every payload KeelMap called invalid also failed in pyais |
| End to end, AIS source | 600 real sentences in UDP datagrams, 1 to 3 sentences each | 518 messages decoded and 69 invalid, identical to pyais's own stream assembler |
| End to end, own ship | A real type 5 message relabelled as VDO, fragments in separate datagrams | MMSI, IMO, call sign and name match pyais, evidence cites both fragment frames, all four values absent from the redacted export |
| End to end, NMEA validity | Real GPS, proprietary and tag-block lines inside IEC 61162-450 datagrams | KeelMap and pynmea2 reject exactly the same 4 lines. Sentence counts per type match. pynmea2 cannot parse AIS sentences, so those were checked with pyais above |

Out-of-order AIS fragments (pyais includes deliberate test cases) are counted as incomplete rather than reassembled. Real transponders send fragments in order. At most 4,096 unfinished messages are held, the oldest is dropped and counted.

The maritime captures above combine real recorded sentences with UDP framing, ports and multicast layout built for the tests. The natural next step is an authorised capture from a vessel, which would extend this validation to a live bridge network.

### LLDP and OUI

| Check | Data | Result |
|---|---|---|
| LLDP fields against tshark 4.2.2 | 19 LLDP frames in 10 captures from tcpdump and Zeek (BSD): two Cisco 3560 switches, an SMC switch, a Linux host with a MUD URL, a data-centre leaf, 4 fuzz and ASAN crash cases | Every accepted frame matches tshark on hostname, verbatim description, enabled capabilities, management addresses and chassis MAC. Every discarded frame (5) is one tshark marks malformed. The leaf switch frame is rejected for its all-zero source MAC |
| LLDP-MED inventory | Built frames, no public capture has these TLVs | tshark decodes the built frames with the intended manufacturer and model |
| OUI lookups against netaddr 1.3.0 | IEEE MA-L file (35,087 entries, February 2024) as shipped in netaddr, every prefix with a random host part, plus 20,000 random MACs | 0 differences once prefixes with several holders are compared as sets. netaddr and a last-wins reading each silently pick one holder for 00-01-C8 and 08-00-30, KeelMap shows the conflict |
| OUI names against tshark | 8 MACs from accepted assets in the LLDP and DHCP captures | Names identical to tshark's own resolution |
| The official CSV files | `oui.csv` (40,347 rows), `mam.csv` (6,641) and `oui36.csv` (7,235) downloaded from the IEEE in October 2026 | All rows load. 162,600 lookups against the longest matching official prefix across the three files, 0 wrong. Every MA-M and MA-S prefix checked resolves to its own holder through the IEEE-held parent block. Names keep the IEEE's exact text, including its own `?` characters in some non-Latin names |
| Names against tshark's bundled list | 13 MACs from real captures | 9 identical, 3 differ only in capitalisation (tshark reformats, KeelMap keeps the IEEE text), 1 reflects a newer registry (F8:ED:A5 is now Commscope, formerly ARRIS Group) |

### Robustness (0.1.1)

| Check | Result |
|---|---|
| Byte-level fuzzing of whole capture files | 0.1.0 crashed on 9 distinct malformed inputs, all in the reader, including a 4 GB allocation. After the fix, 48,479 inputs ran with no crash, hang or invariant violation |
| Structure-aware fuzzing of packet contents, aimed at the decoders | 43,852 inputs, no crash and no invariant violation, before and after the fix |
| Real `tcpdump -i any` captures, both cooked formats | Asset, IP and NMEA roles match tshark, the 3 loopback frames are counted as non-Ethernet |
| Memory on long captures | 0.1.0: 666 MB for 320,000 NMEA datagrams. 0.1.1: 20 MB, flat |
| IP resolution on large networks | 0.1.0: 4 times the devices took 14 times as long. 0.1.1: 96,000 assets in 7.5 seconds |
| Cross-checks after the changes | Modbus still matches tshark on all 8 traces, DHCP and LLDP still match tshark, AIS own-ship still matches pyais |

Invariants checked on every fuzzing input: every exported value has evidence, cited frames exist in their capture, timestamps fall inside it, fields are filled only from their allowed evidence kinds, communications point at exported assets, and no raw vessel identifier appears in a redacted export.

### Second review pass (0.1.1)

| Check | Data | Result |
|---|---|---|
| ARP against tshark | Zeek traces: `arp-who-has`, `communityid/arp`, `linuxsll-arp` (cooked), `arp-leak` (crafted address sizes), `snap-arp` | Every MAC to IP binding matches. All 6 `arp-leak` frames rejected as not Ethernet/IPv4. SNAP ARP is outside Ethernet II framing and ignored |
| DHCP against tshark | 10 Zeek and Wireshark traces, 575 DHCP frames, 14 assets: flood, INFORM, relay agent options, bad cookie, hardware type edge cases | Roles, hostnames and addresses match on every trace. The flood's 250 ACKs from spoofed source addresses and a growth test's 49 forged client addresses are correctly withheld |
| LLDP-MED inventory against tshark | Built frames with every inventory TLV | Manufacturer, model, firmware, serial and asset id all read as tshark reads them |
| Consistency invariants on every real capture | 39 captures | Modbus server, unit, gateway, client, operation and exchange counts all reconcile, NMEA talker and sentence counts agree, scans are deterministic |
| Fuzzing with the consistency invariants | 20,000 inputs | No failures |
| Empty chart | Capture with no decodable device | Renders with no errors |
