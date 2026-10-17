# Changelog

## 0.1.0

First release. Passive asset discovery from pcap and pcapng files.

- Reader for classic pcap and pcapng with Wireshark frame numbering
- Decoders: ARP, DHCP, LLDP (with LLDP-MED inventory and RFC 8520 MUD URLs), Modbus/TCP, NMEA 0183, IEC 61162-450, AIS own-ship identity
- NIC vendor from IEEE OUI files you supply (MA-L, MA-M, MA-S)
- JSON inventory where every value cites capture hash and frame numbers, with vessel identifiers redacted by default
- Offline HTML asset chart with a hash-locked Content Security Policy
- Cross-check tools against tshark, and a headless browser safety check for charts
