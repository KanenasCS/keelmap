# Linux cooked capture fixtures

Made with tcpdump 4.99.4 (`tcpdump -i any -y LINUX_SLL2` and `-y LINUX_SLL`) in KeelMap's
build environment, capturing traffic generated for the purpose. Addresses are a
locally administered MAC and the documentation range 192.0.2.0/24. No third-party data.

| File | SHA-256 | Reference values (tshark 4.2.2) |
|---|---|---|
| cooked_sll2_tcpdump.pcap | 6dcdce1f21eef6b369f36cb4a211beea747de5fb56b88f72e525b872359eed02 | 9 frames. eth0 sender 02:fc:00:00:00:01: NMEA $HEHDT from 192.0.2.2 in frames 1, 4, 6, ARP requests with sender 192.0.2.2 in frames 2, 8, 9. Loopback (hardware type 772, no address) in frames 3, 5, 7 |
| cooked_sll_tcpdump.pcap | a3398dee7e0b12112ddd9f818219a40c049f1d2c325ee34b4dc314a1299fe74d | Same traffic pattern in cooked v1 |
