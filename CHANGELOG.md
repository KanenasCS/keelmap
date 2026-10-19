# Changelog

## 0.1.1

Fixes from a bug hunt with fuzzing, scaling probes and static type checking.

Security and privacy
- Redaction could be reversed. Tokens were plain SHA-256 prefixes of small value spaces, so an IMO number came back in seconds by trying every valid one. Tokens now use HMAC-SHA256 with a random key per export, or a key you keep (`--redaction-key`, created with `keelmap keygen`) for stable tokens. Exports record which kind was used.
- Crafted or damaged capture files could crash the reader, including a 4 GB memory allocation from a 100-byte file. Impossible lengths, short blocks, truncated options and out-of-range timestamps are now counted and reading stops cleanly where the file is damaged.

Scaling
- Memory grew with capture length, about 2 KB per NMEA datagram. It now stays flat, about 20 MB for nine hours of a 10 Hz source. Modbus results are staged per source as they arrive, pending requests and incomplete AIS messages are capped.
- Attaching IPs to assets was quadratic. It now uses an index: 96,000 assets in 7.5 seconds.

Fixes
- The chart showed "Frames and undefined" for NIC vendor evidence. Registry evidence now names the registry file.
- Output files are written before the summary is printed, so a closed console no longer loses the chart.
- `keelmap map` gives a clear error for a damaged or newer inventory instead of a traceback.
- The `merge_from` field pairing is checked, and the code passes mypy.
- Successful IEEE registry lookups were listed under "not turned into evidence". They now have their own line and chart section.
- A pcapng block whose leading and trailing lengths disagree now stops reading as damaged.
- Modbus endpoints must be host addresses. Device identification text is trimmed of trailing spaces.
- Fragmented NMEA datagrams are counted instead of skipped silently.
- `--map` must name a different file from `--output`.

Added
- Linux cooked captures (`tcpdump -i any`, link types 113 and 276).
- AIS type 19 vessel names, validated against pyais on 109 real messages.
- ARP and DHCP cross-checks against tshark on Zeek's real traces, see the validation log.
- The IEEE OUI loader validated on the official October 2026 CSV files, all three registries.
- Plain-language explanations for every skip counter, on the command line and in the chart.
- An evidence verification mode (`KEELMAP_VERIFY_EVIDENCE=1`), on in all tests, that fails if any evidence record is counted twice.
- An 800-case fuzzing run in every test run, and `tools/fuzz.py` for long campaigns.
- mypy in CI.

Changed output
- `modbus@0.1.1`: IP evidence is recorded for every endpoint, also when it joins a MAC-identity asset. Evidence text names the transaction.
- `nmea0183@0.1.1`: evidence names the sentence's line in its datagram and the AIS message number, so counts are per sentence and per message.
- Exports include a `redaction` object describing how values were redacted.

## 0.1.0

First release. Passive asset discovery from pcap and pcapng files.

- Reader for classic pcap and pcapng with Wireshark frame numbering
- Decoders: ARP, DHCP, LLDP (with LLDP-MED inventory and RFC 8520 MUD URLs), Modbus/TCP, NMEA 0183, IEC 61162-450, AIS own-ship identity
- NIC vendor from IEEE OUI files you supply (MA-L, MA-M, MA-S)
- JSON inventory where every value cites capture hash and frame numbers, with vessel identifiers redacted by default
- Offline HTML asset chart with a hash-locked Content Security Policy
- Cross-check tools against tshark, and a headless browser safety check for charts
