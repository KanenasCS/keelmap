# nmea_samples.txt

Real AIS and NMEA 0183 sentences copied from the pyais test data
(https://github.com/M0r13n/pyais, `tests/`), MIT License, Copyright (c) 2019 M0r13n.

| Line | Content | Reference values (decoded by pyais 3.3.1) |
|---|---|---|
| 1 | AIS type 1 | MMSI 247049900 |
| 2-3 | AIS type 5, two fragments | MMSI 258315000, IMO 6514895, call sign LFNA, name FALKVIK |
| 4-5 | AIS type 5, two fragments | MMSI 273315800, IMO 8867052, call sign UANX (sent as " UANX"), name OMSKIY-140 |
| 6 | GPS fix | $GPGGA, valid checksum |
| 7-8 | AIS with NMEA 4 tag blocks | tag source b003669710 |

No vessel in this file is "own ship". Tests relabel VDM as VDO to exercise
own-ship handling, which is stated in each test.
