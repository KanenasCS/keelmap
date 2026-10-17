# Data model

Schema version 0.1.0. Defined in `src/keelmap/model.py`.

## Inventory

| Field | Notes |
|---|---|
| schema_version, tool_version | Both in every export |
| redacted | True unless the caller opted out |
| sources | One entry per capture: SHA-256, frame count, time range. Filename redacted by default |
| registries | Reference files used for registry evidence, such as IEEE OUI files: name, SHA-256, entry count, file date |
| assets | Only assets proven by traffic: field evidence or a recorded communication |
| communications | Only those with at least one recorded packet |
| stats | Counts of frames read and of everything not turned into evidence, with the reason as the key |

## Asset

`asset_id` is the first 16 hex characters of SHA-256 over `identity_key`, so the same device gets the same ID across runs. That is what change detection in 0.2 will rely on.

Field `description` holds free text a device sent about itself, verbatim, never parsed. Field `capabilities` holds what a device says it has enabled, such as bridge or router. Both are self-reported.

Field `device_ids` holds identifiers a device announces for itself that are not hostnames, such as an IEC 61162-450 system function id. Field `vessel_identifiers` holds own-ship MMSI, IMO, call sign and name, and is redacted on export by default.

`identity_key` is `mac:<mac>` for devices on the sensor's own segment, otherwise `ip:<ip>`. In 0.1 a device seen both ways stays as two assets. Merging them needs evidence and is planned for 0.2.

Every value carries `evidence_count`, the exact number of supporting records, and `evidence`, a sample of up to 10 of them with frame numbers. First and last seen are computed from all records, not only the sample.

Each field is either single-valued (known, unknown, conflict) or a set (known or unknown, each member with its own evidence). `first_seen` and `last_seen` come from traffic only. Registry lookups do not count as sightings.

## Communication

Directed: source asset, destination asset, transport (tcp, udp, l2), protocol, destination port. Keeps `exchange_count` (for example request and response pairs), `packet_count` (distinct frames, since several exchanges can share one TCP segment), first and last seen, observed operations such as `modbus/fc:06`, and up to 20 sample evidence records to keep exports small.

## Sentinel mapping (0.2)

The nested export is for humans and tools. For Sentinel, 0.2 will add a flat export generated from one column map, so the DCR transform and table schema cannot drift apart. Planned tables are one row per asset per capture and one row per communication per capture. Evidence goes into a single dynamic column rather than duplicated flat columns, to keep ingestion cost down.
