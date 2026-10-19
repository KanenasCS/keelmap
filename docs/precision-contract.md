# Precision contract

KeelMap reports what the traffic proves. Nothing more.

## Evidence kinds

There are exactly three. There is deliberately no "inferred" kind.

| Kind | Meaning | Example |
|---|---|---|
| observed | Behaviour seen in traffic | Device answered a Modbus FC03 request |
| self_reported | The device described itself | LLDP system name, DHCP hostname, Modbus device identification |
| registry | Public registry lookup | IEEE OUI for the first three bytes of a MAC |

Every observed or self_reported value cites the capture SHA-256 and the 1-based frame numbers, so anyone can open the capture in Wireshark and check it.

## Which evidence fills which field

| Field | Allowed evidence | Why |
|---|---|---|
| macs, ips | observed | Addresses are seen, not claimed |
| roles | observed | A role is behaviour. "modbus/server" needs a response frame |
| hostname, device_vendor, device_model, firmware | self_reported | Only the device can tell us what it is |
| nic_vendor | registry | An OUI names the network card maker, which is often not the device maker |
| description, capabilities | self_reported | Free text and claims a device makes about itself, stored as sent |
| vessel_identifiers | observed, self_reported | MMSI and call sign from own-ship AIS. Redacted on export |

The model raises `PrecisionViolation` for any other combination. Contract tests make sure this stays true.

## States

| State | Meaning |
|---|---|
| known | Exactly one value, with evidence |
| unknown | No evidence. This is a valid answer, not a gap to fill |
| conflict | Two or more values, all kept with their evidence |

## Rules decoders must follow

The model cannot check these. Fixture tests do.

1. **Responses prove roles, requests do not.** A request sent to an address proves only that something tried to talk to it.
2. **No MACs from routed traffic.** On a routed path, the source MAC belongs to the router. Link a MAC to an IP only from same-segment evidence such as an ARP reply or a DHCP exchange.
3. **Cite the frame that holds the value.** Not the session start, not a nearby frame.
4. **Bump the decoder version** whenever its output changes, so old and new inventories can be compared.

## AIS

AIS sentences describe vessels heard over radio. Those vessels are not assets on the network and are not inventoried. The network asset is the transponder or gateway that emitted the sentences. Own-ship identifiers from `!AIVDO` are stored as sensitive vessel identifiers.

## Validation standard

Public sample captures are for development. A release claim needs at least one authorised capture from a real vessel or port network, with every exported asset checked against ground truth from the operator.

## Redaction

Redacted exports replace vessel identifiers and capture filenames. Identifiers become HMAC-SHA256 tokens with a secret key, never plain hashes: MMSI and IMO numbers are few enough that a plain hash can be reversed by trying them all. Without `--redaction-key` the key is random and discarded, so tokens cannot be reversed or linked between exports. With a key you keep, tokens are stable across exports, and only key holders can test a guess.

Redaction covers fields KeelMap knows are sensitive. A hostname or description a device chose for itself, such as one containing the ship's name, is stored as sent. Review those before sharing.
