# Use case: device-originated data

> Status: runnable sample. `go run ./examples/device-data`

Sensors, meters and cameras produce data that other systems rely on: a meter
reading becomes an environmental certificate, a camera frame becomes news or
evidence. That data passes through gateways, platforms and operators before
anyone checks it.

When the device signs the records it emits with its own key, each record can
be attributed to that device no matter how many intermediaries it passed
through.

| Event | Subject |
|---|---|
| Reading or capture | Digest of the reading, frame or segment, signed by the device with its sequence number |

## What this adds

- **Attribution through untrusted paths.** A gateway or platform can drop
  records but cannot alter or forge them.
- **Visible gaps.** With a declared cadence and sequence numbers, missing
  records show up as gaps; see the [trust model](../../spec/trust-model.md).
- **A foundation for other use cases.** Records in
  [proof of environmental value](../environmental-value/),
  [content provenance](../content-provenance/) and
  [operator commitments](../operator-commitments/) can reference the device
  data they were derived from.

## Notes

- Record-level source signatures are planned in the specification (§7).
  Until then, as in the sample, the device signs each reading as a signed
  note, and the signed note is the evidence body.
- Constrained devices can buffer signed readings and forward them through a
  gateway.

## Run the sample

```sh
go run ./examples/device-data
```

Two meters sign a reading every 15 minutes for a day, and a gateway forwards
them to the collector, which records them exactly as received. Anyone with the
registry of device keys and the evidence bodies can check every record. In the
second run the gateway drops four readings and alters one, and someone injects
a reading signed with a key of their own:

```
line 84: meter-18.energy.example: readings 40 to 43 missing since line 78
line 93: reading 1 of meter-17.energy.example is not as the device signed it: no signature from a known key
line 116: reading 60 of meter-17.energy.example is not as the device signed it: signature by meter-17.energy.example: invalid signature
```

| File | Shows |
|---|---|
| [device.go](device.go) | The signed reading, the device, the gateway and the collector |
| [check.go](check.go) | The check against the registry of device keys |
| [main.go](main.go) | The scenario |
