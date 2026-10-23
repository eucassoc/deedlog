# Use case: verifiable operator commitments

> Status: runnable sample. `go run ./examples/operator-commitments`

Operators make promises the public cannot check: "our cameras do not identify
individuals", "we delete footage after 72 hours", "we only share aggregate
counts". Today people have to take the operator's word for it.

An operator that wants to be trusted can adopt deedlog to show that it has
nothing to hide: it publishes what it records, lets independent parties
witness its checkpoints, and accepts that any inconsistency becomes a public
proof of misbehavior. People do not verify anything themselves; they rely on
the fact that anyone could. See the [trust model](../../spec/trust-model.md).

## Example: a city's surveillance cameras

### Commitment

The operator publishes, and records as the first entry of the chain:

- what is recorded, and how often (the declared scope and cadence),
- which software processes the footage, by digest, and where its source code
  is published,
- the retention period,
- which anchors and witnesses are used.

### Evidence recorded

| Event | Recorded by | Subject |
|---|---|---|
| Footage segment captured, every 10 s | Camera | Digest and sequence number of the segment |
| Processing run | Edge device | Digest of the software, its configuration and its output |
| Output published | Platform | Digest of the aggregate output (for example people counts) |
| Segment deleted | Storage | Digest of the deleted segment and the retention rule applied |
| Anchor or witness changed | Operator | The old and new anchor set |

### What a verifier can check

- Every captured segment has a deletion record no later than the retention
  period allows.
- Only software with the published digest processed footage, and the only
  outputs were aggregates.
- No segment is missing from the declared cadence.
- The history shown today matches checkpoints held by witnesses.

### What remains outside

A secret copy taken before deletion leaves no trace in any log. Attestation
by the device's hardware that it runs the published software (using existing
mechanisms such as a trusted execution environment), independent audits and
whistleblower channels remain necessary. deedlog records the results of
such attestations; it does not perform them.

## Anchors for this example

| Anchor | Role |
|---|---|
| Accredited time-stamping authority | Time of each checkpoint |
| The municipality's privacy office | Witness with oversight duty |
| A residents' association or civil liberties organization | Independent witness |
| Any library, university or individual | Permissionless witness |

Residents see a simple indicator on the operator's website: the latest
checkpoint, when it was timestamped, and which witnesses cosigned it.

## Run the sample

```sh
go run ./examples/operator-commitments
```

Two cameras record a segment every minute for a day; published software
counts people in each segment; footage is deleted after 6 hours; two witnesses
(the privacy office and a residents' association) cosign hourly checkpoints.
The second run breaks the promise in four ways, and a check that uses only the
published commitment, the chain and the checkpoint finds each:

```
line 3706: segment still not deleted after 11h45m; the commitment allows 6h00m
line 3992: processing of footage that was not recorded as captured, or already deleted
line 4092: station-south: segments 781 to 800 missing since line 3968 (21m without a record)
line 4691: processing by software 4c48e8dfdbb3, which is not published
line 5051: processing produced "face-match", which the commitment does not allow
```

| File | Shows |
|---|---|
| [cameras.go](cameras.go) | Where the calls go: the camera gateway, the processing pipeline, the retention job |
| [check.go](check.go) | The check against the published commitment |
| [main.go](main.go) | The scenario |
