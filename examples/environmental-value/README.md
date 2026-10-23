# Use case: proof of environmental value

> Status: runnable sample. `go run ./examples/environmental-value`

Environmental value is traded as carbon credits (for example J-Credits) and
energy attribute certificates (for example Japan's non-fossil certificates
with tracking information). Either is only as credible as the data behind it. Their value depends on measurement,
reporting and verification (MRV): how much was generated or reduced, where,
when, and by which equipment.

## Where deedlog fits

deedlog is **not a registry**. Issuance, transfer and retirement of credits
and certificates belong to the official registries and markets, which are
also what prevent double issuance. deedlog provides verifiable evidence for
the data that flows into and out of them:

| Stage | Subject |
|---|---|
| Metering | Digest of each meter reading, referencing the meter's [signed device data](../device-data/) |
| Aggregation and reporting | Digests of the input readings and the resulting report |
| Third-party verification | Digest of the verifier's statement |
| Issuance, transfer, retirement | Digest of the registry's confirmation, with the registry's identifier in `meta` |
| Claim by the end user | Digest of the report in which the retired credit or certificate is claimed |

## What this adds

- **Traceable MRV.** A verifier can follow a certificate back through the
  report to the individual readings and the meters that produced them.
- **Tamper-evident monitoring data.** Readings fixed at collection time cannot
  be adjusted later to inflate reductions.
- **Evidence for claims.** Companies reporting renewable electricity use or
  offsets can show auditors the chain from claim to retirement to generation.

## Run the sample

```sh
go run ./examples/environmental-value
```

Three solar meters report daily for two months into a metering chain. Monthly
reports in a separate MRV chain reference their readings by index and leaf
hash, so a reference cannot be redirected to another record; a verifier's
statement, the registry's issuance and a company's claim follow. Two witnesses
cosign both chains.

An auditor traces every certificate back to the readings. In the second run
the May report counts six April readings again and adds 1,500 kWh, and a
second company claims the April certificate:

```
line 4: reading 0 counted again; the report at line 1 already counted it
line 4: report for 2026-05 claims 12801.0 kWh; its readings add up to 10620.0 kWh
line 8: retailer.example claims certificate REC-2026-04-0001, already claimed by maker.example at line 7
```

The registry remains the authority on issuance and retirement; the sample only
records its confirmations.

| File | Shows |
|---|---|
| [mrv.go](mrv.go) | Where the calls go: metering, reports, verification, issuance and claims |
| [check.go](check.go) | The trace from claim to readings |
| [main.go](main.go) | The scenario |
