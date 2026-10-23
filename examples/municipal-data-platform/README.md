# Use case: municipal data platform

> Status: runnable sample. `go run ./examples/municipal-data-platform`

Smart-city data platforms connect residents, municipalities and service
providers. Residents give consent; the platform provides their data to
services. Residents, municipal auditors and privacy officers need to be able
to check afterwards that **every provision of personal data was preceded by
valid consent**, and that no tenant accessed another tenant's data.

## Evidence recorded

| Event | Source | Subject |
|---|---|---|
| Consent given, changed or withdrawn | Consent management | Keyed digest of the consent record |
| Data provided to a service | Data integration flow | Keyed digest of the request and response metadata |
| Request denied | Data API | Keyed digest of the request |

Personal data never enters the chain: records hold `hmac-sha256` digests
under a key held by the municipality (see spec §6). Residents appear as keyed
pseudonyms, so an auditor can link a resident's consent to the provisions of
their data without learning who they are.

## Deployment notes

- Run the transparency log inside the municipality's or operator's
  environment rather than a public log.
- Agree retention and deletion rules with the municipality's personal
  information protection officer before go-live. Evidence bodies can be
  deleted on schedule; the chain stays verifiable because it holds only
  digests.
- Keep the collector's credentials separate from the platform's
  administrator credentials.

## Run the sample

```sh
go run ./examples/municipal-data-platform
```

Residents of one municipality consent to a childcare support service; one of
them withdraws on the third day. Services request data through the platform's
API every day, and the privacy officers of two municipalities witness the
chain. Each resident gets a receipt for giving or withdrawing consent; the
sample checks the withdrawal receipt against the witnessed checkpoint.

The second run has two common faults: consent cached after withdrawal, and a
consent check that ignores which service is asking. An auditor finds both from
the chain alone, without the key:

```
line 13: service mobility-app of city-b received data of a resident of city-a
line 13: data provided to mobility-app for "childcare support eligibility" without consent
line 24: data provided to childcare-support for "childcare support eligibility" after consent was withdrawn at line 21
```

| File | Shows |
|---|---|
| [platform.go](platform.go) | Where the calls go: consent management and the data API |
| [check.go](check.go) | The auditor's check |
| [main.go](main.go) | The scenario, and the resident's receipt |
