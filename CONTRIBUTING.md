# Contributing

Thank you for helping. Issues and pull requests are welcome in English or
Japanese.

## Before you start

- For changes to the chain format, open an issue first. The specification in
  [`spec/`](spec/) is changed before the code.
- Keep `core/` free of domain- or product-specific logic. Put that in
  collectors, exporters or examples.
- Prefer the Go standard library. New dependencies need a reason in the pull
  request description: every dependency is part of the supply chain we ask
  users to trust.

## Repository layout

| Path | Contents |
|---|---|
| `spec/` | Language-neutral specification (normative) and trust model |
| `core/` | Chain, checkpoints, notes, timestamps, receipts |
| `witness/` | Witness client and server (c2sp.org/tlog-witness) |
| `publish/` | Publication of checkpoints and proofs |
| `verifier/` | Receipt checking against a trust registry |
| `web/` | Verification page (WebAssembly) |
| `cmd/dlog/` | Command-line tool |
| `js/` | JavaScript implementation (the npm package `deedlog`) |
| `testdata/conformance/` | Vectors that the Go and the JavaScript implementation both reproduce |
| `examples/` | Use cases, each a runnable sample |
| `docs/` | Guide and roadmap |

## Developing

```sh
go vet ./...
go test ./...
gofmt -l .
go build -o dlog ./cmd/dlog && (cd js && DLOG=../dlog npm test)
```

A change to what either implementation writes or accepts is made in both,
and shows as a change to `testdata/conformance/vectors.json`
([docs/implementations.md](docs/implementations.md)).

## Sign-off

Contributions are accepted under the
[Developer Certificate of Origin](https://developercertificate.org/).
Sign off every commit:

```sh
git commit -s
```

## AI-assisted contributions

AI-assisted contributions are welcome. You are responsible for understanding
and being able to explain every line you submit.
