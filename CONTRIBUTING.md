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
| `examples/` | Use cases, each a runnable sample |
| `docs/` | Guide and roadmap |

## Developing

```sh
go vet ./...
go test ./...
gofmt -l .
```

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
