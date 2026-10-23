# deedlog

General-purpose, tamper-evident evidence chain: collect → chain → checkpoint
(Merkle root signed by the operator, witness cosignatures, RFC 3161
timestamp) → export (OSCAL, legal, OCSF) → verify. See README.md,
spec/evidence-chain.md, spec/checkpoint.md and spec/trust-model.md.

## Rules

- The specification in `spec/` is normative. Change it first, then the code.
  Keep `core.Verify` in step with evidence-chain.md §8 and checkpoint
  verification in step with checkpoint.md §4 and §8.
- Checkpoints, notes and cosignatures follow C2SP (signed-note,
  tlog-checkpoint, tlog-cosignature, tlog-witness). Do not diverge from them;
  interoperability with existing witnesses is the point.
- Hash bytes, not objects: never re-encode JSON to compute or check a digest.
- `core/` and `spec/` stay domain-neutral. Municipal, legal or product-specific
  logic belongs in `collectors/`, `exporters/` or `examples/`.
- Standard library only unless a dependency is clearly justified (crypto
  primitives from `crypto/*`).
- Never put personal data or evidence bodies into records; use digests, and
  `hmac-sha256` for low-entropy data.
- Every verification failure must say which line failed and why.
- Docs: README.md and docs/guide.md are English; README.ja.md and
  docs/guide.ja.md are the Japanese counterparts and must be kept in sync.
  Keep the READMEs short: what it is, why, how it works, a quick start that
  runs, and links. Details go to docs/.

## Commands

```sh
go vet ./... && go test ./... && gofmt -l .
go run ./cmd/dlog verify FILE
```
