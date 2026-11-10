# deedlog

**Every deed, on the record.**

deedlog (*DEED-log*) records what a system did in an append-only chain,
anchors it with independent witnesses and trusted timestamps, and lets anyone
verify it — without trusting the operator.

[日本語](README.ja.md) · Status: early development; expect breaking changes until v1.0.

## Why

Cyberattacks are getting faster and cheaper, and many recent breaches exposed
data that no longer needed to be where it was: contact form submissions kept
for years on a third-party service, exports left on a shared drive.

The defense is data tiering: delete what is no longer needed, move what must be
kept to a safer place, and — the step usually missing — show that this is
actually done, in a way others can check. Today that evidence is held by the
organization itself, which can edit it, leave things out, or show different
people different versions.

deedlog records each deletion and move as it happens, in a chain no single
party can quietly change and anyone can verify later. With a declared
schedule, a deletion that should have happened and did not shows up as a gap.

The same applies wherever others need to trust what a system did, for example
that an AI agent or a low-code automation did only what it was meant to.

## How it works

```
record ──▶ chain ──▶ checkpoint ──▶ verify
           linked     signed, witnessed,   anyone, offline,
           by hash    timestamped          or in the browser
```

- **Chain**: each record holds the hash of the previous one. Records hold
  hashes of evidence, never the evidence itself.
- **Checkpoint**: the operator signs the chain's Merkle root; independent
  witnesses cosign it (C2SP format) and an RFC 3161 authority timestamps it.
  Two contradictory checkpoints are a proof of misbehavior.
- **Receipts**: people involved in an event get a signed promise of where it
  is recorded, so leaving it out becomes provable.
- **Not a blockchain**: no consensus, no tokens. See the
  [trust model](spec/trust-model.md).

## Quick start

```sh
git clone https://github.com/eucassoc/deedlog && cd deedlog
go install ./cmd/dlog

dlog verify docs/sample/chain.jsonl
dlog keygen -name example.com/log -out operator
dlog checkpoint -key operator.key docs/sample/chain.jsonl > checkpoint
dlog verify -checkpoint checkpoint -key operator.vkey docs/sample/chain.jsonl
```

## Learn more

- [Guide](docs/guide.md): witnesses, timestamps, receipts, publishing
- [Use cases](examples/)
- [Trust model](spec/trust-model.md) and [specification](spec/)
- [Verification page](web/) for receipts
- [Roadmap](docs/roadmap.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## License

Apache-2.0. The name "deedlog" is covered by the [trademark policy](TRADEMARK.md).
