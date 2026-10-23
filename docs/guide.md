# Guide

[日本語](guide.ja.md)

## Checkpoints

The chain ID is the checkpoint origin: a schema-less URL under a domain the
operator controls. The operator's key name is the origin.

```sh
dlog keygen -name city.example/cameras -out operator   # operator.key (secret), operator.vkey (publish)
dlog checkpoint -key operator.key chain.jsonl > checkpoint
dlog verify -checkpoint checkpoint -key operator.vkey chain.jsonl
```

A chain that has grown since the checkpoint still verifies against it.

## Witnesses

Witnesses cosign checkpoints so that the operator cannot show different
histories to different people. deedlog speaks the C2SP witness protocol, so
any C2SP witness works, including those of the public witness network
(witness-network.org).

```sh
dlog cosign -key operator.vkey -witness w1.vkey=https://w1.example -out checkpoint.cosigned chain.jsonl checkpoint
dlog verify -checkpoint checkpoint.cosigned -key operator.vkey -witness w1.vkey -quorum 1 chain.jsonl
```

Anyone can run a witness for the chains they care about:

```sh
dlog keygen -witness -name witness.city.example -out witness
dlog witness -key witness.key -log operator.vkey -state witness.state -listen :8080
```

## Timestamps

```sh
dlog timestamp -tsa https://timestamp.sectigo.com -out checkpoint.tsr checkpoint
dlog verify -checkpoint checkpoint -key operator.vkey -timestamp checkpoint.tsr chain.jsonl
```

Where legal standing matters, use an accredited time-stamping authority and
pass its root certificates with `-tsa-roots`.

## Proofs of misbehavior

If an operator rewrites history, anyone holding an old checkpoint can prove it
with the operator's public key alone:

```sh
dlog misbehavior build -key operator.vkey old.jsonl old-checkpoint new.jsonl new-checkpoint > proof.json
dlog misbehavior check -key operator.vkey proof.json
```

## Receipts

A receipt is the operator's signed promise that an event is at a given index
of its chain. If a later, witnessed checkpoint holds something else there, the
receipt and the checkpoint together prove it.

The promise is always the same signed note, checked with the operator's keys
alone. Only the envelope changes with the recipient:

| Recipient | Envelope |
|---|---|
| People | A link to a verification page, as a QR code, email or download; an SD-JWT VC where wallets are in use |
| Dataspace connectors | Attached to protocol messages |
| AI agents paying with x402 | An HTTP response header |
| Devices | A compact field in the response |

Receipts must stay out of the operator's reach, so they are kept by the person
or deposited, by the person's choice, with an organization that checks them.

```sh
dlog keygen -name city.example/cameras/receipts -out receipts      # distinct from the checkpoint key
dlog receipt issue -key receipts.key -index 123 -url "https://verify.example/?lang=ja" chain.jsonl
dlog serve -chain chain.jsonl -checkpoint checkpoint.cosigned       # latest checkpoint and proofs

dlog prove -index 123 -leaf chain.jsonl > proof
dlog receipt check -receipt receipt -receipt-key receipts.vkey \
                   -checkpoint checkpoint -key operator.vkey -proof proof -out misbehavior.json
# exit 0: included; 3: not yet covered; 4: broken, proof of misbehavior written
```

The [verification page](../web/) checks receipt links in the browser. It is
hosted by someone other than the operator.
