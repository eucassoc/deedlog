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

A time-stamp proves that a checkpoint, and so every record it covers, existed
at that time. One time-stamp covers everything before it, so a chain needs one
per checkpoint, not one per record. A time-stamp cannot be obtained later for
an earlier time.

```sh
dlog timestamp -tsa https://timestamp.sectigo.com -out checkpoint.tsr checkpoint
dlog verify -checkpoint checkpoint -key operator.vkey -timestamp checkpoint.tsr chain.jsonl
```

Authorities whose root certificates are not in the system's store, such as
FreeTSA, need them passed with `-tsa-roots`, both when stamping and when
verifying.

### Free and accredited authorities

Any RFC 3161 authority works; which to use is a matter of operation. Free
authorities (FreeTSA, DigiCert, Sectigo), together with witness cosignatures,
which carry each witness's time, are enough day to day. Stamping with two or
three of them avoids depending on any one.

Where a law requires accredited time-stamps, such as Japan's Electronic Books
Maintenance Act, or a dispute in court is likely, also stamp with an
accredited authority. Accredited stamps are paid for one by one, so stamp
less often:

| | Free authorities | Accredited authority |
|---|---|---|
| How often | Every checkpoint | Once a day, or once an hour |
| Stamps a year | One per checkpoint | 365 (8,760 hourly) |
| Time proven to within | The checkpoint interval | A day, or an hour |

For example, run hourly and daily from cron:

```sh
# Hourly: checkpoint, witnesses, two free authorities
cp="cp/$(date -u +%Y%m%dT%H)"
dlog checkpoint -key operator.key chain.jsonl > "$cp"
dlog cosign -key operator.vkey -witness w1.vkey=https://w1.example -out "$cp.cosigned" chain.jsonl "$cp"
dlog timestamp -tsa https://freetsa.org/tsr -tsa-roots freetsa-root.pem -out "$cp.freetsa.tsr" "$cp"
dlog timestamp -tsa https://timestamp.sectigo.com -out "$cp.sectigo.tsr" "$cp"

# Daily: an accredited authority stamps the latest checkpoint
latest=$(ls cp/*T?? | tail -1)
dlog timestamp -tsa "$ACCREDITED_TSA_URL" -tsa-roots accredited-roots.pem -out "$latest.accredited.tsr" "$latest"
```

When a dispute becomes likely, add an accredited time-stamp at once. It fixes
everything recorded up to that moment, though not the earlier times, which
rest on the time-stamps taken then.

Time-stamps can be verified only while the authority's certificate chain is
valid. Records kept for many years need their time-stamps stamped again
before then, as long-term signature formats such as PAdES do; `dlog` does not
do this yet.

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

## What the published records reveal

The rules an operator declares, such as how long data stays where and how
often it is inventoried, are public by design: verifiers check the chain
against them. Anyone can read them, so posing as a user to obtain a receipt
reveals nothing more, and a receipt shows only its own holder's event.
Publishing the rules does not weaken the systems they describe. Those are
protected by access control, not by keeping the rules secret, and a declared
short retention makes the data held less worth attacking.

Records hold digests, so they do not reveal the evidence. They can reveal
patterns, which the operator should limit:

| Visible in records | Can reveal | What to do |
|---|---|---|
| Counts in inventories | Volume and its changes over time | Record only what the declared rules need |
| Times of recurring jobs | When data moves, and so when it is where | Declare limits only, and vary when jobs run |
| Names of systems and tiers | Vendors and products in use | Use generic names, such as `form-service` and `archive` |
