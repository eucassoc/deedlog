# deedlog anchoring — v0.1 (draft)

Status: **draft**, and not yet implemented by `dlog`. Breaking changes are
expected until v1.0.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as
described in RFC 2119.

## 1. Why

A checkpointed chain ([checkpoint.md](checkpoint.md)) tells its witnesses how
many records it holds and when each batch was added, and a verification page
that reads the chain tells everyone. For many operators that is too much:
the number of inquiries or orders, the hours they arrive, and how many people
handle them can be read off the chain, although no record says anything
about a person.

Anchoring keeps the records with the operator and still lets them be checked:

- a witness learns only that time passes;
- whoever holds a record and its proof can check that the operator committed
  to it, and when;
- whoever is given the whole chain can check that the operator committed to
  exactly that chain.

## 2. Two chains

An anchored chain is two evidence chains
([evidence-chain.md](evidence-chain.md)):

- the **record chain**, which the operator keeps to itself, and
- the **anchor chain**, which is public and checkpointed as described in
  checkpoint.md. Its origin identifies the anchored chain.

The `chain` field of the record chain SHOULD be the anchor chain's origin
followed by `/records`.

At a fixed interval that the operator declares, it appends one **anchor
record** to the anchor chain and obtains a cosigned checkpoint for it. The
operator MUST append an anchor record at every interval, whether or not
records were added to the record chain: otherwise the anchor chain tells
when there was activity. Records are added to the record chain at any time.

## 3. An interval's tree

An anchor record covers the records added to the record chain since the
anchor record before it: the records with sequence numbers `from` (inclusive)
to `to` (exclusive), where `from` is the `to` of the anchor record before, or
0. The range MAY be empty.

For each anchor record the operator draws two fresh random values of at
least 128 bits, the **nonce** and the **pad**, written as lowercase
hexadecimal.

The **size** of the interval's tree is the smallest power of two that is at
least the number of records covered, and at least 1. Every record of an
anchored record chain MUST name a SHA-256 digest of its subject
(`subject.digest.sha256`). The leaves are:

- for the record at position `i` of the interval (counted from 0),
  `SHA-256(0x00 || "deedlog-anchor-leaf/v1\n" || blind || subject || record)`,
  where *blind* is `SHA-256("deedlog-anchor-blind/v1\n" || pad || i)`,
  *subject* is the 32 bytes of the record's subject digest, and *record* is
  the SHA-256 of the record bytes (evidence-chain.md §3);
- then, for each remaining position `j`,
  `SHA-256(0x00 || "deedlog-anchor-pad/v1\n" || pad || j)`.

Positions are 32-bit big-endian integers, and the pad is the bytes its
hexadecimal form encodes. The tree is the Merkle tree of checkpoint.md §2
over these leaves.

A leaf stands for a record without being its bytes. A record's bytes carry
its sequence number, so a proof made of them would tell its holder how many
records came before; a proof made of the leaf's three parts tells only what
the record is about. Filling the tree up to a power of two keeps a proof
from telling how many records the interval held, beyond the order of
magnitude. The blind keeps the holder of one proof from testing guesses
about the records beside it.

## 4. Anchor records

The **commitment** of an interval is the SHA-256, in lowercase hexadecimal,
of the text

```
deedlog-anchor/v1
<chain field of the record chain>
<epoch>
<size>
<base64 root of the interval's tree>
<nonce>
```

with a newline after every line, the last included. The **epoch** is the
time of the interval's end as the operator asserts it, RFC 3339 in UTC to the
second.

An anchor record is a record of the anchor chain whose `meta` has

| Key      | Value |
|----------|-------|
| `event`  | `chain.anchored` |
| `epoch`  | the epoch |
| `commit` | the commitment |

Epochs MUST increase along the anchor chain. The nonce keeps someone who
knows one interval's tree from testing whether a later interval added
nothing.

## 5. Proving a record

A **record proof** shows that the operator committed to a record about a
given subject, without showing the record. It goes with the subject's bytes,
or their SHA-256 digest, and has

| Field    | Description |
|----------|-------------|
| `seq`    | sequence number of the anchor record |
| `epoch`  | its epoch |
| `size`   | size of the interval's tree |
| `index`  | position of the record's leaf in it |
| `path`   | the inclusion proof (RFC 9162 §2.1.3), base64 hashes |
| `nonce`  | the interval's nonce |
| `blind`  | the record's blind, hexadecimal |
| `record` | the SHA-256 of the record bytes, hexadecimal |

A verifier MUST accept the proof only if:

1. the leaf of §3, computed from `blind`, the digest of the subject's bytes
   and `record`, leads with `index`, `size` and `path` to a root that, put
   into the text of §4 with `epoch` and `nonce`, gives the `commit` of the
   anchor record at `seq`;
2. that anchor record's `epoch` equals the proof's; and
3. the anchor chain verifies against a checkpoint, as described in
   checkpoint.md §8, whose tree size is greater than `seq`.

What the proof establishes is that a record about this subject existed when
the witnesses cosigned that checkpoint, and has not been replaced since. A
record added since the last anchor record has no proof yet; the operator
SHOULD say by when it will.

The operator decides to whom it gives proofs. A proof discloses the subject
(or its digest), the size of the interval's tree and the record's position in
it; it does not disclose the record, its sequence number, or anything of the
records beside it. What a verifier shows of a record beyond its subject is
not covered by the proof: an operator that wants a holder to check a record's
time or kind puts them into the subject.

## 6. Checking the whole record chain

Whoever is given the record chain also needs, for each anchor record, its
`seq`, `from`, `to`, `nonce` and `pad`. A verifier MUST:

1. verify the record chain as described in evidence-chain.md §8;
2. verify the anchor chain against a checkpoint, as described in
   checkpoint.md §8;
3. check that there is one entry for every anchor record up to the
   checkpoint's tree size, that the first `from` is 0, and that each `from`
   equals the `to` before it; and
4. for each anchor record, build the tree of §3 from the records `from` to
   `to` and the pad, and check that the commitment of §4 equals the anchor
   record's `commit`.

Records after the last `to` are not yet anchored.

Because every interval is covered by exactly one anchor record and the
ranges are contiguous from 0, a record chain that passes is the one the
operator committed to: nothing was removed, changed, reordered or inserted
before the last anchor record.

## 7. Security considerations

- **What witnesses see.** The anchor chain grows by one record per interval.
  A witness sees its size and root, and nothing of the record chain.
- **Who sees the record chain.** Keeping it private moves the question of
  who may read it to the operator. Operators SHOULD record, in the record
  chain, to whom they gave it.
- **Withholding.** An operator can refuse to give a proof. The holder of a
  record's identifier then has reason to escalate, as with receipts
  (checkpoint.md §7).
- **The interval is the resolution of trusted time.** A record's own
  timestamp is the operator's assertion; the cosignature on the checkpoint
  that covers its anchor record is the witness's. A shorter interval brings
  the two closer and costs more checkpoints.
- **The nonce and the pad are secrets until disclosed.** The nonce is
  disclosed in every proof for its interval, a blind in the proof of its
  record, the pad only with the whole record chain. A pad that leaks lets a
  proof's holder tell padding from records, and so count them.
- **Subjects that can be guessed.** A proof shows a subject to someone who
  already holds it. It does not hide a subject from someone who can guess it
  and is given the proof; the operator gives proofs only to those who may
  know the subject.
