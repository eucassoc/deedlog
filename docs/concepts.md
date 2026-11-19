# Hash chains and Merkle trees

[日本語](concepts.ja.md)

Two mechanisms keep deedlog records from being changed unnoticed. This page
explains them without assuming any background. The exact definitions are in
the [specification](../spec/).

## First, a hash

A hash is a short fingerprint computed from data. deedlog uses SHA-256,
which turns data of any size into 64 hexadecimal characters.

- The same data always gives the same fingerprint, whoever computes it.
- Change a single character and the fingerprint is completely different.
- The fingerprint does not reveal the data, and in practice no one can make other data
  with the same fingerprint.

So if you keep a fingerprint, you can later check that the data has not
changed by a single character. deedlog records hold fingerprints of the
evidence rather than the evidence itself for the same reason.

## Hash chain: copy the previous page's fingerprint

Picture a ledger where every page starts by copying the fingerprint of the
page before it.

```
 record 0          record 1          record 2          record 3
┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐
│ content  │◀─────│prev: fp 0│◀─────│prev: fp 1│◀─────│prev: fp 2│
│          │      │ content  │      │ content  │      │ content  │
└──────────┘      └──────────┘      └──────────┘      └──────────┘
```

Change record 1 and its fingerprint changes, so it no longer matches the
"prev: fp 1" copied into record 2. Removing a record, slipping one in or
reordering them breaks the chain in the same way.

Someone who changes a record can rebuild every record after it, and the
chain matches again. But the fingerprint of the last record changes too. If
someone else kept that last fingerprint, the rebuild shows. Checkpoints,
below, turn "someone else keeps it" into a mechanism.

A hash chain has one weakness: to check that a single record is in the
ledger, you walk it from the start. A ledger of a million records means a
million records.

## Merkle tree: combine fingerprints like a tournament bracket

A Merkle tree pairs up the records' fingerprints like a tournament bracket,
fingerprints each pair, pairs those, and so on until one fingerprint is
left: the **root**. With four records:

```
                 root
            ┌─────┴─────┐
          fp AB        fp CD
         ┌──┴──┐     ┌──┴──┐
         A     B     C     D      ← fingerprints of the records
```

The root is a single 64-character value, yet it stands for the content and
order of every record. If any record changes, the root changes. A deedlog
**checkpoint** is the size and the root, signed by the operator, cosigned by
independent witnesses and timestamped by a timestamp authority. Fixing one
small root fixes every record up to that point.

A Merkle tree gives two things a hash chain does not.

**It shows that one record is included, with a few fingerprints.** To show
that record C is in the tree above, hand over C plus the fingerprint of D and
the fingerprint of AB. The recipient computes CD from C and D, the root from
AB and CD, and compares it with the signed root. The fingerprints needed are
one per round of the bracket: about 20 for a million records, and no other
record's content is shown. This is how the holder of a receipt checks that
their event really was recorded (an inclusion proof).

**It shows that the log only grew.** Comparing yesterday's root with
today's, a few fingerprints show that today's tree is yesterday's with
records added at the end and nothing before them changed (a consistency
proof). Witnesses check this without receiving any record, and cosign only
if it holds. An operator who rewrites the past, or shows different ledgers
to different people, either gets no cosignature or leaves two conflicting
signed checkpoints, which are themselves the proof of misbehavior.

## How deedlog uses each

deedlog computes both from the same records.

| | Hash chain | Merkle tree |
|---|---|---|
| Where | `prev` in each record (the previous record's fingerprint) | The root in a checkpoint |
| Shows | Records are linked in order, none removed or inserted | Every record at a point in time is fixed |
| How it is checked | Walk all records from the start | One record and a few fingerprints; not the whole chain |
| Used by | An auditor holding the whole chain | Receipt holders, witnesses |

A chain alone does not settle who keeps the last fingerprint, and a tree
alone does not let someone holding the records check how each follows the
one before. Using both, with the root held by people other than the
operator, means that changing or dropping a record always leaves a trace.

## What it does not do

- It does not **prevent** tampering; it makes tampering **detectable**. A
  record can still be changed, but not hidden.
- It does not stop false content from being recorded in the first place. It
  shows that a record has not changed since it was recorded.
- If only the operator holds the root, a rebuild goes unnoticed. Witnesses,
  timestamps and receipts exist to put the root out of the operator's reach.

See the [trust model](../spec/trust-model.md), and for the exact
computation, §5 of the [record specification](../spec/evidence-chain.md) and
§2 of the [checkpoint specification](../spec/checkpoint.md). The Merkle tree
is the one in RFC 9162 (Certificate Transparency), also used by the
transparency logs for web certificates.
