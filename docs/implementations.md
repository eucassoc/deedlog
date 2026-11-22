# The two implementations

deedlog is implemented twice in this repository:

- **Go**: [`core/`](../core), [`witness/`](../witness), [`publish/`](../publish),
  [`verifier/`](../verifier) and the `dlog` tool ([`cmd/dlog`](../cmd/dlog)).
  The [verification page](../web) is this code compiled to WebAssembly.
- **JavaScript**: [`js/deedlog.js`](../js/deedlog.js), the npm package
  `deedlog`. One file with no dependencies, for Cloudflare Workers, Node and
  browsers. It was `public/tlog.js` of
  [eucassoc/witness](https://github.com/eucassoc/witness) until it moved here.

The [specification](../spec) is normative for both. This page says what
"the two do not differ" means, what each has, and where they still differ.

## What "no difference" means

[`testdata/conformance/vectors.json`](../testdata/conformance/vectors.json)
holds inputs, the outputs they must give, and things that must be accepted
or refused. Both implementations are tested against it in CI:

- `core/conformance_test.go` builds the whole file from the inputs and
  compares it byte for byte, then verifies its contents;
- `js/test/conformance.test.mjs` reads the inputs from the file, produces
  every output and compares, and verifies the same contents.

So from the same input both give the same record lines and bodies, the same
digests, leaf hashes and roots, the same inclusion and consistency proofs,
the same signed checkpoints and cosignature lines, the same interval trees,
commitments, anchor records and record proofs, and the same answers of a
witness. Both accept the same chains and notes and refuse the same ones, a
chain at the same line.

`js/test/deedlog.test.mjs` then runs each against the other, live: `dlog`
verifies what the JavaScript signs and anchors, the JavaScript verifies what
`dlog` signs and anchors, and each is the other's witness.

A change to what either writes or accepts shows as a change to the vectors.
Regenerate them with `go test ./core -run TestConformance -update` and read
the diff: a changed output is a changed format, and records that are already
cosigned must still verify.

## What each has

| | Specification | Go | JavaScript | Held to the vectors |
|---|---|---|---|---|
| Writing a record of an event | evidence-chain §3–§6 | `core.EventRecord` | `makeRecord`, `nextRecord` | same bytes |
| Writing a record of other evidence | evidence-chain §3–§6 | `core.Writer.Append` | not included | the JavaScript accepts what it writes |
| Verifying a chain | evidence-chain §8 | `core.Verify`, `VerifyLeaves`, `VerifyLines`; `dlog verify` | `readChain` | same chains accepted; refused at the same line |
| Merkle tree and proofs | checkpoint §2 | `Root`, `InclusionProof`, `ConsistencyProof`, `VerifyInclusion`, `VerifyConsistency`; `dlog prove` | `merkleRoot`, `inclusionProof`, `consistencyProof`, `verifyInclusion`, `rootFromInclusion`, `verifyConsistency` | same proofs |
| Keys and signed notes | checkpoint §3 | `GenerateKey`, `GenerateWitnessKey`, `NewSigner`, `NewVerifier`, `Signer.Sign`, `OpenNote`; `dlog keygen` | `generateKey`, `parseSigner`, `parseVerifier`, `signNote`, `openNote`, `parseNote` | same keys read, same signatures |
| Checkpoints | checkpoint §3, §4, §8 | `SignCheckpoint`, `VerifyCheckpoint`, `CheckCheckpoint`; `dlog checkpoint`, `dlog verify -checkpoint` | `signCheckpoint`, `verifyCheckpoint`, `parseCheckpoint` | same notes; same notes accepted and refused |
| Cosignatures | checkpoint §4 | `Cosign`, `AddCosignatures` | `cosign` | same lines |
| Asking a witness | checkpoint §4.1 | `witness.Client`; `dlog cosign` | `requestCosignature` | each against the other's witness |
| Being a witness | checkpoint §4.2 | `witness.Server`, `FileStore`; `dlog witness` | `addCheckpoint` (the caller keeps the state) | same status, same body for 200 and 409 |
| Anchoring: making | anchoring §3–§5 | `Anchor`, `AnchorCommit`, `NewRecordProof`; `dlog anchor add`, `prove` | `anchor`, `anchorCommit`, `recordProof` | same trees, commitments, anchor records, proofs |
| Anchoring: checking one record | anchoring §5 | `RecordProof.Commit`, `CheckRecordProof`, `VerifyAnchors`; `dlog anchor check` | `commitOf` (the caller does steps 2 and 3) | same proofs accepted and refused |
| Anchoring: checking the whole chain | anchoring §6 | `CheckAnchored`; `dlog anchor verify` | `anchor` per interval (the caller does step 3) | same commitments |
| Publication | checkpoint §9 | `publish`; `dlog serve` | not included | |
| RFC 3161 timestamps | checkpoint §5 | `TimestampRequest`, `VerifyTimestamp`; `dlog timestamp` | not included | |
| Receipts | checkpoint §7 | `IssueReceipt`, `VerifyReceipt`, `CheckReceipt`; `dlog receipt` | not included | |
| Proofs of misbehavior | checkpoint §6 | `BuildMisbehaviorProof`, `CheckMisbehavior`; `dlog misbehavior` | not included | |

## Not in the JavaScript, and why

The JavaScript is what a Worker and a browser need, and is kept small enough
that someone checking a record can read what their browser runs.

- **RFC 3161 timestamps.** Verifying one means parsing CMS and validating an
  X.509 chain to a trusted root. Web Crypto offers neither, so it would take
  a certificate library as a dependency, or a large amount of new code in
  the one file. An operator's service stamps its checkpoints with
  `dlog timestamp`; a checkpoint's note text is the same whichever
  implementation signed it. A browser that must check a timestamp uses the
  Go implementation as WebAssembly, as the verification page does.
- **Receipts and proofs of misbehavior.** A receipt names the record's index,
  which tells its holder how many records came before; the services written
  in JavaScript so far keep their records private and hand out record proofs
  (anchoring §5) instead. The page that checks receipts and writes proofs of
  misbehavior is the Go implementation as WebAssembly. A receipt is a signed
  note, so `signNote` and `openNote` already sign and open one; what is
  missing is the receipt's text and the three outcomes of checkpoint §7. To
  be added when a service that publishes its records issues receipts from a
  Worker.
- **Publication endpoints** (checkpoint §9). Two routes that depend on the
  platform's HTTP interface; a service writes them with `inclusionProof`.
- **`core.Writer`'s general records.** A record of evidence held elsewhere:
  a few lines around `JSON.stringify` for a caller that needs it, and what
  it must satisfy is evidence-chain §4.

## Differences that remain

None of these changes a byte that either writes for the inputs in the
vectors; they are about inputs at the edges.

- **Numbers.** Sizes, indices and sequence numbers are `uint64` in Go and
  numbers in JavaScript, which reads at most 16 digits. Trees beyond 2^53
  leaves are out of the JavaScript's reach.
- **How a chain's problems are reported.** `core.Verify` stops at the first
  line that fails. `readChain` goes on, lists every problem with its line,
  and returns the entries it could read; the first problem is at the line
  where Go stops. `readChain` takes the lines, so splitting the file, the
  final newline and a file with no records are the caller's.
- **Fields of the wrong type.** Go decodes a record into its types, and so
  refuses, for example, a `meta` value that is not a string or a
  `collected_at` that is not RFC 3339; evidence-chain §8 does not ask for
  that, and `readChain` does not check it. Go also accepts `"prev": ""` in
  the first record, which `readChain` refuses.
- **What `makeRecord` is given.** It writes `source` as the caller's object,
  whatever its keys, and turns `meta` values into strings; `core.EventRecord`
  takes the three source fields and strings. For those inputs the bytes are
  the same.
- **Signatures.** The same key signs the same text to the same bytes in both
  because Ed25519 (RFC 8032) is deterministic and both platforms implement it
  so. Verification does not depend on it.
- **Anchoring, the caller's part.** `CheckRecordProof` and `CheckAnchored`
  do every step of anchoring §5 and §6. In JavaScript the steps that compare
  with the anchor chain (the epoch, the checkpoint's coverage, one entry per
  anchor record and contiguous ranges) are the caller's; the witness's page
  does them in its own code. Moving them into `js/deedlog.js` is the next
  step.
- **Wording of errors.** Not part of the format. Both name the line.

## What was brought in step

When the JavaScript moved here (it is commit `3dc1580` unchanged, SHA-256
`aea19ac7c844…`), the vectors showed three places where it differed from Go.
All three were in what it accepts or drops, none in a format, and all were
changed in the JavaScript:

- `readChain` did not check evidence-chain §8 step 6 (a subject digest), a
  first record without a chain name, lines ending in CR, or a line that is
  JSON but not an object (`null` made it throw).
- `parseCheckpoint` accepted an empty tree with a root that is not the empty
  tree's; `verifyCheckpoint` counted a note-signing key given as a witness.
- `makeRecord` silently dropped a `meta` key named `__proto__`.

`anchor` and `commitOf` now refuse secrets and proof fields that are not
hexadecimal instead of reading them as zeros. In Go, a witness whose key is
configured twice now counts once towards the quorum, as it did in
JavaScript.

Go gained what it lacked: anchoring (`core/anchor.go`, `dlog anchor`) and
records of events written as the JavaScript writes them (`core/event.go`).

## Other writers

A chain is verified by its bytes, so anything may write one.
[Marumie's ledger demo](https://github.com/eucassoc/marumie/tree/deedlog-demo)
has its own writer in TypeScript. It is not held to the vectors; what it
writes is checked by `dlog verify` and `readChain` like any chain.
