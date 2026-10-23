# deedlog checkpoints — v0.2 (draft)

Status: **draft**. Breaking changes are expected until v1.0.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as
described in RFC 2119.

A checkpoint commits an operator to the exact contents of a chain
([evidence-chain.md](evidence-chain.md)) at a given size. Checkpoints follow
the C2SP transparency log specifications, so that existing witnesses can
cosign them without deedlog-specific code:

- [c2sp.org/signed-note](https://c2sp.org/signed-note@v1.1.0)
- [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint@v1.1.0)
- [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature@v1.1.0)
- [c2sp.org/tlog-witness](https://c2sp.org/tlog-witness@v1.1.0)

The record format of [evidence-chain.md](evidence-chain.md) is unchanged:
records still carry `"spec": "deedlog/v0.1"`.

## 1. Origin

A checkpointed chain is identified by its **origin**, as defined by
c2sp.org/tlog-cosignature. The `chain` field of every record in a
checkpointed chain MUST equal the origin. In addition to the rules of §4 of
evidence-chain.md, the origin MUST be at most 255 bytes and MUST NOT contain
Unicode spaces, `+` (U+002B) or control characters.

The origin SHOULD be a schema-less URL under a domain the operator controls,
such as `city.example/cameras/2026`.

## 2. Merkle tree

The leaves of a chain's Merkle tree are the record bytes (evidence-chain.md
§3) of its records, in order. The tree is the Merkle hash tree of RFC 9162
§2.1 (identical to RFC 6962 §2.1) with SHA-256:

- the hash of the empty tree is `SHA-256("")`,
- the hash of a leaf is `SHA-256(0x00 || record bytes)`,
- the hash of an interior node is `SHA-256(0x01 || left || right)`.

The tree size is the number of records. Leaf hashes differ from the `prev`
digests of evidence-chain.md §5, which hash the record bytes without a
prefix; both are computed from the same bytes.

Inclusion and consistency proofs are those of RFC 9162 §2.1.3 and §2.1.4.
In text form, a proof is one hash per line, base64 encoded, as in
c2sp.org/tlog-witness.

## 3. Checkpoint

A checkpoint is a c2sp.org/tlog-checkpoint signed note whose note text is:

```
<origin>
<tree size>
<base64 root hash>
```

Checkpoints MUST NOT contain extension lines.

The operator signs checkpoints with an Ed25519 log signature
(c2sp.org/signed-note signature type `0x01`) whose key name is the origin.

The operator:

- MUST NOT sign two checkpoints for the same origin that are inconsistent,
  that is, for which no consistency proof exists;
- MUST publish every checkpoint it signs at a stable location, together with
  any cosignatures it obtained;
- SHOULD sign and publish a checkpoint at the interval it declares, even if
  no records were added.

## 4. Witness cosignatures

Operators obtain cosignatures from witnesses with the c2sp.org/tlog-witness
protocol. A cosignature is a note signature appended to the checkpoint.

Verifiers are configured with the operator's verifier key and, optionally,
with a set of witness verifier keys and a quorum. A verifier MUST NOT accept
a checkpoint unless the operator's signature verifies and at least *quorum*
of the configured witnesses' cosignatures verify.

This version supports Ed25519 checkpoint cosignatures (signature type
`0x04`). ML-DSA-44 cosignatures (type `0x06`), which C2SP recommends, are
planned. Signatures from unconfigured keys are ignored.

### 4.1 Submitting checkpoints to witnesses

A witness is identified by its verifier key and its submission URL prefix.
The operator submits each signed checkpoint with the `add-checkpoint` call of
c2sp.org/tlog-witness, which carries the size of the last checkpoint the
witness cosigned and a consistency proof from it. The operator holds the whole
chain, so it can always compute that proof and needs no state about witnesses:

1. Submit with an old size of 0 and no proof, or with the size the operator
   last saw the witness cosign.
2. On `409 Conflict`, the body is the witness's current size. If it is larger
   than the checkpoint's tree size, stop: the checkpoint is older than what the
   witness has already cosigned. Otherwise submit again once, with that size
   and the consistency proof from it.
3. On `200`, append only the returned signature lines that verify with the
   witness's configured key.

Other responses are errors. In particular:

- `404 Not Found`: the witness does not know the origin. Witnesses cosign only
  logs they are configured for. Public witnesses discover logs from published
  log lists, such as those of witness-network.org, which identify a log by its
  verifier key; because the key name of a deedlog checkpoint key is the
  origin, no separate origin line is needed in such lists.
- `422 Unprocessable Entity` after a consistency proof: the witness holds a
  checkpoint that the chain is not consistent with. The operator MUST NOT
  work around this by submitting a different history; the witness may keep the
  submission as evidence of misbehavior.

Operators SHOULD respect the request rate they declared when registering with
a witness.

### 4.2 Running a witness

Anyone can run a witness for the chains it cares about, for example a
municipality for its contractors' chains. deedlog includes a witness that
implements `add-checkpoint` of c2sp.org/tlog-witness with Ed25519
cosignatures. A witness MUST check the operator's signature and the
consistency proof against the last checkpoint it cosigned for that origin,
and update that record atomically before returning its cosignature.

## 5. Trusted timestamps

To bind a checkpoint to a trusted time, the operator obtains an RFC 3161
time-stamp whose message imprint is the hash of the checkpoint note text (the
three lines above, including the final newline). The request SHOULD use
SHA-256, include a nonce and ask for the TSA certificate. The operator
publishes the DER-encoded TimeStampResp next to the checkpoint; verifiers
also accept a bare TimeStampToken.

Because the note text does not include signatures, the same time-stamp
remains valid when cosignatures are added. A checkpoint MAY carry
time-stamps from several TSAs.

A verifier is configured with the root certificates of the TSAs it trusts.
It MUST accept a time-stamp only if:

1. the response status is granted or granted with modifications;
2. the token is CMS signed data whose content type is TSTInfo, with exactly
   one signer whose certificate is included in the token;
3. the signed attributes include the content type, a message digest equal to
   the hash of the TSTInfo, and an ESS signing certificate attribute (v1 or
   v2) whose first certificate ID identifies the signer's certificate;
4. the signature over the signed attributes verifies, and the hash named by
   the signature algorithm, if any, equals the digest algorithm;
5. the signer's certificate has a critical extended key usage of time
   stamping only, and chains to a trusted root at the time of stamping; and
6. the message imprint (SHA-256, SHA-384 or SHA-512) equals the hash of the
   checkpoint note text.

The trusted time is the TSTInfo `genTime`. RSA PKCS #1 v1.5 and ECDSA
signatures are supported.

Where legal standing matters, operators SHOULD use a TSA accredited in the
relevant jurisdiction, such as a time-stamping service accredited by the
Minister for Internal Affairs and Communications in Japan, and verifiers
configure that TSA's root. Revocation checking and long-term validation
(re-stamping before the TSA certificate expires) are not yet specified.

## 6. Proofs of misbehavior

A proof of misbehavior shows that an operator signed statements that cannot
all be true: two checkpoints, or a receipt (§7) and a checkpoint. It is a
JSON object:

| Field         | Type             | Description |
|---------------|------------------|-------------|
| `type`        | string           | `"deedlog-misbehavior/v1"` |
| `checkpoints` | array of strings | Signed checkpoints, as published: two, or one with `receipt` |
| `receipt`     | string           | A signed receipt, as issued; optional |
| `index`       | uint64           | Leaf index; required unless two checkpoints have the same size |
| `leaf_hashes` | array of strings | Base64 leaf hashes, one per checkpoint |
| `proofs`      | array of arrays  | Inclusion proofs (arrays of base64 hashes), one per checkpoint |

A verifier, configured with the operator's checkpoint verifier key (and,
for proofs with a receipt, the operator's receipt verifier key), MUST accept
the proof as showing misbehavior if and only if every checkpoint carries a
valid operator signature, all statements have the same origin, and one of
the following holds:

1. Two checkpoints have the same tree size and different root hashes.
2. Two checkpoints: `index` is less than both tree sizes, the two leaf hashes
   differ, and each inclusion proof verifies the corresponding leaf hash at
   `index` against the corresponding checkpoint.
3. A receipt and one checkpoint: the receipt verifies, `index` equals the
   receipt's index and is less than the checkpoint's tree size, the leaf hash
   differs from the receipt's, and the inclusion proof verifies it at `index`
   against the checkpoint.

Leaf hashes are used rather than record bytes, so that proofs of misbehavior
can be published without disclosing records.

## 7. Receipts

A receipt is the operator's signed promise that a record will appear at a
given index. It lets the party involved in an event detect if the operator
later leaves the event out.

A receipt is a c2sp.org/signed-note whose note text is:

```
deedlog-receipt/v1
<origin>
<index>
<base64 leaf hash>
```

Receipts MUST be signed with a key distinct from the operator's checkpoint
key. The key name SHOULD be the origin followed by `/receipts`.

A receipt for index *i* together with a checkpoint of size greater than *i*
whose inclusion proof at *i* yields a different leaf hash is a proof of
misbehavior (§6, form 3).

To check a receipt, its holder obtains a checkpoint whose tree size is
greater than the index, verifies it as described in §4, and obtains an
inclusion proof for the index from the operator or from anyone holding a copy
of the chain. The result is one of:

- **included**: the proof verifies the receipt's leaf hash;
- **not yet covered**: the tree size is not greater than the index; this
  becomes suspicious once the operator's declared delay has passed; or
- **misbehavior**: the leaf at the index differs from the receipt's.

An operator that refuses to provide an inclusion proof for a covered index
gives the holder reason to escalate, for example to a witness or regulator
that can obtain the chain.

Operators SHOULD declare the maximum delay between issuing a receipt and
publishing a checkpoint that covers it. Operators SHOULD record the receipt
verifier key in the chain, so that it is covered by checkpoints signed with
the checkpoint key.

A receipt MAY be delivered inside an envelope suited to its recipient, such
as a Verifiable Credential for a person's wallet, a field of a protocol
message between systems, or an HTTP header. The envelope does not replace
the receipt's own signature: verifiers and proofs of misbehavior use the
signed note inside.

### 7.1 Text and URL envelopes

The **text envelope** is the signed receipt note itself, for example in the
body of an email or a downloaded file.

The **URL envelope** points to a verification page and carries the receipt in
the fragment, so that the receipt is not sent to the page's server:

```
<verification page URL>#r=<base64url of the signed receipt note, without padding>
```

Base64url is defined in RFC 4648 §5. The URL can be printed as a QR code on a
paper receipt or shown on a screen. Verification pages are run by parties
other than the operator; the page decides which operators and witnesses it
trusts.

## 8. Verifying a chain against a checkpoint

Given a chain and a checkpoint, a verifier MUST:

1. verify the chain as described in evidence-chain.md §8;
2. verify the checkpoint signatures as described in §4;
3. check that the chain ID equals the checkpoint origin;
4. check that the chain has at least as many records as the checkpoint's tree
   size; and
5. check that the Merkle tree hash of the first *tree size* records equals the
   checkpoint's root hash.

A chain longer than the checkpoint is accepted: records may have been added
since.

## 9. Publication

Operators publish their chains' state at a base URL with two read-only
endpoints, so that receipt holders and verification pages can check receipts
without the chain:

- `GET <base>/checkpoint` returns the latest signed checkpoint, with the
  cosignatures obtained so far, as `text/plain`.
- `GET <base>/proof?index=I&size=N` returns, as `text/plain`, the base64 leaf
  hash at index *I* on the first line, followed by the inclusion proof for
  *I* in the tree of size *N*, one base64 hash per line. *N* MUST NOT exceed
  the latest published tree size; otherwise the response is `404`.

Responses SHOULD include `Access-Control-Allow-Origin: *`, so that
verification pages on other origins can read them. Nothing published here is
trusted by itself: checkpoints are verified against the operator's key and
witnesses, and proofs against checkpoints.

## 10. Security considerations

- **Key compromise.** Whoever holds the operator's key can sign inconsistent
  checkpoints; witnesses detect this but cannot prevent it. Key rotation is
  not yet specified.
- **Quantum computers.** Ed25519 is not secure against quantum computers.
  ML-DSA-44 cosignatures are planned.
- **Time.** Witness cosignature timestamps are statements by the witness.
  Only an RFC 3161 time-stamping authority provides time with legal standing.
