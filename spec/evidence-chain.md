# deedlog evidence chain — v0.1 (draft)

Status: **draft**. Breaking changes are expected until v1.0.

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as
described in RFC 2119.

## 1. Goals

An evidence chain lets anyone check, after the fact and without trusting the
operator, that a sequence of evidence records has not been edited, deleted
from or reordered since it was written.

Non-goals for v0.1:

- Proving that a source told the truth. A compromised host can lie. The
  chain proves what was *received*, and when.
- Deciding compliance. Mapping evidence to controls is the job of exporters
  and assessors.
- Being a blockchain. The chain is a hash chain kept by its operator; there
  is no consensus and no token. See [trust-model.md](trust-model.md).

## 2. Design principles

1. **Hash bytes, not objects.** A record's digest is computed over its exact
   serialized bytes. Verifiers never re-encode JSON, so there is no
   canonicalization to get wrong.
2. **Records point to evidence; they do not contain it.** The evidence body
   (log line, screenshot, API response) is stored separately and identified
   by digest. This keeps chains small and lets bodies containing personal
   data be deleted without breaking the chain.
3. **Leave the host fast.** Collectors SHOULD ship records off the observed
   host as soon as they are written. An attacker who gains control later
   cannot change what has already left.
4. **Layered anchoring.** The chain alone detects edits in the middle.
   Checkpoints (§7) anchor the chain outside the operator's control with the
   operator's signature, witness cosignatures and a trusted timestamp.

## 3. File format

A chain is a UTF-8 text file in JSON Lines form:

- Each line is one record (§4) serialized as a single JSON object.
- Lines are separated by a single LF (`0x0A`). CR (`0x0D`) MUST NOT appear
  at the end of a line.
- The final line MAY be followed by an LF.
- Empty lines MUST NOT appear.

The *record bytes* of a line are the bytes of that line excluding its
terminating LF.

## 4. Record

| Field          | Type   | Required | Description |
|----------------|--------|----------|-------------|
| `spec`         | string | yes      | `"deedlog/v0.1"` |
| `chain`        | string | yes      | Chain identifier. Identical for every record in a chain. |
| `seq`          | uint64 | yes      | Sequence number. The first record is `0`; each next record adds 1. |
| `prev`         | string | no       | Digest (§5) of the previous record's bytes. Absent in record `0`. |
| `collected_at` | string | yes      | RFC 3339 time at which the collector observed the evidence, in UTC. |
| `source`       | object | yes      | `type` (e.g. `syslog`, `ai-agent`), `id` (the observed system), `collector` (name and version of the collector). |
| `subject`      | object | yes      | The evidence body: `media_type`, `size`, `digest` (§6), optional `uri`. |
| `meta`         | object | no       | Additional string key/value pairs. |

Verifiers MUST ignore fields they do not recognize. Because digests are
computed over bytes, unknown fields are still protected by the chain.

`collected_at` is asserted by the collector and is not trusted by itself.
Trusted time comes from checkpoint timestamps (§7).

## 5. Digests and linking

A digest is the string `sha256:` followed by the lowercase hexadecimal
SHA-256 of the input.

For every record `n > 0`, `prev` MUST equal the digest of the record bytes
of record `n - 1`. The *head* of a chain is the digest of the record bytes
of its last record.

## 6. Subject digests

`subject.digest` is a map from algorithm to lowercase hexadecimal value and
MUST contain at least one entry.

- `sha256`: SHA-256 of the evidence body.
- `hmac-sha256`: HMAC-SHA-256 of the evidence body under a key held by the
  operator.

Plain digests of low-entropy personal data (phone numbers, dates of birth,
national ID numbers) can be reversed by brute force. Collectors handling
such data MUST use `hmac-sha256` instead of `sha256`. Verifiers without the
key treat keyed digests as opaque.

## 7. Checkpoints

A chain is anchored outside the operator's control by checkpoints, specified
in [checkpoint.md](checkpoint.md). A checkpoint commits to the Merkle tree of
the chain's records at a given size. It is signed by the operator, cosigned
by witnesses and timestamped by an RFC 3161 time-stamping authority. The chain
together with its checkpoints is a transparency log in its own right; no
external log service is required.

Checkpoints contain only hashes, never records or evidence bodies.

Still planned (see [trust-model.md](trust-model.md)):

- **Declared scope and cadence.** A record stating what is recorded and how
  often, so that missing records become detectable.
- **Counterpart references.** A record field that references a
  counterpart's checkpoint, so that two parties exchanging messages witness
  each other's chains without a central log.
- **Source signatures.** Record-level signatures by the system that
  produced the evidence, so that a record can be attributed to it even when
  it passes through untrusted gateways.
- **Cross-chain references.** A record field that references a record in
  another chain, so that evidence can point to the evidence it depends on.

## 8. Verification

A verifier MUST reject a chain unless all of the following hold:

1. The file contains at least one record.
2. Every line is a JSON object and `spec` is a supported version.
3. Record `0` has a non-empty `chain`; every later record has the same
   `chain`.
4. The `seq` of the i-th line (counting from 0) is `i`.
5. Record `0` has no `prev`; for every later record, `prev` equals the
   digest of the previous line's record bytes.
6. `subject.digest` is non-empty and every `sha256` value is 64 lowercase
   hexadecimal characters.

On success the verifier reports `{chain, count, head}`.

## 9. Security considerations

- **Truncation.** Removing records from the *end* of a chain leaves a valid,
  shorter chain. Only a checkpoint anchored outside the operator's control
  reveals that the chain was longer.
- **Wholesale rewrite.** Anyone with write access can build a new, valid
  chain. Again, external checkpoints are what make this detectable.
- **Lying sources.** The chain cannot detect a source that reports false
  evidence. Separate the privileges of collectors from those of the systems
  they observe, and collect from more than one vantage point where possible.
- **Omission.** The chain cannot reveal events that were never recorded.
  Receipts, cross-checking against traces outside the operator's control and
  declared cadence make some omissions detectable; see
  [trust-model.md](trust-model.md).
- **Line ending conversion.** Tools that convert LF to CRLF change record
  bytes and break verification. Store and transfer chains as binary.
