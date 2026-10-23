# Trust model

This document is informative. It explains what deedlog can and cannot
guarantee, and whom a verifier ends up trusting. The normative format is in
[evidence-chain.md](evidence-chain.md).

## Who uses deedlog

deedlog is adopted by the party that **wants to be trusted**: an operator,
a platform, a data provider. The people who need to trust them — residents,
consumers, counterparties — rarely run a verifier themselves.

The value comes from the operator placing itself, voluntarily, in a position
where anyone *could* verify it at any time. Independent parties (auditors,
researchers, journalists, consumer organizations, regulators, competitors)
do the verifying; everyone else benefits from the fact that they can. This is
the same arrangement as Certificate Transparency, where certificate
authorities publish what they issue and browsers and researchers monitor it.

## What any evidence system can prove

At best, deedlog proves:

> This digest existed at time *T* and has not changed since.

Neither deedlog nor a public blockchain can prove that the original data
was true. A false statement anchored correctly is still false. Trust in
sources comes from separating the privileges of collectors from those of the
systems they observe, from signatures by the source, and from collecting at
more than one vantage point.

## deedlog is not a blockchain

The chain is a hash chain: each record holds the digest of the previous
record, like commits in Git. There are no nodes, no consensus and no tokens.
Transparency logs (Rekor, Trillian) are Merkle-tree logs run by an operator,
as used by Certificate Transparency; they are not blockchains either.

## Roles

Witnesses are only one of the parties involved. Each role defends against
something different, and only some of them have to be trusted.

| Role | Does | Defends against | Must be trusted? |
|---|---|---|---|
| Operator | Writes the chain, signs checkpoints and receipts | — | — |
| Witness | Cosigns checkpoints consistent with what it saw before | Rewriting history; showing different histories to different people | No; it only has to keep copies |
| Time-stamping authority | Attests when a checkpoint existed | Backdating | Yes |
| Receipt holder | Keeps the operator's signed promise about an event that concerns them | Leaving events out; substituting records | No |
| Verifier | Fetches what the operator publishes, checks it, and applies the declared rules | Violations going unnoticed; having to take the operator's word | No; anyone can repeat the check |
| Registry curator | Decides which operator keys and witnesses a verifier trusts | Impostor operators; witnesses colluding with the operator | Yes; users rely on its choices, as browsers' users rely on their CT log lists |
| Source | Observes an event first hand and signs what it saw: a device, a counterparty, a service provider | False records | Its interests must differ from the operator's |

Witnesses, receipt holders and verifiers make the record **unchangeable and
visible**. Only sources address whether what was recorded is **true**: a
record signed by a counterparty, such as a service provider confirming a
deletion, holds unless both collude. A record written by the operator alone
remains its own statement, but one fixed in advance, signed, and evidence
against it if other evidence contradicts it.

Some roles can be combined: an organization may run a verifier and curate
its registry. It should not curate a registry that lists witnesses or
operators it controls without saying so, and anyone can run another
verifier with a different registry.

## Two kinds of anchors

| Anchor | Provides | Must be trusted? |
|---|---|---|
| **Time anchor** — an RFC 3161 time-stamping authority, such as an accredited one | When a checkpoint existed | Yes. Only a trusted party can attest to time. Choose authorities with legal standing where it matters. |
| **Consistency witness** — anyone who keeps copies of signed checkpoints | That the operator never showed two different histories | No. See below. |

### Witnesses need not be trusted

The operator signs every checkpoint with its own key and publishes it. Anyone
may fetch and keep checkpoints, without registering or asking permission.

If the operator later rewrites history, or shows different histories to
different people, two checkpoints signed by the operator will contradict each
other. Whoever holds the older one can present both: that pair is a **proof
of misbehavior** that anyone can check, because nobody but the operator can
produce the operator's signature.

So a witness does not have to be honest or reputable. It only has to have kept
a copy. One copy anywhere in the world is enough, and since the operator does
not know who holds copies, it cannot collude with them.

### Why anyone would witness

- **Cost is negligible.** A checkpoint is a few hundred bytes; checking
  consistency takes milliseconds. Libraries, universities and archives can
  witness as a public service.
- **Some parties gain from catching misbehavior.** Competitors, journalists,
  researchers, consumer organizations and regulators.
- **Reciprocity.** Counterparties, for example connectors in a dataspace,
  witness each other.
- **Bounties.** An operator that wants to be trusted can promise a reward for
  any valid proof of misbehavior, putting money behind its commitment.
- **Paid witnessing.** Because a witness can do nothing worse than refuse to
  sign, paying it does not compromise neutrality.

A public blockchain solves the incentive problem with tokens. deedlog makes
witnessing so cheap, and misbehavior so provable, that the parties who already
want to catch cheating are enough.

### Who chooses anchors

The operator must not be the only one choosing. At least one anchor should be
independent of, or opposed in interest to, the operator. Consumers cannot be
expected to evaluate anchors themselves; they delegate to parties they trust,
as browsers do for Certificate Transparency logs. Adding or removing an
anchor is itself recorded in the chain.

## What can be detected

| Misbehavior | Detected by |
|---|---|
| Editing, deleting or reordering records after they were written | The chain |
| Truncating the chain or rewriting it entirely | Checkpoints held by time anchors and witnesses |
| Showing different histories to different people | Proofs of misbehavior from witnesses |
| Never recording an event that left a trace elsewhere | Receipts, cross-checking and declared cadence (below) |
| Never recording an event that left no trace anywhere | **Not detectable** |

### Making omissions visible

A chain cannot reveal what was never written to it. deedlog's approach is
to design systems so that omissions leave a visible gap:

- **Receipts.** When the operator handles an event involving someone else, it
  gives them a signed promise to include the event. A receipt for an event
  that never appears in the chain is a proof of misbehavior. Certificate
  Transparency does the same with signed certificate timestamps.
- **Cross-checking.** Many events leave traces the operator does not control:
  the counterparty's own chain in a dataspace, an on-chain payment for x402, a
  registry entry for an environmental certificate.
- **Declared cadence.** The operator declares what is recorded and how often,
  for example a camera recording the digest of every ten-second segment with a
  sequence number. A missing interval becomes evidence in itself. The source
  must be something the operator cannot filter, such as the device.

Secret copies of data, and other actions that leave no trace, cannot be
detected by any logging system. Hardware attestation, audits and
whistleblowing remain necessary there.

## Relation to remote attestation

Remote attestation and deedlog answer different questions, and are meant
to be used together.

| | Remote attestation | deedlog |
|---|---|---|
| Shows | Which software is running on a machine now | What that software did, and when |
| Covers | The moment of the check | The whole history |
| Checked by | The party that asked | Anyone, at any later time |
| Different answers to different people | Not prevented | Provable misbehavior |
| Rests on | The hardware vendor's keys | Independent witnesses and time-stamping authorities |

Attestation can show that a deletion job is the published one; it cannot show
that a given item was deleted on schedule, and it cannot reach systems the
verifier cannot challenge, such as a third-party service. deedlog records
events, including attestation results: the attestation shows that the right
software ran, and the chain shows what it did, in a history everyone sees the
same way.

## Relation to storage networks

Content-addressed storage such as IPFS proves that an object matches its
identifier. It does not prove when the object was written, whether every
event was written, in what order, or that everyone sees the same "latest"
version. Arweave adds timestamps and persistence, but it is a blockchain and
cannot delete data, which conflicts with privacy law when records relate to
individuals.

deedlog defines what is recorded, in what order, and how omissions and
inconsistencies are proven. Storage networks can serve as a distribution
channel for checkpoints and evidence packages.

## Prior art and what deedlog adds

deedlog builds on transparency logs rather than inventing a new mechanism.

- **Certificate Transparency** (RFC 6962, RFC 9162) logs every public TLS
  certificate. Its signed certificate timestamp (SCT) is a log's promise to
  include a certificate within a maximum merge delay (MMD); an SCT for a
  certificate that never appears is evidence against the log. deedlog's
  receipts follow the same idea.
- **static-ct-api** (C2SP) adds a `leaf_index` extension to SCTs, so the
  promise names an exact position. deedlog's receipts commit to an index in
  the same way, which makes a broken promise checkable with one inclusion
  proof.
- **Gossip and witnesses.** CT long struggled to detect split views through
  gossip between clients. Sigsum and the C2SP witness protocols replaced
  gossip with witness cosignatures. deedlog uses those formats unchanged and
  works with existing witnesses.
- **Verifiable Data Audit** (DeepMind, 2017) proposed an append-only Merkle
  log of every access to hospital patient data, verifiable by third parties.
  It is the closest precedent for recording organizational conduct; as far as
  is publicly known, it was not deployed.
- **SCITT** (RFC 9943) defines transparency services for signed statements
  about supply chain artifacts, in COSE. deedlog keeps the C2SP formats
  instead, to work with existing witnesses, and focuses on what a system did
  rather than on statements about artifacts.

What deedlog adds:

- **Organizational conduct, not public objects.** CT and similar logs record
  things that are already public (certificates, software releases). Like
  Verifiable Data Audit, but as a general-purpose building block, deedlog
  records what a system did, often about people, as digests or keyed hashes,
  so the log can be public while the evidence stays private.
- **Receipts for people.** Receipts reach the people an event concerns, as a
  link or QR code, and anyone can check them in a browser against
  independently chosen witnesses, without trusting the operator's page.
- **Omissions as a design concern.** Receipts, cross-checking and declared
  cadence are combined, with an explicit statement of what remains
  undetectable (see above).
- **A bridge to legal evidence.** Checkpoints are timestamped by RFC 3161
  authorities, including accredited ones, so the same evidence serves both
  technical verification and legal proceedings.
- **Compact proofs of misbehavior,** including one built from a receipt and a
  later checkpoint, in a single portable document.

The aim is to bring the guarantees of transparency logs to new domains, such
as AI agents, public services and dataspaces, while staying interoperable
with the existing ecosystem.
