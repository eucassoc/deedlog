# Use case: dataspaces

> Status: runnable sample. `go run ./examples/dataspaces`

In a dataspace, participants exchange data under contracts that they
negotiate connector to connector, for example with the Dataspace Protocol
and Eclipse Dataspace Components (EDC). Initiatives such as Gaia-X, IDSA and,
in Japan, DATA-EX by the Data Society Alliance (DSA) build on this model.

After an exchange, providers, consumers and auditors need to answer:

- Was this agreement actually concluded, and under which policy?
- Was data transferred only under a valid agreement, and when?
- Did each side enforce the usage policy it agreed to?

## Where deedlog fits

deedlog is not a connector, an identity system or a clearing house. It is
the evidence layer underneath them.

| Layer | Answers | Examples |
|---|---|---|
| Trust framework | Who is this participant? Is this service compliant? | Gaia-X Trust Framework, verifiable credentials |
| Protocol and connector | How are contracts negotiated and data transferred? | Dataspace Protocol, EDC |
| Clearing house | Where are transactions logged for audit and disputes? | IDS Clearing House |
| **Evidence (deedlog)** | **Can anyone verify, without trusting the operator, what actually happened?** | Chains, checkpoints, `dlog verify` |

A clearing house operated by an intermediary still asks participants to
trust that intermediary. deedlog makes the log itself verifiable, whether
it is kept by a clearing house or by each participant.

## Evidence recorded

A connector extension (for EDC, a Java extension) appends a record for each
state change it observes:

| Event | Subject |
|---|---|
| Contract negotiation state change (requested, offered, agreed, verified, finalized, terminated) | Digest of the negotiation message and the policy (ODRL) |
| Transfer process state change (requested, started, suspended, completed, terminated) | Digest of the transfer message; digest of the data where available |
| Usage policy enforcement decision | Digest of the decision and the policy it evaluated |

Records hold digests only. The data and the contract stay with the
participants.

## Decentralized witnessing

Dataspaces avoid a single point of trust. deedlog can follow that
principle: when two connectors exchange messages, each records the other's
latest checkpoint. Each participant then holds evidence of the other's chain
at that moment, and neither can later rewrite its history without the
discrepancy showing up in the counterpart's chain. A clearing house or a
transparency log remains optional.

The sample records the counterpart's signed checkpoint as evidence, with the
checkpoint itself as the body. A dedicated field for counterpart references
is planned in the specification (§7).

## Integration notes

- EDC is written in Java, while deedlog's reference implementation is Go.
  The extension writes records according to the language-neutral
  specification and verifies them with `dlog verify`.
- Use the participant's own key for checkpoints so that evidence can be tied
  to the identity established by the trust framework.

## Run the sample

```sh
go run ./examples/dataspaces
```

A provider and a consumer negotiate a contract and transfer data with
Dataspace Protocol messages. Each connector records every message it sends or
receives, and attaches a checkpoint of its own chain to every message it
sends; the receiver records that checkpoint. No witness server or clearing
house is involved.

Later the consumer disputes having received the data and presents its chain
without the transfer. The rewritten chain is internally consistent, but it
does not match the checkpoint the consumer signed and sent to the provider:

```
against the consumer's checkpoint held by the provider: chain has 9 records, checkpoint covers 12
```

In the second run the provider terminates the negotiation and transfers
anyway. Both chains show it:

```
line 9: transfer tp-1 started under agr-1 (agreement TERMINATED at line 6)
```

| File | Shows |
|---|---|
| [connector.go](connector.go) | Where the calls go in a connector: sending and receiving messages with checkpoints |
| [check.go](check.go) | The check against the protocol |
| [main.go](main.go) | The scenario, and the audit of a rewritten chain |
