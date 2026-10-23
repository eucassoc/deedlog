# Use case: agent payments (x402)

> Status: runnable sample. `go run ./examples/agent-payments`

x402 uses the HTTP 402 Payment Required status to let clients, including AI
agents, pay for an API call or resource within the HTTP request itself,
typically with stablecoins settled on a blockchain.

The payment is recorded on-chain, so deedlog does not duplicate it. What
the blockchain does not show is **what was requested and what was delivered
in return**. That is what a deedlog chain kept by the server, the client or
both records:

| Event | Subject |
|---|---|
| Payment required | Digest of the request and of the payment requirements offered |
| Payment verified and settled | Digest of the payment payload and the settlement result, with the transaction hash in `meta` |
| Resource delivered | Digest of the response body |

## What this adds

- **Disputes.** Either party can show that a specific response was delivered
  for a specific payment.
- **Agent accountability.** Operators of AI agents can audit what their agents
  bought, from whom, and what they received, with evidence the agent cannot
  rewrite afterwards.
- **Accounting and audit.** Each on-chain payment is linked to the business
  event it paid for.

Collection fits naturally into the HTTP middleware that already handles
x402 on the server, or into the client library on the agent side.

## Run the sample

```sh
go run ./examples/agent-payments
```

An agent buys reports from an API that charges with x402. Payments are settled
by a stand-in facilitator; no blockchain is used. The seller's middleware
records each step and returns, with every delivery, a receipt for its record
in an `X-Deedlog-Receipt` header. The agent keeps its own chain of what it
paid for and received.

An arbiter then settles a dispute about what was delivered, from the buyer's
receipt and body, the seller's witnessed checkpoint and the record the receipt
points to. The seller cannot substitute another record, and the buyer cannot
present another body:

```
the seller recorded delivering exactly this body for /reports/2, paid by transaction 0x10ae…
the body presented is NOT what the seller recorded delivering for transaction 0x10ae…
```

In the second run, one report fails after payment and the facilitator reports
one transaction twice. An audit of the seller's chain finds both:

```
line 5: transaction 0x04abc882 already paid for /reports/1 at line 2
line 8: payment 0xd155d4b4 for /reports/3 settled, but nothing was delivered
```

| File | Shows |
|---|---|
| [x402.go](x402.go) | Where the calls go: the seller's middleware and the agent's client |
| [check.go](check.go) | The audit of the seller's chain, and the arbiter's decision |
| [main.go](main.go) | The scenario |
