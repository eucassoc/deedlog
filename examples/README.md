# Use cases

deedlog itself is domain-neutral. Each directory here describes how it is
applied in one domain, and where it sits next to the systems already used
there. In every case, deedlog is adopted by the party that wants to be
trusted; see the [trust model](../spec/trust-model.md).

Each use case is also a runnable sample. It shows where the calls go in the
systems of that domain, runs a scenario once as it should go and once with
the failures that matter there, and checks the result with only public
material, reporting each failure with the chain line where it shows.

```sh
go run ./examples/data-tiering        # or any other directory below
```

Witnesses run in-process and speak the C2SP witness protocol, as public
witnesses do. Each run writes its chain, checkpoint and keys to a directory,
where `dlog verify` checks them.

The samples that issue receipts (data tiering, municipal data platform, agent
payments, official videos, reward vouchers) also write the receipt and a `registry.json`, so
the receipt can be checked on the [verification page](../web/):

```sh
go run ./examples/data-tiering -out out
web/build.sh site && cp out/1/registry.json site/
(cd site && python3 -m http.server 8080) &
dlog serve -chain out/1/chain.jsonl -checkpoint out/1/checkpoint &
cat out/1/receipt.url    # open this link in a browser
```

| Use case | Evidence of | Sits next to |
|---|---|---|
| [Data tiering](data-tiering/) | That data is moved and deleted on schedule, and nothing outlives its tier | Retention policies, breach response |
| [AI agents and automations](ai-agents/) | Every tool call an agent made, against the tools it may use | MCP, Claude Code hooks, agent permissions |
| [Verifiable operator commitments](operator-commitments/) | That an operator keeps its public promises, such as deletion and non-identification | Privacy policies, audits |
| [Municipal data platform](municipal-data-platform/) | Consent preceding each provision of personal data | Smart-city data platforms |
| [Dataspaces](dataspaces/) | Contract negotiations, transfers and policy enforcement between connectors | Dataspace Protocol, EDC, Gaia-X, DATA-EX |
| [Device-originated data](device-data/) | Data signed by the device that produced it | Sensors, meters, cameras |
| [Content provenance](content-provenance/) | Capture, editing and publication of media | C2PA |
| [Official videos edited with AI](official-videos/) | That each video was made from registered footage under a published editing recipe | Fan clubs, sports and entertainment media |
| [Agent payments](agent-payments/) | What was requested and delivered for each payment | x402 |
| [Reward vouchers](reward-vouchers/) | Vouchers issued and redeemed across stores, settled without a customer database | Point programs, verifiable credentials, agent wallets |
| [Proof of environmental value](environmental-value/) | Metering, reporting and verification behind carbon credits and energy certificates | J-Credits, non-fossil certificates, registries |

Outside this repository,
[shinten's web-shop example](https://github.com/eucassoc/shinten/tree/main/examples/web-shop)
uses `dlog` for data tiering on a fictional shop: an order form encrypted in
the browser, its receipt, decryption on the shipping desk and deletion of
the label file recorded in a chain that two witnesses cosign, and checked
with `dlog verify`.

The samples hold domain logic; the shared plumbing in
[internal/demo](internal/demo/) is for the samples only. Products use the
`core`, `witness` and `publish` packages directly.

Use cases reference each other: device-originated data underpins metering for
environmental value, capture for content provenance and camera footage for
operator commitments.
