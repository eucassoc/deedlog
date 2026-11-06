# Use case: reward vouchers without a customer database

> Status: runnable sample. `go run ./examples/reward-vouchers`

Reward programs are a fixture of retail in Japan: points on every purchase,
redeemable later, often across many stores. Each program keeps a member
database, and those databases are where breaches hurt: names, phone numbers
and purchase histories that were only there to keep a balance. Small stores
increasingly drop their own programs rather than carry that risk, and when
customers' AI agents do the shopping, the app the program ran in loses its
purpose anyway.

A program can keep the reward and drop the database. Instead of a balance,
the store issues a **voucher**: a signed credential of fixed value, bound to
a key held by the customer's agent, valid for a limited time. Any store in
the program accepts it, checking only the issuer's signature, the holder's
signature and the expiry, with nothing but the published program to hand.
The redeeming store keeps the voucher as its claim on the issuer, as shops
have kept paper coupons for decades. Nobody holds a customer record.

Vouchers can be copied, so the one problem a signature cannot solve is a
holder presenting the same voucher at two stores. That is what the chains
settle.

## Where deedlog fits

| Event | Recorded by | Subject |
|---|---|---|
| Program declared | Each store, as its first record | Digest of the published program: the stores, their voucher keys, the voucher value and validity |
| Voucher issued | The issuing store | Digest of the signed voucher |
| Voucher redeemed | The redeeming store | Digest of the presentation: the voucher, the store, the store's challenge and the holder's signature |

Records hold digests. The voucher goes to the holder's agent; the
presentation stays with the redeeming store until settlement. Neither names
anyone: a voucher carries a random identifier and the holder's key, and a
chain shows that a voucher issued at one store was used at another, not by
whom.

At settlement the program operator opens each store's witnessed chain and the
presentations it submits, and pays each voucher once, to the first store that
recorded it. Everything else is a finding:

- a voucher presented at two stores, found by the earlier record, in time
  order across every chain;
- a voucher carrying a store's signature that the store never recorded
  issuing, which is either off-book issuance or a stolen key;
- a voucher redeemed after it expired;
- a presentation that does not match the record the store made of it.

The holder's agent gets a receipt for every redemption record, so a store
cannot later deny that it took a voucher. With checkpoints published daily,
a double spend shows the day after, not at the end of the settlement period,
and a store's exposure is bounded by the voucher value and the checkpoint
interval.

## What this adds

- **No customer data to breach.** Stores keep signing keys, their own chain
  and the vouchers they took. Losing all three exposes nobody.
- **Settlement from evidence.** Stores need not trust each other or the
  operator's bookkeeping: the chains the operator settles from are witnessed,
  and any store can repeat the settlement.
- **An agent-shaped interface.** The customer's side is a key and a wallet
  of credentials, which is what an AI agent holds anyway; there is no app for
  the customer to open.

## What remains outside

A signature cannot stop the same voucher being presented twice before anyone
compares chains; the program accepts a bounded loss, keeps vouchers small and
short-lived, and bars the holder key that did it. A store's clock is its own
claim; the checkpoint timestamp bounds it. Whether the discount was actually
given at the till is not in the chain.

In production the voucher is a verifiable credential (an SD-JWT VC or a W3C
VC) bound to the holder's key, and the presentation a verifiable
presentation; the sample reduces both to the fields it uses. The issuing and
settlement service this sample models is developed in the open at
[joeartsea/walife](https://github.com/joeartsea/walife).

## Run the sample

```sh
go run ./examples/reward-vouchers
```

Three stores in a shopping-street program issue 100-unit vouchers valid for
a week to eight customers' agents over two weeks, and accept each other's.
Two witnesses (the chamber of commerce and a consumer organization) cosign
every store's checkpoint. The operator settles from the chains:

```
  settlement           issued  accepted    own  receives      pays
  bakery.example           15         7      1       700       300
  cafe.example             18         1      3       100       700
  bookshop.example         22         5      7       500       300
```

In the second run an agent presents one voucher at two stores, a store
issues a voucher without recording it, and a store accepts a voucher four
days after it expired. The settlement finds each and pays none of them:

```
line 13: bakery.example: voucher signed with bookshop.example's key, but bookshop.example never recorded issuing it; off-book issuance or a stolen key
line 15: bookshop.example: voucher already redeemed at cafe.example line 10; holder 07o20npK presented it twice
line 24: cafe.example: voucher from bakery.example (line 2) expired 4d01h before it was redeemed
```

| File | Shows |
|---|---|
| [voucher.go](voucher.go) | Where the calls go: the store's point of sale, issuing and redeeming, and the agent's wallet |
| [check.go](check.go) | The settlement: the audit of every store's chain and what each store receives and pays |
| [main.go](main.go) | The scenario |
