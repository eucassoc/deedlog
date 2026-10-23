# Web demo: data tiering

A demo in Japanese for people who are not engineers, built on the data
tiering sample and the real deedlog packages.

```sh
go run ./examples/data-tiering/webdemo
```

Open <http://localhost:8090/>, the website of a fictional city. A resident
sends an inquiry through its contact form and gets a receipt: a link to an
independent checking site (<http://localhost:8091/>), run by a citizens'
organization, which fetches what the city publishes and checks it itself
against two witnesses, a library and an audit firm.

The panel at the bottom of every page is for the demo only. It lets days
pass, breaks the job that moves inquiries off the outsourced form service,
announces a breach of the form service, and has the city rewrite its chain.
The checking site then shows the resident:

- whether their inquiry was moved off the form service and deleted as the
  city promised;
- on the day the breach is announced, whether their inquiry was still on the
  form service at that time;
- how many inquiries city-wide broke the promise;
- that the city rewrote its records, with the resident's receipt and the
  city's signed checkpoint as a proof of misbehavior anyone can check.

## Roles in the demo

The checking site's page "この仕組みの登場人物" explains the roles of the
[trust model](../../../spec/trust-model.md#roles) with the demo's cast:

| Role | In the demo |
|---|---|
| Operator | The city |
| Witnesses | The city library and an audit firm |
| Receipt holders | The residents |
| Verifier and registry curator | The checking site, run by a citizens' organization |
| Time-stamping authority | Left out of the demo |
| Source | The city itself: moves and deletions are the city's own statements. A service provider signing its deletions would make them more than that. |

| File | Shows |
|---|---|
| [world.go](world.go) | The simulated city: form, archive, daily job, chain and witnesses |
| [verify.go](verify.go) | The checking site: what it verifies, and what it tells the resident |
| [main.go](main.go), [assets/](assets/) | The two websites and the demo panel |
