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

## Walkthrough

The steps of the recorded demo, about three minutes. Buttons are named as
they appear on the pages.

1. On the city's home page, click 「お問い合わせはこちら」 and send an
   inquiry. The receipt page shows the city's promise: off the form service
   within 7 days, deleted 30 days later, witnessed by the library and the
   audit firm.
2. Click 「処理状況を確認する（記録確認ネット）」. The checking site shows
   「受付済み・第三者の確認待ち」: the city has not had today's records
   cosigned yet.
3. In the panel, click 「7日進める」. The inquiry was moved to the city's
   archive: 「約束どおりに扱われています」.
4. Back on the city's site, click 「移動ジョブが止まる（障害）」 and send a
   second inquiry. Keep its link.
5. Click 「7日進める」 and 「1日進める」 three times, then
   「委託先の漏洩が公表される」. The city's home page announces the breach,
   saying inquiries are moved off the form service within 7 days.
6. Open the second inquiry's link: 「市の約束が守られていません」. It was
   still on the form service, 10 days after it was sent, when the breach was
   announced. The first inquiry's link shows it had left before.
7. Click 「市が記録を書き換える」 and open the second link again: the
   checking site finds the rewrite and offers the proof of misbehavior as a
   file anyone can verify.

「最初から」 starts over. Receipt links differ only after `#`, so reload the
checking site after opening another link.

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
