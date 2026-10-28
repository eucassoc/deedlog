# Web demo: official videos edited with AI

A demo in Japanese for people who are not engineers, built on the official
videos sample and the real deedlog packages.

```sh
go run ./examples/official-videos/webdemo
```

Open <http://localhost:8090/>, the fan club site of a fictional boxer. Each
video page links to an independent checking site (<http://localhost:8091/>),
which fetches what the fan club publishes and checks it itself: the recipe,
the rendering engine's signed statements, and the cosignatures of two
witnesses, a fans' association and an audit firm.

The panel at the bottom of every page is for the demo only. It publishes a
video made as declared, one with a scene added by AI, one edited in another
app, and has the fan club rewrite its chain. The checking site then shows the
fan:

- how the video was made: the registered clips, the recipe, what the engine
  did, and where it was published;
- which operations broke the recipe, from the engine's own statement;
- that a video has no record of how it was made;
- how many of the fan club's videos broke the recipe;
- that the fan club rewrote its records, with the video's receipt and the
  fan club's signed checkpoint as a proof of misbehavior anyone can check.

## Walkthrough

The steps of the recorded demo, about two minutes. Buttons are named as they
appear on the pages.

1. On the fan club's home page, click 「公式動画の作り方」. The recipe lists
   the operations the engine may apply, and says no scene the footage does
   not contain is made with AI.
2. Back on the home page, open the video 「公開スパーリング ハイライト」 and
   click 「この動画の来歴を確認する」. The checking site shows
   「公開レシピどおりに作られた公式動画です」, and below it the clips, the
   recipe, the engine's signature and the publication.
3. In the panel, click 「AIで場面を足して公開」. On the home page the new
   video looks like any other. Open it and check it:
   「公開レシピにない加工が含まれています」, with the added crowd scene
   named in the engine's step.
4. Click 「別のアプリで編集して公開」, open the new video and check it:
   「制作工程の記録がありません」.
5. Click 「運営が記録を書き換える」 and open the link of the video from
   step 3 again: the checking site finds the rewrite and offers the proof of
   misbehavior as a file anyone can verify.

「最初から」 starts over. Receipt links differ only after `#`, so reload the
checking site after opening another link.

## Roles in the demo

| Role | In the demo |
|---|---|
| Operator | The fan club's official account |
| Source | The rendering engine, run by a production company with its own key |
| Witnesses | A fans' association and an audit firm |
| Receipt holders | Fans, through the link next to each video |
| Verifier and registry curator | The checking site, independent of the fan club |
| Time-stamping authority | Left out of the demo |

| File | Shows |
|---|---|
| [world.go](world.go) | The simulated fan club: shoots, engine, publication, chain and witnesses |
| [verify.go](verify.go) | The checking site: what it verifies, and what it tells the fan |
| [main.go](main.go), [assets/](assets/) | The two websites and the demo panel |
