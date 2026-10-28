# Use case: official videos edited with AI

> Status: runnable sample. `go run ./examples/official-videos`

Fan clubs, sports teams and artists publish short official videos every day.
Generative AI makes editing them cheap, and makes fans ask whether what they
see really happened. An official account can answer that by publishing how
its videos are made, and letting anyone check each video against it:
footage registered at the shoot, edited by an engine that may only trim,
crop, join and add the club's own logo and music.

## Example: a fan club's daily videos

### Commitment

The official account publishes, and records before any video:

- the recipe: the operations the engine may apply, and the assets (logo,
  jingle, music) it may add. Anything that creates a scene the footage does
  not contain is outside it,
- the rendering engine's public key. The engine is run by a party other than
  the account, such as the production company,
- which anchors and witnesses are used.

### Evidence recorded

| Event | Recorded by | Subject |
|---|---|---|
| Recipe declared | Official account | The recipe |
| Clip registered | Shooting staff, as each clip comes off the camera | Digest of the clip, camera and time |
| Video rendered | Rendering engine | Its signed statement: recipe, input clips, operations and output, by digest |
| Video published | Official account | Digest of the video and its URL |

The recipe and the engine's statements hold digests only, so they are
published with the chain; clips and videos stay with the account. Each
published video comes with a receipt, so a fan can follow the link next to it
to the video's history.

### What a verifier can check

- Every published video was rendered by the engine, under the declared recipe.
- Every clip it was made from was registered before it was rendered.
- The engine applied only the operations the recipe allows. The engine reports
  every operation, so a scene added by AI shows in its own signed statement.
- The history shown today matches checkpoints held by witnesses.

### What remains outside

- The engine's statement is its own word. It is the word of a party other
  than the account, which is why the engine is run by someone else; checking
  each scene against the footage needs the footage, or perceptual hashes of
  it, and is left to auditors.
- Platforms re-encode uploaded videos, so a copy found on a social network no
  longer matches by digest. Fans check through the link published next to the
  video; matching copies needs C2PA soft bindings (watermarks or
  fingerprints), see [content provenance](../content-provenance/).
- Clips can be traced to a camera only if the camera signs them, see
  [device-originated data](../device-data/).

## Anchors for this example

| Anchor | Role |
|---|---|
| Time-stamping authority | Time of each checkpoint |
| A fans' association or members' representatives | Witness with an interest in honest videos |
| An auditor, league or sports body | Independent witness |
| Any library, university or individual | Permissionless witness |

## Run the sample

```sh
go run ./examples/official-videos
```

The sample produces a video a day for five days, with two witnesses
cosigning a checkpoint after each. The first run follows the recipe. In the
second, the engine is asked to add a crowd scene, a video edited in another
app is published, stock footage is used, and the account signs a render
statement itself. A check, using only public material, reports each of them
with the chain line where it shows:

```
line 12: operation "generate" (crowd scene added) is not allowed by recipe "highlights-v1" at line 1
line 18: published a video that the engine did not render
line 23: input 1 is footage that was never registered
line 29: render statement not signed by the engine engine.studio.example: no signature from a known key
```

It also follows the receipt next to the first video, from the recipe and the
registered clips to its render and publication.

| File | Shows |
|---|---|
| [studio/studio.go](studio/studio.go) | Where the calls go: the recipe, the shoot, the engine and publication |
| [studio/check.go](studio/check.go) | The check against the recipe, and tracing a video |
| [main.go](main.go) | The scenario, and what a fan holding the receipt can check |

## Web demo

[webdemo](webdemo/) tells the same story on familiar web pages, in Japanese,
for people who are not engineers: a fictional boxer's fan club site, and an
independent checking site that shows a fan how each video was made, and which
ones were not made as promised.

```sh
go run ./examples/official-videos/webdemo    # then open http://localhost:8090/
```
