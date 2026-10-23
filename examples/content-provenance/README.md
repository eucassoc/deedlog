# Use case: content provenance (C2PA)

> Status: runnable sample. `go run ./examples/content-provenance`

C2PA attaches a signed manifest to an image, video or document, describing
who created it and how it was edited. It answers "where did this asset come
from?" from the asset itself.

deedlog does not replace C2PA manifests. It records the events around them
in a chain that the asset's publisher or archive keeps independently of the
asset:

| Event | Subject |
|---|---|
| Asset captured or ingested | Digest of the asset and of its C2PA manifest |
| Manifest validated | Digest of the validation result |
| Asset edited or transcoded | Digests of input, output and the new manifest |
| Asset published or archived | Digest of the published asset and its URL |

## What this adds

- **Survives stripped metadata.** Platforms often remove embedded manifests.
  Records also hold the digest of the content without its manifest, so a
  stripped copy still matches and the chain shows when it existed and where
  it came from. Copies that were re-encoded no longer match by digest; C2PA
  soft bindings (watermarks or fingerprints) cover those.
- **Fixes the timeline.** Checkpoints with trusted timestamps prove when an
  asset was held or published, which matters for news, legal preservation and
  disputes.
- **Links to the capturing device.** A record can reference the camera's
  [device-originated data](../device-data/).

C2PA already uses RFC 3161 timestamps and X.509 signatures; deedlog's
checkpoints use the same building blocks, so both can share a timestamp
authority and key infrastructure.

## Run the sample

```sh
go run ./examples/content-provenance
```

A newsroom ingests a photographer's image, crops and resizes it, and publishes
it; an archive and a press council witness the chain. Manifests are a stand-in
for C2PA: a real integration reads and validates them with a C2PA SDK and
records the same events.

A copy found on social media, with its manifest stripped, is traced back to
the photographer's upload; a doctored copy is not found:

```
2026-04-01 06:00  ingested from photographer upload, manifest valid (line 1)
2026-04-01 06:40  edited: c2pa.cropped (line 2)
2026-04-01 06:40  edited: c2pa.resized (line 3)
2026-04-01 07:00  published at https://news.example/2026/04/01/flood (line 4)
```

In the second run the newsroom takes shortcuts, and a check of its chain shows
them:

```
line 7: published an asset whose source at line 5 was ingested with untrusted signer unknown-app.example
line 8: edit of an asset that was never ingested
```

| File | Shows |
|---|---|
| [pipeline.go](pipeline.go) | Where the calls go: ingest, edit and publish; tracing a file |
| [check.go](check.go) | The check of the newsroom's chain |
| [main.go](main.go) | The scenario |
