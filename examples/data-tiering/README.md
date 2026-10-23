# Use case: data tiering

> Status: runnable sample. `go run ./examples/data-tiering`

Many breaches expose data that no longer needed to be where it was: form
submissions kept for years on a third-party service, exports left on a shared
drive. Data tiering limits the damage: delete what is no longer needed, and
move what must be kept to a safer place. deedlog adds the last step:
showing that this is actually done, in a way others can check.

## Example: a contact form

An organization collects inquiries through a form hosted by a website
service. Inquiries must be answered, and some must be kept for a few years.

### Commitment

The operator publishes, and records as the first entry of the chain:

- the tiers and how long data may stay in each, for example at most 7 days on
  the form service, then moved to an internal archive, then deleted after
  3 years,
- how often each tier is inventoried, for example daily,
- which anchors and witnesses are used.

### Evidence recorded

| Event | Recorded by | Subject |
|---|---|---|
| Submission received | Form service or its webhook | HMAC of the submission |
| Moved to the archive | Transfer job | HMAC of the submission, source and destination tier |
| Deleted from a tier | The tier's storage | HMAC of the submission and the rule applied |
| Inventory | Each tier, on the declared cadence | Number of items held and the age of the oldest one |
| Tier or rule changed | Operator | The old and new policy |

Submissions contain names and free text, so records use `hmac-sha256`, never
the submission itself. The person who submitted can be given a receipt, so
the receipt's index ties their submission to its later move and deletion
records.

### What a verifier can check

- Every submission was moved off the form service within 7 days, and deleted
  from the archive within 3 years.
- Every inventory reports nothing older than its tier allows, and no
  inventory is missing from the declared cadence.
- The history shown today matches checkpoints held by witnesses.

### What remains outside

The chain records what the operator's systems did and reported. It cannot
show that no other copy exists: backups and logs inside the form service,
or a file exported by hand. The operator should ask service providers to
record their own deletions, in their own chains or as signed statements that
the operator records, and rely on audits for the rest.

## Anchors for this example

| Anchor | Role |
|---|---|
| Accredited time-stamping authority | Time of each checkpoint |
| The organization's internal audit or privacy office | Witness with oversight duty |
| An auditor, industry association or consumer organization | Independent witness |
| Any library, university or individual | Permissionless witness |

## Run the sample

```sh
go run ./examples/data-tiering
```

The sample simulates 60 days twice, with two witnesses cosigning weekly
checkpoints over the C2SP witness protocol. The first run follows the policy.
The second has a transfer job outage, a skipped inventory and an export copied
into the archive by hand. An auditor's check, using only public material,
reports each of them with the chain line where it shows:

```
line 152: moved off form-service after 11.6 days; the policy allows 7 days (entered at line 101)
line 259: no inventory of form-service for 2.0 days since line 244; the policy declares one every 24 hours
line 291: archive holds 61 items, but the chain accounts for 60: data entered or left it unrecorded
```

It also follows the first person's receipt link: the promise is checked
against the witnessed checkpoint, and their submission is traced to its move
and deletion.

| File | Shows |
|---|---|
| [tiering/tiering.go](tiering/tiering.go) | Where the calls go: the form webhook, the daily tiering job, the inventory |
| [tiering/check.go](tiering/check.go) | The auditor's check against the declared policy |
| [main.go](main.go) | The scenario, and what the person holding a receipt can check |

## Web demo

[webdemo](webdemo/) tells the same story on familiar web pages, in Japanese,
for people who are not engineers: a city's contact form, the receipt, and an
independent checking site that tells a resident, on the day the form
service's breach is announced, whether their inquiry was still there.

```sh
go run ./examples/data-tiering/webdemo    # then open http://localhost:8090/
```
