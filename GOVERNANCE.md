# Governance

## Principles

- **Vendor-neutral.** deedlog is not an add-on to any company's product.
  Domain- or product-specific code lives in collectors, exporters and
  examples, never in `core/` or `spec/`.
- **Specification first.** Changes to the chain format start as a change to
  [`spec/`](spec/). The Go implementation follows the specification, not the
  other way around.
- **Humans decide merges.** Automation and AI assistants may triage issues
  and propose changes, but every merge to `main` is approved by a
  maintainer.

## Maintainers

Maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md). They review and
merge changes, cut releases and handle security reports.

New maintainers are nominated by an existing maintainer and confirmed when no
other maintainer objects within 7 days.

## Decisions

Decisions are made by lazy consensus on the relevant issue or pull request.
Changes to `spec/`, to this document or to the license require explicit
approval from a majority of maintainers.
