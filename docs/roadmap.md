# Roadmap

Done:

- [x] Chain format and verifier
- [x] Merkle tree checkpoints in the C2SP format, inclusion and consistency
      proofs, proofs of misbehavior
- [x] RFC 3161 timestamps, verified with the standard library only
- [x] Witness client and server (c2sp.org/tlog-witness), tested against the
      transparency-dev OmniWitness
- [x] Receipts, URL envelopes for QR codes, publication with `dlog serve`, and
      a verification page in the browser
- [x] Runnable samples for each use case, including an MCP proxy and Claude
      Code hooks for AI agents

Next:

- [ ] Libraries for embedding in products, and a collector for other languages
- [ ] SD-JWT VC receipt envelope (OpenID4VCI / OpenID4VP)
- [ ] ML-DSA-44 cosignatures
- [ ] Declared scope and cadence; source signatures; references between chains
- [ ] Exporters: OSCAL assessment results, legal evidence bundle
