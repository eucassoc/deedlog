// The conformance vectors, ../../testdata/conformance/vectors.json, are what
// this implementation and the Go one (core/) are both held to: from the
// inputs in the file, each must produce the outputs in the file, byte for
// byte, and accept or refuse what the file says. core/conformance_test.go
// does the same on the Go side; see docs/implementations.md.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import * as t from '../deedlog.js';

const v = JSON.parse(readFileSync(new URL('../../testdata/conformance/vectors.json', import.meta.url), 'utf8'));
const leavesOf = (lines) => lines.map((l) => t.leafHash(l));

test('key names', () => {
  for (const name of v.names.valid) assert.equal(t.validName(name), true, JSON.stringify(name));
  for (const name of v.names.invalid) assert.equal(t.validName(name), false, JSON.stringify(name));
});

test('keys are read as Go reads them', async () => {
  for (const [who, k] of Object.entries(v.keys)) {
    const signer = await t.parseSigner(k.skey);
    assert.equal(signer.vkey, k.vkey, who);
    assert.equal(t.parseVerifier(k.vkey).name, signer.name);
  }
});

test('the same events make the same records, digests and roots', () => {
  const r = v.records;
  const lines = [];
  r.events.forEach((e, i) => {
    const made = t.makeRecord(t.readChain(lines), { name: r.chain, source: r.source, event: e.event, meta: Object.fromEntries(e.meta ?? []), at: new Date(e.at) });
    assert.equal(made.line, r.lines[i], `record ${i}`);
    assert.equal(made.body, r.bodies[i], `body ${i}`);
    lines.push(made.line);
    assert.equal('sha256:' + t.readChain(lines).head, r.heads[i], `head after record ${i}`);
    assert.equal(t.b64(t.leafHash(made.line)), r.leaves[i], `leaf ${i}`);
  });
  const leaves = leavesOf(lines);
  r.roots.forEach((root, size) => assert.equal(t.b64(t.merkleRoot(leaves, size)), root, `root at size ${size}`));
});

test('the same proofs, and each leads to its root', () => {
  const r = v.records;
  const leaves = r.leaves.map(t.unb64);
  const roots = r.roots.map(t.unb64);
  for (const p of r.proofs.inclusion) {
    assert.deepEqual(t.inclusionProof(leaves, p.index, p.size).map(t.b64), p.proof, `inclusion of ${p.index} in ${p.size}`);
    t.verifyInclusion(p.index, p.size, leaves[p.index], p.proof.map(t.unb64), roots[p.size]);
    if (p.size > 1) assert.throws(() => t.verifyInclusion(p.index, p.size, leaves[(p.index + 1) % p.size], p.proof.map(t.unb64), roots[p.size]));
  }
  for (const p of r.proofs.consistency) {
    assert.deepEqual(t.consistencyProof(leaves, p.old, p.new).map(t.b64), p.proof, `consistency from ${p.old} to ${p.new}`);
    t.verifyConsistency(p.old, p.new, roots[p.old], roots[p.new], p.proof.map(t.unb64));
  }
});

test('chains are accepted and refused alike, at the same line', () => {
  for (const c of v.accepted) {
    const got = t.readChain(c.lines);
    assert.deepEqual(got.problems, [], c.name);
    assert.equal(got.entries.length, c.count, c.name);
    assert.equal('sha256:' + got.head, c.head, c.name);
    assert.equal(t.b64(t.merkleRoot(leavesOf(c.lines))), c.root, c.name);
  }
  for (const c of v.refused) {
    const got = t.readChain(c.lines);
    // A chain without records has no line to name; a reader of lines finds nothing to read.
    if (c.line === 0) assert.equal(got.entries.length, 0, c.name);
    else assert.equal(got.problems[0]?.line, c.line, `${c.name}: ${JSON.stringify(got.problems)}`);
  }
});

test('anchoring: the same trees, commitments, anchor records and proofs', () => {
  const a = v.anchoring;
  const lines = v.records.lines;
  const outer = [];
  for (const iv of a.intervals) {
    const terms = { chain: a.chain, epoch: iv.epoch, nonce: iv.nonce, pad: iv.pad };
    const made = t.anchor(lines.slice(iv.from, iv.to), terms);
    assert.deepEqual([made.size, t.b64(made.root), made.commit], [iv.size, iv.root, iv.commit], `interval ${iv.seq}`);
    const line = t.nextRecord(t.readChain(outer), { name: a.origin, source: a.source, event: 'chain.anchored', meta: { epoch: iv.epoch, commit: made.commit }, at: new Date(iv.at) });
    assert.equal(line, iv.line, `anchor record ${iv.seq}`);
    outer.push(line);
  }
  const commits = t.readChain(outer).entries.map((e) => e.meta);
  for (const p of a.proofs) {
    const iv = a.intervals.find((x) => p.record >= x.from && p.record < x.to);
    const proof = t.recordProof(lines.slice(iv.from, iv.to), p.record - iv.from, iv);
    assert.equal(JSON.stringify(proof), p.proof, `proof of record ${p.record}`);
    assert.equal(p.body, v.records.bodies[p.record]);
    assert.equal(t.commitOf(p.body, a.chain, JSON.parse(p.proof)), commits[proof.seq].commit, `record ${p.record}`);
    assert.equal(commits[proof.seq].epoch, proof.epoch);
  }
  for (const p of a.refused) {
    const at = JSON.parse(p.proof);
    const anchor = commits[at.seq];
    let ok;
    try {
      ok = !!anchor && anchor.epoch === at.epoch && t.commitOf(p.body, p.chain, at) === anchor.commit;
    } catch {
      ok = false;
    }
    assert.equal(ok, false, p.name);
  }
});

test('the same checkpoints and cosignatures, and notes accepted and refused alike', async () => {
  const operator = t.parseVerifier(v.keys.operator.vkey);
  const witness = t.parseVerifier(v.keys.witness.vkey);
  const signer = await t.parseSigner(v.keys.operator.skey);
  const cosigner = await t.parseSigner(v.keys.witness.skey);
  const leaves = leavesOf(v.anchoring.intervals.map((iv) => iv.line));
  for (const c of v.checkpoints) {
    assert.equal(t.checkpointText(operator.name, c.size, t.merkleRoot(leaves, c.size)), c.text);
    const note = await t.signCheckpoint(leaves, signer, c.size);
    assert.equal(note, c.note, `checkpoint at size ${c.size}`);
    assert.equal(note + (await t.cosign(c.text, cosigner, c.time)), c.cosigned, `cosignature at size ${c.size}`);
    const got = await t.verifyCheckpoint(c.cosigned, operator, [witness], 1);
    assert.deepEqual([got.size, got.cosigned[0].time], [c.size, c.time]);
  }
  for (const n of v.notes) {
    const ok = await t.verifyCheckpoint(n.note, operator, [witness], n.quorum).then(() => true, () => false);
    assert.equal(ok, n.ok, n.name);
  }
});

test('a witness answers alike', async () => {
  const operator = t.parseVerifier(v.keys.operator.vkey);
  const state = new Map();
  let now = 0;
  const witness = { signer: await t.parseSigner(v.keys.witness.skey), logs: (o) => (o === operator.name ? operator : undefined), latest: async (o) => state.get(o), put: async (o, c) => void state.set(o, c), now: () => new Date(now * 1000) };
  for (const step of v.witness) {
    now = step.time;
    const r = await t.addCheckpoint(step.body, witness);
    assert.equal(r.status, step.status, `${step.name}: ${r.body}`);
    if (r.status === 200 || r.status === 409) assert.equal(r.body, step.response, step.name);
    if (r.status === 409) assert.equal(r.type, 'text/x.tlog.size');
  }
});
