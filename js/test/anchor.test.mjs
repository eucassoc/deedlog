// Anchoring: what the operator's service, the witness and the page of
// whoever checks a record all have to agree on (spec/anchoring.md).
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import * as t from '../deedlog.js';

const hex = (n) => randomBytes(n).toString('hex');

/** `k` records of a chain, as lines and as the bodies their subject digests are of. */
function records(k, name = 'log.example/dlm/records') {
  const lines = [];
  const bodies = [];
  for (let i = 0; i < k; i++) {
    const r = t.makeRecord(t.readChain(lines), { name, source: { type: 'test', id: name, collector: 'test' }, event: 'thing.happened', meta: { item: hex(16) } });
    lines.push(r.line);
    bodies.push(r.body);
  }
  return { lines, bodies };
}

test('what a record is about leads to its interval\'s commitment, and to no other', () => {
  for (const k of [0, 1, 2, 3, 4, 5, 8, 9, 31]) {
    const { lines, bodies } = records(k);
    const terms = { chain: 'log.example/dlm/records', epoch: '2026-11-19T03:20:00Z', nonce: hex(16), pad: hex(16) };
    const a = t.anchor(lines, terms);
    assert.equal(a.size, k <= 1 ? 1 : 2 ** Math.ceil(Math.log2(k)), `${k} records fill a tree of a power of two`);
    bodies.forEach((body, i) => {
      const at = t.recordProof(lines, i, { seq: 7, ...terms });
      assert.deepEqual([at.seq, at.epoch, at.size, at.index], [7, terms.epoch, a.size, i]);
      assert.equal(t.commitOf(body, terms.chain, at), a.commit);
      assert.notEqual(t.commitOf(body + ' ', terms.chain, at), a.commit, 'something else');
      assert.notEqual(t.commitOf(body, terms.chain, { ...at, epoch: '2026-11-19T03:30:00Z' }), a.commit, 'another interval');
      assert.notEqual(t.commitOf(body, terms.chain, { ...at, nonce: hex(16) }), a.commit, 'another nonce');
      assert.notEqual(t.commitOf(body, terms.chain, { ...at, blind: hex(32) }), a.commit, 'another blind');
      assert.notEqual(t.commitOf(body, terms.chain, { ...at, record: hex(32) }), a.commit, 'another record');
      if (a.size > 1) assert.notEqual(t.commitOf(body, terms.chain, { ...at, index: (i + 1) % a.size }), a.commit, 'another place');
      // What is handed over says nothing of the record's place in the chain.
      assert.deepEqual(Object.keys(at).sort(), ['blind', 'epoch', 'index', 'nonce', 'path', 'record', 'seq', 'size']);
      assert.deepEqual(Object.keys(JSON.parse(body)).sort(), ['at', 'event', 'item']);
    });
    // A line changed anywhere but in what it is about still changes the commitment.
    if (k) assert.notEqual(t.anchor([lines[0].replace('"type":"test"', '"type":"tess"'), ...lines.slice(1)], terms).commit, a.commit);
  }
});

test('an interval with nothing in it looks like any other', () => {
  const terms = (epoch) => ({ chain: 'c', epoch, nonce: hex(16), pad: hex(16) });
  const a = t.anchor([], terms('2026-11-19T03:20:00Z'));
  const b = t.anchor([], terms('2026-11-19T03:30:00Z'));
  assert.equal(a.size, 1);
  assert.notEqual(a.commit, b.commit);
  assert.match(a.commit, /^[0-9a-f]{64}$/);
});

test('secrets that are not hexadecimal are refused, not read as something else', () => {
  const terms = { chain: 'c', epoch: '2026-11-19T03:20:00Z', nonce: hex(16), pad: hex(16) };
  assert.throws(() => t.anchor([], { ...terms, pad: 'not hexadecimal' }), /pad/);
  assert.throws(() => t.anchor([], { ...terms, pad: 'abc' }), /pad/);
  assert.throws(() => t.anchor([], { ...terms, nonce: undefined }), /nonce/);
});
