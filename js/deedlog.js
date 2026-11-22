// deedlog in JavaScript: chains of records (spec/evidence-chain.md), signed
// notes, checkpoints, cosignatures and Merkle trees as C2SP defines them
// (signed-note, tlog-checkpoint, tlog-cosignature, tlog-witness) and as
// deedlog uses them (spec/checkpoint.md), and anchoring (spec/anchoring.md).
// One file with no dependencies, so that the same code runs in a witness, in
// an operator's service and in the browser of whoever checks a record.
//
// The Go implementation is core/ of the same repository. Both are held to
// testdata/conformance: the same input gives the same bytes in both, and
// each accepts what the other writes. docs/implementations.md lists what
// each has and where they differ.
//
// SHA-256 is implemented here and is synchronous, because a Merkle root is
// many small hashes. Ed25519 is the platform's (Web Crypto).

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

export const utf8 = (s) => enc.encode(s);
export const text = (b) => dec.decode(b);

// ---- bytes ----

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

export const hex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('');

export function b64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

/** Decodes base64 and refuses encodings that are not canonical, as C2SP requires. */
export function unb64(s) {
  let bin;
  try {
    bin = atob(s);
  } catch {
    throw new Error(`invalid base64 ${JSON.stringify(s)}`);
  }
  const out = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  if (b64(out) !== s) throw new Error(`invalid base64 ${JSON.stringify(s)}`);
  return out;
}

export const b64url = (bytes) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// ---- SHA-256 ----

const primes = (n) => {
  const out = [];
  for (let c = 2; out.length < n; c++) if (out.every((p) => c % p)) out.push(c);
  return out;
};
const frac = (x) => Math.floor((x - Math.floor(x)) * 0x100000000) >>> 0;
const K = Uint32Array.from(primes(64), (p) => frac(Math.cbrt(p)));
const H0 = Uint32Array.from(primes(8), (p) => frac(Math.sqrt(p)));
const rotr = (x, n) => (x >>> n) | (x << (32 - n));

/** SHA-256 of bytes, as bytes. */
export function sha256(data) {
  const H = Uint32Array.from(H0);
  const len = data.length;
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(len / 0x20000000));
  dv.setUint32(padded.length - 4, (len << 3) >>> 0);
  const w = new Uint32Array(64);
  for (let o = 0; o < padded.length; o += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  H.forEach((v, i) => ov.setUint32(i * 4, v));
  return out;
}

export const sha256hex = (s) => hex(sha256(typeof s === 'string' ? utf8(s) : s));

// ---- Merkle tree (RFC 9162 section 2.1, the same as RFC 6962) ----

export const EMPTY_ROOT = sha256(new Uint8Array(0));
/** The leaf hash of a record: its bytes, without the newline that ends the line. */
export const leafHash = (record) => sha256(concat(Uint8Array.of(0), typeof record === 'string' ? utf8(record) : record));
const node = (l, r) => sha256(concat(Uint8Array.of(1), l, r));
const split = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

function mth(leaves, lo, hi) {
  const n = hi - lo;
  if (n === 1) return leaves[lo];
  const k = split(n);
  return node(mth(leaves, lo, lo + k), mth(leaves, lo + k, hi));
}

/** The root of the tree over the first `size` leaf hashes. */
export function merkleRoot(leaves, size = leaves.length) {
  if (size > leaves.length) throw new Error(`the tree has ${leaves.length} leaves, not ${size}`);
  return size === 0 ? EMPTY_ROOT : mth(leaves, 0, size);
}

/** The proof that the tree of size `m` is a prefix of the tree of size `n`. */
export function consistencyProof(leaves, m, n = leaves.length) {
  if (m > n || n > leaves.length) throw new Error(`no proof from ${m} to ${n} in a tree of ${leaves.length}`);
  if (m === 0 || m === n) return [];
  const sub = (m, lo, hi, whole) => {
    const n = hi - lo;
    if (m === n) return whole ? [] : [mth(leaves, lo, hi)];
    const k = split(n);
    return m <= k ? [...sub(m, lo, lo + k, whole), mth(leaves, lo + k, hi)] : [...sub(m - k, lo + k, hi, false), mth(leaves, lo, lo + k)];
  };
  return sub(m, 0, n, true);
}

/** Throws unless `proof` shows that the tree (m, root1) is a prefix of the tree (n, root2). */
export function verifyConsistency(m, n, root1, root2, proof) {
  if (m > n) throw new Error('the old tree is larger than the new one');
  if (m === n) {
    if (proof.length) throw new Error('a proof between trees of the same size must be empty');
    if (!equal(root1, root2)) throw new Error('same size, different root: the log shows two histories');
    return;
  }
  if (m === 0) {
    if (proof.length) throw new Error('a proof from the empty tree must be empty');
    return;
  }
  const path = [...proof];
  if (Number.isInteger(Math.log2(m))) path.unshift(root1);
  if (!path.length) throw new Error('the consistency proof is empty');
  let fn = m - 1;
  let sn = n - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) throw new Error('the consistency proof is too long');
    if (fn % 2 === 1 || fn === sn) {
      fr = node(c, fr);
      sr = node(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else sr = node(sr, c);
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new Error('the consistency proof is too short');
  if (!equal(fr, root1)) throw new Error('the consistency proof does not lead to the old root');
  if (!equal(sr, root2)) throw new Error('the consistency proof does not lead to the new root');
}

/** The proof that leaf `i` is in the tree of size `n`. */
export function inclusionProof(leaves, i, n = leaves.length) {
  if (i >= n || n > leaves.length) throw new Error(`no leaf ${i} in a tree of ${n}`);
  const path = (i, lo, hi) => {
    const n = hi - lo;
    if (n === 1) return [];
    const k = split(n);
    return i < k ? [...path(i, lo, lo + k), mth(leaves, lo + k, hi)] : [...path(i - k, lo + k, hi), mth(leaves, lo, lo + k)];
  };
  return path(i, 0, n);
}

/** Throws unless `proof` shows that `leaf` is leaf `index` of the tree (size, root). */
export function verifyInclusion(index, size, leaf, proof, root) {
  if (!equal(rootFromInclusion(leaf, index, size, proof), root)) throw new Error('the inclusion proof does not lead to the root');
}

// ---- keys (c2sp.org/signed-note) ----

export const SIG_ED25519 = 0x01; // a note signature: operators
export const SIG_COSIGNATURE = 0x04; // a timestamped checkpoint cosignature: witnesses

const PKCS8 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

export function validName(name) {
  if (typeof name !== 'string' || !name || utf8(name).length > 255) return false;
  // No "+", no control characters, no Unicode spaces.
  return !/[+\x00-\x1f\x85\p{Z}]/u.test(name);
}

const keyId = (name, typ, pub) => sha256(concat(utf8(name), Uint8Array.of(0x0a, typ), pub)).subarray(0, 4);

function parseKey(s) {
  const i = s.indexOf('+');
  const j = s.indexOf('+', i + 1);
  if (i < 0 || j < 0) throw new Error('malformed key');
  const name = s.slice(0, i);
  const id = s.slice(i + 1, j);
  if (!validName(name)) throw new Error(`invalid key name ${JSON.stringify(name)}`);
  if (!/^[0-9a-f]{8}$/.test(id)) throw new Error('malformed key ID');
  const material = unb64(s.slice(j + 1));
  if (material.length < 2) throw new Error('malformed key material');
  return { name, id, typ: material[0], material: material.subarray(1) };
}

/** Reads a verifier key, `name+id+base64(type || public key)`. */
export function parseVerifier(vkey) {
  const k = parseKey(vkey.trim());
  if (k.typ !== SIG_ED25519 && k.typ !== SIG_COSIGNATURE) throw new Error(`unsupported signature type 0x${k.typ.toString(16).padStart(2, '0')}`);
  if (k.material.length !== 32) throw new Error('verifier key is not an Ed25519 public key');
  if (hex(keyId(k.name, k.typ, k.material)) !== k.id) throw new Error('verifier key ID does not match key');
  return { name: k.name, id: k.id, typ: k.typ, pub: k.material, vkey: vkey.trim() };
}

async function privateKey(seed) {
  return crypto.subtle.importKey('pkcs8', concat(PKCS8, seed), { name: 'Ed25519' }, true, ['sign']);
}

async function publicOf(seed) {
  const jwk = await crypto.subtle.exportKey('jwk', await privateKey(seed));
  return unb64(jwk.x.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (jwk.x.length % 4)) % 4));
}

/** Reads a signer key, `PRIVATE+KEY+name+id+base64(type || seed)`, as `dlog keygen` writes it. */
export async function parseSigner(skey) {
  const s = skey.trim();
  if (!s.startsWith('PRIVATE+KEY+')) throw new Error('not a signer key');
  const k = parseKey(s.slice(12));
  if ((k.typ !== SIG_ED25519 && k.typ !== SIG_COSIGNATURE) || k.material.length !== 32) throw new Error('signer key is not an Ed25519 note or cosignature key');
  const pub = await publicOf(k.material);
  if (hex(keyId(k.name, k.typ, pub)) !== k.id) throw new Error('signer key ID does not match key');
  return { name: k.name, id: k.id, typ: k.typ, pub, key: await privateKey(k.material), vkey: `${k.name}+${k.id}+${b64(concat(Uint8Array.of(k.typ), pub))}` };
}

/** A new key: for an operator's checkpoints (`SIG_ED25519`) or a witness's cosignatures (`SIG_COSIGNATURE`). */
export async function generateKey(name, typ = SIG_ED25519) {
  if (!validName(name)) throw new Error(`invalid key name ${JSON.stringify(name)}`);
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const pub = await publicOf(seed);
  const id = hex(keyId(name, typ, pub));
  return { skey: `PRIVATE+KEY+${name}+${id}+${b64(concat(Uint8Array.of(typ), seed))}`, vkey: `${name}+${id}+${b64(concat(Uint8Array.of(typ), pub))}` };
}

// ---- notes ----

const DASH = String.fromCharCode(0x2014) + ' ';

function checkNoteText(t) {
  if (!t.endsWith('\n')) throw new Error('note text must end with a newline');
  if (/[\x00-\x09\x0b-\x1f]/.test(t)) throw new Error('note contains a control character');
}

const sigLine = (signer, sig) => `${DASH}${signer.name} ${b64(concat(unhex(signer.id), sig))}\n`;
export const unhex = (s) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));

/** Signs note text: the text, an empty line, and the signature line. */
export async function signNote(noteText, signer) {
  if (signer.typ !== SIG_ED25519) throw new Error('cosignature keys cannot sign notes');
  checkNoteText(noteText);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, signer.key, utf8(noteText)));
  return noteText + '\n' + sigLine(signer, sig);
}

const cosignedMessage = (noteText, time) => utf8(`cosignature/v1\ntime ${time}\n${noteText}`);

/** A witness's cosignature line over checkpoint text, at `time` (seconds since 1970). */
export async function cosign(noteText, signer, time) {
  if (signer.typ !== SIG_COSIGNATURE) throw new Error('only cosignature keys can cosign');
  checkNoteText(noteText);
  const stamp = new Uint8Array(8);
  new DataView(stamp.buffer).setBigUint64(0, BigInt(time));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, signer.key, cosignedMessage(noteText, time)));
  return sigLine(signer, concat(stamp, sig));
}

/** Splits a signed note into its text and its signature lines. */
export function parseNote(note) {
  checkNoteText(note);
  const i = note.lastIndexOf('\n\n');
  if (i < 0 || i + 2 >= note.length) throw new Error('note has no signatures');
  const sigs = [];
  for (const line of note.slice(i + 2).split('\n')) {
    if (!line) continue;
    const rest = line.startsWith(DASH) ? line.slice(DASH.length) : undefined;
    const sp = rest === undefined ? -1 : rest.indexOf(' ');
    if (sp < 1 || !validName(rest.slice(0, sp))) throw new Error(`malformed signature line ${JSON.stringify(line)}`);
    const raw = unb64(rest.slice(sp + 1));
    if (raw.length < 4) throw new Error(`malformed signature line ${JSON.stringify(line)}`);
    sigs.push({ name: rest.slice(0, sp), id: hex(raw.subarray(0, 4)), sig: raw.subarray(4), line: line + '\n' });
  }
  return { text: note.slice(0, i + 1), sigs };
}

async function verifySig(v, noteText, sig) {
  const key = await crypto.subtle.importKey('raw', v.pub, { name: 'Ed25519' }, false, ['verify']);
  if (v.typ === SIG_ED25519) return { ok: await crypto.subtle.verify({ name: 'Ed25519' }, key, sig, utf8(noteText)) };
  if (sig.length !== 8 + 64) return { ok: false };
  const time = Number(new DataView(sig.buffer, sig.byteOffset, 8).getBigUint64(0));
  return { ok: await crypto.subtle.verify({ name: 'Ed25519' }, key, sig.subarray(8), cosignedMessage(noteText, time)), time };
}

/**
 * Checks a note against keys, as c2sp.org/signed-note says: signatures from
 * unknown keys are ignored, and a failing signature from a known key rejects
 * the note. Returns the text and, for each key that signed, its verifier, the
 * signature line and, for a cosignature, its time.
 */
export async function openNote(note, verifiers) {
  const { text: noteText, sigs } = parseNote(note);
  const verified = [];
  for (const s of sigs) {
    for (const v of verifiers) {
      if (v.name !== s.name || v.id !== s.id) continue;
      const r = await verifySig(v, noteText, s.sig);
      if (!r.ok) throw new Error(`signature by ${v.name}: invalid`);
      verified.push({ verifier: v, line: s.line, ...(r.time !== undefined ? { time: r.time } : {}) });
    }
  }
  return { text: noteText, verified };
}

// ---- checkpoints (c2sp.org/tlog-checkpoint, without extension lines) ----

export const checkpointText = (origin, size, root) => `${origin}\n${size}\n${b64(root)}\n`;

export function parseCheckpoint(noteText) {
  const lines = noteText.split('\n');
  if (lines.length !== 4 || lines[3] !== '') throw new Error('a checkpoint is three lines: origin, size, root');
  const [origin, sizeText, rootText] = lines;
  if (!validName(origin)) throw new Error('malformed checkpoint origin');
  if (!/^(0|[1-9][0-9]{0,15})$/.test(sizeText)) throw new Error('malformed checkpoint size');
  const root = unb64(rootText);
  if (root.length !== 32) throw new Error('malformed checkpoint root');
  if (sizeText === '0' && !equal(root, EMPTY_ROOT)) throw new Error('an empty checkpoint must have the root of the empty tree');
  return { origin, size: Number(sizeText), root };
}

/** The origin a signed checkpoint names, before anything about it is verified. */
export function noteOrigin(note) {
  const origin = note.slice(0, Math.max(0, note.indexOf('\n')));
  if (!validName(origin)) throw new Error('malformed checkpoint');
  return origin;
}

/** Signs the checkpoint of a tree. The signer's name is the origin. */
export async function signCheckpoint(leaves, signer, size = leaves.length) {
  return signNote(checkpointText(signer.name, size, merkleRoot(leaves, size)), signer);
}

/**
 * Checks a signed checkpoint: the operator must have signed it, and at least
 * `quorum` of the witnesses. Returns the checkpoint and who cosigned.
 */
export async function verifyCheckpoint(note, operator, witnesses = [], quorum = 0) {
  if (operator.typ !== SIG_ED25519) throw new Error('the operator key is not a note signing key');
  for (const w of witnesses) if (w.typ !== SIG_COSIGNATURE) throw new Error(`the witness key ${w.name} is not a cosignature key`);
  const { text: noteText, verified } = await openNote(note, [operator, ...witnesses]);
  if (!verified.some((v) => v.verifier === operator)) throw new Error('no signature from the operator');
  const c = parseCheckpoint(noteText);
  if (c.origin !== operator.name) throw new Error(`the checkpoint is for ${c.origin}, the key for ${operator.name}`);
  const cosigned = verified.filter((v) => v.verifier !== operator);
  const distinct = new Set(cosigned.map((v) => v.verifier.vkey));
  if (distinct.size < quorum) throw new Error(`${distinct.size} of ${quorum} required cosignatures`);
  return { ...c, text: noteText, cosigned };
}

// ---- the witness side of c2sp.org/tlog-witness ----

/** Reads an add-checkpoint request: `old N`, the consistency proof, an empty line, the checkpoint. */
export function parseAddCheckpoint(body) {
  const cut = body.indexOf('\n\n');
  if (cut < 0) throw new Error('missing empty line before checkpoint');
  const head = body.slice(0, cut).split('\n');
  const m = /^old (0|[1-9][0-9]{0,15})$/.exec(head[0] ?? '');
  if (!m) throw new Error('malformed old size line');
  if (head.length - 1 > 63) throw new Error('too many consistency proof lines');
  const proof = head.slice(1).map((l) => {
    let h;
    try {
      h = unb64(l);
    } catch {
      throw new Error('malformed consistency proof line');
    }
    if (h.length !== 32) throw new Error('malformed consistency proof line');
    return h;
  });
  return { oldSize: Number(m[1]), proof, note: body.slice(cut + 2) };
}

/**
 * A witness's answer to add-checkpoint. `logs` maps an origin to the
 * operator's verifier; `latest` and `put` read and write the last checkpoint
 * cosigned for an origin, and the caller makes sure that no other call runs
 * between them. Returns the HTTP status, the body and, for 409, the content type.
 */
export async function addCheckpoint(body, { signer, logs, latest, put, now = () => new Date() }) {
  let req;
  let origin;
  try {
    req = parseAddCheckpoint(body);
    origin = noteOrigin(req.note);
  } catch (e) {
    return { status: 400, body: e.message + '\n' };
  }
  const operator = logs(origin);
  if (!operator) return { status: 404, body: 'unknown origin\n' };
  let c;
  try {
    c = await verifyCheckpoint(req.note, operator);
  } catch (e) {
    return { status: 403, body: e.message + '\n' };
  }
  if (req.oldSize > c.size) return { status: 400, body: 'old size larger than checkpoint size\n' };
  const last = (await latest(origin)) ?? { size: 0, root: EMPTY_ROOT };
  if (req.oldSize !== last.size) return { status: 409, body: `${last.size}\n`, type: 'text/x.tlog.size' };
  try {
    verifyConsistency(last.size, c.size, last.root, c.root, req.proof);
  } catch (e) {
    return { status: 422, body: e.message + '\n' };
  }
  const time = Math.floor(now().getTime() / 1000);
  await put(origin, { size: c.size, root: c.root, time });
  return { status: 200, body: await cosign(c.text, signer, time) };
}

// ---- the operator side ----

/**
 * Asks a witness to cosign. `post(body)` sends an add-checkpoint request and
 * resolves to `{ status, body }`. Returns the cosignature lines that verify
 * with the witness's key, and the size the witness now holds.
 */
export async function requestCosignature(note, leaves, witness, post, oldSize = 0) {
  const { text: noteText } = parseNote(note);
  const c = parseCheckpoint(noteText);
  const send = (old) => post(`old ${old}\n${consistencyProof(leaves, old, c.size).map((h) => b64(h) + '\n').join('')}\n${note}`);
  let r = await send(Math.min(oldSize, c.size));
  if (r.status === 409) {
    const held = Number(r.body.trim());
    if (!Number.isInteger(held) || held < 0) throw new Error(`${witness.name}: malformed size in 409`);
    if (held > c.size) throw new Error(`${witness.name} already holds size ${held}; this checkpoint is for ${c.size}`);
    r = await send(held);
  }
  if (r.status !== 200) throw new Error(`${witness.name}: ${r.status} ${r.body.trim()}`);
  const lines = [];
  for (const line of r.body.split('\n').filter(Boolean)) {
    const opened = await openNote(noteText + '\n' + line + '\n', [witness]).catch(() => undefined);
    if (opened?.verified.length) lines.push(line + '\n');
  }
  if (!lines.length) throw new Error(`${witness.name}: no cosignature that verifies with its key`);
  return { lines, size: c.size };
}

// ---- reading a chain (deedlog/v0.1 records, one per line) ----

/**
 * Checks the lines of a chain: the sequence numbers and the link from each
 * record to the one before. Every problem names its line.
 */
export function readChain(lines) {
  const problems = [];
  const entries = [];
  let prev;
  let name;
  lines.forEach((line, i) => {
    const n = i + 1;
    let r;
    try {
      r = JSON.parse(line);
    } catch {
      r = undefined;
    }
    if (r === null || typeof r !== 'object' || Array.isArray(r)) {
      problems.push({ line: n, reason: line.endsWith('\r') ? 'the line ends with CR; the file may have been converted to CRLF' : 'not a JSON object' });
      prev = 'sha256:' + sha256hex(line);
      return;
    }
    if (line.endsWith('\r')) problems.push({ line: n, reason: 'the line ends with CR; the file may have been converted to CRLF' });
    if (r.spec !== 'deedlog/v0.1') problems.push({ line: n, reason: `spec is ${JSON.stringify(r.spec)}, not "deedlog/v0.1"` });
    if (i === 0 && typeof r.chain === 'string') name = r.chain;
    if (i === 0 && !name) problems.push({ line: n, reason: 'the first record names no chain' });
    if (r.chain !== name) problems.push({ line: n, reason: `chain is ${JSON.stringify(r.chain)}; the first record names ${JSON.stringify(name)}` });
    if (r.seq !== i) problems.push({ line: n, reason: `seq is ${JSON.stringify(r.seq)}; ${i} follows the line before` });
    if (r.prev !== prev) problems.push({ line: n, reason: i ? 'prev does not match the digest of the line before; a record was changed, removed or reordered' : 'the first record names a record before it' });
    const digest = r.subject?.digest;
    if (!digest || typeof digest !== 'object' || !Object.keys(digest).length) problems.push({ line: n, reason: 'the subject has no digest' });
    else if ('sha256' in digest && !/^[0-9a-f]{64}$/.test(digest.sha256)) problems.push({ line: n, reason: 'the SHA-256 digest of the subject is not 64 lowercase hexadecimal characters' });
    prev = 'sha256:' + sha256hex(line);
    const meta = {};
    if (r.meta && typeof r.meta === 'object') for (const [k, v] of Object.entries(r.meta)) if (typeof v === 'string') meta[k] = v;
    const { event, ...rest } = meta;
    entries.push({ seq: i, at: typeof r.collected_at === 'string' ? r.collected_at : '', event: event ?? '', meta: rest, digest: prev.slice(7) });
  });
  return { name, entries, head: prev?.slice(7), problems };
}

/**
 * The next record of a chain, as its line. The subject is the event itself:
 * the names and identifiers in `meta`, never the data the event is about.
 */
export function makeRecord(chain, { name, source, event, meta = {}, at = new Date() }) {
  const time = at.toISOString().replace(/\.\d{3}Z$/, 'Z');
  // No prototype: a key is recorded whatever its name, "__proto__" included.
  const clean = Object.assign(Object.create(null), { event });
  for (const [k, v] of Object.entries(meta)) if (v !== undefined && v !== '' && k !== 'event') clean[k] = String(v);
  const body = JSON.stringify({ ...clean, at: time });
  const line = JSON.stringify({
    spec: 'deedlog/v0.1',
    chain: chain.name ?? name,
    seq: chain.entries.length,
    ...(chain.head ? { prev: 'sha256:' + chain.head } : {}),
    collected_at: time,
    source,
    subject: { media_type: 'application/json', size: utf8(body).length, digest: { sha256: sha256hex(body) } },
    meta: clean,
  });
  return { line, body };
}

/** The next record of a chain, as its line. */
export const nextRecord = (chain, opts) => makeRecord(chain, opts).line;

// ---- anchoring: a chain kept private, committed to through a public one ----
//
// The operator keeps its chain of records to itself. At a fixed interval it
// appends one record to a second, public chain: a commitment to the records
// added since the last one. A witness cosigns the public chain, and so learns
// only that time passes. Whoever is shown what a record is about, with its
// proof, can still check that it was committed to; whoever is given the whole
// chain can check that it is the one committed to (deedlog spec/anchoring.md).
//
// A leaf stands for one record without being its bytes: a record's line
// carries its place in the chain, and showing that to someone would tell them
// how many records came before.

const pow2 = (k) => {
  let s = 1;
  while (s < k) s *= 2;
  return s;
};
const u32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const LEAF = utf8('deedlog-anchor-leaf/v1\n');
const BLIND = utf8('deedlog-anchor-blind/v1\n');
const PAD = utf8('deedlog-anchor-pad/v1\n');

/** The leaf of a record: its blind, the digest of what it is about (its `subject`), and the digest of its line. */
export const anchorLeaf = (blind, subject, record) => sha256(concat(Uint8Array.of(0), LEAF, blind, subject, record));

/** The blind of the record at position `i` of an interval, from the interval's pad. */
export const anchorBlind = (pad, i) => sha256(concat(BLIND, pad, u32(i)));

/** The digest of what a record is about, as its line states it. */
function subjectOf(line) {
  const d = JSON.parse(line)?.subject?.digest?.sha256;
  if (typeof d !== 'string' || !/^[0-9a-f]{64}$/.test(d)) throw new Error('the record names no SHA-256 digest of its subject');
  return unhex(d);
}

/**
 * An interval's tree and commitment, from the lines of its records. `nonce`
 * and `pad` are hexadecimal, fresh for every interval. The tree is filled up
 * to a power of two, so that it does not tell how many records there were.
 */
export function anchor(lines, { chain, epoch, nonce, pad }) {
  for (const [what, v] of [['nonce', nonce], ['pad', pad]]) if (typeof v !== 'string' || !/^([0-9a-fA-F]{2})*$/.test(v)) throw new Error(`the ${what} is not hexadecimal`);
  const p = unhex(pad);
  const size = pow2(Math.max(1, lines.length));
  const leaves = lines.map((line, i) => anchorLeaf(anchorBlind(p, i), subjectOf(line), sha256(utf8(line))));
  for (let j = lines.length; j < size; j++) leaves.push(sha256(concat(Uint8Array.of(0), PAD, p, u32(j))));
  const root = merkleRoot(leaves);
  return { size, root, commit: anchorCommit({ chain, epoch, size, root, nonce }), leaves };
}

/** What the public record carries for an interval. `chain` is the name of the private chain. */
export const anchorCommit = ({ chain, epoch, size, root, nonce }) => sha256hex(`deedlog-anchor/v1\n${chain}\n${epoch}\n${size}\n${b64(root)}\n${nonce}\n`);

/** What is handed to someone who may see one record: where it sits in its interval, and what it takes to check that. */
export function recordProof(lines, i, { seq, epoch, nonce, pad }) {
  const made = anchor(lines, { chain: '', epoch, nonce, pad });
  return { seq, epoch, size: made.size, index: i, path: inclusionProof(made.leaves, i).map(b64), nonce, blind: hex(anchorBlind(unhex(pad), i)), record: sha256hex(lines[i]) };
}

/** The root a leaf leads to, given its place in a tree and the proof (RFC 9162, 2.1.3.2). */
export function rootFromInclusion(leaf, index, size, proof) {
  if (!Number.isInteger(index) || !Number.isInteger(size) || index < 0 || index >= size) throw new Error(`no leaf ${index} in a tree of ${size}`);
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) throw new Error('the inclusion proof is too long');
    if (fn % 2 === 1 || fn === sn) {
      r = node(p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else r = node(r, p);
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new Error('the inclusion proof is too short');
  return r;
}

/**
 * The commitment that what a record is about leads to. `body` is the bytes
 * the record's subject digest is of, as text; `at` is the proof:
 * `{ epoch, size, index, path, nonce, blind, record }`. The caller compares
 * the result with the public record of that interval.
 */
export function commitOf(body, chain, at) {
  for (const what of ['blind', 'record']) if (typeof at[what] !== 'string' || !/^[0-9a-fA-F]{64}$/.test(at[what])) throw new Error(`the ${what} is not 64 hexadecimal characters`);
  const leaf = anchorLeaf(unhex(at.blind), sha256(utf8(body)), unhex(at.record));
  const root = rootFromInclusion(leaf, at.index, at.size, at.path.map(unb64));
  return anchorCommit({ chain, epoch: at.epoch, size: at.size, root, nonce: at.nonce });
}
