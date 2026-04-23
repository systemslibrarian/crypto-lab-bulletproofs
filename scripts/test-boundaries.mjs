import { commit } from '../src/crypto/pedersen.ts';
import { randomScalar, addScalars, mulScalars } from '../src/crypto/scalar.ts';
import { proveRange, verifyRange } from '../src/proofs/range-proof.ts';
import { Transcript } from '../src/crypto/transcript.ts';
import {
  rangeProofByteLength,
  serializeRangeProof,
} from '../src/proofs/serialize.ts';

let failed = 0;
let passed = 0;
function ok(name, cond) {
  if (cond) {
    passed++;
    console.log(`PASS: ${name}`);
  } else {
    failed++;
    console.log(`FAIL: ${name}`);
    process.exitCode = 1;
  }
}

function proveAndVerify(value) {
  const r = randomScalar();
  const V = commit(value, r);
  const proof = proveRange(value, r, V, new Transcript('demo'));
  return verifyRange(proof, V, new Transcript('demo'));
}

// --- Boundary cases for the legal range [0, 2^64) ---
ok('boundary: v = 0 verifies', proveAndVerify(0n));
ok('boundary: v = 1 verifies', proveAndVerify(1n));
ok('boundary: v = 2^32 verifies', proveAndVerify(1n << 32n));
ok('boundary: v = 2^64 - 1 verifies', proveAndVerify((1n << 64n) - 1n));

// --- Out-of-range values: prover must refuse ---
for (const bad of [-1n, 1n << 64n, (1n << 64n) + 1n, (1n << 80n)]) {
  let threw = false;
  try {
    const r = randomScalar();
    const V = commit(bad, r);
    proveRange(bad, r, V, new Transcript('demo'));
  } catch {
    threw = true;
  }
  ok(`prover rejects v = ${bad.toString()}`, threw);
}

// --- Domain separation: verifier with mismatched transcript label rejects ---
{
  const v = 99n, r = randomScalar(), V = commit(v, r);
  const proof = proveRange(v, r, V, new Transcript('domain-A'));
  const accepted = verifyRange(proof, V, new Transcript('domain-B'));
  ok('mismatched transcript domain is rejected', accepted === false);
}

// --- Cross-commitment substitution: same proof against a different V ---
{
  const v = 7n, r = randomScalar(), V = commit(v, r);
  const proof = proveRange(v, r, V, new Transcript('demo'));
  const otherV = commit(v + 1n, r);
  ok('substituting a different commitment is rejected', !verifyRange(proof, otherV, new Transcript('demo')));
}

// --- Tampering with each scalar field is rejected ---
{
  const v = 12345n, r = randomScalar(), V = commit(v, r);
  const proof = proveRange(v, r, V, new Transcript('demo'));
  for (const field of ['t_hat', 'tau_x', 'mu']) {
    const tampered = { ...proof, [field]: addScalars(proof[field], 1n) };
    ok(`tampered ${field} is rejected`, !verifyRange(tampered, V, new Transcript('demo')));
  }
  // Tamper IPA scalars too
  const badIpaA = { ...proof, ipa_proof: { ...proof.ipa_proof, a: addScalars(proof.ipa_proof.a, 1n) } };
  ok('tampered IPA.a is rejected', !verifyRange(badIpaA, V, new Transcript('demo')));
  const badIpaB = { ...proof, ipa_proof: { ...proof.ipa_proof, b: mulScalars(proof.ipa_proof.b, 2n) } };
  ok('tampered IPA.b is rejected', !verifyRange(badIpaB, V, new Transcript('demo')));
}

// --- Serialization size is deterministic and matches reported length ---
{
  const v = 555n, r = randomScalar(), V = commit(v, r);
  const proof = proveRange(v, r, V, new Transcript('demo'));
  const bytes = serializeRangeProof(proof);
  ok('serialized length matches rangeProofByteLength', bytes.length === rangeProofByteLength(proof));
  // 4 points + 3 scalars + 12 IPA points (n=64 -> 6 rounds, 6*L+6*R) + 2 IPA scalars
  // = 4*32 + 3*32 + 12*32 + 2*32 = 672
  ok('serialized size for n=64 equals 672 bytes', bytes.length === 672);
}

console.log(`\n${passed} passed, ${failed} failed`);
