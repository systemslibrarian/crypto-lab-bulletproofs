import { commit } from '../src/crypto/pedersen.ts';
import { randomScalar, addScalars } from '../src/crypto/scalar.ts';
import { proveRange, verifyRange } from '../src/proofs/range-proof.ts';
import { verifyRangeBatched } from '../src/proofs/batch-verify.ts';
import { Transcript } from '../src/crypto/transcript.ts';

let failed = 0, passed = 0;
function ok(name, cond) {
  if (cond) { passed++; console.log(`PASS: ${name}`); }
  else { failed++; console.log(`FAIL: ${name}`); process.exitCode = 1; }
}

function fresh(v) {
  const r = randomScalar();
  const V = commit(v, r);
  const proof = proveRange(v, r, V, new Transcript('demo'));
  return { V, proof };
}

// Honest proofs accepted by both verifiers.
for (const v of [0n, 1n, 999n, (1n << 32n) + 7n, (1n << 64n) - 1n]) {
  const { V, proof } = fresh(v);
  const refOk = verifyRange(proof, V, new Transcript('demo'));
  const batchOk = verifyRangeBatched(proof, V, new Transcript('demo'));
  ok(`reference verifier accepts v=${v}`, refOk);
  ok(`batch verifier accepts v=${v}`, batchOk);
}

// Tampered proofs rejected by the batch verifier.
{
  const { V, proof } = fresh(123n);
  const tampered = { ...proof, t_hat: addScalars(proof.t_hat, 1n) };
  ok('batch verifier rejects tampered t_hat', !verifyRangeBatched(tampered, V, new Transcript('demo')));
}
{
  const { V, proof } = fresh(456n);
  const tampered = { ...proof, mu: addScalars(proof.mu, 1n) };
  ok('batch verifier rejects tampered mu', !verifyRangeBatched(tampered, V, new Transcript('demo')));
}
{
  const { V, proof } = fresh(789n);
  const tampered = {
    ...proof,
    ipa_proof: { ...proof.ipa_proof, a: addScalars(proof.ipa_proof.a, 1n) },
  };
  ok('batch verifier rejects tampered IPA.a', !verifyRangeBatched(tampered, V, new Transcript('demo')));
}
{
  const { V, proof } = fresh(2222n);
  const otherV = commit(2223n, randomScalar());
  ok('batch verifier rejects substituted commitment', !verifyRangeBatched(proof, otherV, new Transcript('demo')));
}

// Equivalence: both verifiers always agree on the same input.
for (let i = 0; i < 5; i++) {
  const v = BigInt(Math.floor(Math.random() * 100000));
  const { V, proof } = fresh(v);
  const a = verifyRange(proof, V, new Transcript('demo'));
  const b = verifyRangeBatched(proof, V, new Transcript('demo'));
  ok(`verifier equivalence iter ${i}`, a === b && a === true);
}

console.log(`\n${passed} passed, ${failed} failed`);
