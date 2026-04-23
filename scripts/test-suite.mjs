import { commit } from '../src/crypto/pedersen.ts';
import { randomScalar, addScalars } from '../src/crypto/scalar.ts';
import { proveRange, verifyRange } from '../src/proofs/range-proof.ts';
import { proveAggregateRange, verifyAggregateRange } from '../src/proofs/aggregate-range.ts';
import { Transcript } from '../src/crypto/transcript.ts';

function ok(name, cond) {
  console.log(`${cond ? 'PASS' : 'FAIL'}: ${name}`);
  if (!cond) process.exitCode = 1;
}

// 1) Honest verify
{
  const v = 42n, r = randomScalar(), V = commit(v, r);
  const proof = proveRange(v, r, V, new Transcript('demo'));
  ok('honest range proof verifies', verifyRange(proof, V, new Transcript('demo')));
}

// 2) Tampering: alter t_hat
{
  const v = 1234n, r = randomScalar(), V = commit(v, r);
  const proof = proveRange(v, r, V, new Transcript('demo'));
  const tampered = { ...proof, t_hat: addScalars(proof.t_hat, 1n) };
  ok('tampered t_hat is rejected', !verifyRange(tampered, V, new Transcript('demo')));
}

// 3) Wrong commitment: verify against a different V should fail
{
  const v = 7n, r = randomScalar(), V = commit(v, r);
  const proof = proveRange(v, r, V, new Transcript('demo'));
  const wrongV = commit(8n, r);
  ok('wrong commitment is rejected', !verifyRange(proof, wrongV, new Transcript('demo')));
}

// 4) Out-of-range cheat: prover refuses to construct an out-of-range proof
{
  const cheatV = commit(1n << 64n, randomScalar());
  let threw = false;
  try { proveRange(1n << 64n, 1n, cheatV, new Transcript('demo')); }
  catch { threw = true; }
  ok('proveRange refuses v >= 2^64', threw);
}

// 5) Aggregate
{
  const m = 3;
  const values = [10n, 20n, 30n];
  const blinders = values.map(() => randomScalar());
  const commits = values.map((v, i) => commit(v, blinders[i]));
  const proof = proveAggregateRange(values, blinders, commits, new Transcript('agg'));
  ok('aggregate verifies', verifyAggregateRange(proof, commits, new Transcript('agg')));
  // Tamper one inner proof's t_hat
  const tamperedProofs = proof.proofs.slice();
  tamperedProofs[1] = { ...tamperedProofs[1], t_hat: addScalars(tamperedProofs[1].t_hat, 1n) };
  const bad = { ...proof, proofs: tamperedProofs };
  ok('aggregate tampering is rejected', !verifyAggregateRange(bad, commits, new Transcript('agg')));
}
