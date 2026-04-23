import { commit } from '../src/crypto/pedersen.ts';
import { randomScalar, addScalars, setDeterministicRng, clearDeterministicRng } from '../src/crypto/scalar.ts';
import { proveTrueAggregate, verifyTrueAggregate } from '../src/proofs/true-aggregate.ts';
import { verifyTrueAggregateBatched } from '../src/proofs/aggregate-batch-verify.ts';
import { Transcript } from '../src/crypto/transcript.ts';
import { proveRange } from '../src/proofs/range-proof.ts';
import { serializeRangeProof } from '../src/proofs/serialize.ts';

let failed = 0, passed = 0;
function ok(name, cond) {
  if (cond) { passed++; console.log(`PASS: ${name}`); }
  else { failed++; console.log(`FAIL: ${name}`); process.exitCode = 1; }
}

// Aggregate batch verifier: honest acceptance for several m.
for (const m of [1, 2, 4, 8]) {
  const values = Array.from({ length: m }, (_, i) => BigInt(i * 13 + 1));
  const blinders = values.map(() => randomScalar());
  const V = values.map((v, i) => commit(v, blinders[i]));
  const proof = proveTrueAggregate(values, blinders, V, new Transcript('agg'));
  const ref = verifyTrueAggregate(proof, V, new Transcript('agg'));
  const batched = verifyTrueAggregateBatched(proof, V, new Transcript('agg'));
  ok(`reference agg verifier accepts m=${m}`, ref);
  ok(`batched agg verifier accepts m=${m}`, batched);
}

// Tampering rejected by the batched aggregate verifier.
{
  const values = [10n, 20n, 30n, 40n];
  const blinders = values.map(() => randomScalar());
  const V = values.map((v, i) => commit(v, blinders[i]));
  const proof = proveTrueAggregate(values, blinders, V, new Transcript('agg'));
  const tampered = { ...proof, t_hat: addScalars(proof.t_hat, 1n) };
  ok('batched agg verifier rejects tampered t_hat',
    !verifyTrueAggregateBatched(tampered, V, new Transcript('agg')));
  const swapped = [...V];
  [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
  ok('batched agg verifier rejects swapped commitments',
    !verifyTrueAggregateBatched(proof, swapped, new Transcript('agg')));
}

// Deterministic seed: same seed -> identical proof bytes.
{
  setDeterministicRng('demo:seed:42');
  const v = 4242n;
  const r = randomScalar();
  const V = commit(v, r);
  const p1 = proveRange(v, r, V, new Transcript('det-demo'));
  const b1 = serializeRangeProof(p1);

  setDeterministicRng('demo:seed:42');
  const r2 = randomScalar();
  const V2 = commit(v, r2);
  const p2 = proveRange(v, r2, V2, new Transcript('det-demo'));
  const b2 = serializeRangeProof(p2);
  clearDeterministicRng();

  let same = b1.length === b2.length;
  for (let i = 0; same && i < b1.length; i++) same = b1[i] === b2[i];
  ok('deterministic seed produces identical proof bytes', same);
}

// Different seed -> different proof bytes.
{
  setDeterministicRng('seed:A');
  const v = 7n;
  const r1 = randomScalar();
  const V1 = commit(v, r1);
  const p1 = proveRange(v, r1, V1, new Transcript('d'));
  const b1 = serializeRangeProof(p1);

  setDeterministicRng('seed:B');
  const r2 = randomScalar();
  const V2 = commit(v, r2);
  const p2 = proveRange(v, r2, V2, new Transcript('d'));
  const b2 = serializeRangeProof(p2);
  clearDeterministicRng();

  let different = false;
  for (let i = 0; i < b1.length; i++) if (b1[i] !== b2[i]) { different = true; break; }
  ok('different seeds produce different proof bytes', different);
}

console.log(`\n${passed} passed, ${failed} failed`);
