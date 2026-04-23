import { commit } from '../src/crypto/pedersen.ts';
import { randomScalar, addScalars } from '../src/crypto/scalar.ts';
import {
  proveTrueAggregate,
  verifyTrueAggregate,
  trueAggregateByteLength,
} from '../src/proofs/true-aggregate.ts';
import { Transcript } from '../src/crypto/transcript.ts';

let failed = 0;
let passed = 0;
function ok(name, cond) {
  if (cond) { passed++; console.log(`PASS: ${name}`); }
  else { failed++; console.log(`FAIL: ${name}`); process.exitCode = 1; }
}

function setup(values) {
  const blinders = values.map(() => randomScalar());
  const V = values.map((v, i) => commit(v, blinders[i]));
  return { values, blinders, V };
}

// Honest verify across power-of-two batch sizes.
for (const m of [1, 2, 4, 8]) {
  const values = Array.from({ length: m }, (_, i) => BigInt(i + 1) * 100n);
  const { blinders, V } = setup(values);
  const proof = proveTrueAggregate(values, blinders, V, new Transcript('agg'));
  const ok1 = verifyTrueAggregate(proof, V, new Transcript('agg'));
  ok(`true-aggregate m=${m} verifies`, ok1);
}

// Boundary values.
{
  const values = [0n, 1n, (1n << 64n) - 1n, 1n << 32n];
  const { blinders, V } = setup(values);
  const proof = proveTrueAggregate(values, blinders, V, new Transcript('agg'));
  ok('true-aggregate boundary mix verifies', verifyTrueAggregate(proof, V, new Transcript('agg')));
}

// Out-of-range value: prover refuses.
{
  const values = [10n, 1n << 64n];
  const blinders = values.map(() => randomScalar());
  const V = values.map((v, i) => commit(v, blinders[i]));
  let threw = false;
  try { proveTrueAggregate(values, blinders, V, new Transcript('agg')); } catch { threw = true; }
  ok('true-aggregate prover refuses out-of-range value', threw);
}

// Non-power-of-two m: prover refuses.
{
  const values = [10n, 20n, 30n];
  const blinders = values.map(() => randomScalar());
  const V = values.map((v, i) => commit(v, blinders[i]));
  let threw = false;
  try { proveTrueAggregate(values, blinders, V, new Transcript('agg')); } catch { threw = true; }
  ok('true-aggregate prover refuses non-power-of-two m', threw);
}

// Wrong commitment (substitute one V_j) is rejected.
{
  const values = [10n, 20n];
  const { blinders, V } = setup(values);
  const proof = proveTrueAggregate(values, blinders, V, new Transcript('agg'));
  const wrongV = [...V];
  wrongV[1] = commit(21n, blinders[1]);
  ok('true-aggregate rejects substituted commitment', !verifyTrueAggregate(proof, wrongV, new Transcript('agg')));
}

// Tampering with t_hat is rejected.
{
  const values = [5n, 6n, 7n, 8n];
  const { blinders, V } = setup(values);
  const proof = proveTrueAggregate(values, blinders, V, new Transcript('agg'));
  const tampered = { ...proof, t_hat: addScalars(proof.t_hat, 1n) };
  ok('true-aggregate rejects tampered t_hat', !verifyTrueAggregate(tampered, V, new Transcript('agg')));
}

// Size: log-size advantage. For m=8 (512-bit IPA), 9 IPA rounds.
//   bytes = 4*32 + 3*32 + (9+9)*32 + 2*32 = 128 + 96 + 576 + 64 = 864
// versus batched 8 single proofs = 8 * 672 = 5376.
{
  const values = Array.from({ length: 8 }, () => 42n);
  const { blinders, V } = setup(values);
  const proof = proveTrueAggregate(values, blinders, V, new Transcript('agg'));
  const bytes = trueAggregateByteLength(proof);
  ok('true-aggregate m=8 size is 864 bytes', bytes === 864);
}

console.log(`\n${passed} passed, ${failed} failed`);
