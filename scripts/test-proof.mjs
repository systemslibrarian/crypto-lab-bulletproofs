import { commit } from '../src/crypto/pedersen.ts';
import { randomScalar } from '../src/crypto/scalar.ts';
import { proveRange, verifyRange } from '../src/proofs/range-proof.ts';
import { Transcript } from '../src/crypto/transcript.ts';

async function run() {
  const v = 12345n;
  const r = randomScalar();
  const V = commit(v, r);
  const t1 = new Transcript('bulletproofs-demo');
  let proof;
  try {
    proof = proveRange(v, r, V, t1);
  } catch (e) {
    console.log('PROVE_ERR:', e.message);
    process.exit(2);
  }
  const t2 = new Transcript('bulletproofs-demo');
  try {
    const ok = verifyRange(proof, V, t2);
    console.log('VERIFY:', ok);
    process.exit(ok ? 0 : 1);
  } catch (e) {
    console.log('VERIFY_THROW:', e.message);
    process.exit(3);
  }
}
run();
