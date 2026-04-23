import { hashToRistretto, generateGVec, generateHVec, innerProductPoints, addPoints, scalarMult } from '../src/crypto/ristretto.ts';
import { randomScalar, mulScalars, addScalars } from '../src/crypto/scalar.ts';
import { proveIPA, verifyIPA } from '../src/proofs/inner-product.ts';
import { Transcript } from '../src/crypto/transcript.ts';

const u = hashToRistretto('test:u');
for (const n of [2, 4, 8, 16, 32]) {
  const G = generateGVec(n);
  const H = generateHVec(n);
  const a = Array.from({ length: n }, () => randomScalar());
  const b = Array.from({ length: n }, () => randomScalar());
  let c = 0n;
  for (let i = 0; i < n; i++) c = addScalars(c, mulScalars(a[i], b[i]));
  const P = addPoints(addPoints(innerProductPoints(a, G), innerProductPoints(b, H)), scalarMult(c, u));
  const tp = new Transcript('ipa-test');
  let proof, ok;
  try { proof = proveIPA(a, b, u, G, H, P, tp); } catch (e) { console.log('PROVE_ERR n=', n, e.message); continue; }
  const tv = new Transcript('ipa-test');
  try { ok = verifyIPA(proof, P, u, G, H, tv); } catch (e) { console.log('VERIFY_THROW n=', n, e.message); continue; }
  console.log('n=', n, 'verify=', ok);
}
