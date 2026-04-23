/**
 * Single-MSM batch verifier for true aggregated Bulletproofs.
 *
 * Mirrors batch-verify.ts (single-value) but for the aggregated proof: one
 * accumulated point check covers both the polynomial-identity equation and
 * the IPA collapse, with vectors of dimension n*m.
 */

import {
  generateGVec,
  generateHVec,
  addPoints,
  scalarMult,
  RISTRETTO_BASEPOINT,
  hashToRistretto,
  type RistrettoPointValue,
} from '../crypto/ristretto';
import { RistrettoPoint } from '@noble/curves/ed25519';
import { getHGenerator } from '../crypto/pedersen';
import {
  addScalars,
  mulScalars,
  negScalar,
  invScalar,
  randomScalar,
} from '../crypto/scalar';
import { Transcript } from '../crypto/transcript';
import type { TrueAggregateProof } from './true-aggregate';

const N = 64;

function getU(): RistrettoPointValue {
  return hashToRistretto('bulletproofs:u');
}

function powerVector(base: bigint, n: number): bigint[] {
  const out: bigint[] = new Array(n);
  let acc = 1n;
  for (let i = 0; i < n; i++) {
    out[i] = acc;
    acc = mulScalars(acc, base);
  }
  return out;
}

function isPowerOfTwo(n: number): boolean {
  return n > 0 && (n & (n - 1)) === 0;
}

function deltaAggregate(z: bigint, y_pow_nm: bigint[], two_pow_n: bigint[], m: number): bigint {
  const z2 = mulScalars(z, z);
  const sumYnm = y_pow_nm.reduce((acc, v) => addScalars(acc, v), 0n);
  const sumTwoN = two_pow_n.reduce((acc, v) => addScalars(acc, v), 0n);
  const term1 = mulScalars(addScalars(z, negScalar(z2)), sumYnm);
  let zPow = mulScalars(z2, z);
  let term2 = 0n;
  for (let j = 0; j < m; j++) {
    term2 = addScalars(term2, mulScalars(zPow, sumTwoN));
    zPow = mulScalars(zPow, z);
  }
  return addScalars(term1, negScalar(term2));
}

export function verifyTrueAggregateBatched(
  proof: TrueAggregateProof,
  V: RistrettoPointValue[],
  transcript: Transcript
): boolean {
  const m = proof.m;
  if (V.length !== m) return false;
  if (!isPowerOfTwo(m)) return false;

  const nm = N * m;
  const G_vec = generateGVec(nm);
  const H_vec = generateHVec(nm);
  const g = RISTRETTO_BASEPOINT;
  const h = getHGenerator();
  const u = getU();

  // Replay transcript.
  transcript.appendLabel('aggregate-bulletproof');
  transcript.appendScalar('m', BigInt(m));
  transcript.appendScalar('n', BigInt(N));
  for (let j = 0; j < m; j++) transcript.appendPoint(`V${j}`, V[j]);

  transcript.appendPoint('A', proof.A);
  transcript.appendPoint('S', proof.S);
  const y = transcript.challengeScalar('y');
  const z = transcript.challengeScalar('z');

  transcript.appendPoint('T1', proof.T1);
  transcript.appendPoint('T2', proof.T2);
  const x = transcript.challengeScalar('x');
  const xx = mulScalars(x, x);
  const z2 = mulScalars(z, z);

  transcript.appendScalar('t_hat', proof.t_hat);
  transcript.appendScalar('tau_x', proof.tau_x);
  transcript.appendScalar('mu', proof.mu);

  const k = proof.ipa_proof.L.length;
  if (proof.ipa_proof.R.length !== k) return false;
  if ((1 << k) !== nm) return false;

  const ipaChallenges: bigint[] = new Array(k);
  for (let j = 0; j < k; j++) {
    transcript.appendPoint(`L${j}`, proof.ipa_proof.L[j]);
    transcript.appendPoint(`R${j}`, proof.ipa_proof.R[j]);
    ipaChallenges[j] = transcript.challengeScalar(`x${j}`);
  }

  const y_pow = powerVector(y, nm);
  const two_pow_n = powerVector(2n, N);
  const yInv = invScalar(y);
  const yInv_pow = powerVector(yInv, nm);

  const xSq: bigint[] = new Array(k);
  const xInv: bigint[] = new Array(k);
  const xInvSq: bigint[] = new Array(k);
  for (let j = 0; j < k; j++) {
    xSq[j] = mulScalars(ipaChallenges[j], ipaChallenges[j]);
    xInv[j] = invScalar(ipaChallenges[j]);
    xInvSq[j] = invScalar(xSq[j]);
  }

  // s_i for nm-dimensional folding.
  const s: bigint[] = new Array(nm);
  for (let i = 0; i < nm; i++) {
    let si = 1n;
    for (let j = 0; j < k; j++) {
      const bit = (i >> (k - 1 - j)) & 1;
      si = mulScalars(si, bit === 1 ? ipaChallenges[j] : xInv[j]);
    }
    s[i] = si;
  }
  const sRev: bigint[] = new Array(nm);
  for (let i = 0; i < nm; i++) sRev[i] = s[nm - 1 - i];

  // z^{j+2} table.
  const zPows: bigint[] = new Array(m);
  let zCur = mulScalars(z, z);
  for (let j = 0; j < m; j++) {
    zPows[j] = zCur;
    zCur = mulScalars(zCur, z);
  }

  const c = randomScalar();
  const negC = negScalar(c);
  const a = proof.ipa_proof.a;
  const b = proof.ipa_proof.b;

  const gScalar = addScalars(
    mulScalars(c, proof.t_hat),
    mulScalars(negC, deltaAggregate(z, y_pow, two_pow_n, m))
  );
  const hScalar = addScalars(mulScalars(c, proof.tau_x), proof.mu);
  const uScalar = addScalars(mulScalars(a, b), negScalar(proof.t_hat));

  let acc = scalarMult(gScalar, g);
  acc = addPoints(acc, scalarMult(hScalar, h));
  acc = addPoints(acc, scalarMult(uScalar, u));

  for (let j = 0; j < m; j++) {
    acc = addPoints(acc, scalarMult(mulScalars(negC, zPows[j]), V[j]));
  }
  acc = addPoints(acc, scalarMult(mulScalars(negC, x), proof.T1));
  acc = addPoints(acc, scalarMult(mulScalars(negC, xx), proof.T2));
  acc = addPoints(acc, scalarMult(negScalar(1n), proof.A));
  acc = addPoints(acc, scalarMult(negScalar(x), proof.S));

  for (let j = 0; j < m; j++) {
    for (let i = 0; i < N; i++) {
      const idx = j * N + i;
      // G_idx scalar: a*s_idx + z
      const gi = addScalars(mulScalars(a, s[idx]), z);
      acc = addPoints(acc, scalarMult(gi, G_vec[idx]));

      // H_idx scalar: b*y^{-idx}*sRev_idx - z - z^{j+2} * 2^i * y^{-idx}
      const hi_main = mulScalars(b, mulScalars(yInv_pow[idx], sRev[idx]));
      const hi_extra = negScalar(mulScalars(zPows[j], mulScalars(two_pow_n[i], yInv_pow[idx])));
      const hi = addScalars(addScalars(hi_main, negScalar(z)), hi_extra);
      acc = addPoints(acc, scalarMult(hi, H_vec[idx]));
    }
  }

  for (let j = 0; j < k; j++) {
    acc = addPoints(acc, scalarMult(negScalar(xSq[j]), proof.ipa_proof.L[j]));
    acc = addPoints(acc, scalarMult(negScalar(xInvSq[j]), proof.ipa_proof.R[j]));
  }

  return acc.equals(RistrettoPoint.ZERO);
}
