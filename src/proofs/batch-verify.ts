/**
 * Batch verifier for the single-value range proof.
 *
 * The reference verifier in range-proof.ts is structured for clarity: it
 * builds intermediate points step-by-step and uses the IPA verifier as a
 * black box. This module implements the standard Bulletproofs optimization:
 * collapse the IPA verification into a single multi-scalar multiplication
 * and combine it with the polynomial-identity check using a fresh random
 * combiner c. Verification then reduces to checking that one accumulated
 * point equals the identity.
 *
 * Reference: Bünz et al. 2018, §6.2 ("Optimizations").
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
import type { RangeProof } from './range-proof';

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

function delta(z: bigint, y_pow: bigint[], two_pow: bigint[]): bigint {
  const z2 = mulScalars(z, z);
  const z3 = mulScalars(z2, z);
  const sumYn = y_pow.reduce((acc, v) => addScalars(acc, v), 0n);
  const sumTwoN = two_pow.reduce((acc, v) => addScalars(acc, v), 0n);
  const term1 = mulScalars(addScalars(z, negScalar(z2)), sumYn);
  const term2 = mulScalars(z3, sumTwoN);
  return addScalars(term1, negScalar(term2));
}

/**
 * Verify a single-value range proof using one combined multi-scalar
 * multiplication. Returns true iff the proof is valid.
 */
export function verifyRangeBatched(
  proof: RangeProof,
  V: RistrettoPointValue,
  transcript: Transcript
): boolean {
  const G_vec = generateGVec(N);
  const H_vec = generateHVec(N);
  const g = RISTRETTO_BASEPOINT;
  const h = getHGenerator();
  const u = getU();

  // Replay transcript to derive y, z, x and IPA challenges.
  transcript.appendPoint('V', V);
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

  const ipaChallenges: bigint[] = new Array(k);
  for (let j = 0; j < k; j++) {
    transcript.appendPoint(`L${j}`, proof.ipa_proof.L[j]);
    transcript.appendPoint(`R${j}`, proof.ipa_proof.R[j]);
    ipaChallenges[j] = transcript.challengeScalar(`x${j}`);
  }

  // Power vectors and IPA-derived s_i scalars.
  const y_pow = powerVector(y, N);
  const two_pow = powerVector(2n, N);
  const yInv = invScalar(y);
  const yInv_pow = powerVector(yInv, N);

  const xSq: bigint[] = new Array(k);
  const xInv: bigint[] = new Array(k);
  const xInvSq: bigint[] = new Array(k);
  for (let j = 0; j < k; j++) {
    xSq[j] = mulScalars(ipaChallenges[j], ipaChallenges[j]);
    xInv[j] = invScalar(ipaChallenges[j]);
    xInvSq[j] = invScalar(xSq[j]);
  }

  // s_i = product over rounds (matching the proveIPA bit indexing).
  const s: bigint[] = new Array(N);
  for (let i = 0; i < N; i++) {
    let si = 1n;
    for (let j = 0; j < k; j++) {
      const bit = (i >> (k - 1 - j)) & 1;
      si = mulScalars(si, bit === 1 ? ipaChallenges[j] : xInv[j]);
    }
    s[i] = si;
  }

  // Random linear combiner so a single accumulator covers both equations.
  // Using a transcript-independent fresh scalar prevents a malicious prover
  // from biasing toward a c that nulls out a tampered field.
  const c = randomScalar();

  // Equation (1) combined: c * (lhs - rhs) == 0
  //   c*t_hat*g + c*tau_x*h - c*z^2*V - c*delta*g - c*x*T1 - c*x^2*T2
  //
  // Equation (2) collapsed via standard IPA reduction:
  //   sum_i (a*s_i) * G_i  +  sum_i (b*y^{-i}*s_{n-1-i}) * H_i  +  a*b*u
  //   - A - x*S - sum_i (-z) * G_i
  //   - sum_i (z*y^i + z^2*2^i) * y^{-i} * H_i  +  mu*h - t_hat*u
  //   - sum_j (x_j^2 * L_j + x_j^{-2} * R_j) == 0
  //
  // We aggregate every term into a single sum of (scalar, point) pairs and
  // require the result to be the identity.

  const a = proof.ipa_proof.a;
  const b = proof.ipa_proof.b;
  const negC = negScalar(c);

  // s reversed for b·y^{-i}·s_{n-1-i}.
  const sRev: bigint[] = new Array(N);
  for (let i = 0; i < N; i++) sRev[i] = s[N - 1 - i];

  // Scalar coefficients per generator.
  const gScalar = addScalars(
    mulScalars(c, proof.t_hat),
    mulScalars(negC, delta(z, y_pow, two_pow))
  );
  const hScalar = addScalars(mulScalars(c, proof.tau_x), proof.mu);
  const uScalar = addScalars(mulScalars(a, b), negScalar(proof.t_hat));

  // Build the MSM.
  let acc = scalarMult(gScalar, g);
  acc = addPoints(acc, scalarMult(hScalar, h));
  acc = addPoints(acc, scalarMult(uScalar, u));
  acc = addPoints(acc, scalarMult(mulScalars(negC, z2), V));
  acc = addPoints(acc, scalarMult(mulScalars(negC, x), proof.T1));
  acc = addPoints(acc, scalarMult(mulScalars(negC, xx), proof.T2));
  acc = addPoints(acc, scalarMult(negScalar(1n), proof.A));
  acc = addPoints(acc, scalarMult(negScalar(x), proof.S));

  for (let i = 0; i < N; i++) {
    // G_i scalar: a*s_i + z   (since the verifier has -<-z, G> = +<z, G>
    // moved to the same side of the equation as the rest.)
    const gi = addScalars(mulScalars(a, s[i]), z);
    acc = addPoints(acc, scalarMult(gi, G_vec[i]));

    // H_i scalar: y^{-i} * (b*s_{n-1-i} - z*y^i - z^2*2^i)
    //          = b*y^{-i}*s_{n-1-i} - z - z^2 * 2^i * y^{-i}
    const hi_term = addScalars(
      mulScalars(b, mulScalars(yInv_pow[i], sRev[i])),
      negScalar(z)
    );
    const hi = addScalars(
      hi_term,
      negScalar(mulScalars(z2, mulScalars(two_pow[i], yInv_pow[i])))
    );
    acc = addPoints(acc, scalarMult(hi, H_vec[i]));
  }

  for (let j = 0; j < k; j++) {
    acc = addPoints(acc, scalarMult(negScalar(xSq[j]), proof.ipa_proof.L[j]));
    acc = addPoints(acc, scalarMult(negScalar(xInvSq[j]), proof.ipa_proof.R[j]));
  }

  // The accumulator should equal the identity iff the proof is valid.
  return acc.equals(RistrettoPoint.ZERO);
}
