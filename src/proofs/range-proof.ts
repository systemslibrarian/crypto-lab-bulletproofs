/**
 * Single-value 64-bit range proof for Bulletproofs.
 *
 * Proves that a Pedersen-committed value v lies in [0, 2^64).
 * Protocol: Bünz et al. 2018, Protocol 2 ("Inner Product Range Proof"),
 * with the basis change H'_i = y^{-i} * H_i so the inner-product argument
 * is run in basis (G, H').
 */

import {
  generateGVec,
  generateHVec,
  addPoints,
  scalarMult,
  innerProductPoints,
  RISTRETTO_BASEPOINT,
  hashToRistretto,
  type RistrettoPointValue,
} from '../crypto/ristretto';
import { getHGenerator } from '../crypto/pedersen';
import {
  reduceScalar,
  addScalars,
  mulScalars,
  negScalar,
  invScalar,
  randomScalar,
} from '../crypto/scalar';
import { Transcript } from '../crypto/transcript';
import { proveIPA, verifyIPA, type IPAProof } from './inner-product';

const N = 64;

/**
 * Range proof for a single value.
 */
export interface RangeProof {
  A: RistrettoPointValue;
  S: RistrettoPointValue;
  T1: RistrettoPointValue;
  T2: RistrettoPointValue;
  tau_x: bigint;
  mu: bigint;
  t_hat: bigint;
  ipa_proof: IPAProof;
  /** Fiat-Shamir challenges, kept for UI introspection only. Not part of the proof. */
  challenges?: { y: bigint; z: bigint; x: bigint };
}

/** Independent generator for the IPA inner-product term. Distinct from g, h. */
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

function innerProduct(a: bigint[], b: bigint[]): bigint {
  let acc = 0n;
  for (let i = 0; i < a.length; i++) {
    acc = addScalars(acc, mulScalars(a[i], b[i]));
  }
  return acc;
}

/**
 * delta(y, z) = (z - z^2) * <1^n, y^n>  -  z^3 * <1^n, 2^n>
 */
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
 * Generate a 64-bit range proof for a committed value V = v*g + r*h.
 */
export function proveRange(
  value: bigint,
  blinder: bigint,
  V: RistrettoPointValue,
  transcript: Transcript
): RangeProof {
  if (value < 0n || value >= 1n << 64n) {
    throw new Error('Value must be in [0, 2^64)');
  }

  const v = reduceScalar(value);
  const gamma = reduceScalar(blinder);

  const G_vec = generateGVec(N);
  const H_vec = generateHVec(N);
  const g = RISTRETTO_BASEPOINT;
  const h = getHGenerator();

  // Bind V to the transcript so challenges depend on the statement.
  transcript.appendPoint('V', V);

  // a_L : bit decomposition of v, a_R = a_L - 1^N
  const a_L: bigint[] = new Array(N);
  const a_R: bigint[] = new Array(N);
  let tmp = v;
  for (let i = 0; i < N; i++) {
    const bit = tmp & 1n;
    a_L[i] = bit;
    a_R[i] = addScalars(bit, negScalar(1n));
    tmp >>= 1n;
  }

  // A = alpha*h + <a_L, G> + <a_R, H>
  const alpha = randomScalar();
  const A = addPoints(
    addPoints(scalarMult(alpha, h), innerProductPoints(a_L, G_vec)),
    innerProductPoints(a_R, H_vec)
  );

  // S = rho*h + <s_L, G> + <s_R, H>, with s_L, s_R uniformly random.
  const s_L = Array.from({ length: N }, () => randomScalar());
  const s_R = Array.from({ length: N }, () => randomScalar());
  const rho = randomScalar();
  const S = addPoints(
    addPoints(scalarMult(rho, h), innerProductPoints(s_L, G_vec)),
    innerProductPoints(s_R, H_vec)
  );

  transcript.appendPoint('A', A);
  transcript.appendPoint('S', S);
  const y = transcript.challengeScalar('y');
  const z = transcript.challengeScalar('z');

  const y_pow = powerVector(y, N);
  const two_pow = powerVector(2n, N);
  const z2 = mulScalars(z, z);

  // l(X) = (a_L - z*1^N) + s_L * X
  // r(X) = y^N ∘ (a_R + z*1^N + s_R * X) + z^2 * 2^N
  const l0: bigint[] = new Array(N);
  const l1: bigint[] = new Array(N);
  const r0: bigint[] = new Array(N);
  const r1: bigint[] = new Array(N);
  for (let i = 0; i < N; i++) {
    l0[i] = addScalars(a_L[i], negScalar(z));
    l1[i] = s_L[i];
    const aRplusZ = addScalars(a_R[i], z);
    r0[i] = addScalars(mulScalars(y_pow[i], aRplusZ), mulScalars(z2, two_pow[i]));
    r1[i] = mulScalars(y_pow[i], s_R[i]);
  }

  const t0 = innerProduct(l0, r0);
  const t1 = addScalars(innerProduct(l0, r1), innerProduct(l1, r0));
  const t2 = innerProduct(l1, r1);

  const tau1 = randomScalar();
  const tau2 = randomScalar();
  const T1 = addPoints(scalarMult(t1, g), scalarMult(tau1, h));
  const T2 = addPoints(scalarMult(t2, g), scalarMult(tau2, h));

  transcript.appendPoint('T1', T1);
  transcript.appendPoint('T2', T2);
  const x = transcript.challengeScalar('x');
  const xx = mulScalars(x, x);

  const l: bigint[] = new Array(N);
  const r_vec: bigint[] = new Array(N);
  for (let i = 0; i < N; i++) {
    l[i] = addScalars(l0[i], mulScalars(l1[i], x));
    r_vec[i] = addScalars(r0[i], mulScalars(r1[i], x));
  }

  const t_hat = addScalars(t0, addScalars(mulScalars(t1, x), mulScalars(t2, xx)));
  const tau_x = addScalars(
    addScalars(mulScalars(tau1, x), mulScalars(tau2, xx)),
    mulScalars(z2, gamma)
  );
  const mu = addScalars(alpha, mulScalars(rho, x));

  transcript.appendScalar('t_hat', t_hat);
  transcript.appendScalar('tau_x', tau_x);
  transcript.appendScalar('mu', mu);

  // Run IPA in basis (G, H') with H'_i = y^{-i} * H_i.
  const yInv = invScalar(y);
  const yInv_pow = powerVector(yInv, N);
  const H_prime: RistrettoPointValue[] = new Array(N);
  for (let i = 0; i < N; i++) {
    H_prime[i] = scalarMult(yInv_pow[i], H_vec[i]);
  }

  const u = getU();
  // P' = <l, G> + <r, H'> + <l,r> * u
  const Pprime = addPoints(
    addPoints(innerProductPoints(l, G_vec), innerProductPoints(r_vec, H_prime)),
    scalarMult(t_hat, u)
  );

  const ipa_proof = proveIPA(l, r_vec, u, G_vec, H_prime, Pprime, transcript);

  return { A, S, T1, T2, tau_x, mu, t_hat, ipa_proof, challenges: { y, z, x } };
}

/**
 * Verify a 64-bit range proof.
 */
export function verifyRange(
  proof: RangeProof,
  V: RistrettoPointValue,
  transcript: Transcript
): boolean {
  const G_vec = generateGVec(N);
  const H_vec = generateHVec(N);
  const g = RISTRETTO_BASEPOINT;
  const h = getHGenerator();

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

  const y_pow = powerVector(y, N);
  const two_pow = powerVector(2n, N);

  // (1) t_hat * g + tau_x * h ?= z^2 * V + delta(y,z) * g + x * T1 + x^2 * T2
  const lhs = addPoints(scalarMult(proof.t_hat, g), scalarMult(proof.tau_x, h));
  const d = delta(z, y_pow, two_pow);
  const rhs = addPoints(
    addPoints(scalarMult(z2, V), scalarMult(d, g)),
    addPoints(scalarMult(x, proof.T1), scalarMult(xx, proof.T2))
  );
  if (!lhs.equals(rhs)) return false;

  // (2) Reconstruct P' for the IPA in basis (G, H'), H'_i = y^{-i} * H_i.
  //   P' = A + x*S + <-z * 1^N, G> + <z*y^N + z^2*2^N, H'> - mu*h + t_hat*u
  const yInv = invScalar(y);
  const yInv_pow = powerVector(yInv, N);
  const H_prime: RistrettoPointValue[] = new Array(N);
  for (let i = 0; i < N; i++) {
    H_prime[i] = scalarMult(yInv_pow[i], H_vec[i]);
  }

  const negZ = negScalar(z);
  const negZVec: bigint[] = new Array(N).fill(negZ);
  const rCoeffs: bigint[] = new Array(N);
  for (let i = 0; i < N; i++) {
    rCoeffs[i] = addScalars(mulScalars(z, y_pow[i]), mulScalars(z2, two_pow[i]));
  }

  const u = getU();
  let Pprime = addPoints(proof.A, scalarMult(x, proof.S));
  Pprime = addPoints(Pprime, innerProductPoints(negZVec, G_vec));
  Pprime = addPoints(Pprime, innerProductPoints(rCoeffs, H_prime));
  Pprime = addPoints(Pprime, scalarMult(negScalar(proof.mu), h));
  Pprime = addPoints(Pprime, scalarMult(proof.t_hat, u));

  return verifyIPA(proof.ipa_proof, Pprime, u, G_vec, H_prime, transcript);
}
