/**
 * True aggregated Bulletproof for m values, each in [0, 2^n).
 *
 * Protocol: Bünz et al. 2018, §4.3 ("Aggregating Logarithmic Proofs").
 * Produces a SINGLE proof of size (2*ceil(log2(n*m)) + 9) * 32 bytes,
 * not m independent proofs.
 *
 * Prover proves knowledge of v_1..v_m in [0, 2^n) and gamma_1..gamma_m
 * such that V_j = v_j * g + gamma_j * h, by reducing to one inner-product
 * argument of dimension n*m.
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

/** Bits per value. Matches the single-value range proof. */
const N = 64;

/** True aggregated range proof for m values. */
export interface TrueAggregateProof {
  m: number;
  A: RistrettoPointValue;
  S: RistrettoPointValue;
  T1: RistrettoPointValue;
  T2: RistrettoPointValue;
  tau_x: bigint;
  mu: bigint;
  t_hat: bigint;
  ipa_proof: IPAProof;
  challenges?: { y: bigint; z: bigint; x: bigint };
}

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

function isPowerOfTwo(n: number): boolean {
  return n > 0 && (n & (n - 1)) === 0;
}

/**
 * delta(y, z) = (z - z^2) * <1^{nm}, y^{nm}>  -  sum_{j=1..m} z^{j+2} * <1^n, 2^n>
 */
function deltaAggregate(z: bigint, y_pow_nm: bigint[], two_pow_n: bigint[], m: number): bigint {
  const z2 = mulScalars(z, z);
  const sumYnm = y_pow_nm.reduce((acc, v) => addScalars(acc, v), 0n);
  const sumTwoN = two_pow_n.reduce((acc, v) => addScalars(acc, v), 0n);
  const term1 = mulScalars(addScalars(z, negScalar(z2)), sumYnm);

  let zPow = mulScalars(z2, z); // z^3
  let term2 = 0n;
  for (let j = 0; j < m; j++) {
    term2 = addScalars(term2, mulScalars(zPow, sumTwoN));
    zPow = mulScalars(zPow, z);
  }
  return addScalars(term1, negScalar(term2));
}

/**
 * Generate a true aggregated range proof for m values, each in [0, 2^64).
 * m must be a power of two so the IPA dimension n*m is also a power of two.
 */
export function proveTrueAggregate(
  values: bigint[],
  blinders: bigint[],
  V: RistrettoPointValue[],
  transcript: Transcript
): TrueAggregateProof {
  const m = values.length;
  if (m === 0) throw new Error('At least one value required');
  if (blinders.length !== m || V.length !== m) {
    throw new Error('values, blinders, and commitments must have equal length');
  }
  if (!isPowerOfTwo(m)) {
    throw new Error('m must be a power of two for the aggregated IPA');
  }
  for (const v of values) {
    if (v < 0n || v >= 1n << BigInt(N)) {
      throw new Error('Each value must be in [0, 2^64)');
    }
  }

  const nm = N * m;
  const G_vec = generateGVec(nm);
  const H_vec = generateHVec(nm);
  const g = RISTRETTO_BASEPOINT;
  const h = getHGenerator();

  // Bind aggregation parameters and statements to the transcript.
  transcript.appendLabel('aggregate-bulletproof');
  transcript.appendScalar('m', BigInt(m));
  transcript.appendScalar('n', BigInt(N));
  for (let j = 0; j < m; j++) {
    transcript.appendPoint(`V${j}`, V[j]);
  }

  // a_L is concatenation of m bit-decompositions of v_j; a_R = a_L - 1.
  const a_L: bigint[] = new Array(nm);
  const a_R: bigint[] = new Array(nm);
  for (let j = 0; j < m; j++) {
    let tmp = reduceScalar(values[j]);
    for (let i = 0; i < N; i++) {
      const bit = tmp & 1n;
      a_L[j * N + i] = bit;
      a_R[j * N + i] = addScalars(bit, negScalar(1n));
      tmp >>= 1n;
    }
  }

  // A = alpha*h + <a_L, G> + <a_R, H>
  const alpha = randomScalar();
  const A = addPoints(
    addPoints(scalarMult(alpha, h), innerProductPoints(a_L, G_vec)),
    innerProductPoints(a_R, H_vec)
  );

  // S = rho*h + <s_L, G> + <s_R, H>
  const s_L = Array.from({ length: nm }, () => randomScalar());
  const s_R = Array.from({ length: nm }, () => randomScalar());
  const rho = randomScalar();
  const S = addPoints(
    addPoints(scalarMult(rho, h), innerProductPoints(s_L, G_vec)),
    innerProductPoints(s_R, H_vec)
  );

  transcript.appendPoint('A', A);
  transcript.appendPoint('S', S);
  const y = transcript.challengeScalar('y');
  const z = transcript.challengeScalar('z');

  const y_pow_nm = powerVector(y, nm);
  const two_pow_n = powerVector(2n, N);

  // l(X) = (a_L - z*1^{nm}) + s_L * X
  // r(X) = y^{nm} ∘ (a_R + z*1^{nm} + s_R * X)
  //         + sum_{j=0..m-1} z^{j+2} * (0^{j*n} || 2^n || 0^{(m-1-j)*n})
  const l0: bigint[] = new Array(nm);
  const l1: bigint[] = new Array(nm);
  const r0: bigint[] = new Array(nm);
  const r1: bigint[] = new Array(nm);

  // Precompute z^{j+2} for j = 0..m-1, i.e. z^2, z^3, ..., z^{m+1}.
  const zPows: bigint[] = new Array(m);
  let zCur = mulScalars(z, z);
  for (let j = 0; j < m; j++) {
    zPows[j] = zCur;
    zCur = mulScalars(zCur, z);
  }

  for (let j = 0; j < m; j++) {
    for (let i = 0; i < N; i++) {
      const idx = j * N + i;
      l0[idx] = addScalars(a_L[idx], negScalar(z));
      l1[idx] = s_L[idx];
      const aRplusZ = addScalars(a_R[idx], z);
      const yi = y_pow_nm[idx];
      const r0_main = mulScalars(yi, aRplusZ);
      const r0_extra = mulScalars(zPows[j], two_pow_n[i]);
      r0[idx] = addScalars(r0_main, r0_extra);
      r1[idx] = mulScalars(yi, s_R[idx]);
    }
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

  const l: bigint[] = new Array(nm);
  const r_vec: bigint[] = new Array(nm);
  for (let i = 0; i < nm; i++) {
    l[i] = addScalars(l0[i], mulScalars(l1[i], x));
    r_vec[i] = addScalars(r0[i], mulScalars(r1[i], x));
  }

  const t_hat = addScalars(t0, addScalars(mulScalars(t1, x), mulScalars(t2, xx)));

  // tau_x = tau1*x + tau2*x^2 + sum_{j} z^{j+2} * gamma_j
  let tau_x = addScalars(mulScalars(tau1, x), mulScalars(tau2, xx));
  for (let j = 0; j < m; j++) {
    tau_x = addScalars(tau_x, mulScalars(zPows[j], reduceScalar(blinders[j])));
  }
  const mu = addScalars(alpha, mulScalars(rho, x));

  transcript.appendScalar('t_hat', t_hat);
  transcript.appendScalar('tau_x', tau_x);
  transcript.appendScalar('mu', mu);

  // Run IPA in basis (G, H') with H'_i = y^{-i} * H_i, dimension n*m.
  const yInv = invScalar(y);
  const yInv_pow = powerVector(yInv, nm);
  const H_prime: RistrettoPointValue[] = new Array(nm);
  for (let i = 0; i < nm; i++) {
    H_prime[i] = scalarMult(yInv_pow[i], H_vec[i]);
  }

  const u = getU();
  const Pprime = addPoints(
    addPoints(innerProductPoints(l, G_vec), innerProductPoints(r_vec, H_prime)),
    scalarMult(t_hat, u)
  );

  const ipa_proof = proveIPA(l, r_vec, u, G_vec, H_prime, Pprime, transcript);

  return {
    m,
    A,
    S,
    T1,
    T2,
    tau_x,
    mu,
    t_hat,
    ipa_proof,
    challenges: { y, z, x },
  };
}

/** Verify a true aggregated range proof. */
export function verifyTrueAggregate(
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

  transcript.appendLabel('aggregate-bulletproof');
  transcript.appendScalar('m', BigInt(m));
  transcript.appendScalar('n', BigInt(N));
  for (let j = 0; j < m; j++) {
    transcript.appendPoint(`V${j}`, V[j]);
  }

  transcript.appendPoint('A', proof.A);
  transcript.appendPoint('S', proof.S);
  const y = transcript.challengeScalar('y');
  const z = transcript.challengeScalar('z');

  transcript.appendPoint('T1', proof.T1);
  transcript.appendPoint('T2', proof.T2);
  const x = transcript.challengeScalar('x');
  const xx = mulScalars(x, x);

  transcript.appendScalar('t_hat', proof.t_hat);
  transcript.appendScalar('tau_x', proof.tau_x);
  transcript.appendScalar('mu', proof.mu);

  const y_pow_nm = powerVector(y, nm);
  const two_pow_n = powerVector(2n, N);

  // z^{j+2} table
  const zPows: bigint[] = new Array(m);
  let zCur = mulScalars(z, z);
  for (let j = 0; j < m; j++) {
    zPows[j] = zCur;
    zCur = mulScalars(zCur, z);
  }

  // (1) t_hat * g + tau_x * h ?= sum_j z^{j+2} * V_j + delta(y,z) * g + x * T1 + x^2 * T2
  const lhs = addPoints(scalarMult(proof.t_hat, g), scalarMult(proof.tau_x, h));
  const d = deltaAggregate(z, y_pow_nm, two_pow_n, m);
  let sumZV = scalarMult(zPows[0], V[0]);
  for (let j = 1; j < m; j++) {
    sumZV = addPoints(sumZV, scalarMult(zPows[j], V[j]));
  }
  const rhs = addPoints(
    addPoints(sumZV, scalarMult(d, g)),
    addPoints(scalarMult(x, proof.T1), scalarMult(xx, proof.T2))
  );
  if (!lhs.equals(rhs)) return false;

  // (2) Reconstruct P' for the IPA in basis (G, H') with dim n*m.
  //   P' = A + x*S + <-z, G> + < z*y^{nm} + per-value z^{j+2}*2^n , H' > - mu*h + t_hat*u
  const yInv = invScalar(y);
  const yInv_pow = powerVector(yInv, nm);
  const H_prime: RistrettoPointValue[] = new Array(nm);
  for (let i = 0; i < nm; i++) {
    H_prime[i] = scalarMult(yInv_pow[i], H_vec[i]);
  }

  const negZ = negScalar(z);
  const negZVec: bigint[] = new Array(nm).fill(negZ);
  const rCoeffs: bigint[] = new Array(nm);
  for (let j = 0; j < m; j++) {
    for (let i = 0; i < N; i++) {
      const idx = j * N + i;
      rCoeffs[idx] = addScalars(
        mulScalars(z, y_pow_nm[idx]),
        mulScalars(zPows[j], two_pow_n[i])
      );
    }
  }

  const u = getU();
  let Pprime = addPoints(proof.A, scalarMult(x, proof.S));
  Pprime = addPoints(Pprime, innerProductPoints(negZVec, G_vec));
  Pprime = addPoints(Pprime, innerProductPoints(rCoeffs, H_prime));
  Pprime = addPoints(Pprime, scalarMult(negScalar(proof.mu), h));
  Pprime = addPoints(Pprime, scalarMult(proof.t_hat, u));

  return verifyIPA(proof.ipa_proof, Pprime, u, G_vec, H_prime, transcript);
}

/** Serialized byte length of a true aggregate proof. */
export function trueAggregateByteLength(proof: TrueAggregateProof): number {
  const POINT = 32, SCALAR = 32;
  const ipaPoints = (proof.ipa_proof.L.length + proof.ipa_proof.R.length) * POINT;
  return 4 * POINT + 3 * SCALAR + ipaPoints + 2 * SCALAR;
}
