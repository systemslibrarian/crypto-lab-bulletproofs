/**
 * Single-value 64-bit range proof for Bulletproofs.
 * 
 * Proves that a Pedersen-committed value v lies in [0, 2^64).
 * Protocol: Bünz et al. 2018, Protocol 2
 */

import {
  generateGVec,
  generateHVec,
  addPoints,
  scalarMult,
  innerProductPoints,
  RISTRETTO_BASEPOINT,
  type RistrettoPointValue,
} from '../crypto/ristretto';
import { getHGenerator, vectorCommit } from '../crypto/pedersen';
import {
  reduceScalar,
  addScalars,
  mulScalars,
  negScalar,
  randomScalar,
} from '../crypto/scalar';
import { Transcript } from '../crypto/transcript';
import { proveIPA, verifyIPA, type IPAProof } from './inner-product';

const N = 64; // Bit length

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
}

/**
 * Generate a 64-bit range proof for a committed value.
 * 
 * @param value The value to prove (must be in [0, 2^64))
 * @param blinder The Pedersen blinding factor used in Commit(value, blinder)
 * @param V The Pedersen commitment
 * @param transcript Fiat-Shamir transcript
 * @returns Range proof
 */
export function proveRange(
  value: bigint,
  blinder: bigint,
  V: RistrettoPointValue,
  transcript: Transcript
): RangeProof {
  // Verify value is in range
  if (value < 0n || value >= (1n << 64n)) {
    throw new Error('Value must be in [0, 2^64)');
  }

  const v = reduceScalar(value);
  const blinding = reduceScalar(blinder);

  // Generate basis vectors
  const G_vec = generateGVec(N);
  const H_vec = generateHVec(N);
  const g = RISTRETTO_BASEPOINT;
  const h = getHGenerator();

  // Bit decomposition: a_L[i] = bit i of v
  const a_L: bigint[] = [];
  let v_copy = v;
  for (let i = 0; i < N; i++) {
    a_L.push(v_copy & 1n);
    v_copy = v_copy >> 1n;
  }

  // a_R = a_L - 1^N
  const a_R = a_L.map((a) => addScalars(a, negScalar(1n)));

  // Random blinding: s_L, s_R
  const s_L = Array.from({ length: N }, () => randomScalar());
  const s_R = Array.from({ length: N }, () => randomScalar());

  // Commitments A, S
  const rA = randomScalar();
  const A = vectorCommit(a_L, G_vec, a_R, H_vec, rA);
  
  const rS = randomScalar();
  const S = vectorCommit(s_L, G_vec, s_R, H_vec, rS);

  // Get challenges y, z from transcript
  transcript.appendPoint('A', A);
  transcript.appendPoint('S', S);
  const y = transcript.challengeScalar('y');
  const z = transcript.challengeScalar('z');

  // Polynomials l(X) = a_L + s_L * X, r(X) = y^N ⊙ (a_R + z*1^N) + s_R * X ⊙ y^N
  const y_pow: bigint[] = [];
  let y_i = 1n;
  for (let i = 0; i < N; i++) {
    y_pow.push(y_i);
    y_i = mulScalars(y_i, y);
  }

  const z_sq = mulScalars(z, z);
  
  // t(X) = <l(X), r(X)>
  // t_0 = <a_L, y^N ⊙ (a_R + z*1^N)> + z*v + z^2*r
  // t_1 = <a_L, s_R ⊙ y^N> + <s_L, y^N ⊙ (a_R + z*1^N)>
  // t_2 = <s_L, s_R ⊙ y^N>

  // Compute t_0
  let t_0 = 0n;
  for (let i = 0; i < N; i++) {
    const ar = addScalars(a_R[i], z);
    t_0 = addScalars(t_0, mulScalars(mulScalars(a_L[i], y_pow[i]), ar));
  }
  t_0 = addScalars(t_0, mulScalars(z, v));
  t_0 = addScalars(t_0, mulScalars(z_sq, blinding));

  // Compute t_1
  let t_1 = 0n;
  for (let i = 0; i < N; i++) {
    t_1 = addScalars(
      t_1,
      mulScalars(a_L[i], mulScalars(s_R[i], y_pow[i]))
    );
  }
  for (let i = 0; i < N; i++) {
    const ar = addScalars(a_R[i], z);
    t_1 = addScalars(
      t_1,
      mulScalars(s_L[i], mulScalars(y_pow[i], ar))
    );
  }

  // Compute t_2
  let t_2 = 0n;
  for (let i = 0; i < N; i++) {
    t_2 = addScalars(t_2, mulScalars(s_L[i], mulScalars(s_R[i], y_pow[i])));
  }

  // Commitments T1, T2
  const tau1 = randomScalar();
  const tau2 = randomScalar();
  const T1 = addPoints(scalarMult(t_1, g), scalarMult(tau1, h));
  const T2 = addPoints(scalarMult(t_2, g), scalarMult(tau2, h));

  // Get challenge x
  transcript.appendPoint('T1', T1);
  transcript.appendPoint('T2', T2);
  const x = transcript.challengeScalar('x');
  const x_sq = mulScalars(x, x);

  // Compute l, r at X=x
  let t_hat = t_0;
  t_hat = addScalars(t_hat, mulScalars(t_1, x));
  t_hat = addScalars(t_hat, mulScalars(t_2, x_sq));

  let tau_x = mulScalars(tau1, x);
  tau_x = addScalars(tau_x, mulScalars(tau2, x_sq));

  let mu = mulScalars(rA, x);
  mu = addScalars(mu, mulScalars(rS, x_sq));

  // Compute l and r vectors at X=x
  const l: bigint[] = [];
  for (let i = 0; i < N; i++) {
    l.push(addScalars(a_L[i], mulScalars(s_L[i], x)));
  }

  const r_vec: bigint[] = [];
  for (let i = 0; i < N; i++) {
    const ar = addScalars(a_R[i], z);
    const sr_y = mulScalars(s_R[i], y_pow[i]);
    r_vec.push(
      addScalars(
        mulScalars(y_pow[i], addScalars(ar, mulScalars(z, 1n))),
        mulScalars(sr_y, x)
      )
    );
  }

  // Inner-product argument
  const P = addPoints(V, addPoints(scalarMult(z, innerProductPoints(y_pow, H_vec)), scalarMult(z_sq, innerProductPoints(Array(N).fill(1n), H_vec))));
  const u = RISTRETTO_BASEPOINT; // Placeholder
  const ipa_proof = proveIPA(l, r_vec, u, G_vec, H_vec, P, transcript);

  return {
    A,
    S,
    T1,
    T2,
    tau_x,
    mu,
    t_hat,
    ipa_proof,
  };
}

/**
 * Verify a 64-bit range proof.
 * 
 * @param proof Range proof
 * @param V The Pedersen commitment
 * @param transcript Fiat-Shamir transcript
 * @returns true if valid, false otherwise
 */
export function verifyRange(
  proof: RangeProof,
  V: RistrettoPointValue,
  transcript: Transcript
): boolean {
  // Generate basis vectors
  const G_vec = generateGVec(N);
  const H_vec = generateHVec(N);
  const g = RISTRETTO_BASEPOINT;
  const h = getHGenerator();

  // Retrieve challenges from transcript  
  transcript.appendPoint('A', proof.A);
  transcript.appendPoint('S', proof.S);
  const y = transcript.challengeScalar('y');
  const z = transcript.challengeScalar('z');

  transcript.appendPoint('T1', proof.T1);
  transcript.appendPoint('T2', proof.T2);
  const x = transcript.challengeScalar('x');
  const x_sq = mulScalars(x, x);

  // Compute y powers
  const y_pow: bigint[] = [];
  let y_i = 1n;
  for (let i = 0; i < N; i++) {
    y_pow.push(y_i);
    y_i = mulScalars(y_i, y);
  }

  const z_sq = mulScalars(z, z);

  // Polynomial checks: verify t_hat computation via Pedersen commitments
  // Check: t_hat*g + tau_x*h == V + z*<y^N, H> + z^2*<1^N, H> + x*T1 + x^2*T2
  
  const left = addPoints(
    scalarMult(proof.t_hat, g),
    scalarMult(proof.tau_x, h)
  );

  // Compute sum of y^N ⊙ H (Hadamard product as inner product with coefficients)
  const z_y_commitment = scalarMult(z, innerProductPoints(y_pow, H_vec));

  // Compute sum of z^2 * H_vec
  const z_sq_commitment = scalarMult(z_sq, innerProductPoints(Array(N).fill(1n), H_vec));

  // Recompute polynomial commitment check point
  let right = V;
  right = addPoints(right, z_y_commitment);
  right = addPoints(right, z_sq_commitment);
  right = addPoints(right, scalarMult(x, proof.T1));
  right = addPoints(right, scalarMult(x_sq, proof.T2));

  // Verify polynomial commitment
  if (!left.equals(right)) {
    return false;
  }

  // Verify inner-product argument against computed P
  const P = addPoints(proof.A, addPoints(scalarMult(x, proof.S), 
    addPoints(
      addPoints(
        scalarMult(z, innerProductPoints(y_pow, H_vec)),
        scalarMult(z_sq, innerProductPoints(Array(N).fill(1n), H_vec))
      ),
      V
    )
  ));

  const u = RISTRETTO_BASEPOINT;
  return verifyIPA(proof.ipa_proof, P, u, G_vec, H_vec, transcript);
}
