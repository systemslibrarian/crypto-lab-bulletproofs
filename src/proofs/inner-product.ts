/**
 * Inner-Product Argument (IPA) for Bulletproofs.
 * 
 * Proves knowledge of a, b such that:
 *   P = <a, G> + <b, H> + <a,b> * u
 * 
 * Protocol: Bünz et al. 2018, Protocol 1
 */

import {
  addPoints,
  scalarMult,
  innerProductPoints,
  innerProductScalars,
  type RistrettoPointValue,
} from '../crypto/ristretto';
import { addScalars, mulScalars, invScalar } from '../crypto/scalar';
import { Transcript } from '../crypto/transcript';

/**
 * Inner-Product Argument proof.
 */
export interface IPAProof {
  // L and R vectors: pair of points for each round
  L: RistrettoPointValue[];
  R: RistrettoPointValue[];
  // Final scalars
  a: bigint;
  b: bigint;
}

/**
 * Prove an inner-product argument.
 * 
 * @param a Left coefficient vector
 * @param b Right coefficient vector
 * @param u Additional generator point
 * @param G Point vector
 * @param H Point vector
 * @param P Initial commitment point
 * @param transcript Fiat-Shamir transcript
 * @returns Inner-product proof
 */
export function proveIPA(
  a: bigint[],
  b: bigint[],
  u: RistrettoPointValue,
  G: RistrettoPointValue[],
  H: RistrettoPointValue[],
  P: RistrettoPointValue,
  transcript: Transcript
): IPAProof {
  if (a.length !== b.length || a.length !== G.length || a.length !== H.length) {
    throw new Error('Vector lengths must match');
  }

  const n = a.length;
  if (n === 0 || (n & (n - 1)) !== 0) {
    throw new Error('Vector length must be a power of 2');
  }

  const L: RistrettoPointValue[] = [];
  const R: RistrettoPointValue[] = [];
  let a_vec = [...a];
  let b_vec = [...b];
  let G_vec = [...G];
  let H_vec = [...H];

  for (let round = 0; round < Math.log2(n); round++) {
    const n_half = a_vec.length / 2;

    // Left and right halves
    const aL = a_vec.slice(0, n_half);
    const aR = a_vec.slice(n_half);
    const bL = b_vec.slice(0, n_half);
    const bR = b_vec.slice(n_half);
    const GL = G_vec.slice(0, n_half);
    const GR = G_vec.slice(n_half);
    const HL = H_vec.slice(0, n_half);
    const HR = H_vec.slice(n_half);

    // Compute L and R
    const cL = innerProductScalars(aL, bR);
    const cR = innerProductScalars(aR, bL);
    const L_point = addPoints(
      addPoints(
        innerProductPoints(aL, GR),
        innerProductPoints(bR, HL)
      ),
      scalarMult(cL, u)
    );
    const R_point = addPoints(
      addPoints(
        innerProductPoints(aR, GL),
        innerProductPoints(bL, HR)
      ),
      scalarMult(cR, u)
    );

    L.push(L_point);
    R.push(R_point);

    // Challenge
    transcript.appendPoint(`L${round}`, L_point);
    transcript.appendPoint(`R${round}`, R_point);
    const x = transcript.challengeScalar(`x${round}`);
    const x_inv = invScalar(x);

    // Fold
    const newA: bigint[] = [];
    for (let i = 0; i < n_half; i++) {
      newA.push(
        addScalars(
          mulScalars(aL[i], x),
          mulScalars(aR[i], x_inv)
        )
      );
    }

    const newB: bigint[] = [];
    for (let i = 0; i < n_half; i++) {
      newB.push(
        addScalars(
          mulScalars(bL[i], x_inv),
          mulScalars(bR[i], x)
        )
      );
    }

    const newG: RistrettoPointValue[] = [];
    for (let i = 0; i < n_half; i++) {
      newG.push(
        addPoints(
          scalarMult(x_inv, GL[i]),
          scalarMult(x, GR[i])
        )
      );
    }

    const newH: RistrettoPointValue[] = [];
    for (let i = 0; i < n_half; i++) {
      newH.push(
        addPoints(
          scalarMult(x, HL[i]),
          scalarMult(x_inv, HR[i])
        )
      );
    }

    a_vec = newA;
    b_vec = newB;
    G_vec = newG;
    H_vec = newH;
  }

  return {
    L,
    R,
    a: a_vec[0],
    b: b_vec[0],
  };
}

/**
 * Verify an inner-product argument.
 * 
 * @param proof IPA proof
 * @param P Initial commitment point
 * @param u Additional generator point
 * @param G Point vector
 * @param H Point vector
 * @param transcript Fiat-Shamir transcript
 * @returns true if valid, false otherwise
 */
export function verifyIPA(
  proof: IPAProof,
  P: RistrettoPointValue,
  u: RistrettoPointValue,
  G: RistrettoPointValue[],
  H: RistrettoPointValue[],
  transcript: Transcript
): boolean {
  const n = G.length;
  if (H.length !== n || !isPowerOfTwo(n)) {
    return false;
  }

  const k = Math.log2(n);
  if (proof.L.length !== k || proof.R.length !== k) {
    return false;
  }

  // Reconstruct challenges
  const challenges: bigint[] = [];
  for (let round = 0; round < k; round++) {
    transcript.appendPoint(`L${round}`, proof.L[round]);
    transcript.appendPoint(`R${round}`, proof.R[round]);
    challenges.push(transcript.challengeScalar(`x${round}`));
  }

  // Compute s_i = product over round j of x_j^(bit j of i)
  const s: bigint[] = [];
  for (let i = 0; i < n; i++) {
    let si = 1n;
    for (let j = 0; j < k; j++) {
      const bit = (i >> j) & 1;
      if (bit === 1) {
        si = mulScalars(si, challenges[j]);
      } else {
        si = mulScalars(si, invScalar(challenges[j]));
      }
    }
    s.push(si);
  }

  // Reconstruct P' = <s, G> + <s^-1, H> + ab * u + sum(x_j^2 * L_j + x_j^-2 * R_j)
  const aTimesS = s.map((si) => mulScalars(proof.a, si));
  let P_prime = innerProductPoints(aTimesS, G);
  
  const s_inv: bigint[] = [];
  for (const si of s) {
    s_inv.push(invScalar(si));
  }
  const bTimesSInv = s_inv.map((si) => mulScalars(proof.b, si));
  P_prime = addPoints(P_prime, innerProductPoints(bTimesSInv, H));
  P_prime = addPoints(P_prime, scalarMult(mulScalars(proof.a, proof.b), u));

  for (let j = 0; j < k; j++) {
    const x_sq = mulScalars(challenges[j], challenges[j]);
    const x_inv_sq = invScalar(x_sq);
    P_prime = addPoints(P_prime, scalarMult(x_sq, proof.L[j]));
    P_prime = addPoints(P_prime, scalarMult(x_inv_sq, proof.R[j]));
  }

  return P_prime.equals(P);
}

function isPowerOfTwo(n: number): boolean {
  return n > 0 && (n & (n - 1)) === 0;
}
