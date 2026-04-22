/**
 * Pedersen commitments over Ristretto255.
 * Commit(v, r) = v*g + r*h
 * VectorCommit(a, b, r) = <a, G_vec> + <b, H_vec> + r*h
 */

import {
  RISTRETTO_BASEPOINT,
  bytesToPoint,
  hashToRistretto,
  scalarMult,
  addPoints,
  innerProductPoints,
  pointToBytes,
  type RistrettoPointValue,
} from './ristretto';
import { reduceScalar } from './scalar';

/**
 * The secondary generator h = hashToRistretto("bulletproofs:h").
 * Computed once and cached.
 */
let H_CACHED: RistrettoPointValue | null = null;

export function getHGenerator(): RistrettoPointValue {
  if (!H_CACHED) {
    H_CACHED = hashToRistretto('bulletproofs:h');
  }
  return H_CACHED;
}

/**
 * Compute a Pedersen commitment to a single value.
 * Commit(v, r) = v*g + r*h
 * Where g = RISTRETTO_BASEPOINT and h is the secondary generator.
 */
export function commit(value: bigint, blinder: bigint): RistrettoPointValue {
  const v = reduceScalar(value);
  const r = reduceScalar(blinder);
  const g = RISTRETTO_BASEPOINT;
  const h = getHGenerator();

  const vg = scalarMult(v, g);
  const rh = scalarMult(r, h);
  return addPoints(vg, rh);
}

/**
 * Compute a vector Pedersen commitment.
 * VectorCommit(a, b, r) = <a, G_vec> + <b, H_vec> + r*h
 * 
 * @param a Coefficient vector (left side)
 * @param gVec Point vector for left side
 * @param b Coefficient vector (right side)
 * @param hVec Point vector for right side
 * @param blinder Blinding factor
 * @returns Commitment point
 */
export function vectorCommit(
  a: bigint[],
  gVec: RistrettoPointValue[],
  b: bigint[],
  hVec: RistrettoPointValue[],
  blinder: bigint
): RistrettoPointValue {
  if (a.length !== gVec.length || b.length !== hVec.length) {
    throw new Error('Coefficient and point vector lengths must match');
  }

  const ag = innerProductPoints(a, gVec);
  const bh = innerProductPoints(b, hVec);
  const rh = scalarMult(blinder, getHGenerator());

  return addPoints(addPoints(ag, bh), rh);
}

/**
 * Serialize a Pedersen commitment to bytes for transmission or storage.
 */
export function commitmentToBytes(commitment: RistrettoPointValue): Uint8Array {
  return pointToBytes(commitment);
}

/**
 * Deserialize a commitment from bytes.
 */
export function bytesToCommitment(bytes: Uint8Array): RistrettoPointValue {
  return bytesToPoint(bytes);
}
