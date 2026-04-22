/**
 * Ristretto255 point helpers and generator derivation.
 * Uses @noble/curves/ed25519 ristretto255.
 */

import { RistrettoPoint } from '@noble/curves/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { reduceScalar } from './scalar';

export type RistrettoPointValue = InstanceType<typeof RistrettoPoint>;

/**
 * The Ristretto255 base point (standard generator).
 */
export const RISTRETTO_BASEPOINT = RistrettoPoint.BASE;

/**
 * Hash a string to a Ristretto255 point using RFC 9380 map.
 * Uses SHA-512 for hashing the label, then map-to-curve.
 */
export function hashToRistretto(label: string): RistrettoPointValue {
  const labelBytes = new TextEncoder().encode(label);
  const hash = sha512(labelBytes);
  // Use the first 64 bytes as input to hash-to-curve
  return RistrettoPoint.hashToCurve(hash);
}

/**
 * Multiple a scalar by a point (constant-time scalar multiplication).
 */
export function scalarMult(scalar: bigint, point: RistrettoPointValue): RistrettoPointValue {
  return point.multiply(reduceScalar(scalar));
}

/**
 * Add two Ristretto255 points.
 */
export function addPoints(p: RistrettoPointValue, q: RistrettoPointValue): RistrettoPointValue {
  return p.add(q);
}

/**
 * Negate a Ristretto255 point.
 */
export function negPoint(p: RistrettoPointValue): RistrettoPointValue {
  return p.negate();
}

/**
 * Check if two points are equal.
 */
export function pointsEqual(p: RistrettoPointValue, q: RistrettoPointValue): boolean {
  return p.equals(q);
}

/**
 * Convert a point to Ristretto compressed encoding (32 bytes).
 */
export function pointToBytes(p: RistrettoPointValue): Uint8Array {
  return p.toBytes();
}

/**
 * Convert compressed bytes to a Ristretto255 point.
 */
export function bytesToPoint(bytes: Uint8Array): RistrettoPointValue {
  return RistrettoPoint.fromHex(bytes);
}

/**
 * Generate n deterministic, independent Ristretto255 points for the prover's basis vectors.
 * G_vec[i] = hashToRistretto("bulletproofs:G:i")
 */
export function generateGVec(n: number): RistrettoPointValue[] {
  const result: RistrettoPointValue[] = [];
  for (let i = 0; i < n; i++) {
    result.push(hashToRistretto(`bulletproofs:G:${i}`));
  }
  return result;
}

/**
 * Generate n deterministic, independent Ristretto255 points for the commitment basis vectors.
 * H_vec[i] = hashToRistretto("bulletproofs:H:i")
 */
export function generateHVec(n: number): RistrettoPointValue[] {
  const result: RistrettoPointValue[] = [];
  for (let i = 0; i < n; i++) {
    result.push(hashToRistretto(`bulletproofs:H:${i}`));
  }
  return result;
}

/**
 * Verify that all points in a vector are distinct (sanity check for independence).
 */
export function pointsAreDistinct(points: RistrettoPointValue[]): boolean {
  const seen = new Set<string>();
  for (const p of points) {
    const hex = p.toHex();
    if (seen.has(hex)) {
      return false;
    }
    seen.add(hex);
  }
  return true;
}

/**
 * Compute inner product of a scalar vector and a point vector.
 * Returns sum of scalar[i] * points[i].
 */
export function innerProductPoints(
  scalars: bigint[],
  points: RistrettoPointValue[]
): RistrettoPointValue {
  if (scalars.length !== points.length) {
    throw new Error('Scalar and point vector lengths must match');
  }

  let result = RistrettoPoint.ZERO;
  for (let i = 0; i < scalars.length; i++) {
    result = addPoints(result, scalarMult(scalars[i], points[i]));
  }
  return result;
}

/**
 * Compute inner product of two scalar vectors.
 * Returns sum of a[i] * b[i].
 */
export function innerProductScalars(a: bigint[], b: bigint[]): bigint {
  if (a.length !== b.length) {
    throw new Error('Vector lengths must match');
  }
  let result = 0n;
  for (let i = 0; i < a.length; i++) {
    result += a[i] * b[i];
  }
  return result;
}
