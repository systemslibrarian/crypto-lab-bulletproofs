/**
 * Ristretto255 point helpers and generator derivation.
 * Uses @noble/curves/ed25519 ristretto255.
 */

import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { reduceScalar } from './scalar';

/**
 * @noble/curves v2 replaced the `RistrettoPoint` export with `ristretto255.Point`.
 * Re-exported here so this module stays the one place that touches the curve
 * library directly.
 */
export const RistrettoPoint = ristretto255.Point;

export type RistrettoPointValue = InstanceType<typeof RistrettoPoint>;

/**
 * The Ristretto255 base point (standard generator).
 */
export const RISTRETTO_BASEPOINT = RistrettoPoint.BASE;

/**
 * `deriveToCurve` is optional on @noble/curves' shared hasher interface, because
 * not every curve defines a one-way map. ristretto255 always does, so resolve it
 * once here and fail loudly if a future version drops it -- silently falling back
 * to a different map would change every generator this file derives.
 */
function requireDeriveToCurve() {
  const fn = ristretto255_hasher.deriveToCurve;
  if (!fn) {
    throw new Error(
      'ristretto255_hasher.deriveToCurve is unavailable in this @noble/curves build; ' +
        'the RFC 9496 one-way map is required to derive the Bulletproofs generators.'
    );
  }
  return fn.bind(ristretto255_hasher);
}

const deriveToCurve = requireDeriveToCurve();

/**
 * Hash a string to a Ristretto255 point using the RFC 9496 one-way map.
 * Uses SHA-512 for hashing the label, then map-to-curve.
 *
 * `deriveToCurve` is the v2 name for what v1 exposed as
 * `RistrettoPoint.hashToCurve`: the RFC 9496 §4.3.4 one-way map from 64
 * uniform bytes. It is NOT the same function as the v2
 * `ristretto255_hasher.hashToCurve`, which is the RFC 9380 hash-to-curve and
 * would derive different generators.
 */
export function hashToRistretto(label: string): RistrettoPointValue {
  const labelBytes = new TextEncoder().encode(label);
  const hash = sha512(labelBytes);
  // Use the first 64 bytes as input to the one-way map
  return deriveToCurve(hash);
}

/**
 * Multiply a scalar by a point. Returns the identity for scalar = 0,
 * because @noble/curves rejects zero scalars in `multiply` even though
 * 0 * P = O is mathematically valid and arises naturally in Bulletproofs
 * (bit decompositions, IPA folding, vector inner products with sparse vectors).
 */
export function scalarMult(scalar: bigint, point: RistrettoPointValue): RistrettoPointValue {
  const s = reduceScalar(scalar);
  if (s === 0n) {
    return RistrettoPoint.ZERO;
  }
  return point.multiply(s);
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
  // v2's `fromHex` takes a hex string only; `fromBytes` is the Uint8Array path
  // that v1's `fromHex` used to accept as an overload.
  return RistrettoPoint.fromBytes(bytes);
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
