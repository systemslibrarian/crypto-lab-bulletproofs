/**
 * Scalar field arithmetic modulo ℓ (the Ristretto255 / ed25519 subgroup order).
 * ℓ = 2^252 + 27742317777884353535851937790883648493
 *   = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
 */

const ORDER =
  0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3edn;

/**
 * Reduce a bigint modulo ℓ.
 */
export function reduceScalar(x: bigint): bigint {
  return ((x % ORDER) + ORDER) % ORDER;
}

/**
 * Add two scalars modulo ℓ.
 */
export function addScalars(a: bigint, b: bigint): bigint {
  return reduceScalar(a + b);
}

/**
 * Multiply two scalars modulo ℓ.
 */
export function mulScalars(a: bigint, b: bigint): bigint {
  return reduceScalar(a * b);
}

/**
 * Negate a scalar modulo ℓ.
 */
export function negScalar(a: bigint): bigint {
  return reduceScalar(-a);
}

/**
 * Compute modular inverse of a scalar using the extended Euclidean algorithm.
 */
export function invScalar(a: bigint): bigint {
  a = reduceScalar(a);

  if (a === 0n) {
    throw new Error('Cannot invert zero scalar');
  }

  let t = 0n;
  let newt = 1n;
  let r = ORDER;
  let newr = a;

  while (newr !== 0n) {
    const quotient = r / newr;
    [t, newt] = [newt, t - quotient * newt];
    [r, newr] = [newr, r - quotient * newr];
  }

  if (r > 1n) {
    throw new Error('Scalar is not invertible');
  }

  if (t < 0n) {
    t = t + ORDER;
  }

  return t;
}

/**
 * Generate a random scalar using crypto.getRandomValues.
 */
export function randomScalar(): bigint {
  // Loop until we draw a non-zero scalar; probability of zero is ~2^-252,
  // but we still need a guarantee for downstream blinding factors.
  for (;;) {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    let result = 0n;
    for (let i = 0; i < 32; i++) {
      result = (result << 8n) | BigInt(bytes[i]);
    }
    const s = reduceScalar(result);
    if (s !== 0n) return s;
  }
}

/**
 * Convert scalar to big-endian byte array (32 bytes).
 */
export function scalarToBytes(s: bigint): Uint8Array {
  s = reduceScalar(s);
  const bytes = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(s & 0xffn);
    s = s >> 8n;
  }
  return bytes;
}

/**
 * Convert big-endian byte array to scalar.
 */
export function bytesToScalar(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new Error('Expected 32 bytes');
  }
  let result = 0n;
  for (let i = 0; i < 32; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return reduceScalar(result);
}
