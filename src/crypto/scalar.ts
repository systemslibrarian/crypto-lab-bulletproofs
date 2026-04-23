/**
 * Scalar field arithmetic modulo ℓ (the Ristretto255 / ed25519 subgroup order).
 * ℓ = 2^252 + 27742317777884353535851937790883648493
 *   = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
 */

import { sha512 } from '@noble/hashes/sha512';

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
 *
 * If a deterministic seed has been installed via `setDeterministicRng`,
 * draws are pulled from that PRNG instead. This is for reproducible demos
 * and tests only; production use must keep the default crypto-RNG path.
 */
export function randomScalar(): bigint {
  // Loop until we draw a non-zero scalar; probability of zero is ~2^-252,
  // but we still need a guarantee for downstream blinding factors.
  for (;;) {
    const bytes = new Uint8Array(32);
    if (deterministicRng) {
      deterministicRng(bytes);
    } else {
      crypto.getRandomValues(bytes);
    }
    let result = 0n;
    for (let i = 0; i < 32; i++) {
      result = (result << 8n) | BigInt(bytes[i]);
    }
    const s = reduceScalar(result);
    if (s !== 0n) return s;
  }
}

let deterministicRng: ((out: Uint8Array) => void) | null = null;

/**
 * Install a deterministic PRNG seeded from `seed`. Subsequent calls to
 * `randomScalar` will draw from this stream until `clearDeterministicRng`
 * is called. Uses a SHA-512-based counter construction.
 */
export function setDeterministicRng(seed: string): void {
  let counter = 0;
  const seedBytes = new TextEncoder().encode(seed);
  let pool = sha512(seedBytes);
  let poolOffset = 0;
  deterministicRng = (out: Uint8Array) => {
    let written = 0;
    while (written < out.length) {
      if (poolOffset >= pool.length) {
        counter++;
        const counterBytes = new Uint8Array(8);
        let c = counter;
        for (let i = 7; i >= 0; i--) {
          counterBytes[i] = c & 0xff;
          c >>>= 8;
        }
        const next = new Uint8Array(seedBytes.length + counterBytes.length);
        next.set(seedBytes, 0);
        next.set(counterBytes, seedBytes.length);
        pool = sha512(next);
        poolOffset = 0;
      }
      const take = Math.min(out.length - written, pool.length - poolOffset);
      out.set(pool.subarray(poolOffset, poolOffset + take), written);
      poolOffset += take;
      written += take;
    }
  };
}

/** Restore the default crypto-RNG behaviour. */
export function clearDeterministicRng(): void {
  deterministicRng = null;
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
