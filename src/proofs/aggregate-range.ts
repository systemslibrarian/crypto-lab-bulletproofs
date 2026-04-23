/**
 * Batched range proofs for multiple values.
 *
 * NOTE: This is *not* the true aggregated Bulletproof from Bünz et al. 2018
 * Section 4.3. A true aggregate produces a single proof of size
 *   (2 * ceil(log2(n*m)) + 9) * 32 bytes.
 *
 * What this module does instead is run the single-value protocol m times,
 * binding each round into a shared parent transcript so that a verifier
 * cannot mix-and-match proofs across batches. The serialized size grows
 * linearly with m. The educational value is the batched verifier flow and
 * domain-separated transcript composition; the size-savings claim of true
 * aggregation is reported separately by the UI as a theoretical comparison.
 */

import type { RistrettoPointValue } from '../crypto/ristretto';
import { Transcript } from '../crypto/transcript';
import { proveRange, verifyRange, type RangeProof } from './range-proof';

/**
 * Batched range proof: m independent single-value proofs bound to one transcript.
 */
export interface AggregateRangeProof {
  valueCount: number;
  proofs: RangeProof[];
}

/**
 * Prove multiple values in range [0, 2^64) as a batched (not aggregated) proof.
 *
 * @param values Values to prove
 * @param blinders Blinding factors for each commitment
 * @param commitments Pedersen commitments
 * @param transcript Fiat-Shamir transcript
 * @returns Batched range proof (m single-value proofs)
 */
export function proveAggregateRange(
  values: bigint[],
  blinders: bigint[],
  commitments: RistrettoPointValue[],
  transcript: Transcript
): AggregateRangeProof {
  if (values.length !== blinders.length || values.length !== commitments.length) {
    throw new Error('All input arrays must have the same length');
  }

  if (values.length === 0) {
    throw new Error('At least one value is required for aggregation');
  }

  const proofs: RangeProof[] = [];
  transcript.appendLabel('aggregate-range:start');
  transcript.appendScalar('aggregate-count', BigInt(values.length));
  for (let i = 0; i < values.length; i++) {
    transcript.appendLabel(`aggregate-item:${i}`);
    const itemTranscript = new Transcript('bulletproofs-aggregate-item');
    const proof = proveRange(values[i], blinders[i], commitments[i], itemTranscript);
    proofs.push(proof);
  }

  return {
    valueCount: values.length,
    proofs,
  };
}

/**
 * Verify an aggregated range proof.
 * 
 * @param proof Aggregated range proof
 * @param commitments Pedersen commitments
 * @param transcript Fiat-Shamir transcript
 * @returns true if valid, false otherwise
 */
export function verifyAggregateRange(
  proof: AggregateRangeProof,
  commitments: RistrettoPointValue[],
  transcript: Transcript
): boolean {
  if (proof.valueCount !== commitments.length || proof.proofs.length !== commitments.length) {
    return false;
  }

  transcript.appendLabel('aggregate-range:start');
  transcript.appendScalar('aggregate-count', BigInt(commitments.length));
  for (let i = 0; i < commitments.length; i++) {
    transcript.appendLabel(`aggregate-item:${i}`);
    const itemTranscript = new Transcript('bulletproofs-aggregate-item');
    if (!verifyRange(proof.proofs[i], commitments[i], itemTranscript)) {
      return false;
    }
  }

  return true;
}
