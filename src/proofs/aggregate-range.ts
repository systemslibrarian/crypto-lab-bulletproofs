/**
 * Aggregated range proofs for multiple values.
 * 
 * Proves m values are in [0, 2^n) with proof size O(log(n*m)) + O(1).
 * Protocol: Bünz et al. 2018, Protocol 2 extended
 */

import type { RistrettoPointValue } from '../crypto/ristretto';
import { Transcript } from '../crypto/transcript';
import { proveRange, verifyRange, type RangeProof } from './range-proof';

/**
 * Aggregated range proof.
 */
export interface AggregateRangeProof {
  valueCount: number;
  proofs: RangeProof[];
}

/**
 * Prove multiple values in range [0, 2^64) in a single proof.
 * 
 * @param values Values to prove
 * @param blinders Blinding factors for each commitment
 * @param commitments Pedersen commitments
 * @param transcript Fiat-Shamir transcript
 * @returns Aggregated range proof
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
