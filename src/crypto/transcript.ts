/**
 * Fiat-Shamir transcript for Bulletproofs.
 * Backed by SHA-512 with domain separation labels.
 * 
 * Protocol: Bünz et al. 2018 - "Bulletproofs: Short Proofs for Confidential Transactions and More"
 */

import { sha512 } from '@noble/hashes/sha512';
import type { RistrettoPointValue } from './ristretto';
import { bytesToScalar, scalarToBytes } from './scalar';

/**
 * Transcript entry for logging/visualization.
 */
export interface TranscriptEntry {
  type: 'label' | 'point' | 'scalar' | 'challenge';
  label: string;
  bytes: Uint8Array;
  value?: string;
}

/**
 * Fiat-Shamir Transcript with labeled domain separation.
 */
export class Transcript {
  private state: Uint8Array;
  private entries: TranscriptEntry[] = [];

  /**
   * Create a new transcript with optional domain label.
   * Default: "libBulletproofs"
   */
  constructor(domainLabel: string = 'libBulletproofs') {
    // Initialize with domain label
    const labelBytes = new TextEncoder().encode(domainLabel);
    this.state = sha512(labelBytes);
  }

  /**
   * Append a domain label (string) to the transcript.
   */
  appendLabel(label: string): void {
    const labelBytes = new TextEncoder().encode(label);
    this.state = sha512(this.concatBytes(this.state, labelBytes));
    this.entries.push({
      type: 'label',
      label,
      bytes: labelBytes,
    });
  }

  /**
   * Append a point to the transcript.
   */
  appendPoint(label: string, p: RistrettoPointValue): void {
    const pointBytes = p.toBytes();
    const labelBytes = new TextEncoder().encode(label);
    const combined = this.concatBytes(labelBytes, pointBytes);
    this.state = sha512(this.concatBytes(this.state, combined));
    this.entries.push({
      type: 'point',
      label,
      bytes: combined,
      value: p.toHex(),
    });
  }

  /**
   * Append a scalar to the transcript.
   */
  appendScalar(label: string, s: bigint): void {
    const scalarBytes = scalarToBytes(s);
    const labelBytes = new TextEncoder().encode(label);
    const combined = this.concatBytes(labelBytes, scalarBytes);
    this.state = sha512(this.concatBytes(this.state, combined));
    this.entries.push({
      type: 'scalar',
      label,
      bytes: combined,
      value: s.toString(16),
    });
  }

  /**
   * Generate a challenge scalar by hashing the current state.
   * The label is prepended to distinguish different challenges.
   */
  challengeScalar(label: string): bigint {
    const labelBytes = new TextEncoder().encode(label);
    const combined = this.concatBytes(labelBytes, this.state);
    let challengeBytes = sha512(combined);
    let challenge = bytesToScalar(challengeBytes.slice(0, 32));

    // IPA verification requires invertible challenges, so avoid zero deterministically.
    if (challenge === 0n) {
      challengeBytes = sha512(this.concatBytes(challengeBytes, new Uint8Array([1])));
      challenge = bytesToScalar(challengeBytes.slice(0, 32));
      if (challenge === 0n) {
        challenge = 1n;
      }
    }

    // Update state for next round
    this.state = challengeBytes;

    this.entries.push({
      type: 'challenge',
      label,
      bytes: challengeBytes.slice(0, 32),
      value: challenge.toString(16),
    });
    return challenge;
  }

  /**
   * Get all transcript entries (for logging/visualization).
   */
  getEntries(): readonly TranscriptEntry[] {
    return this.entries;
  }

  /**
   * Clear entries for testing/fresh start (does NOT reset state).
   */
  clearEntries(): void {
    this.entries = [];
  }

  /**
   * Concatenate two byte arrays.
   */
  private concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);
    return result;
  }
}
