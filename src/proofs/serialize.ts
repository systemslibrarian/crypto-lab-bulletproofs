/**
 * Serialization helpers for range proofs.
 *
 * Used to report the *actual* on-the-wire size of the proof object this
 * implementation produces, so the UI can compare it against the theoretical
 * Bulletproof size formula instead of asking the user to take the formula on
 * faith.
 */

import { scalarToBytes, bytesToScalar } from '../crypto/scalar';
import { bytesToPoint } from '../crypto/ristretto';
import type { RangeProof } from './range-proof';
import type { IPAProof } from './inner-product';

/** Compressed Ristretto255 point: 32 bytes. */
const POINT_BYTES = 32;
/** Canonical scalar encoding: 32 bytes. */
const SCALAR_BYTES = 32;

/** Number of bytes needed to encode a single IPA proof. */
export function ipaProofByteLength(proof: IPAProof): number {
  return proof.L.length * POINT_BYTES + proof.R.length * POINT_BYTES + 2 * SCALAR_BYTES;
}

/** Number of bytes needed to encode a single range proof. */
export function rangeProofByteLength(proof: RangeProof): number {
  // A, S, T1, T2 = 4 points; tau_x, mu, t_hat = 3 scalars; plus IPA proof.
  return 4 * POINT_BYTES + 3 * SCALAR_BYTES + ipaProofByteLength(proof.ipa_proof);
}

/** Serialize a single range proof to a flat byte array. */
export function serializeRangeProof(proof: RangeProof): Uint8Array {
  const out = new Uint8Array(rangeProofByteLength(proof));
  let offset = 0;

  const writeBytes = (bytes: Uint8Array) => {
    out.set(bytes, offset);
    offset += bytes.length;
  };

  writeBytes(proof.A.toBytes());
  writeBytes(proof.S.toBytes());
  writeBytes(proof.T1.toBytes());
  writeBytes(proof.T2.toBytes());
  writeBytes(scalarToBytes(proof.tau_x));
  writeBytes(scalarToBytes(proof.mu));
  writeBytes(scalarToBytes(proof.t_hat));

  for (const L of proof.ipa_proof.L) writeBytes(L.toBytes());
  for (const R of proof.ipa_proof.R) writeBytes(R.toBytes());
  writeBytes(scalarToBytes(proof.ipa_proof.a));
  writeBytes(scalarToBytes(proof.ipa_proof.b));

  return out;
}

/** Per-component byte breakdown, suitable for displaying in the UI. */
export function rangeProofComponentSizes(proof: RangeProof): Array<{ label: string; bytes: number }> {
  const ipaPoints = (proof.ipa_proof.L.length + proof.ipa_proof.R.length) * POINT_BYTES;
  const ipaScalars = 2 * SCALAR_BYTES;
  return [
    { label: 'A, S (commitments to a_L, a_R, s_L, s_R)', bytes: 2 * POINT_BYTES },
    { label: 'T1, T2 (commitments to t(X) coefficients)', bytes: 2 * POINT_BYTES },
    { label: 'tau_x, mu, t_hat (response scalars)', bytes: 3 * SCALAR_BYTES },
    { label: `IPA L/R points (${proof.ipa_proof.L.length + proof.ipa_proof.R.length} × 32 B)`, bytes: ipaPoints },
    { label: 'IPA final a, b scalars', bytes: ipaScalars },
  ];
}

/**
 * Deserialize a range proof from bytes. The IPA round count must match the
 * statement (n=64 implies 6 rounds), so the caller passes the expected number
 * of IPA rounds (k = log2(n)).
 */
export function deserializeRangeProof(bytes: Uint8Array, ipaRounds: number): RangeProof {
  const expectedLen = 4 * POINT_BYTES + 3 * SCALAR_BYTES + 2 * ipaRounds * POINT_BYTES + 2 * SCALAR_BYTES;
  if (bytes.length !== expectedLen) {
    throw new Error(`Expected ${expectedLen} bytes for ${ipaRounds}-round IPA proof, got ${bytes.length}`);
  }
  let offset = 0;
  const readPoint = () => {
    const slice = bytes.slice(offset, offset + POINT_BYTES);
    offset += POINT_BYTES;
    return bytesToPoint(slice);
  };
  const readScalar = () => {
    const slice = bytes.slice(offset, offset + SCALAR_BYTES);
    offset += SCALAR_BYTES;
    return bytesToScalar(slice);
  };

  const A = readPoint();
  const S = readPoint();
  const T1 = readPoint();
  const T2 = readPoint();
  const tau_x = readScalar();
  const mu = readScalar();
  const t_hat = readScalar();

  const L: ReturnType<typeof readPoint>[] = [];
  for (let i = 0; i < ipaRounds; i++) L.push(readPoint());
  const R: ReturnType<typeof readPoint>[] = [];
  for (let i = 0; i < ipaRounds; i++) R.push(readPoint());
  const a = readScalar();
  const b = readScalar();

  const ipa_proof: IPAProof = { L, R, a, b };
  return { A, S, T1, T2, tau_x, mu, t_hat, ipa_proof };
}

/** Encode bytes as lowercase hex. */
export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

/** Decode lowercase or uppercase hex (with optional 0x prefix and whitespace) to bytes. */
export function hexToBytes(hex: string): Uint8Array {
  let clean = hex.trim().replace(/\s+/g, '');
  if (clean.startsWith('0x') || clean.startsWith('0X')) clean = clean.slice(2);
  if (clean.length % 2 !== 0) throw new Error('Hex string has odd length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`Invalid hex character at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
}
