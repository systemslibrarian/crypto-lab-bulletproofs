import { commit } from '../src/crypto/pedersen.ts';
import { randomScalar } from '../src/crypto/scalar.ts';
import { proveRange, verifyRange } from '../src/proofs/range-proof.ts';
import { Transcript } from '../src/crypto/transcript.ts';
import {
  serializeRangeProof,
  deserializeRangeProof,
  bytesToHex,
  hexToBytes,
} from '../src/proofs/serialize.ts';

let failed = 0, passed = 0;
function ok(name, cond) {
  if (cond) { passed++; console.log(`PASS: ${name}`); }
  else { failed++; console.log(`FAIL: ${name}`); process.exitCode = 1; }
}

// Round trip via bytes
{
  const v = 4242n, r = randomScalar(), V = commit(v, r);
  const proof = proveRange(v, r, V, new Transcript('demo'));
  const bytes = serializeRangeProof(proof);
  const back = deserializeRangeProof(bytes, 6);
  ok('deserialized proof verifies', verifyRange(back, V, new Transcript('demo')));
  // Re-serialize and compare bytes for byte-exactness.
  const bytes2 = serializeRangeProof(back);
  let same = bytes.length === bytes2.length;
  for (let i = 0; same && i < bytes.length; i++) same = bytes[i] === bytes2[i];
  ok('serialize is deterministic round-trip', same);
}

// Hex helpers
{
  const data = new Uint8Array([0, 1, 15, 16, 254, 255]);
  const hex = bytesToHex(data);
  ok('hex encode lowercase', hex === '00010f10feff');
  const back = hexToBytes('  0X' + hex.toUpperCase() + '  ');
  let same = back.length === data.length;
  for (let i = 0; same && i < data.length; i++) same = back[i] === data[i];
  ok('hex decode tolerates 0x prefix and whitespace', same);
  let threw = false;
  try { hexToBytes('abc'); } catch { threw = true; }
  ok('hex decode rejects odd length', threw);
  threw = false;
  try { hexToBytes('zz'); } catch { threw = true; }
  ok('hex decode rejects bad characters', threw);
}

// Wrong IPA round count is rejected at the boundary.
{
  const v = 5n, r = randomScalar(), V = commit(v, r);
  const proof = proveRange(v, r, V, new Transcript('demo'));
  const bytes = serializeRangeProof(proof);
  let threw = false;
  try { deserializeRangeProof(bytes, 5); } catch { threw = true; }
  ok('deserialize rejects mismatched IPA round count', threw);
}

console.log(`\n${passed} passed, ${failed} failed`);
