/**
 * Bit-grid → inner-product bridge.
 *
 * The demo shows two endpoints — "prove each bit is 0/1" (bit-grid) and "fold
 * two 64-length vectors" (IPA) — but the conceptual link between them is the
 * heart of Bulletproofs. This panel builds that link explicitly: from the bit
 * vector a_L the prover derives two vectors
 *
 *     l = a_L − z·1ⁿ
 *     r = yⁿ ∘ (a_R + z·1ⁿ) + z²·2ⁿ,   a_R = a_L − 1ⁿ
 *
 * and the single scalar t̂ = ⟨l, r⟩. Proving that ONE inner product equals t̂
 * certifies all 64 bit-constraints at once. We recompute the first few entries
 * of l and r honestly from the real value and the real Fiat–Shamir challenges,
 * so the arrays shown are exactly what the live proof used (evaluated at X = x,
 * dropping the s_L / s_R blinding terms, which cancel in ⟨l,r⟩'s constant term).
 */

import { addScalars, mulScalars, negScalar } from '../crypto/scalar';

const N = 64;
const SHOW = 8; // first byte's worth of entries, then an ellipsis

function powerVec(base: bigint, n: number): bigint[] {
  const out: bigint[] = new Array(n);
  let acc = 1n;
  for (let i = 0; i < n; i++) {
    out[i] = acc;
    acc = mulScalars(acc, base);
  }
  return out;
}

/** Short signed-ish decimal for a scalar that is likely small in magnitude. */
function scalarCell(v: bigint, L: bigint): string {
  // Values like a_L−z are z-heavy field elements; show a compact hex tail so the
  // arrays read as "real field scalars", not toy integers.
  const near = v > L / 2n ? v - L : v; // fold the top half to a small negative
  if (near > -100000n && near < 100000n) return near.toString();
  const hex = v.toString(16);
  return hex.length <= 8 ? hex : `…${hex.slice(-6)}`;
}

/**
 * Render the bridge between the bit vector and the inner product, using the
 * value's real bits and the proof's real challenges y, z. `order` is the
 * curve order ℓ, used only to display near-zero scalars as small negatives.
 */
export function renderBridge(
  value: bigint,
  challenges: { y: bigint; z: bigint },
  order: bigint
): string {
  const { y, z } = challenges;
  const v = value < 0n ? 0n : value;

  const a_L: bigint[] = new Array(N);
  const a_R: bigint[] = new Array(N);
  let t = v;
  for (let i = 0; i < N; i++) {
    const bit = t & 1n;
    a_L[i] = bit;
    a_R[i] = addScalars(bit, negScalar(1n));
    t >>= 1n;
  }

  const yPow = powerVec(y, N);
  const twoPow = powerVec(2n, N);
  const z2 = mulScalars(z, z);

  // Constant terms of l(X), r(X) — the parts that survive into ⟨l,r⟩'s meaning.
  const l: bigint[] = new Array(N);
  const r: bigint[] = new Array(N);
  for (let i = 0; i < N; i++) {
    l[i] = addScalars(a_L[i], negScalar(z));
    const aRplusZ = addScalars(a_R[i], z);
    r[i] = addScalars(mulScalars(yPow[i], aRplusZ), mulScalars(z2, twoPow[i]));
  }

  const bitRow = a_L
    .slice(0, SHOW)
    .map((b) => `<span class="bridge-cell bit${b === 1n ? ' on' : ''}">${b}</span>`)
    .join('');
  const lRow = l
    .slice(0, SHOW)
    .map((s) => `<span class="bridge-cell">${scalarCell(s, order)}</span>`)
    .join('');
  const rRow = r
    .slice(0, SHOW)
    .map((s) => `<span class="bridge-cell">${scalarCell(s, order)}</span>`)
    .join('');

  return `
    <div class="bridge">
      <p class="panel-copy bridge-lead">From the 64 bits <code>a<sub>L</sub></code>, the prover derives two vectors and one scalar. Showing the first ${SHOW} of 64 entries (evaluated at the live challenges):</p>
      <div class="bridge-rows" role="group" aria-label="Derived vectors l and r alongside the bits">
        <div class="bridge-line">
          <span class="bridge-tag"><code>a<sub>L</sub></code> <span class="bridge-tag-sub">the bits</span></span>
          <span class="bridge-vec" aria-label="first 8 bits">${bitRow}<span class="bridge-ell">…</span></span>
        </div>
        <div class="bridge-line">
          <span class="bridge-tag"><code>l = a<sub>L</sub> − z·1ⁿ</code></span>
          <span class="bridge-vec" aria-label="first 8 entries of l">${lRow}<span class="bridge-ell">…</span></span>
        </div>
        <div class="bridge-line">
          <span class="bridge-tag"><code>r = yⁿ∘(a<sub>R</sub>+z·1ⁿ) + z²·2ⁿ</code></span>
          <span class="bridge-vec" aria-label="first 8 entries of r">${rRow}<span class="bridge-ell">…</span></span>
        </div>
      </div>
      <p class="bridge-punch">Proving the single inner product <code>⟨l, r⟩ = t̂</code> certifies all 64 bit-constraints at once — <strong>that</strong> is why a range claim becomes one inner product, which the folding below then collapses in <code>log₂(64) = 6</code> rounds.</p>
    </div>`;
}

/** Placeholder shown before a proof exists (challenges y, z aren't defined yet). */
export function bridgePlaceholder(): string {
  return `
    <div class="bridge">
      <p class="panel-copy">The range proof never checks "is v &lt; 2⁶⁴?" directly. Instead it turns the 64 bits <code>a<sub>L</sub></code> into two vectors <code>l</code> and <code>r</code> whose inner product <code>⟨l, r⟩ = t̂</code> encodes every bit-constraint at once.</p>
      <p class="panel-copy">Generate a proof to see <code>l</code> and <code>r</code> built from your value's real bits and the live Fiat–Shamir challenges.</p>
    </div>`;
}
