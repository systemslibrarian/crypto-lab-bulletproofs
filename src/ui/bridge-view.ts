/**
 * Bit-grid → inner-product bridge.
 *
 * The demo shows two endpoints — "prove each bit is 0/1" (bit-grid) and "fold
 * two 64-length vectors" (IPA) — but the conceptual link between them is the
 * heart of Bulletproofs. This panel builds that link explicitly: from the bit
 * vector a_L the prover derives two vector polynomials whose constant terms are
 *
 *     l(0) = a_L − z·1ⁿ
 *     r(0) = yⁿ ∘ (a_R + z·1ⁿ) + z²·2ⁿ,   a_R = a_L − 1ⁿ
 *
 * Those are the two vectors of eq. (39) in section 4.1 of the Bulletproofs
 * paper, so ⟨l(0), r(0)⟩ = t₀ = z²·v + δ(y,z): collapsing all 64
 * bit-constraints into ONE inner product is what that identity buys. It is NOT
 * t̂. The proof sends the blinded vectors l(x) = l(0) + s_L·x and
 * r(x) = r(0) + (yⁿ ∘ s_R)·x — the paper blinds a_R inside the yⁿ Hadamard
 * product, r(X) = yⁿ ∘ (a_R + z·1ⁿ + s_R·X) + z²·2ⁿ, so the X coefficient of
 * r carries the yⁿ factor too (see r1 in src/proofs/range-proof.ts) — and
 * t̂ = t(x) = ⟨l(x), r(x)⟩. The entries below are the constant terms,
 * recomputed here from the real value and the real Fiat–Shamir challenges y, z.
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
      <p class="panel-copy bridge-lead">From the 64 bits <code>a<sub>L</sub></code>, the prover derives two vectors and one scalar. Showing the first ${SHOW} of 64 entries, built from the live challenges <code>y</code> and <code>z</code>:</p>
      <div class="bridge-rows" role="group" aria-label="Derived vectors l and r alongside the bits">
        <div class="bridge-line">
          <span class="bridge-tag"><code>a<sub>L</sub></code> <span class="bridge-tag-sub">the bits</span></span>
          <span class="bridge-vec" aria-label="first 8 bits">${bitRow}<span class="bridge-ell">…</span></span>
        </div>
        <div class="bridge-line">
          <span class="bridge-tag"><code>l(0) = a<sub>L</sub> − z·1ⁿ</code> <span class="bridge-tag-sub">constant term of l(X)</span></span>
          <span class="bridge-vec" aria-label="first 8 entries of the constant term of l">${lRow}<span class="bridge-ell">…</span></span>
        </div>
        <div class="bridge-line">
          <span class="bridge-tag"><code>r(0) = yⁿ∘(a<sub>R</sub>+z·1ⁿ) + z²·2ⁿ</code> <span class="bridge-tag-sub">constant term of r(X)</span></span>
          <span class="bridge-vec" aria-label="first 8 entries of the constant term of r">${rRow}<span class="bridge-ell">…</span></span>
        </div>
      </div>
      <p class="bridge-punch">Multiply those two rows out and you get one scalar, <code>⟨l(0), r(0)⟩ = t₀ = z²·v + δ(y,z)</code> — <strong>that</strong> is why all 64 bit-constraints become a single inner product. What the prover actually sends is the blinded pair <code>l = l(0) + s<sub>L</sub>·x</code> and <code>r = r(0) + (yⁿ∘s<sub>R</sub>)·x</code>, without which the vectors would leak <code>a<sub>L</sub></code>; their inner product is <code>t̂ = t(x)</code>, and that is the one the folding below collapses in <code>log₂(64) = 6</code> rounds.</p>
    </div>`;
}

/** Placeholder shown before a proof exists (challenges y, z aren't defined yet). */
export function bridgePlaceholder(): string {
  return `
    <div class="bridge">
      <p class="panel-copy">The range proof never checks "is v &lt; 2⁶⁴?" directly. Instead it turns the 64 bits <code>a<sub>L</sub></code> into two vectors whose inner product is a single scalar encoding every bit-constraint at once: the constant terms give <code>t₀ = z²·v + δ(y,z)</code>, and the blinded vectors the prover actually sends give <code>t̂ = t(x)</code>.</p>
      <p class="panel-copy">Generate a proof to see <code>l(0)</code> and <code>r(0)</code> built from your value's real bits and the live Fiat–Shamir challenges.</p>
    </div>`;
}
