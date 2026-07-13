/**
 * Bit-decomposition visualizer.
 *
 * Renders the committed value as its 64-bit vector a_L — the object the range
 * proof actually operates on. Bulletproofs prove that *every one* of these 64
 * bits is exactly 0 or 1; once that holds, Σ a_L[i]·2^i necessarily lies in
 * [0, 2^64). Showing the bits makes that claim concrete.
 */

const N = 64;
/** The value slider can only set the low SLIDER_BITS bits (max 16,777,215). */
const SLIDER_BITS = 24;

/** Render the 64-bit decomposition of `value` (MSB-first), grouped per byte. */
export function renderBitGrid(value: bigint): string {
  const bits: number[] = new Array(N);
  let t = value < 0n ? 0n : value;
  for (let i = 0; i < N; i++) {
    bits[i] = Number(t & 1n);
    t >>= 1n;
  }

  let set = 0;
  let groups = '';
  // 8 bytes, MSB byte first; within each byte, MSB bit first.
  for (let b = N / 8 - 1; b >= 0; b--) {
    let cells = '';
    for (let k = 7; k >= 0; k--) {
      const i = b * 8 + k;
      const on = bits[i] === 1;
      // Bits 0..23 are reachable by the slider; 24..63 are proven but the slider
      // can never light them — mark them so the permanent darkness is explained,
      // not mistaken for "only 24 bits are being proven".
      const reachable = i < SLIDER_BITS;
      if (on) set++;
      cells += `<span class="bit-cell${on ? ' on' : ''}${reachable ? '' : ' out-of-reach'}" title="bit ${i} = ${bits[i]}${reachable ? '' : ' (beyond the slider, still proven)'}"></span>`;
    }
    groups += `<span class="bit-byte" aria-hidden="true">${cells}</span>`;
  }

  return `
    <div class="bit-grid" role="img" aria-label="64-bit decomposition of the committed value: ${set} of 64 bits set; the slider reaches the low ${SLIDER_BITS} bits, but the proof covers all 64.">
      <div class="bit-cells">${groups}</div>
      <div class="bit-grid-caption">
        <span><strong>a<sub>L</sub></strong> &mdash; the value as 64 bits (high &rarr; low)</span>
        <span class="bit-count" data-bit-count>${set} / 64 set</span>
      </div>
      <div class="bit-grid-legend">
        <span class="bit-legend-item"><span class="bit-swatch reach" aria-hidden="true"></span>bits 0&ndash;${SLIDER_BITS - 1}: reachable by the slider</span>
        <span class="bit-legend-item"><span class="bit-swatch beyond" aria-hidden="true"></span>bits ${SLIDER_BITS}&ndash;63: still proven, slider can't reach them</span>
      </div>
      <p class="bit-grid-foot">The proof <strong>always</strong> covers the full range <code>[0, 2⁶⁴)</code>. The slider tops out at 2²⁴−1, so the top ${N - SLIDER_BITS} bits stay 0 here — but the verifier still checks all 64 are 0 or 1.</p>
    </div>`;
}
