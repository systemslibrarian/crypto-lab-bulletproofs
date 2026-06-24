/**
 * Bit-decomposition visualizer.
 *
 * Renders the committed value as its 64-bit vector a_L — the object the range
 * proof actually operates on. Bulletproofs prove that *every one* of these 64
 * bits is exactly 0 or 1; once that holds, Σ a_L[i]·2^i necessarily lies in
 * [0, 2^64). Showing the bits makes that claim concrete.
 */

const N = 64;

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
      if (on) set++;
      cells += `<span class="bit-cell${on ? ' on' : ''}" title="bit ${i} = ${bits[i]}"></span>`;
    }
    groups += `<span class="bit-byte" aria-hidden="true">${cells}</span>`;
  }

  return `
    <div class="bit-grid" role="img" aria-label="64-bit decomposition of the committed value: ${set} of 64 bits set">
      <div class="bit-cells">${groups}</div>
      <div class="bit-grid-caption">
        <span><strong>a<sub>L</sub></strong> &mdash; the value as 64 bits (high &rarr; low)</span>
        <span class="bit-count" data-bit-count>${set} / 64 set</span>
      </div>
    </div>`;
}
