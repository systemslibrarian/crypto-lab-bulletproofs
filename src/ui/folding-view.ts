/**
 * Inner-product-argument folding visualization.
 *
 * The IPA is where Bulletproofs earn their log-size: instead of sending the two
 * 64-length vectors l and r, the prover halves them over log₂(64) = 6 rounds,
 * sending only one (L, R) point pair per round and two final scalars. This
 * renders each round with the real L/R points so the collapse is visible.
 */

import type { IPAProof } from '../proofs/inner-product';

const N = 64;
const POINT_BYTES = 32;
const SCALAR_BYTES = 32;

/** Render the round-by-round folding of the IPA, using the proof's real L/R. */
export function renderFolding(ipa: IPAProof): string {
  const rounds = ipa.L.length;
  let sizeNow = N;
  let rows = '';
  for (let r = 0; r < rounds; r++) {
    const next = sizeNow / 2;
    const pct = Math.max(7, (next / N) * 100);
    const lHex = ipa.L[r].toHex().slice(0, 10);
    const rHex = ipa.R[r].toHex().slice(0, 10);
    rows += `
      <li class="fold-row">
        <span class="fold-round">round ${r + 1}</span>
        <span class="fold-bar-wrap"><span class="fold-bar" style="width:${pct.toFixed(1)}%"></span></span>
        <span class="fold-sizes">${sizeNow}&rarr;${next}</span>
        <span class="fold-lr"><code>L ${lHex}…</code><code>R ${rHex}…</code></span>
      </li>`;
    sizeNow = next;
  }

  const ipaBytes = rounds * 2 * POINT_BYTES + 2 * SCALAR_BYTES;
  const naiveBytes = 2 * N * SCALAR_BYTES; // sending l and r directly

  return `
    <ol class="fold-list" aria-label="Inner-product argument folding rounds">${rows}</ol>
    <p class="panel-copy fold-note">
      Each round halves the vectors and transmits one <code>(L, R)</code> pair. After
      ${rounds} rounds the two 64-length vectors collapse to the scalars <code>a, b</code>.
      IPA payload: <strong>${ipaBytes} B</strong> versus <strong>${naiveBytes} B</strong>
      to send <code>l</code> and <code>r</code> outright — the logarithmic win.
    </p>`;
}
