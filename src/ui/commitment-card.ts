/**
 * Commitment card UI component - displays a Pedersen commitment, its visual
 * fingerprint, and the 64-bit decomposition the range proof operates on.
 */

import { gloss } from './glossary';

export function createCommitmentCard(): HTMLElement {
  const card = document.createElement('div');
  card.className = 'commitment-card';
  card.innerHTML = `
    <h3>Commit &amp; prove</h3>
    <p id="value-slider-help" class="panel-copy">Pick a secret value. The demo hides it inside a ${gloss('Pedersen commitment')}, then generates a ${gloss('range proof')} that it stays inside <code>[0, 2⁶⁴)</code> &mdash; without revealing the value.</p>
    <div class="control-group">
      <label for="value-slider">Value:</label>
      <input type="range" id="value-slider" min="0" max="16777215" value="1337" aria-describedby="value-slider-help value-display" />
      <output id="value-display" for="value-slider">1337</output>
    </div>
    <div class="preset-row" role="group" aria-label="Quick value presets">
      <button type="button" class="preset-chip" data-preset="0">0</button>
      <button type="button" class="preset-chip" data-preset="255">255</button>
      <button type="button" class="preset-chip" data-preset="65535">65,535</button>
      <button type="button" class="preset-chip" data-preset="16777215">16,777,215</button>
    </div>
    <div class="commitment-readout">
      <div id="commitment-identicon" class="commitment-identicon"></div>
      <div id="commitment-output" class="info-block commitment-output" role="status" aria-live="polite"></div>
    </div>
    ${renderBitGridSlot()}
    <button id="prove-button" type="button">Generate Range Proof</button>
  `;
  return card;
}

function renderBitGridSlot(): string {
  return `<div id="bit-grid-slot" class="bit-grid-slot"></div>`;
}
