/**
 * Commitment card UI component - displays a Pedersen commitment.
 */

export function createCommitmentCard(): HTMLElement {
  const card = document.createElement('div');
  card.className = 'commitment-card';
  card.innerHTML = `
    <h3>Commit &amp; prove</h3>
    <p id="value-slider-help" class="panel-copy">Pick a value with the slider. The demo hides it inside a Pedersen commitment, then generates a range proof that it stays inside <code>[0, 2⁶⁴)</code> &mdash; without revealing the value.</p>
    <div class="control-group">
      <label for="value-slider">Value (0-2^16):</label>
      <input type="range" id="value-slider" min="0" max="65535" value="500" aria-describedby="value-slider-help value-display" />
      <output id="value-display" for="value-slider">500</output>
    </div>
    <div id="commitment-output" class="info-block" role="status" aria-live="polite"></div>
    <button id="prove-button" type="button">Generate Range Proof</button>
  `;
  return card;
}
