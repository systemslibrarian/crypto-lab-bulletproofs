/**
 * Fiat-Shamir transcript view component.
 */

export function createTranscriptView(): HTMLElement {
  const container = document.createElement('div');
  container.className = 'transcript-view';
  container.innerHTML = `
    <h3>Fiat-Shamir Transcript</h3>
    <p class="panel-copy">Each append and challenge is rendered in order so the prover and verifier transcript state can be compared.</p>
    <ol id="transcript-entries" class="transcript-entries" aria-live="polite" aria-label="Transcript events"></ol>
  `;
  return container;
}
