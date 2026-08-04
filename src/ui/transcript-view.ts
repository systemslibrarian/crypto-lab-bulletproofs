/**
 * Fiat-Shamir transcript view component.
 */

export function createTranscriptView(): HTMLElement {
  const container = document.createElement('div');
  container.className = 'transcript-view';
  container.innerHTML = `
    <h3>Fiat-Shamir Transcript</h3>
    <p class="panel-copy">Each append and challenge is rendered in order so the prover and verifier transcript state can be compared.</p>
    <!-- tabindex="0": this list is capped at 300px and scrolls, so WCAG 2.1.1
         requires it to be reachable by keyboard. It only overflows once a proof
         has been generated, which is why a load-time-only scan never saw it. -->
    <ol id="transcript-entries" class="transcript-entries scroll-region" tabindex="0" aria-live="polite" aria-label="Transcript events"></ol>
  `;
  return container;
}
