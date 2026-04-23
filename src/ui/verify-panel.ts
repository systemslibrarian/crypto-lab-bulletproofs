/**
 * Verify panel component.
 */

export function createVerifyPanel(): HTMLElement {
  const container = document.createElement('div');
  container.className = 'verify-panel';
  container.innerHTML = `
    <h3>Verify Proof</h3>
    <p class="panel-copy">Rebuild the verifier transcript and compare the reconstructed point equations against the current proof.</p>
    <div class="button-row">
      <button id="verify-button" type="button">Verify (reference)</button>
      <button id="verify-batched-button" type="button">Verify (single-MSM)</button>
    </div>
    <div id="verify-result" class="verify-result" role="status" aria-live="polite">No verification has been run yet.</div>
  `;
  return container;
}
