/**
 * Verify panel component.
 */

export function createVerifyPanel(): HTMLElement {
  const container = document.createElement('div');
  container.className = 'verify-panel';
  container.innerHTML = `
    <h3>Verify Proof</h3>
    <p class="panel-copy">Rebuild the verifier transcript and compare the reconstructed point equations against the current proof.</p>
    <button id="verify-button" type="button">Verify Range Proof</button>
    <div id="verify-result" class="verify-result" role="status" aria-live="polite">No verification has been run yet.</div>
  `;
  return container;
}
