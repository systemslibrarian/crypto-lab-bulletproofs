/**
 * Proof size chart component.
 */

export function createProofSizeChart(): HTMLElement {
  const container = document.createElement('div');
  container.className = 'proof-size-chart';
  container.innerHTML = `
    <h3>Proof Size Comparison</h3>
    <div id="chart-container" class="chart-container"></div>
  `;
  return container;
}
