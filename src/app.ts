/**
 * Main application component for Bulletproofs demo.
 */

import { createCommitmentCard } from './ui/commitment-card';
import { createTranscriptView } from './ui/transcript-view';
import { createProofSizeChart } from './ui/proof-size-chart';
import { createVerifyPanel } from './ui/verify-panel';
import { commit } from './crypto/pedersen';
import { randomScalar } from './crypto/scalar';
import type { RistrettoPointValue } from './crypto/ristretto';
import { proveRange, verifyRange } from './proofs/range-proof';
import { Transcript } from './crypto/transcript';
import type { RangeProof } from './proofs/range-proof';

/**
 * Application state for the demo.
 */
export interface AppState {
  currentValue: bigint;
  currentBlinder: bigint;
  currentCommitment: RistrettoPointValue | null;
  currentProof: RangeProof | null;
  transcript: Transcript | null;
}

let appState: AppState = {
  currentValue: 100n,
  currentBlinder: randomScalar(),
  currentCommitment: null,
  currentProof: null,
  transcript: null,
};

const MAX_AGGREGATE_VALUES = 16;
const AGGREGATE_BITS = 64;

/**
 * Initialize the main application UI.
 */
export function initializeApp(container: HTMLElement): void {
  container.innerHTML = `
    <header>
      <h1>Bulletproofs Range Proofs</h1>
      <p>Live zero-knowledge proofs over ristretto255, no trusted setup</p>
      <button id="theme-toggle" type="button" aria-label="Switch to light mode" style="position: absolute; top: 0; right: 0;">🌙</button>
    </header>
    <main id="main-content" tabindex="-1">
      <section class="app-status" aria-label="Application status">
        <div id="app-status" class="info-block" role="status" aria-live="polite">Ready. Commit a value to start exploring the protocol.</div>
      </section>
      <div class="panels">
        <div id="commitment-panel" aria-label="Commit a value panel"></div>
        <div id="transcript-panel" aria-label="Transcript panel"></div>
        <div id="verify-panel" aria-label="Verify panel"></div>
        <section id="aggregate-panel" class="utility-panel"></section>
        <section id="cheat-panel" class="utility-panel"></section>
        <div id="chart-panel" aria-label="Proof size comparison panel"></div>
      </div>
    </main>
  `;

  // Mount UI components
  const commitmentPanel = document.getElementById('commitment-panel');
  const transcriptPanel = document.getElementById('transcript-panel');
  const verifyPanel = document.getElementById('verify-panel');
  const aggregatePanel = document.getElementById('aggregate-panel');
  const cheatPanel = document.getElementById('cheat-panel');
  const chartPanel = document.getElementById('chart-panel');

  if (commitmentPanel) commitmentPanel.appendChild(createCommitmentCard());
  if (transcriptPanel) transcriptPanel.appendChild(createTranscriptView());
  if (verifyPanel) verifyPanel.appendChild(createVerifyPanel());
  if (aggregatePanel) aggregatePanel.innerHTML = createAggregatePanelMarkup();
  if (cheatPanel) cheatPanel.innerHTML = createCheatPanelMarkup();
  if (chartPanel) chartPanel.appendChild(createProofSizeChart());

  // Setup initial commitment
  updateCommitment();

  // Wire up events
  const valueSlider = document.getElementById('value-slider') as HTMLInputElement;
  if (valueSlider) {
    valueSlider.addEventListener('input', () => {
      appState.currentValue = BigInt(parseInt(valueSlider.value));
      updateCommitment();
    });
  }

  // Wire up prove button
  const proveButton = document.getElementById('prove-button');
  if (proveButton) {
    proveButton.addEventListener('click', () => {
      generateProof();
    });
  }

  // Wire up verify button
  const verifyButton = document.getElementById('verify-button');
  if (verifyButton) {
    verifyButton.addEventListener('click', () => {
      verifyProof();
    });
  }

  const aggregateCount = document.getElementById('aggregate-count') as HTMLInputElement | null;
  if (aggregateCount) {
    aggregateCount.addEventListener('input', () => {
      renderAggregateEstimate();
      renderProofSizeChart();
    });
  }

  const cheatUpper = document.getElementById('cheat-upper');
  if (cheatUpper) {
    cheatUpper.addEventListener('click', () => runCheatDemo(1n << 64n));
  }

  const cheatNegative = document.getElementById('cheat-negative');
  if (cheatNegative) {
    cheatNegative.addEventListener('click', () => runCheatDemo(-1n));
  }

  renderAggregateEstimate();
  renderProofSizeChart();
}

/**
 * Update the commitment display.
 */
function updateCommitment(): void {
  appState.currentBlinder = randomScalar();
  appState.currentCommitment = commit(appState.currentValue, appState.currentBlinder);

  const valueDisplay = document.getElementById('value-display');
  if (valueDisplay) {
    valueDisplay.textContent = appState.currentValue.toString();
  }

  const commitmentOutput = document.getElementById('commitment-output');
  if (commitmentOutput) {
    commitmentOutput.innerHTML = `
      <div><strong>Committed value:</strong> ${appState.currentValue.toString()}</div>
      <div><strong>Compressed point:</strong> ${appState.currentCommitment.toHex().substring(0, 32)}...</div>
    `;
  }

  setAppStatus(`Committed value ${appState.currentValue.toString()} with a fresh random blinding factor.`);
}

/**
 * Generate a range proof for the current value.
 */
function generateProof(): void {
  if (!appState.currentCommitment) {
    setAppStatus('No commitment is available yet. Choose a value first.', 'error');
    return;
  }

  try {
    const transcript = new Transcript('bulletproofs-demo');
    const proof = proveRange(
      appState.currentValue,
      appState.currentBlinder,
      appState.currentCommitment,
      transcript
    );

    appState.currentProof = proof;
    appState.transcript = transcript;

    // Update transcript view
    const transcriptEntries = document.getElementById('transcript-entries');
    if (transcriptEntries) {
      const entries = transcript.getEntries();
      transcriptEntries.innerHTML = entries
        .map(
          (entry) =>
            `<li class="transcript-entry"><strong>${entry.label}</strong> (${entry.type}): <span aria-label="${entry.bytes.length} bytes">${entry.bytes.length} bytes</span></li>`
        )
        .join('');
    }

    setAppStatus(`Range proof generated. Transcript contains ${transcript.getEntries().length} events.`, 'success');
  } catch (error) {
    setAppStatus(`Error generating proof: ${formatError(error)}`, 'error');
  }
}

/**
 * Verify the current proof.
 */
function verifyProof(): void {
  if (!appState.currentProof || !appState.currentCommitment || !appState.transcript) {
    setAppStatus('No proof is available yet. Generate a proof before verification.', 'error');
    return;
  }

  try {
    // Create a fresh transcript for verification
    const verifyTranscript = new Transcript('bulletproofs-demo');
    const isValid = verifyRange(appState.currentProof, appState.currentCommitment, verifyTranscript);

    const verifyResult = document.getElementById('verify-result');
    if (verifyResult) {
      if (isValid) {
        verifyResult.className = 'verify-result success';
        verifyResult.innerHTML = '<strong>✓ Proof verified successfully!</strong>';
        setAppStatus('Verifier accepted the current proof.', 'success');
      } else {
        verifyResult.className = 'verify-result failure';
        verifyResult.innerHTML = '<strong>✗ Proof verification failed!</strong>';
        setAppStatus('Verifier rejected the current proof. The reconstructed equations did not match.', 'error');
      }
    }
  } catch (error) {
    const verifyResult = document.getElementById('verify-result');
    if (verifyResult) {
      verifyResult.className = 'verify-result failure';
      verifyResult.innerHTML = `<strong>✗ Error during verification:</strong> ${formatError(error)}`;
    }
    setAppStatus(`Error during verification: ${formatError(error)}`, 'error');
  }
}

function createAggregatePanelMarkup(): string {
  return `
    <h3>Aggregate</h3>
    <p class="panel-copy">Estimate the size savings from batching up to 16 committed 64-bit values into one proof.</p>
    <div class="control-group stack-on-mobile">
      <label for="aggregate-count">Values:</label>
      <input id="aggregate-count" type="range" min="1" max="${MAX_AGGREGATE_VALUES}" value="4" aria-describedby="aggregate-count-value" />
      <output id="aggregate-count-value" for="aggregate-count">4</output>
    </div>
    <div id="aggregate-summary" class="info-block" role="status" aria-live="polite"></div>
  `;
}

function createCheatPanelMarkup(): string {
  return `
    <h3>Try to Cheat</h3>
    <p class="panel-copy">Commit to an out-of-range value and compare it with what a 64-bit proof would need to open. The mismatch should show up immediately.</p>
    <div class="button-row">
      <button id="cheat-upper" type="button">Use 2^64</button>
      <button id="cheat-negative" type="button">Use -1</button>
    </div>
    <div id="cheat-result" class="info-block" role="status" aria-live="polite"></div>
  `;
}

function renderAggregateEstimate(): void {
  const aggregateCount = document.getElementById('aggregate-count') as HTMLInputElement | null;
  const aggregateCountValue = document.getElementById('aggregate-count-value');
  const aggregateSummary = document.getElementById('aggregate-summary');
  if (!aggregateCount || !aggregateCountValue || !aggregateSummary) {
    return;
  }

  const count = Number.parseInt(aggregateCount.value, 10);
  aggregateCountValue.textContent = String(count);

  const singleBytes = bulletproofBytes(AGGREGATE_BITS);
  const nonAggregatedBytes = singleBytes * count;
  const aggregatedBytes = bulletproofBytes(AGGREGATE_BITS * count);
  const naiveBytes = schnorrBytes(AGGREGATE_BITS * count);
  const savedBytes = nonAggregatedBytes - aggregatedBytes;

  aggregateSummary.innerHTML = `
    <div><strong>Non-aggregated:</strong> ${nonAggregatedBytes} bytes</div>
    <div><strong>Aggregated:</strong> ${aggregatedBytes} bytes</div>
    <div><strong>Naive disjunctive Schnorr:</strong> ${naiveBytes} bytes</div>
    <div><strong>Bytes saved:</strong> ${savedBytes}</div>
  `;
}

function runCheatDemo(value: bigint): void {
  const cheatResult = document.getElementById('cheat-result');
  if (!cheatResult) {
    return;
  }

  // Honest commitment to the *original* (out-of-range) value.
  const blinder = randomScalar();
  const honestCommitment = commit(value, blinder);

  // The prover refuses inputs outside [0, 2^64). The classic cheat is to
  // construct a 64-bit witness that opens the SAME commitment, which would
  // require breaking the discrete log of g and h. Instead we demonstrate the
  // closest a malicious prover can do: build a proof for the 64-bit
  // truncation v mod 2^64 and check that the verifier rejects it because
  // the commitment does not open to that witness.
  const truncated = BigInt.asUintN(64, value);
  const fakeCommitment = commit(truncated, blinder);
  const proverTranscript = new Transcript('bulletproofs-demo-cheat');
  let proof: RangeProof | null = null;
  let proverError = '';
  try {
    proof = proveRange(truncated, blinder, fakeCommitment, proverTranscript);
  } catch (e) {
    proverError = formatError(e);
  }

  let verifierMessage = 'Verifier was not run because the prover aborted.';
  if (proof) {
    const verifyTranscript = new Transcript('bulletproofs-demo-cheat');
    const acceptedAgainstHonest = verifyRange(proof, honestCommitment, verifyTranscript);
    verifierMessage = acceptedAgainstHonest
      ? 'Verifier UNEXPECTEDLY accepted: this should never happen.'
      : 'Verifier rejected: the proof opens a different commitment than the one published.';
  }

  cheatResult.innerHTML = `
    <div><strong>Attempted value:</strong> ${value.toString()}</div>
    <div><strong>64-bit normalized value:</strong> ${truncated.toString()}</div>
    <div><strong>Honest commitment prefix:</strong> ${honestCommitment.toHex().slice(0, 32)}...</div>
    <div><strong>Prover status:</strong> ${proverError ? 'aborted (' + proverError + ')' : 'produced a proof for the truncated witness'}</div>
    <div><strong>Verifier outcome:</strong> ${verifierMessage}</div>
  `;

  setAppStatus(
    `Cheat demo for ${value.toString()}: ${proverError ? 'prover aborted' : 'verifier rejected'}.`,
    'error'
  );
}

function renderProofSizeChart(): void {
  const container = document.getElementById('chart-container');
  const aggregateCount = document.getElementById('aggregate-count') as HTMLInputElement | null;
  if (!container || !aggregateCount) {
    return;
  }

  const count = Number.parseInt(aggregateCount.value, 10);
  const values = [
    {
      label: 'Non-aggregated Bulletproofs',
      bytes: bulletproofBytes(AGGREGATE_BITS) * count,
      className: 'chart-bar standard',
    },
    {
      label: 'Aggregated Bulletproof',
      bytes: bulletproofBytes(AGGREGATE_BITS * count),
      className: 'chart-bar aggregate',
    },
    {
      label: 'Naive Disjunctive Schnorr',
      bytes: schnorrBytes(AGGREGATE_BITS * count),
      className: 'chart-bar naive',
    },
  ];

  const maxBytes = Math.max(...values.map((entry) => entry.bytes));
  container.innerHTML = values
    .map((entry) => {
      const width = Math.max(12, Math.round((entry.bytes / maxBytes) * 100));
      return `
        <div class="chart-row">
          <div class="chart-label">${entry.label}</div>
          <div class="chart-track">
            <div class="${entry.className}" style="width: ${width}%"></div>
          </div>
          <div class="chart-value">${entry.bytes} B</div>
        </div>
      `;
    })
    .join('');
}

function bulletproofBytes(bits: number): number {
  return Math.round((2 * Math.log2(bits) + 9) * 32);
}

function schnorrBytes(bits: number): number {
  return bits * 64;
}

export function getAppState(): AppState {
  return appState;
}

function setAppStatus(message: string, tone: 'neutral' | 'success' | 'error' = 'neutral'): void {
  const status = document.getElementById('app-status');
  if (!status) {
    return;
  }

  status.textContent = message;
  status.className = `info-block app-status-box ${tone}`;
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
