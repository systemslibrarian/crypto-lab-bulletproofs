/**
 * Main application component for Bulletproofs demo.
 */

import { createCommitmentCard } from './ui/commitment-card';
import { createTranscriptView } from './ui/transcript-view';
import { createProofSizeChart } from './ui/proof-size-chart';
import { createVerifyPanel } from './ui/verify-panel';
import { renderBitGrid } from './ui/bit-grid';
import { identiconSvg } from './ui/identicon';
import { renderFolding } from './ui/folding-view';
import { renderStepper, type JourneyState } from './ui/stepper';
import { gloss } from './ui/glossary';
import { attachCopyButtons } from './ui/clipboard';
import { commit, getHGenerator } from './crypto/pedersen';
import {
  randomScalar,
  setDeterministicRng,
  clearDeterministicRng,
  addScalars,
  mulScalars,
  negScalar,
} from './crypto/scalar';
import type { RistrettoPointValue } from './crypto/ristretto';
import { bytesToPoint, scalarMult, addPoints, RISTRETTO_BASEPOINT } from './crypto/ristretto';
import { proveRange, verifyRange } from './proofs/range-proof';
import { verifyRangeBatched } from './proofs/batch-verify';
import {
  rangeProofByteLength,
  rangeProofComponentSizes,
  serializeRangeProof,
  deserializeRangeProof,
  bytesToHex,
  hexToBytes,
} from './proofs/serialize';
import {
  proveTrueAggregate,
  verifyTrueAggregate,
  trueAggregateByteLength,
} from './proofs/true-aggregate';
import { verifyTrueAggregateBatched } from './proofs/aggregate-batch-verify';
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
  proved: boolean;
  verified: boolean;
  /** Wall-clock prover time of the current proof, retained for re-renders. */
  lastProverMs: number | null;
}

let appState: AppState = {
  currentValue: 1337n,
  currentBlinder: randomScalar(),
  currentCommitment: null,
  currentProof: null,
  transcript: null,
  proved: false,
  verified: false,
  lastProverMs: null,
};

const MAX_AGGREGATE_VALUES = 16;
const AGGREGATE_BITS = 64;

/**
 * Initialize the main application UI.
 */
export function initializeApp(container: HTMLElement): void {
  container.innerHTML = `
    <section class="hero">
      <div class="hero-inner">
        <header class="cl-hero">
          <div class="cl-hero-main">
            <h1 class="cl-hero-title">Bulletproofs</h1>
            <p class="cl-hero-sub">Zero-knowledge range proof · no trusted setup · ristretto255</p>
            <p class="cl-hero-desc">Commit a secret value, generate a short range proof that it lies in <code>[0, 2⁶⁴)</code>, and verify it live — inspecting the Pedersen commitment, Fiat–Shamir transcript, and logarithmic inner-product argument.</p>
          </div>
          <aside class="cl-hero-why" aria-label="Why it matters">
            <span class="cl-hero-why-label">WHY IT MATTERS</span>
            <p class="cl-hero-why-text">Confidential transactions and audits need to prove an amount is valid without revealing it. Bulletproofs do this with tiny proofs and no trusted setup, so there is no toxic waste and nothing to trust but the math.</p>
          </aside>
        </header>
      </div>
    </section>
    <main id="main-content" tabindex="-1">
      <nav id="journey-stepper" class="journey-stepper" aria-label="Demo progress"></nav>
      <div id="app-status" class="app-status-box" role="status" aria-live="polite">Ready. Commit a value to start exploring the protocol.</div>

      <section class="journey" aria-labelledby="sec-flow-title">
        <div class="section-head">
          <h2 id="sec-flow-title">The core flow</h2>
          <p>Commit to a secret value, prove it is in range, then verify the proof two independent ways.</p>
        </div>
        <div class="panels">
          <div id="commitment-panel" class="step" data-step="1" aria-label="Commit a value panel"></div>
          <div id="verify-panel" class="step" data-step="2" aria-label="Verify panel"></div>
        </div>
      </section>

      <section class="journey" aria-labelledby="sec-inspect-title">
        <div class="section-head">
          <h2 id="sec-inspect-title">Look inside the proof</h2>
          <p>Every challenge is derived from the ${gloss('transcript')}, and every byte is accounted for. Inspect both.</p>
        </div>
        <div class="panels">
          <div id="transcript-panel" aria-label="Transcript panel"></div>
          <section id="introspection-panel" class="utility-panel" aria-label="Proof introspection panel"></section>
          <section id="equations-panel" class="utility-panel" aria-label="Verifier equations panel"></section>
          <section id="folding-panel" class="utility-panel" aria-label="Inner-product folding panel"></section>
        </div>
      </section>

      <section class="journey" aria-labelledby="sec-attack-title">
        <div class="section-head">
          <h2 id="sec-attack-title">Try to break it</h2>
          <p>Soundness means cheating fails. Push an out-of-range value, tamper with a finished proof, or replay it against a different commitment.</p>
        </div>
        <div class="panels">
          <section id="cheat-panel" class="utility-panel" aria-label="Cheat attempt panel"></section>
          <section id="tamper-panel" class="utility-panel" aria-label="Manual tampering panel"></section>
          <section id="replay-panel" class="utility-panel" aria-label="Replay attack panel"></section>
        </div>
      </section>

      <section class="journey" aria-labelledby="sec-advanced-title">
        <div class="section-head">
          <h2 id="sec-advanced-title">Going further</h2>
          <p>Aggregation, byte-for-byte portability, deterministic reproduction, and live timings.</p>
        </div>
        <div class="panels">
          <section id="aggregate-panel" class="utility-panel" aria-label="Aggregation panel"></section>
          <div id="chart-panel" aria-label="Proof size comparison panel"></div>
          <section id="portable-panel" class="utility-panel" aria-label="Export and import proof panel"></section>
          <section id="seed-panel" class="utility-panel" aria-label="Deterministic seed panel"></section>
          <section id="benchmark-panel" class="utility-panel" aria-label="Benchmark panel"></section>
        </div>
      </section>
    </main>
    <div class="scripture-footer" role="note" aria-label="Scope notice">
      <p><strong>Educational demo only.</strong> This is a from-scratch TypeScript implementation of Bulletproofs intended for teaching. It has not been audited and must not be used to protect real assets.</p>
    </div>
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
  const introspectionPanel = document.getElementById('introspection-panel');
  if (introspectionPanel) introspectionPanel.innerHTML = createIntrospectionPanelMarkup();
  const equationsPanel = document.getElementById('equations-panel');
  if (equationsPanel) equationsPanel.innerHTML = createEquationsPanelMarkup();
  const foldingPanel = document.getElementById('folding-panel');
  if (foldingPanel) foldingPanel.innerHTML = createFoldingPanelMarkup();
  const portablePanel = document.getElementById('portable-panel');
  if (portablePanel) portablePanel.innerHTML = createPortablePanelMarkup();
  const tamperPanel = document.getElementById('tamper-panel');
  if (tamperPanel) tamperPanel.innerHTML = createTamperPanelMarkup();
  const replayPanel = document.getElementById('replay-panel');
  if (replayPanel) replayPanel.innerHTML = createReplayPanelMarkup();
  const seedPanel = document.getElementById('seed-panel');
  if (seedPanel) seedPanel.innerHTML = createSeedPanelMarkup();
  const benchmarkPanel = document.getElementById('benchmark-panel');
  if (benchmarkPanel) benchmarkPanel.innerHTML = createBenchmarkPanelMarkup();

  // Setup initial commitment + progress stepper.
  updateCommitment();
  updateStepper();

  // Wire up events
  const valueSlider = document.getElementById('value-slider') as HTMLInputElement;
  if (valueSlider) {
    valueSlider.addEventListener('input', () => {
      appState.currentValue = BigInt(parseInt(valueSlider.value));
      updateCommitment();
    });
  }

  // Quick-value presets jump the slider to interesting bit patterns.
  document.querySelectorAll<HTMLButtonElement>('.preset-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const preset = chip.getAttribute('data-preset');
      if (!preset || !valueSlider) return;
      valueSlider.value = preset;
      appState.currentValue = BigInt(preset);
      updateCommitment();
    });
  });

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
      verifyProof(false);
    });
  }
  const verifyBatchedButton = document.getElementById('verify-batched-button');
  if (verifyBatchedButton) {
    verifyBatchedButton.addEventListener('click', () => {
      verifyProof(true);
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

  const aggregateRun = document.getElementById('aggregate-run');
  if (aggregateRun) {
    aggregateRun.addEventListener('click', () => runTrueAggregateDemo());
  }

  const exportButton = document.getElementById('export-proof');
  if (exportButton) exportButton.addEventListener('click', () => exportProof());
  const importButton = document.getElementById('import-proof');
  if (importButton) importButton.addEventListener('click', () => importProof());

  const tamperButton = document.getElementById('tamper-run');
  if (tamperButton) tamperButton.addEventListener('click', () => runTamperDemo());

  const replayButton = document.getElementById('replay-run');
  if (replayButton) replayButton.addEventListener('click', () => runReplayDemo());

  const seedApply = document.getElementById('seed-apply');
  if (seedApply) seedApply.addEventListener('click', () => applySeed());
  const seedClear = document.getElementById('seed-clear');
  if (seedClear) seedClear.addEventListener('click', () => clearSeed());

  const benchRun = document.getElementById('bench-run');
  if (benchRun) benchRun.addEventListener('click', () => runBenchmark());

  renderAggregateEstimate();
  renderProofSizeChart();
  attachCopyButtons(container);

  // WCAG 1.4.13: focus-triggered glossary tooltips must be dismissable.
  container.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const active = document.activeElement as HTMLElement | null;
    if (active && active.classList.contains('gloss')) active.blur();
  });

  // Anchor each glossary popover toward the viewport so it can't clip off-screen.
  const anchorGloss = (e: Event) => {
    const target = e.target as HTMLElement | null;
    const g = target?.closest?.('.gloss') as HTMLElement | null;
    if (g) positionGloss(g);
  };
  container.addEventListener('pointerover', anchorGloss);
  container.addEventListener('focusin', anchorGloss);
}

/** Pick a left/center/right anchor for a glossary popover based on its position. */
function positionGloss(el: HTMLElement): void {
  const pop = el.querySelector('.gloss-pop') as HTMLElement | null;
  if (!pop) return;
  el.classList.remove('gloss-left', 'gloss-right');
  const rect = el.getBoundingClientRect();
  const vw = window.innerWidth || 0;
  if (!vw) return;
  const center = rect.left + rect.width / 2;
  const popW = pop.offsetWidth || 288;
  if (center - popW / 2 < 8) el.classList.add('gloss-left');
  else if (center + popW / 2 > vw - 8) el.classList.add('gloss-right');
}

/** Re-render the journey progress stepper from current app state. */
function updateStepper(): void {
  const host = document.getElementById('journey-stepper');
  if (!host) return;
  const state: JourneyState = {
    committed: appState.currentCommitment !== null,
    proved: appState.proved,
    verified: appState.verified,
  };
  host.innerHTML = renderStepper(state);
}

/** Toggle a button into a disabled "busy" state with temporary label text. */
function setBusy(id: string, busy: boolean, busyLabel?: string): void {
  const btn = document.getElementById(id) as HTMLButtonElement | null;
  if (!btn) return;
  if (busy) {
    if (!btn.dataset.idleLabel) btn.dataset.idleLabel = btn.textContent ?? '';
    btn.disabled = true;
    btn.classList.add('is-busy');
    if (busyLabel) btn.textContent = busyLabel;
  } else {
    btn.disabled = false;
    btn.classList.remove('is-busy');
    if (btn.dataset.idleLabel) btn.textContent = btn.dataset.idleLabel;
  }
}

/** Format an integer with thousands separators. */
function fmt(n: number): string {
  return n.toLocaleString('en-US');
}

/**
 * Update the commitment display.
 */
function updateCommitment(): void {
  appState.currentBlinder = randomScalar();
  appState.currentCommitment = commit(appState.currentValue, appState.currentBlinder);

  // A new commitment invalidates any prior proof; reset the journey.
  appState.currentProof = null;
  appState.transcript = null;
  appState.proved = false;
  appState.verified = false;
  appState.lastProverMs = null;

  const valueDisplay = document.getElementById('value-display');
  if (valueDisplay) {
    valueDisplay.textContent = fmt(Number(appState.currentValue));
  }

  const fullHex = appState.currentCommitment.toHex();

  const identicon = document.getElementById('commitment-identicon');
  if (identicon) {
    identicon.innerHTML = identiconSvg(appState.currentCommitment.toBytes());
  }

  const commitmentOutput = document.getElementById('commitment-output');
  if (commitmentOutput) {
    commitmentOutput.innerHTML = `
      <div><strong>Committed value:</strong> ${fmt(Number(appState.currentValue))}</div>
      <div class="hex-row">
        <span><strong>Commitment V:</strong> <code>${fullHex.slice(0, 24)}…</code></span>
        <button type="button" class="mini-copy" data-copy-text="${fullHex}" aria-label="Copy commitment hex">Copy</button>
      </div>
    `;
    // Keep the copy text fresh and (re)wire the freshly rendered button.
    attachCopyButtons(commitmentOutput);
  }

  const bitSlot = document.getElementById('bit-grid-slot');
  if (bitSlot) {
    bitSlot.innerHTML = renderBitGrid(appState.currentValue);
  }

  resetProofUI();
  updateStepper();

  setAppStatus(`Committed value ${fmt(Number(appState.currentValue))} with a fresh random blinding factor.`);
}

/** Clear downstream proof-dependent panels when the commitment changes. */
function resetProofUI(): void {
  const introspection = document.getElementById('introspection-content');
  if (introspection) introspection.innerHTML = 'No proof has been generated yet.';
  const folding = document.getElementById('folding-content');
  if (folding) folding.innerHTML = 'Generate a proof to watch the inner-product vectors fold from 64 down to 1.';
  const evalBox = document.getElementById('equation-eval');
  if (evalBox) evalBox.innerHTML = 'Generate a proof to evaluate the equation on live values.';
  const verifyResult = document.getElementById('verify-result');
  if (verifyResult) {
    verifyResult.className = 'verify-result';
    verifyResult.textContent = 'No verification has been run yet.';
  }
  // The transcript view belongs to the previous proof — clear it too.
  const transcriptEntries = document.getElementById('transcript-entries');
  if (transcriptEntries) transcriptEntries.innerHTML = '';
  // The exported snapshot is now stale; clear it so a later "verify pasted
  // proof" can't silently re-check a proof for the old value.
  const exportOutput = document.getElementById('export-output') as HTMLTextAreaElement | null;
  if (exportOutput) exportOutput.value = '';
  const commitmentHex = document.getElementById('commitment-hex') as HTMLTextAreaElement | null;
  if (commitmentHex) commitmentHex.value = '';
  const portableResult = document.getElementById('portable-result');
  if (portableResult) portableResult.textContent = 'No proof exported or imported yet.';
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
    const t0 = performance.now();
    const proof = proveRange(
      appState.currentValue,
      appState.currentBlinder,
      appState.currentCommitment,
      transcript
    );
    const proverMs = performance.now() - t0;

    appState.currentProof = proof;
    appState.transcript = transcript;
    appState.proved = true;
    appState.verified = false;
    appState.lastProverMs = proverMs;

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

    renderIntrospection(proof, proverMs, null);
    renderFoldingView(proof);
    renderEquationEval(proof);
    updateStepper();

    const proofBytes = rangeProofByteLength(proof);
    setAppStatus(
      `Range proof generated in ${proverMs.toFixed(1)} ms. Serialized size: ${proofBytes} B (${transcript.getEntries().length} transcript events).`,
      'success'
    );
  } catch (error) {
    setAppStatus(`Error generating proof: ${formatError(error)}`, 'error');
  }
}

/**
 * Verify the current proof.
 */
function verifyProof(batched: boolean): void {
  if (!appState.currentProof || !appState.currentCommitment || !appState.transcript) {
    setAppStatus('No proof is available yet. Generate a proof before verification.', 'error');
    return;
  }

  try {
    // Create a fresh transcript for verification
    const verifyTranscript = new Transcript('bulletproofs-demo');
    const t0 = performance.now();
    const isValid = batched
      ? verifyRangeBatched(appState.currentProof, appState.currentCommitment, verifyTranscript)
      : verifyRange(appState.currentProof, appState.currentCommitment, verifyTranscript);
    const verifierMs = performance.now() - t0;
    const label = batched ? 'single-MSM verifier' : 'reference verifier';

    renderIntrospection(appState.currentProof, appState.lastProverMs, verifierMs);

    const verifyResult = document.getElementById('verify-result');
    if (verifyResult) {
      if (isValid) {
        appState.verified = true;
        updateStepper();
        verifyResult.className = 'verify-result success pulse';
        verifyResult.innerHTML = `<strong>✓ ${label} accepted</strong> in ${verifierMs.toFixed(1)} ms.`;
        setAppStatus(`${label} accepted the current proof in ${verifierMs.toFixed(1)} ms.`, 'success');
      } else {
        verifyResult.className = 'verify-result failure';
        verifyResult.innerHTML = `<strong>✗ ${label} rejected the proof.</strong>`;
        setAppStatus(`${label} rejected the current proof.`, 'error');
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
    <h3>Batched Proofs</h3>
    <p class="panel-copy">This demo runs the single-value protocol once per value, bound to a shared transcript. The bars below contrast that with what a true Bulletproofs aggregate would cost in theory. Use the button to also run a real aggregated proof for power-of-two batch sizes.</p>
    <div class="control-group stack-on-mobile">
      <label for="aggregate-count">Values:</label>
      <input id="aggregate-count" type="range" min="1" max="${MAX_AGGREGATE_VALUES}" value="4" aria-describedby="aggregate-count-value" />
      <output id="aggregate-count-value" for="aggregate-count">4</output>
    </div>
    <div id="aggregate-summary" class="info-block" role="status" aria-live="polite"></div>
    <div class="button-row" style="margin-top: 1rem;">
      <button id="aggregate-run" type="button">Run true aggregated proof</button>
    </div>
    <div id="aggregate-run-result" class="info-block" role="status" aria-live="polite">No aggregated proof has been run yet.</div>
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
    <div><strong>This demo (batched, ${count} × single proofs):</strong> ${nonAggregatedBytes} bytes</div>
    <div><strong>True aggregated Bulletproof (theoretical):</strong> ${aggregatedBytes} bytes</div>
    <div><strong>Naive disjunctive Schnorr (theoretical):</strong> ${naiveBytes} bytes</div>
    <div><strong>Bytes a true aggregate would save vs this demo:</strong> ${savedBytes}</div>
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
      label: `This demo (batched ${count} × 64-bit)`,
      bytes: bulletproofBytes(AGGREGATE_BITS) * count,
      className: 'chart-bar standard',
    },
    {
      label: 'True aggregated Bulletproof (theoretical)',
      bytes: bulletproofBytes(AGGREGATE_BITS * count),
      className: 'chart-bar aggregate',
    },
    {
      label: 'Naive disjunctive Schnorr (theoretical)',
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

function createIntrospectionPanelMarkup(): string {
  return `
    <h3>Proof Introspection</h3>
    <p class="panel-copy">Generate a proof to inspect the Fiat-Shamir challenges, the per-component byte breakdown, and prover/verifier wall-clock times.</p>
    <div id="introspection-content" class="info-block" role="status" aria-live="polite">No proof has been generated yet.</div>
  `;
}

function shortHex(value: bigint, prefixChars = 12): string {
  const hex = value.toString(16);
  if (hex.length <= prefixChars * 2 + 1) return hex;
  return `${hex.slice(0, prefixChars)}...${hex.slice(-prefixChars)}`;
}

function renderIntrospection(
  proof: RangeProof,
  proverMs: number | null,
  verifierMs: number | null
): void {
  const target = document.getElementById('introspection-content');
  if (!target) return;

  const totalBytes = rangeProofByteLength(proof);
  const components = rangeProofComponentSizes(proof);
  const componentRows = components
    .map((c) => `<div>&nbsp;&nbsp;<span>${c.label}</span>: <strong>${c.bytes} B</strong></div>`)
    .join('');

  const ch = proof.challenges;
  const challengeRows = ch
    ? `
      <div>&nbsp;&nbsp;y = <code>${shortHex(ch.y)}</code></div>
      <div>&nbsp;&nbsp;z = <code>${shortHex(ch.z)}</code></div>
      <div>&nbsp;&nbsp;x = <code>${shortHex(ch.x)}</code></div>
    `
    : '<div>&nbsp;&nbsp;(challenges unavailable)</div>';

  const ipaRounds = proof.ipa_proof.L.length;

  const proverLine =
    proverMs !== null ? `<div><strong>Prover time:</strong> ${proverMs.toFixed(1)} ms</div>` : '';
  const verifierLine =
    verifierMs !== null ? `<div><strong>Verifier time:</strong> ${verifierMs.toFixed(1)} ms</div>` : '';

  const fullBytes = serializeRangeProof(proof);
  const fullHex = bytesToHex(fullBytes);
  const sampleHex = fullHex.slice(0, 32);

  target.innerHTML = `
    <div><strong>Serialized proof size:</strong> ${totalBytes} B (${ipaRounds} IPA rounds for n=64)</div>
    <div><strong>Component breakdown:</strong></div>
    ${componentRows}
    <div><strong>Fiat-Shamir challenges:</strong></div>
    ${challengeRows}
    ${proverLine}
    ${verifierLine}
    <div class="hex-row"><span><strong>First 16 bytes:</strong> <code>${sampleHex}</code></span><button type="button" class="mini-copy" data-copy-text="${fullHex}" aria-label="Copy full proof hex">Copy all</button></div>
  `;
  attachCopyButtons(target);
}

function createEquationsPanelMarkup(): string {
  return `
    <h3>What the Verifier Checks</h3>
    <p class="panel-copy">A 64-bit Bulletproof verifier accepts only when these two equations both hold over ristretto255.</p>
    <div class="info-block">
      <div><strong>(1) Polynomial identity at challenge x:</strong></div>
      <div><code>t̂·g + τₓ·h  ?=  z²·V + δ(y,z)·g + x·T₁ + x²·T₂</code></div>
      <div class="panel-copy" style="margin-top: 0.5rem;">Proves t̂ = t(x) for the committed quadratic t(X) and that V opens to the claimed value with blinding γ.</div>
    </div>
    <div class="info-block" style="margin-top: 0.75rem;">
      <div><strong>(2) Inner-product argument over basis (G, H'):</strong></div>
      <div><code>P' = A + x·S + ⟨−z·1ⁿ, G⟩ + ⟨z·yⁿ + z²·2ⁿ, H'⟩ − μ·h + t̂·u</code></div>
      <div class="panel-copy" style="margin-top: 0.5rem;">The IPA then proves knowledge of l, r with ⟨l,r⟩ = t̂ in O(log n) rounds, giving the log-size proof.</div>
    </div>
    <div class="info-block" style="margin-top: 0.75rem;">
      <div><strong>Why cheating fails:</strong> z, y, x are derived from the ${gloss('transcript')} via ${gloss('Fiat–Shamir')}, so a malicious prover cannot pick them. Any tampered field changes the reconstructed P' or breaks equation (1), and the verifier rejects.</div>
    </div>
    <div style="margin-top: 0.75rem;"><strong>Live evaluation of equation (1):</strong></div>
    <div id="equation-eval" class="info-block" role="status" aria-live="polite" style="margin-top: 0.5rem;">Generate a proof to evaluate the equation on live values.</div>
  `;
}

function createFoldingPanelMarkup(): string {
  return `
    <h3>Inner-product folding</h3>
    <p class="panel-copy">The ${gloss('inner-product argument')} is where the proof goes logarithmic: the two 64-length vectors halve each round until only two scalars remain.</p>
    <div id="folding-content" class="info-block" role="status" aria-live="polite">Generate a proof to watch the inner-product vectors fold from 64 down to 1.</div>
  `;
}

function renderFoldingView(proof: RangeProof): void {
  const target = document.getElementById('folding-content');
  if (!target) return;
  target.innerHTML = renderFolding(proof.ipa_proof);
}

/** Local power-vector and δ(y,z), mirroring range-proof.ts, for live display. */
function powerVec(base: bigint, n: number): bigint[] {
  const out: bigint[] = new Array(n);
  let acc = 1n;
  for (let i = 0; i < n; i++) {
    out[i] = acc;
    acc = mulScalars(acc, base);
  }
  return out;
}

function deltaYZ(z: bigint, yPow: bigint[], twoPow: bigint[]): bigint {
  const z2 = mulScalars(z, z);
  const z3 = mulScalars(z2, z);
  const sumYn = yPow.reduce((a, v) => addScalars(a, v), 0n);
  const sumTwoN = twoPow.reduce((a, v) => addScalars(a, v), 0n);
  const term1 = mulScalars(addScalars(z, negScalar(z2)), sumYn);
  const term2 = mulScalars(z3, sumTwoN);
  return addScalars(term1, negScalar(term2));
}

/**
 * Recompute verifier equation (1) on the live proof and commitment and show
 * both sides plus the match result. This uses only public proof fields,
 * the commitment V, and the Fiat–Shamir challenges — exactly what a verifier has.
 *
 *   t̂·g + τₓ·h  ?=  z²·V + δ(y,z)·g + x·T₁ + x²·T₂
 */
function renderEquationEval(proof: RangeProof): void {
  const target = document.getElementById('equation-eval');
  if (!target) return;
  if (!proof.challenges || !appState.currentCommitment) {
    target.innerHTML = 'Equation evaluation unavailable for this proof.';
    return;
  }

  const { y, z, x } = proof.challenges;
  const V = appState.currentCommitment;
  const g = RISTRETTO_BASEPOINT;
  const h = getHGenerator();
  const yPow = powerVec(y, 64);
  const twoPow = powerVec(2n, 64);
  const z2 = mulScalars(z, z);
  const xx = mulScalars(x, x);
  const d = deltaYZ(z, yPow, twoPow);

  const lhs = addPoints(scalarMult(proof.t_hat, g), scalarMult(proof.tau_x, h));
  const rhs = addPoints(
    addPoints(scalarMult(z2, V), scalarMult(d, g)),
    addPoints(scalarMult(x, proof.T1), scalarMult(xx, proof.T2))
  );
  const match = lhs.equals(rhs);

  target.innerHTML = `
    <div>&nbsp;&nbsp;LHS = t̂·g + τₓ·h = <code>${lhs.toHex().slice(0, 24)}…</code></div>
    <div>&nbsp;&nbsp;RHS = z²·V + δ(y,z)·g + x·T₁ + x²·T₂ = <code>${rhs.toHex().slice(0, 24)}…</code></div>
    <div>&nbsp;&nbsp;δ(y,z) = <code>${shortHex(d)}</code></div>
    <div class="eval-verdict ${match ? 'ok' : 'bad'}">${match ? '✓ LHS = RHS — equation (1) holds on the live points.' : '✗ LHS ≠ RHS — the equation fails.'}</div>
  `;
}

function createReplayPanelMarkup(): string {
  return `
    <h3>Replay attack</h3>
    <p class="panel-copy">A proof is bound to its commitment. Take the current valid proof and verify it against a <em>different</em>, freshly committed value &mdash; it must be rejected. Generate a proof first.</p>
    <button id="replay-run" type="button">Replay against a new commitment</button>
    <div id="replay-result" class="info-block" role="status" aria-live="polite" style="margin-top: 0.5rem;">No replay attempted yet.</div>
  `;
}

function runReplayDemo(): void {
  const result = document.getElementById('replay-result');
  if (!result) return;
  if (!appState.currentProof) {
    result.innerHTML = '<div><strong>No proof yet.</strong> Click <em>Generate Range Proof</em> first.</div>';
    return;
  }

  // A fresh, unrelated commitment to a different value + blinder.
  const otherValue = (appState.currentValue + 4242n) % (1n << 24n);
  const otherBlinder = randomScalar();
  const otherCommitment = commit(otherValue, otherBlinder);

  let accepted = true;
  let err = '';
  try {
    accepted = verifyRange(appState.currentProof, otherCommitment, new Transcript('bulletproofs-demo'));
  } catch (e) {
    accepted = false;
    err = formatError(e);
  }

  result.innerHTML = `
    <div><strong>Original proof:</strong> the one you just generated</div>
    <div><strong>Replayed against:</strong> a fresh commitment to ${fmt(Number(otherValue))} (<code>${otherCommitment.toHex().slice(0, 16)}…</code>)</div>
    <div class="eval-verdict ${accepted ? 'bad' : 'ok'}">${accepted ? '✗ UNEXPECTEDLY accepted — this must never happen.' : '✓ Rejected — the proof only validates its own commitment.'} ${err ? `(${err})` : ''}</div>
  `;
  setAppStatus(
    accepted ? 'Replay attack unexpectedly accepted.' : 'Replay attack rejected: proof is bound to its commitment.',
    accepted ? 'error' : 'success'
  );
}

function createPortablePanelMarkup(): string {
  return `
    <h3>Export &amp; Import Proof</h3>
    <p class="panel-copy">A non-interactive proof is just bytes. Export the current proof + commitment as hex, paste them into another browser, and verify — no prover state required.</p>
    <div class="button-row">
      <button id="export-proof" type="button">Export current proof</button>
      <button id="import-proof" type="button">Verify pasted proof</button>
    </div>
    <label for="commitment-hex" class="panel-copy" style="display:block; margin-top:0.75rem;"><strong>Commitment (hex, 32 B):</strong></label>
    <textarea id="commitment-hex" rows="2" style="width:100%; font-family:monospace; font-size:0.8rem;" placeholder="paste commitment hex"></textarea>
    <label for="export-output" class="panel-copy" style="display:block; margin-top:0.5rem;"><strong>Proof (hex, 672 B):</strong></label>
    <textarea id="export-output" rows="6" style="width:100%; font-family:monospace; font-size:0.8rem;" placeholder="paste proof hex"></textarea>
    <div id="portable-result" class="info-block" role="status" aria-live="polite" style="margin-top:0.75rem;">No proof exported or imported yet.</div>
  `;
}

function exportProof(): void {
  const output = document.getElementById('export-output') as HTMLTextAreaElement | null;
  const commitmentBox = document.getElementById('commitment-hex') as HTMLTextAreaElement | null;
  const result = document.getElementById('portable-result');
  if (!output || !commitmentBox || !result) return;

  if (!appState.currentProof || !appState.currentCommitment) {
    result.innerHTML = '<div>Generate a proof first.</div>';
    return;
  }

  const proofHex = bytesToHex(serializeRangeProof(appState.currentProof));
  const commitmentHex = appState.currentCommitment.toHex();
  output.value = proofHex;
  commitmentBox.value = commitmentHex;
  result.innerHTML = `<div>Exported ${proofHex.length / 2} B proof and ${commitmentHex.length / 2} B commitment. Copy them anywhere.</div>`;
}

function importProof(): void {
  const output = document.getElementById('export-output') as HTMLTextAreaElement | null;
  const commitmentBox = document.getElementById('commitment-hex') as HTMLTextAreaElement | null;
  const result = document.getElementById('portable-result');
  if (!output || !commitmentBox || !result) return;

  try {
    const proofBytes = hexToBytes(output.value);
    const commitmentBytes = hexToBytes(commitmentBox.value);
    if (commitmentBytes.length !== 32) throw new Error('Commitment must be 32 bytes');
    // n=64 -> 6 IPA rounds.
    const proof = deserializeRangeProof(proofBytes, 6);
    const V = bytesToPoint(commitmentBytes);
    const t0 = performance.now();
    const accepted = verifyRange(proof, V, new Transcript('bulletproofs-demo'));
    const ms = performance.now() - t0;
    result.innerHTML = accepted
      ? `<div><strong>✓ Verifier accepted</strong> the imported proof in ${ms.toFixed(1)} ms.</div>`
      : `<div><strong>✗ Verifier rejected</strong> the imported proof.</div>`;
  } catch (e) {
    result.innerHTML = `<div><strong>Import failed:</strong> ${formatError(e)}</div>`;
  }
}

function runTrueAggregateDemo(): void {
  const result = document.getElementById('aggregate-run-result');
  const aggregateCount = document.getElementById('aggregate-count') as HTMLInputElement | null;
  if (!result || !aggregateCount) return;

  const requested = Number.parseInt(aggregateCount.value, 10);
  // Snap to the largest power of two ≤ requested (and ≥ 1).
  let m = 1;
  while (m * 2 <= requested) m *= 2;

  const values = Array.from({ length: m }, (_, i) => BigInt((i * 7919) % 1000) + 1n);
  const blinders = values.map(() => randomScalar());
  const V = values.map((v, i) => commit(v, blinders[i]));

  let proverMs = 0, verifierRefMs = 0, verifierMsmMs = 0;
  let acceptedRef = false, acceptedMsm = false, bytes = 0;
  let error = '';
  try {
    const tProver = performance.now();
    const proof = proveTrueAggregate(values, blinders, V, new Transcript('agg-demo'));
    proverMs = performance.now() - tProver;
    bytes = trueAggregateByteLength(proof);

    const tRef = performance.now();
    acceptedRef = verifyTrueAggregate(proof, V, new Transcript('agg-demo'));
    verifierRefMs = performance.now() - tRef;

    const tMsm = performance.now();
    acceptedMsm = verifyTrueAggregateBatched(proof, V, new Transcript('agg-demo'));
    verifierMsmMs = performance.now() - tMsm;
  } catch (e) {
    error = formatError(e);
  }

  if (error) {
    result.innerHTML = `<div><strong>Failed:</strong> ${error}</div>`;
    return;
  }

  const batched = 672 * m;
  const savedVsBatched = batched - bytes;

  result.innerHTML = `
    <div><strong>Batch size used:</strong> ${m} (snapped from ${requested} to nearest power of two)</div>
    <div><strong>Single aggregated proof size:</strong> ${bytes} B</div>
    <div><strong>Equivalent batched (m × 672 B):</strong> ${batched} B</div>
    <div><strong>Bytes saved by aggregation:</strong> ${savedVsBatched} B</div>
    <div><strong>Prover time:</strong> ${proverMs.toFixed(1)} ms</div>
    <div><strong>Reference verifier:</strong> ${verifierRefMs.toFixed(1)} ms — ${acceptedRef ? '✓ accepted' : '✗ rejected'}</div>
    <div><strong>Single-MSM verifier:</strong> ${verifierMsmMs.toFixed(1)} ms — ${acceptedMsm ? '✓ accepted' : '✗ rejected'}</div>
  `;

  setAppStatus(
    `True aggregated proof for ${m} values: ${bytes} B vs ${batched} B batched.`,
    acceptedRef && acceptedMsm ? 'success' : 'error'
  );
}

function createTamperPanelMarkup(): string {
  return `
    <h3>Manual tampering</h3>
    <p>Flip one bit in <code>t̂</code> of the most recent single-value proof and watch both verifiers reject. Generate a proof first.</p>
    <button id="tamper-run" type="button">Tamper t̂ and re-verify</button>
    <div id="tamper-result" class="info-block" style="margin-top: 0.5rem;">No tampering attempted yet.</div>
  `;
}

function runTamperDemo(): void {
  const result = document.getElementById('tamper-result');
  if (!result) return;
  if (!appState.currentProof || !appState.currentCommitment) {
    result.innerHTML = '<div><strong>No proof yet.</strong> Click <em>Generate proof</em> first.</div>';
    return;
  }
  const original = appState.currentProof;
  const V = appState.currentCommitment;
  const tampered: RangeProof = { ...original, t_hat: addScalars(original.t_hat, 1n) };
  // Must match the domain the live proof was generated with (generateProof),
  // otherwise the verifier would reject for the wrong reason (mismatched
  // challenges) rather than because of the tamper.
  let refOk = true, msmOk = true, refErr = '', msmErr = '';
  try { refOk = verifyRange(tampered, V, new Transcript('bulletproofs-demo')); }
  catch (e) { refOk = false; refErr = formatError(e); }
  try { msmOk = verifyRangeBatched(tampered, V, new Transcript('bulletproofs-demo')); }
  catch (e) { msmOk = false; msmErr = formatError(e); }
  result.innerHTML = `
    <div><strong>Mutation:</strong> t̂ → t̂ + 1 (mod ℓ)</div>
    <div><strong>Reference verifier:</strong> ${refOk ? '✗ INCORRECTLY accepted' : '✓ rejected'} ${refErr ? `(${refErr})` : ''}</div>
    <div><strong>Single-MSM verifier:</strong> ${msmOk ? '✗ INCORRECTLY accepted' : '✓ rejected'} ${msmErr ? `(${msmErr})` : ''}</div>
    <div style="margin-top:0.5rem; color: var(--text-muted);">A single bit flip breaks the inner-product equation, so honest verifiers always reject.</div>
  `;
}

function createSeedPanelMarkup(): string {
  return `
    <h3>Deterministic seed</h3>
    <p>Replace <code>crypto.getRandomValues</code> with a SHA-512 counter PRNG so blinders and proofs are reproducible. Useful for teaching and testing only — never in production.</p>
    <label for="seed-value" style="display:block; margin-bottom:0.25rem;">Seed string</label>
    <input id="seed-value" type="text" value="bulletproofs-demo" style="width:100%; max-width: 360px; margin-bottom: 0.5rem;" />
    <div>
      <button id="seed-apply" type="button">Apply seed</button>
      <button id="seed-clear" type="button">Use crypto RNG</button>
    </div>
    <div id="seed-status" class="info-block" style="margin-top: 0.5rem;">RNG: <code>crypto.getRandomValues</code></div>
  `;
}

function applySeed(): void {
  const input = document.getElementById('seed-value') as HTMLInputElement | null;
  const status = document.getElementById('seed-status');
  if (!input || !status) return;
  const seed = input.value || 'bulletproofs-demo';
  setDeterministicRng(seed);
  updateCommitment();
  status.innerHTML = `RNG: <strong>deterministic</strong> (seed = <code>${escapeHtml(seed)}</code>). Generate a proof to see reproducible bytes.`;
}

function clearSeed(): void {
  const status = document.getElementById('seed-status');
  clearDeterministicRng();
  updateCommitment();
  if (status) status.innerHTML = 'RNG: <code>crypto.getRandomValues</code>';
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

function createBenchmarkPanelMarkup(): string {
  return `
    <h3>Benchmark</h3>
    <p>Times prover and both verifiers for the single-value proof and the true aggregated proof at <em>m</em> = 1, 2, 4, 8.</p>
    <button id="bench-run" type="button">Run benchmark</button>
    <div id="bench-result" class="info-block" style="margin-top: 0.5rem;">Click the button above. May take a few seconds.</div>
  `;
}

function runBenchmark(): void {
  const result = document.getElementById('bench-result');
  if (!result) return;
  result.innerHTML = '<div>Running…</div>';
  setBusy('bench-run', true, 'Running…');
  // Defer so the UI can repaint.
  setTimeout(() => {
    try {
      const rows: string[] = [];
      rows.push('<tr><th style="text-align:left;">Configuration</th><th>Size (B)</th><th>Prove (ms)</th><th>Verify ref (ms)</th><th>Verify MSM (ms)</th></tr>');

      // Single-value
      {
        const v = 12345n;
        const r = randomScalar();
        const V = commit(v, r);
        const tP = performance.now();
        const proof = proveRange(v, r, V, new Transcript('bench'));
        const proveMs = performance.now() - tP;
        const tR = performance.now();
        verifyRange(proof, V, new Transcript('bench'));
        const verRefMs = performance.now() - tR;
        const tM = performance.now();
        verifyRangeBatched(proof, V, new Transcript('bench'));
        const verMsmMs = performance.now() - tM;
        rows.push(`<tr><td>single value (n=64)</td><td>${rangeProofByteLength(proof)}</td><td>${proveMs.toFixed(1)}</td><td>${verRefMs.toFixed(1)}</td><td>${verMsmMs.toFixed(1)}</td></tr>`);
      }

      // Aggregate m = 1, 2, 4, 8
      for (const m of [1, 2, 4, 8]) {
        const values = Array.from({ length: m }, (_, i) => BigInt((i * 7919) % 1000) + 1n);
        const blinders = values.map(() => randomScalar());
        const V = values.map((vi, i) => commit(vi, blinders[i]));
        const tP = performance.now();
        const proof = proveTrueAggregate(values, blinders, V, new Transcript('bench-agg'));
        const proveMs = performance.now() - tP;
        const tR = performance.now();
        verifyTrueAggregate(proof, V, new Transcript('bench-agg'));
        const verRefMs = performance.now() - tR;
        const tM = performance.now();
        verifyTrueAggregateBatched(proof, V, new Transcript('bench-agg'));
        const verMsmMs = performance.now() - tM;
        rows.push(`<tr><td>aggregate m=${m}</td><td>${trueAggregateByteLength(proof)}</td><td>${proveMs.toFixed(1)}</td><td>${verRefMs.toFixed(1)}</td><td>${verMsmMs.toFixed(1)}</td></tr>`);
      }

      result.innerHTML = `<table style="border-collapse: collapse; width: 100%;">${rows.join('')}</table>`;
    } catch (e) {
      result.innerHTML = `<div><strong>Failed:</strong> ${formatError(e)}</div>`;
    } finally {
      setBusy('bench-run', false);
    }
  }, 30);
}
