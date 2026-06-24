/**
 * Headless smoke test for the redesigned UI: mounts the real app into a
 * linkedom DOM, exercises the core commit → prove → verify flow, and the
 * cheat / tamper / export paths, asserting the wired elements exist and respond.
 */
import { parseHTML } from 'linkedom';

const { window, document } = parseHTML(`<!doctype html><html><body><div id="app"></div></body></html>`);

// Minimal browser globals the app/crypto expect.
globalThis.window = window;
globalThis.document = document;
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.performance = globalThis.performance ?? { now: () => 0 };
// linkedom has no clipboard; stub a capturing one so copy buttons are testable.
// Node exposes `navigator` as a read-only global, so define the property on it.
let lastCopied = null;
const clipboardStub = { writeText: async (t) => { lastCopied = t; } };
if (typeof globalThis.navigator === 'undefined') {
  Object.defineProperty(globalThis, 'navigator', { value: { clipboard: clipboardStub }, configurable: true });
} else {
  Object.defineProperty(globalThis.navigator, 'clipboard', { value: clipboardStub, configurable: true });
}
document.documentElement.setAttribute('data-theme', 'dark');

const { initializeApp } = await import('../src/app.ts');

let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) { pass++; console.log('PASS:', msg); } else { fail++; console.log('FAIL:', msg); } };

initializeApp(document.getElementById('app'));

// Structure: every wired id present.
const ids = [
  'value-slider', 'prove-button', 'verify-button', 'verify-batched-button',
  'aggregate-count', 'aggregate-run', 'cheat-upper', 'cheat-negative',
  'export-proof', 'import-proof', 'tamper-run', 'replay-run', 'seed-apply', 'seed-clear',
  'bench-run', 'app-status', 'transcript-entries', 'introspection-content',
  'journey-stepper', 'commitment-identicon', 'bit-grid-slot', 'folding-content',
  'equation-eval', 'replay-result',
];
for (const id of ids) ok(document.getElementById(id), `element #${id} mounted`);

// No duplicate banner / leftover theme toggle.
ok(!document.getElementById('theme-toggle'), 'in-page theme toggle removed');
ok(document.querySelector('.hero h1'), 'hero title present');
ok(document.querySelectorAll('.step[data-step]').length === 2, 'two numbered step cards');

// Narrative scaffolding: stepper + glossary tooltips present.
ok(document.querySelectorAll('.stepper-step').length === 4, 'four-step progress stepper rendered');
ok(document.querySelectorAll('.gloss').length > 0, 'glossary tooltips rendered');

// Visual intuition: bit grid + identicon render for the initial commitment.
ok(document.querySelectorAll('#bit-grid-slot .bit-cell').length === 64, '64 bit cells rendered');
ok(document.querySelector('#commitment-identicon svg'), 'commitment identicon SVG rendered');

// Core flow: commit (slider input) → prove → verify.
const slider = document.getElementById('value-slider');
slider.value = '4242';
slider.dispatchEvent(new window.Event('input'));
ok(document.getElementById('value-display').textContent === '4,242', 'slider updates committed value');
ok(document.querySelectorAll('#bit-grid-slot .bit-cell.on').length > 0, 'bit grid lights up set bits');

document.getElementById('prove-button').dispatchEvent(new window.Event('click'));
const introspection = document.getElementById('introspection-content').textContent;
ok(/Serialized proof size/.test(introspection), 'prove populates introspection');
ok(document.querySelectorAll('#transcript-entries li').length > 0, 'transcript entries rendered');
ok(document.querySelectorAll('#folding-content .fold-row').length === 6, 'IPA folding shows 6 rounds');
ok(/LHS = RHS/.test(document.getElementById('equation-eval').textContent), 'live equation (1) holds on real points');
ok(document.querySelector('.stepper-step.done'), 'stepper marks a step done after proving');

document.getElementById('verify-button').dispatchEvent(new window.Event('click'));
ok(/accepted/i.test(document.getElementById('verify-result').textContent), 'reference verifier accepts honest proof');

document.getElementById('verify-batched-button').dispatchEvent(new window.Event('click'));
ok(/accepted/i.test(document.getElementById('verify-result').textContent), 'single-MSM verifier accepts honest proof');

// Attack paths reject.
document.getElementById('tamper-run').dispatchEvent(new window.Event('click'));
ok(/rejected/i.test(document.getElementById('tamper-result').textContent), 'tampered proof rejected');

document.getElementById('cheat-upper').dispatchEvent(new window.Event('click'));
ok(/rejected|aborted/i.test(document.getElementById('cheat-result').textContent), 'cheat attempt rejected');

document.getElementById('replay-run').dispatchEvent(new window.Event('click'));
ok(/rejected/i.test(document.getElementById('replay-result').textContent), 'replay against new commitment rejected');

// Copy-to-clipboard wiring writes the full proof hex to the stub clipboard.
const copyBtn = document.querySelector('#introspection-content .mini-copy');
ok(copyBtn, 'copy-proof button present');
copyBtn.dispatchEvent(new window.Event('click'));
await Promise.resolve();
ok(lastCopied && /^[0-9a-f]+$/.test(lastCopied) && lastCopied.length === 672 * 2, 'copy writes full 672 B proof hex');

// Export round-trips.
document.getElementById('export-proof').dispatchEvent(new window.Event('click'));
const exported = document.getElementById('export-output').value;
ok(exported.length > 0 && /^[0-9a-f]+$/.test(exported), 'export produces hex bytes');
document.getElementById('import-proof').dispatchEvent(new window.Event('click'));
ok(/accepted/i.test(document.getElementById('portable-result').textContent), 'exported proof re-verifies on import');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
