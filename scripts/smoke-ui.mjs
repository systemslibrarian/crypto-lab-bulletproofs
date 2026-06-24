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
document.documentElement.setAttribute('data-theme', 'dark');

const { initializeApp } = await import('../src/app.ts');

let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) { pass++; console.log('PASS:', msg); } else { fail++; console.log('FAIL:', msg); } };

initializeApp(document.getElementById('app'));

// Structure: every wired id present.
const ids = [
  'value-slider', 'prove-button', 'verify-button', 'verify-batched-button',
  'aggregate-count', 'aggregate-run', 'cheat-upper', 'cheat-negative',
  'export-proof', 'import-proof', 'tamper-run', 'seed-apply', 'seed-clear',
  'bench-run', 'app-status', 'transcript-entries', 'introspection-content',
];
for (const id of ids) ok(document.getElementById(id), `element #${id} mounted`);

// No duplicate banner / leftover theme toggle.
ok(!document.getElementById('theme-toggle'), 'in-page theme toggle removed');
ok(document.querySelector('.hero h1'), 'hero title present');
ok(document.querySelectorAll('.step[data-step]').length === 2, 'two numbered step cards');

// Core flow: commit (slider input) → prove → verify.
const slider = document.getElementById('value-slider');
slider.value = '4242';
slider.dispatchEvent(new window.Event('input'));
ok(document.getElementById('value-display').textContent === '4242', 'slider updates committed value');

document.getElementById('prove-button').dispatchEvent(new window.Event('click'));
const introspection = document.getElementById('introspection-content').textContent;
ok(/Serialized proof size/.test(introspection), 'prove populates introspection');
ok(document.querySelectorAll('#transcript-entries li').length > 0, 'transcript entries rendered');

document.getElementById('verify-button').dispatchEvent(new window.Event('click'));
ok(/accepted/i.test(document.getElementById('verify-result').textContent), 'reference verifier accepts honest proof');

document.getElementById('verify-batched-button').dispatchEvent(new window.Event('click'));
ok(/accepted/i.test(document.getElementById('verify-result').textContent), 'single-MSM verifier accepts honest proof');

// Attack paths reject.
document.getElementById('tamper-run').dispatchEvent(new window.Event('click'));
ok(/rejected/i.test(document.getElementById('tamper-result').textContent), 'tampered proof rejected');

document.getElementById('cheat-upper').dispatchEvent(new window.Event('click'));
ok(/rejected|aborted/i.test(document.getElementById('cheat-result').textContent), 'cheat attempt rejected');

// Export round-trips.
document.getElementById('export-proof').dispatchEvent(new window.Event('click'));
const exported = document.getElementById('export-output').value;
ok(exported.length > 0 && /^[0-9a-f]+$/.test(exported), 'export produces hex bytes');
document.getElementById('import-proof').dispatchEvent(new window.Event('click'));
ok(/accepted/i.test(document.getElementById('portable-result').textContent), 'exported proof re-verifies on import');

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
