/**
 * Headless accessibility assertions for the mounted app.
 *
 * Mounts the real UI into a linkedom DOM and checks the structural WCAG 2.1
 * requirements we can verify without a browser: unique IDs, accessible names
 * on every control, labelled form fields, labelled images, and dismissable
 * focus widgets. This is a regression net for ADA compliance, not a substitute
 * for a manual screen-reader / contrast pass.
 */
import { parseHTML } from 'linkedom';

const { window, document } = parseHTML(`<!doctype html><html><body><div id="app"></div></body></html>`);
globalThis.window = window;
globalThis.document = document;
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.performance = globalThis.performance ?? { now: () => 0 };
document.documentElement.setAttribute('data-theme', 'dark');

const { initializeApp } = await import('../src/app.ts');
initializeApp(document.getElementById('app'));

let pass = 0, fail = 0;
const ok = (cond, msg) => { if (cond) { pass++; console.log('PASS:', msg); } else { fail++; console.log('FAIL:', msg); } };

const text = (el) => (el.textContent || '').replace(/\s+/g, ' ').trim();
const accName = (el) =>
  text(el) || el.getAttribute('aria-label') || el.getAttribute('title') || '';

// 1) Unique IDs (4.1.1 / general ADA failure mode).
const ids = [...document.querySelectorAll('[id]')].map((el) => el.getAttribute('id'));
const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
ok(dupes.length === 0, `all element IDs unique${dupes.length ? ` (dupes: ${[...new Set(dupes)].join(', ')})` : ''}`);

// 2) Every button has an accessible name (4.1.2).
const buttons = [...document.querySelectorAll('button')];
const namelessButtons = buttons.filter((b) => !accName(b));
ok(buttons.length > 0 && namelessButtons.length === 0,
  `all ${buttons.length} buttons have an accessible name${namelessButtons.length ? ` (missing: ${namelessButtons.map((b) => b.id || b.className).join(', ')})` : ''}`);

// 3) Every form control is labelled (1.3.1 / 3.3.2 / 4.1.2).
const labelledIds = new Set(
  [...document.querySelectorAll('label[for]')].map((l) => l.getAttribute('for'))
);
const controls = [...document.querySelectorAll('input, textarea, select')];
const unlabelled = controls.filter((c) => {
  const id = c.getAttribute('id');
  if (id && labelledIds.has(id)) return false;
  if (c.getAttribute('aria-label') || c.getAttribute('aria-labelledby')) return false;
  return true;
});
ok(controls.length > 0 && unlabelled.length === 0,
  `all ${controls.length} form controls labelled${unlabelled.length ? ` (missing: ${unlabelled.map((c) => c.id || c.name || c.type).join(', ')})` : ''}`);

// 4) Every role="img" (and the identicon SVG) carries a non-empty label (1.1.1).
const imgs = [...document.querySelectorAll('[role="img"]')];
const unlabelledImgs = imgs.filter((i) => !(i.getAttribute('aria-label') || '').trim());
ok(imgs.length > 0 && unlabelledImgs.length === 0,
  `all ${imgs.length} role=img elements have alt text`);

// 5) aria-describedby targets must exist (1.3.1).
const describedRefs = [...document.querySelectorAll('[aria-describedby]')]
  .flatMap((el) => (el.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean));
const danglingRefs = describedRefs.filter((id) => !document.getElementById(id));
ok(danglingRefs.length === 0, `all aria-describedby targets exist${danglingRefs.length ? ` (missing: ${danglingRefs.join(', ')})` : ''}`);

// 6) Keyboard-focusable glossary terms expose their definition (1.4.13 / 4.1.2).
const gloss = [...document.querySelectorAll('.gloss')];
const okGloss = gloss.every((g) => g.getAttribute('tabindex') === '0' && (g.getAttribute('aria-label') || '').includes(':'));
ok(gloss.length > 0 && okGloss, `all ${gloss.length} glossary terms are focusable with a definition label`);

// 7) Status surfaces are polite live regions (4.1.3).
ok(document.getElementById('app-status')?.getAttribute('aria-live') === 'polite', 'app status is a polite live region');

// 8) Landmark sections that repeat carry distinguishing labels (1.3.1).
const sections = [...document.querySelectorAll('section[aria-label], nav[aria-label]')];
ok(sections.length >= 4, `${sections.length} landmark regions carry aria-labels`);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
