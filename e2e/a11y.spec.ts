import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

import { auditContrast, formatContrastFailures } from './contrast';

/**
 * WCAG regression gate. Deploys are already gated on the range-proof KATs; this
 * gates them on accessibility the same way.
 *
 * Two things this file deliberately does NOT do, both of which it used to:
 *
 * 1. It does not scan straight after `page.goto`. The whole UI is written into
 *    an empty `<div id="app">` by JS, and most of what is worth scanning — the
 *    transcript, the folding view, the verdict panels, the benchmark table —
 *    only exists after a button has been pressed. A scan that runs before the
 *    content exists checks an empty box and passes having checked nothing.
 *    Every scan below therefore asserts its content is present first, via
 *    `expectRendered`, and the page is driven into its real states.
 *
 * 2. It does not inject `transition: none`. While that injection was present
 *    the suite was structurally unable to observe a transition or theme-swap
 *    defect, because it had deleted the thing it was meant to be checking.
 *    Motion is settled honestly instead: `page.emulateMedia({ reducedMotion:
 *    'reduce' })`, which exercises the stylesheet's real
 *    `prefers-reduced-motion` block, plus a poll until nothing is animating.
 *
 *    `test.use({ reducedMotion: 'reduce' })` is NOT equivalent — on Playwright
 *    1.61.1 it silently does nothing, both at file level and inside
 *    `test.describe`, and the page still reports `matches === false`. Hence
 *    `emulateMedia` plus `assertReducedMotion`, so a regression to the no-op
 *    form fails loudly rather than quietly disabling the premise.
 *
 * Contrast is additionally measured arithmetically in `./contrast`. axe cannot
 * compute contrast over a background gradient and drops those nodes into
 * "incomplete", which never reaches the violations array — and this lab paints
 * several text-bearing controls with a gradient.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** Fail loudly if reduced motion is not actually in effect. */
async function assertReducedMotion(page: Page): Promise<void> {
  const matches = await page.evaluate(
    () => window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
  expect(
    matches,
    'reduced motion is not in effect — page.emulateMedia is the only form that works here'
  ).toBe(true);
}

/** Poll until no animation is running, rather than deleting animations. */
async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () =>
      document.getAnimations().every((a) => a.playState === 'finished' || a.playState === 'idle'),
    undefined,
    { timeout: 15_000 }
  );
}

/**
 * Guard against the empty-container scan. Every scan names the content it
 * expects to be looking at; if that content is missing the test fails here
 * rather than passing an axe run over nothing.
 */
async function expectRendered(page: Page, selectors: string[]): Promise<void> {
  for (const sel of selectors) {
    const locator = page.locator(sel);
    await expect(locator, `expected content at ${sel}`).toBeVisible();
    const text = (await locator.innerText()).trim();
    expect(text.length, `expected non-empty content at ${sel}`).toBeGreaterThan(0);
  }
}

async function open(page: Page, theme: 'dark' | 'light'): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  await assertReducedMotion(page);
  // #app ships empty; wait for the real first paint before believing anything.
  await expectRendered(page, ['#commitment-output', '#journey-stepper', '#app-status']);
  // Defensive: expand any native disclosure widget (none today).
  await page.evaluate(() => {
    for (const d of Array.from(document.querySelectorAll('details'))) {
      (d as HTMLDetailsElement).open = true;
    }
  });
  await settle(page);
}

async function scan(page: Page, label: string): Promise<void> {
  await settle(page);

  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary, `axe violations in state: ${label}`).toEqual([]);

  const failures = await auditContrast(page);
  expect(
    formatContrastFailures(failures),
    `measured contrast failures in state: ${label}`
  ).toEqual([]);
}

async function driveToProved(page: Page): Promise<void> {
  await page.locator('#prove-button').click();
  await expect(page.locator('#transcript-entries li').first()).toBeVisible();
  await expectRendered(page, ['#introspection-content', '#bridge-content', '#folding-content']);
}

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations on first paint (${theme})`, async ({ page }) => {
    await open(page, theme);
    await scan(page, `${theme} / initial`);
  });

  test(`no WCAG A/AA violations across the proof journey (${theme})`, async ({ page }) => {
    await open(page, theme);

    await driveToProved(page);
    await scan(page, `${theme} / proof generated`);

    await page.locator('#verify-button').click();
    await expect(page.locator('#verify-result')).toHaveClass(/success/);
    await expect(page.locator('#equation-eval .eval-verdict')).toBeVisible();
    await scan(page, `${theme} / verifier accepted`);
  });

  test(`no WCAG A/AA violations in the attack panels (${theme})`, async ({ page }) => {
    await open(page, theme);
    await driveToProved(page);

    await page.locator('#tamper-run').click();
    await expect(page.locator('#tamper-result')).toContainText('Reference verifier');

    await page.locator('#replay-run').click();
    await expect(page.locator('#replay-result')).toContainText('Rejected');

    await page.locator('#cheat-upper').click();
    await expect(page.locator('#cheat-result')).not.toBeEmpty();

    await page.locator('#cheat-negative').click();
    await expect(page.locator('#cheat-result')).not.toBeEmpty();

    await scan(page, `${theme} / rejected verdicts`);
  });

  test(`no WCAG A/AA violations in the export/import states (${theme})`, async ({ page }) => {
    await open(page, theme);
    await driveToProved(page);

    await page.locator('#export-proof').click();
    await expect(page.locator('#portable-result')).toContainText('Exported');
    await page.locator('#import-proof').click();
    await expect(page.locator('#portable-result')).toContainText('accepted');
    await scan(page, `${theme} / imported proof accepted`);

    // An import failure is a first-class rendered state that only ever appears
    // after user input — exactly the kind a load-time-only scan cannot see.
    await page.locator('#commitment-hex').fill('not-hex');
    await page.locator('#import-proof').click();
    await expect(page.locator('#portable-result')).toContainText('Import failed');
    await scan(page, `${theme} / import failed`);
  });

  test(`no WCAG A/AA violations in the result tables (${theme})`, async ({ page }) => {
    await open(page, theme);

    await page.locator('#aggregate-run').click();
    await expect(page.locator('#aggregate-run-result')).toContainText('aggregate', {
      timeout: 60_000,
    });

    await page.locator('#bench-run').click();
    await expect(page.locator('#bench-result table')).toBeVisible({ timeout: 120_000 });

    await scan(page, `${theme} / aggregate + benchmark tables`);
  });
}
