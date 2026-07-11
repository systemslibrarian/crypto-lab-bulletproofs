import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the range-proof KATs;
 * this gates them on accessibility the same way. Scans the full page in both
 * themes. This lab renders every panel inline (no <details>, no class-toggled
 * accordions), so all content is already on-screen; we still defensively open
 * any <details> and neutralize opacity-based reveal animations so nothing is
 * scanned mid-transition.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Expand any native disclosure widgets (defensive: none today).
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Neutralize any opacity/animation-based reveals so panels are scanned in
    // their settled, fully-opaque state rather than mid-transition.
    const style = document.createElement('style');
    style.textContent =
      '*, *::before, *::after { animation: none !important; transition: none !important; }';
    document.head.appendChild(style);
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealAll(page);
  await scan(page);
});
