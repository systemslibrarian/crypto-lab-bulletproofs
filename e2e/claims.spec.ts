import { expect, test, type Page } from '@playwright/test';

/**
 * Claims gate — asserts what the PAGE says against what the page itself computed.
 *
 * The a11y spec proves the document is reachable and the node suites prove the
 * crypto is correct in isolation; this one proves the rendered demo is honest.
 * Sizes, counts and verdicts are never hardcoded where the page derives them:
 * each is checked against a second surface that must agree.
 *
 * The load-bearing cross-path checks:
 *
 *   app status "Serialized size: N B"  ↔  introspection total
 *                                      ↔  its own component breakdown, summed
 *                                      ↔  the exported hex, in bytes
 *                                      ↔  the aggregation panel's per-proof cost
 *                                      ↔  the benchmark's single-value row
 *   introspection IPA components       ↔  the folding view's "IPA payload"
 *   "(K transcript events)"            ↔  the transcript list, counted
 *   theoretical aggregate estimate     ↔  the size of the REAL aggregated proof
 *   equation (1) verdict               ↔  the LHS and RHS points it printed
 *   bit-grid "N / 64 set"              ↔  the lit cells ↔ popcount of the value
 */

const POINT = 32;
const SCALAR = 32;

const text = (p: Page, id: string) =>
  p.evaluate((i) => document.getElementById(i)?.textContent?.replace(/\s+/g, ' ').trim() ?? '', id);

/** First capture group as a number, with the assertion message baked in. */
function grab(s: string, re: RegExp, what: string): number {
  const m = s.match(re);
  expect(m, `could not read ${what} from: ${s}`).not.toBeNull();
  return Number((m as RegExpMatchArray)[1].replace(/,/g, ''));
}

function popcount(v: bigint): number {
  let n = 0;
  for (let x = v; x > 0n; x >>= 1n) if (x & 1n) n++;
  return n;
}

async function prove(page: Page): Promise<void> {
  await page.locator('#prove-button').click();
  await expect(page.locator('#app-status')).toContainText('Range proof generated in', {
    timeout: 30_000,
  });
}

// ---------------------------------------------------------------------------
// 1. The commitment exhibit: value, bit grid and lit cells are one fact.
// ---------------------------------------------------------------------------
test('the bit grid counts the committed value it is drawn from', async ({ page }) => {
  await page.goto('.');

  // 64 cells, of which exactly the low 24 are reachable by the slider — the
  // caption promises both numbers, so both must be true of the DOM.
  await expect(page.locator('.bit-cell')).toHaveCount(64);
  await expect(page.locator('.bit-cell:not(.out-of-reach)')).toHaveCount(24);
  await expect(page.locator('#bit-grid-slot')).toContainText('always');
  await expect(page.locator('#bit-grid-slot')).toContainText('[0, 2⁶⁴)');

  for (const preset of ['0', '255', '65535', '16777215', '1337'] as const) {
    if (preset === '1337') {
      await page.locator('#value-slider').fill('1337');
      await page.locator('#value-slider').dispatchEvent('input');
    } else {
      await page.locator(`.preset-chip[data-preset="${preset}"]`).click();
    }
    const v = BigInt(preset);
    const expected = popcount(v);
    const pretty = Number(v).toLocaleString('en-US');

    await expect(page.locator('#value-display')).toHaveText(pretty);
    await expect(page.locator('#commitment-output')).toContainText(`Committed value: ${pretty}`);
    // the caption's count, the lit cells, and popcount of the value must agree
    const caption = await page.locator('[data-bit-count]').textContent();
    expect(caption?.trim()).toBe(`${expected} / 64 set`);
    await expect(page.locator('.bit-cell.on')).toHaveCount(expected);
    await expect(page.locator('.bit-grid')).toHaveAttribute(
      'aria-label',
      new RegExp(`${expected} of 64 bits set`),
    );
  }
});

// ---------------------------------------------------------------------------
// 2. The proof size the page reports is the size of the bytes it produced.
// ---------------------------------------------------------------------------
test('every surface reports the same measured proof size', async ({ page }) => {
  await page.goto('.');
  await prove(page);

  const status = await text(page, 'app-status');
  const statusBytes = grab(status, /Serialized size: ([\d,]+) B/, 'status proof size');
  const events = grab(status, /\(([\d,]+) transcript events\)/, 'transcript event count');

  // the event counter is the list the page rendered, not a guess
  await expect(page.locator('li.transcript-entry')).toHaveCount(events);

  const intro = await text(page, 'introspection-content');
  const introBytes = grab(intro, /Serialized proof size: ([\d,]+) B/, 'introspection size');
  const rounds = grab(intro, /\(([\d,]+) IPA rounds for n=64\)/, 'IPA round count');
  expect(introBytes, 'introspection size vs status size').toBe(statusBytes);
  expect(rounds).toBe(Math.log2(64));

  // the component breakdown must sum to the total it is a breakdown of
  const components = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#introspection-content div'))
      .map((d) => d.textContent ?? '')
      .filter((t) => /: \d+ B$/.test(t.trim()))
      .map((t) => Number((t.match(/: (\d+) B$/) as RegExpMatchArray)[1])),
  );
  expect(components.length).toBe(5);
  expect(
    components.reduce((a, b) => a + b, 0),
    'component breakdown vs the total it breaks down',
  ).toBe(introBytes);

  // the IPA point row must be 2 points per round, at 32 B each
  const ipaPoints = grab(intro, /IPA L\/R points \((\d+) × 32 B\)/, 'IPA point count');
  expect(ipaPoints).toBe(2 * rounds);
  expect(components[3]).toBe(ipaPoints * POINT);
  expect(components[4]).toBe(2 * SCALAR);

  // …and the folding view's payload figure is those two rows added up
  const folding = await text(page, 'folding-content');
  const payload = grab(folding, /IPA payload: ([\d,]+) B/, 'IPA payload');
  expect(payload, 'folding IPA payload vs the introspection components').toBe(
    components[3] + components[4],
  );
  const naive = grab(folding, /versus ([\d,]+) B/, 'naive vector cost');
  expect(naive).toBe(2 * 64 * SCALAR);
  expect(payload).toBeLessThan(naive); // the logarithmic win it advertises

  // the folding rows really halve 64 down to 1, one row per IPA round
  const foldRows = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.fold-row')).map(
      (r) => r.querySelector('.fold-sizes')?.textContent?.trim() ?? '',
    ),
  );
  expect(foldRows.length).toBe(rounds);
  let size = 64;
  for (const row of foldRows) {
    expect(row).toBe(`${size}→${size / 2}`);
    size /= 2;
  }
  expect(size).toBe(1);

  // exporting the proof yields exactly that many bytes of hex
  await page.locator('#export-proof').click();
  const hex = await page.locator('#export-output').inputValue();
  expect(hex.length / 2, 'exported hex vs the reported proof size').toBe(introBytes);
  expect(hex).toMatch(/^[0-9a-f]+$/);
  const commitHex = await page.locator('#commitment-hex').inputValue();
  expect(commitHex.length / 2).toBe(POINT);
  await expect(page.locator('#portable-result')).toHaveText(
    `Exported ${introBytes} B proof and ${POINT} B commitment. Copy them anywhere.`,
  );
  // the panel's own label quotes the same size
  await expect(page.locator('label[for="export-output"]')).toContainText(`${introBytes} B`);
});

// ---------------------------------------------------------------------------
// 3. Verification: both verifiers accept, and equation (1) really balances.
// ---------------------------------------------------------------------------
test('both verifiers accept and the live equation balances', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#verify-result')).toHaveText('No verification has been run yet.');
  await prove(page);

  // the stepper says what is left to do, and it is right
  const stepClasses = () =>
    page.evaluate(() =>
      Array.from(document.querySelectorAll('.stepper-step')).map((s) => ({
        label: s.querySelector('.stepper-label')?.textContent ?? '',
        done: s.classList.contains('done'),
        active: s.classList.contains('active'),
      })),
    );
  let steps = await stepClasses();
  expect(steps.map((s) => s.label)).toEqual(['Commit', 'Prove', 'Verify', 'Explore']);
  expect(steps[0].done && steps[1].done).toBe(true);
  expect(steps[2].done).toBe(false);
  expect(steps[2].active, 'Verify is the next action after proving').toBe(true);

  // equation (1): the verdict must match the two points the page printed
  const evalText = await text(page, 'equation-eval');
  const lhs = evalText.match(/LHS = t̂·g \+ τₓ·h = ([0-9a-f]+)…/);
  const rhs = evalText.match(/RHS = z²·V \+ δ\(y,z\)·g \+ x·T₁ \+ x²·T₂ = ([0-9a-f]+)…/);
  expect(lhs, `no LHS point in: ${evalText}`).not.toBeNull();
  expect(rhs, `no RHS point in: ${evalText}`).not.toBeNull();
  const claimsMatch = evalText.includes('✓ LHS = RHS');
  expect(
    (lhs as RegExpMatchArray)[1] === (rhs as RegExpMatchArray)[1],
    'the ✓/✗ verdict vs the two points it printed',
  ).toBe(claimsMatch);
  expect(claimsMatch, 'an honest proof must satisfy equation (1)').toBe(true);
  await expect(page.locator('#equation-eval .eval-verdict')).toHaveClass(/\bok\b/);

  await page.locator('#verify-button').click();
  await expect(page.locator('#verify-result')).toContainText('✓ reference verifier accepted');
  await expect(page.locator('#verify-result')).toHaveClass(/success/);
  const refMs = grab(await text(page, 'verify-result'), /in ([\d.]+) ms/, 'reference verifier time');
  expect(refMs).toBeGreaterThan(0);
  await expect(page.locator('#app-status')).toContainText('reference verifier accepted');
  // the introspection panel picks up the verifier time it just measured
  expect(await text(page, 'introspection-content')).toContain(`Verifier time: ${refMs.toFixed(1)} ms`);

  await page.locator('#verify-batched-button').click();
  await expect(page.locator('#verify-result')).toContainText('✓ single-MSM verifier accepted');
  await expect(page.locator('#verify-result')).toHaveClass(/success/);

  steps = await stepClasses();
  expect(steps.every((s) => s.done), 'every step is done once a proof verifies').toBe(true);
});

// ---------------------------------------------------------------------------
// 4. The bridge derives l and r from the value's own bits.
// ---------------------------------------------------------------------------
test('the bits-to-inner-product bridge uses the real bits of the committed value', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('.preset-chip[data-preset="65535"]').click();
  await prove(page);

  const bits = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.bridge-cell.bit')).map((c) => c.textContent?.trim() ?? ''),
  );
  expect(bits.length).toBe(8);
  const v = 65535n;
  // the bridge prints a_L LSB-first; the value's own low 8 bits must match
  expect(bits.join('')).toBe(
    Array.from({ length: 8 }, (_, i) => String((v >> BigInt(i)) & 1n)).join(''),
  );
  // …and the l and r rows are populated from the live challenges, not blank
  const bridge = await text(page, 'bridge-content');
  expect(bridge).toContain('l = aL − z·1ⁿ');
  expect(bridge).toContain('⟨l, r⟩ = t̂');
  await expect(page.locator('.bridge-line')).toHaveCount(3);
  const rowLens = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.bridge-vec')).map((r) => r.querySelectorAll('.bridge-cell').length),
  );
  expect(rowLens).toEqual([8, 8, 8]);
});

// ---------------------------------------------------------------------------
// 5. Cheating: out-of-range values are rejected, and the page shows WHY.
// ---------------------------------------------------------------------------
for (const [label, buttonId, value] of [
  ['2^64', 'cheat-upper', (1n << 64n).toString()],
  ['-1', 'cheat-negative', '-1'],
] as const) {
  test(`cheating with ${label} is rejected as a binding failure`, async ({ page }) => {
    await page.goto('.');
    await page.locator(`#${buttonId}`).click();
    await expect(page.locator('#cheat-result')).toContainText('binding', { timeout: 30_000 });

    const v = BigInt(value);
    const truncated = BigInt.asUintN(64, v);
    const body = await text(page, 'cheat-result');
    expect(body).toContain(`You committed to ${v.toString()}`);
    expect(body).toContain(`v mod 2⁶⁴ = ${truncated.toString()}`);
    expect(body).toContain(`V = ${v.toString()}·g + γ·h`);
    expect(body).toContain(`V' = ${truncated.toString()}·g + γ·h`);
    expect(truncated).not.toBe(v); // the whole point: a different value

    // the "these are different points" claim is checked against the two hexes
    const hexes = await page.evaluate(() =>
      Array.from(document.querySelectorAll('.cheat-hex')).map((h) => h.textContent?.replace('…', '') ?? ''),
    );
    expect(hexes.length).toBe(2);
    expect(hexes[0], 'the two commitments must actually differ').not.toBe(hexes[1]);
    // …and the differing nibbles are marked, so the claim is visible
    expect(await page.locator('.cheat-hex mark.hex-diff').count()).toBeGreaterThan(0);

    const verdict = page.locator('.cheat-verdict');
    await expect(verdict).toHaveClass(/\bok\b/);
    await expect(verdict).toContainText('✓');
    await expect(verdict).not.toContainText('UNEXPECTEDLY');
    expect(body).toContain('does not open to the witness');
    await expect(page.locator('#app-status')).toContainText('verifier rejected');
  });
}

// ---------------------------------------------------------------------------
// 6. Tampering with a finished proof: both verifiers must reject it.
// ---------------------------------------------------------------------------
test('flipping one bit of t-hat is rejected by both verifiers', async ({ page }) => {
  await page.goto('.');
  // before a proof exists the panel says so rather than pretending
  await page.locator('#tamper-run').click();
  await expect(page.locator('#tamper-result')).toContainText('No proof yet.');

  await prove(page);
  await page.locator('#tamper-run').click();
  const body = await text(page, 'tamper-result');
  expect(body).toContain('Mutation: t̂ → t̂ + 1 (mod ℓ)');
  expect(body).toMatch(/Reference verifier: ✓ rejected/);
  expect(body).toMatch(/Single-MSM verifier: ✓ rejected/);
  expect(body, 'a tampered proof must never be accepted').not.toContain('INCORRECTLY accepted');
  expect(body).toContain('honest verifiers always reject');

  // the untampered proof in the app is untouched and still verifies
  await page.locator('#verify-button').click();
  await expect(page.locator('#verify-result')).toContainText('✓ reference verifier accepted');
});

// ---------------------------------------------------------------------------
// 7. Replay: a proof is bound to its own commitment.
// ---------------------------------------------------------------------------
test('replaying a proof against another commitment is rejected', async ({ page }) => {
  await page.goto('.');
  await page.locator('#replay-run').click();
  await expect(page.locator('#replay-result')).toContainText('No proof yet.');

  await prove(page);
  await page.locator('#export-proof').click();
  const ownCommitment = await page.locator('#commitment-hex').inputValue();

  await page.locator('#replay-run').click();
  const body = await text(page, 'replay-result');
  const other = body.match(/fresh commitment to ([\d,]+) \(([0-9a-f]+)…\)/);
  expect(other, `replay panel did not name its target: ${body}`).not.toBeNull();
  const otherPrefix = (other as RegExpMatchArray)[2];
  expect(
    ownCommitment.startsWith(otherPrefix),
    'the replay target must be a different commitment',
  ).toBe(false);

  await expect(page.locator('#replay-result .eval-verdict')).toHaveClass(/\bok\b/);
  expect(body).toContain('✓ Rejected — the proof only validates its own commitment.');
  expect(body).not.toContain('UNEXPECTEDLY');
  await expect(page.locator('#app-status')).toContainText('Replay attack rejected');
});

// ---------------------------------------------------------------------------
// 8. Portability: the honest bytes re-verify, and every corruption is caught.
// ---------------------------------------------------------------------------
test('exported proof re-verifies, and corrupted bytes never do', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('.');
  await prove(page);
  await page.locator('#export-proof').click();
  const hex = await page.locator('#export-output').inputValue();
  const commit = await page.locator('#commitment-hex').inputValue();

  await page.locator('#import-proof').click();
  await expect(page.locator('#portable-result')).toContainText('✓ Verifier accepted');

  const flip = (h: string, i: number) => h.slice(0, i) + (h[i] === '0' ? '1' : '0') + h.slice(i + 1);
  // t̂ sits after A, S, T1, T2, tau_x, mu = 6 × 32 B, so byte 192 → hex index 384.
  const tHatHexIndex = 6 * POINT * 2;

  const cases: Array<[string, string, string, RegExp]> = [
    ['t̂ nibble flipped', flip(hex, tHatHexIndex), commit, /✗ Verifier rejected/],
    ['final IPA scalar flipped', flip(hex, hex.length - 2), commit, /✗ Verifier rejected/],
    // A mangled point usually fails to decode, but a corrupted 32-byte string is
    // occasionally still a valid ristretto encoding — in which case it decodes to
    // the WRONG point and the verifier rejects instead. Either is a pass; being
    // accepted is not. (Pinning only the decode error would flake on the bytes.)
    [
      'point encoding corrupted',
      flip(hex, 2),
      commit,
      /Import failed: invalid ristretto255|✗ Verifier rejected/,
    ],
    ['proof truncated', hex.slice(0, 100), commit, /Import failed: Expected \d+ bytes/],
    ['not hex at all', 'zzzz', commit, /Import failed: Invalid hex/],
    ['commitment too short', hex, commit.slice(0, 40), /Import failed: Commitment must be 32 bytes/],
  ];

  for (const [label, proofHex, commitHex, expected] of cases) {
    await page.locator('#export-output').fill(proofHex);
    await page.locator('#commitment-hex').fill(commitHex);
    await page.locator('#import-proof').click();
    const result = await text(page, 'portable-result');
    expect(result, `${label}: expected ${expected}`).toMatch(expected);
    expect(result, `${label} must never be accepted`).not.toContain('✓ Verifier accepted');
  }

  // and pasting the honest bytes back still works, so the panel is not just
  // stuck in a failure state
  await page.locator('#export-output').fill(hex);
  await page.locator('#commitment-hex').fill(commit);
  await page.locator('#import-proof').click();
  await expect(page.locator('#portable-result')).toContainText('✓ Verifier accepted');
});

// ---------------------------------------------------------------------------
// 9. Aggregation: the theoretical estimate must equal the real proof's size.
//    This is the strongest check on the page — a formula in one panel and a
//    measured byte count from an actual proof in another.
// ---------------------------------------------------------------------------
test('the aggregation estimate matches the real aggregated proof it predicts', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('.');
  await prove(page);
  const singleBytes = grab(
    await text(page, 'introspection-content'),
    /Serialized proof size: ([\d,]+) B/,
    'measured single-proof size',
  );

  for (const count of [1, 4]) {
    await page.locator('#aggregate-count').fill(String(count));
    await expect(page.locator('#aggregate-count-value')).toHaveText(String(count));

    const summary = await text(page, 'aggregate-summary');
    const batched = grab(summary, /batched, \d+ × single proofs\): ([\d,]+) bytes/, 'batched bytes');
    const aggregated = grab(summary, /True aggregated Bulletproof \(theoretical\): ([\d,]+) bytes/, 'aggregate bytes');
    const naive = grab(summary, /Naive disjunctive Schnorr \(theoretical\): ([\d,]+) bytes/, 'naive bytes');
    const saved = grab(summary, /would save vs this demo: ([\d,]+)/, 'saved bytes');

    // parts vs whole, all from the numbers the panel itself printed
    expect(batched, 'batched cost vs the measured cost of one proof').toBe(singleBytes * count);
    expect(saved).toBe(batched - aggregated);
    expect(aggregated).toBeLessThanOrEqual(batched);
    expect(naive).toBe(64 * count * 64);

    // the chart draws the same three numbers, and the biggest bar is full width
    const bars = await page.evaluate(() =>
      Array.from(document.querySelectorAll('.chart-row')).map((r) => ({
        bytes: Number((r.querySelector('.chart-value')?.textContent ?? '').replace(/[^\d]/g, '')),
        width: Number(((r.querySelector('.chart-track > div') as HTMLElement)?.style.width ?? '').replace('%', '')),
      })),
    );
    expect(bars.map((b) => b.bytes)).toEqual([batched, aggregated, naive]);
    const widest = bars.reduce((a, b) => (b.bytes > a.bytes ? b : a));
    expect(widest.width).toBe(100);
    for (const b of bars) expect(b.width).toBeLessThanOrEqual(100);

    // now build the real thing and compare it with the estimate above
    await page.locator('#aggregate-run').click();
    await expect(page.locator('#aggregate-run-result')).toContainText('Batch size used:', {
      timeout: 90_000,
    });
    const run = await text(page, 'aggregate-run-result');
    const m = grab(run, /Batch size used: (\d+)/, 'batch size');
    const realBytes = grab(run, /Single aggregated proof size: ([\d,]+) B/, 'real aggregate size');
    const runBatched = grab(run, /Equivalent batched \(m × \d+ B\): ([\d,]+) B/, 'run batched size');
    const runSaved = grab(run, /Bytes saved by aggregation: ([\d,]+) B/, 'run saved bytes');

    expect(m, `${count} is a power of two, so nothing should be snapped away`).toBe(count);
    expect(realBytes, 'the theoretical estimate vs the proof actually built').toBe(aggregated);
    expect(runBatched).toBe(singleBytes * m);
    expect(runSaved).toBe(runBatched - realBytes);
    // and it is a proof, not just a size: both verifiers accepted it
    expect(run).toMatch(/Reference verifier: [\d.]+ ms — ✓ accepted/);
    expect(run).toMatch(/Single-MSM verifier: [\d.]+ ms — ✓ accepted/);
    expect(run).not.toContain('✗ rejected');
  }
});

// ---------------------------------------------------------------------------
// 10. Aggregation snaps DOWN to a power of two, and says so accurately.
// ---------------------------------------------------------------------------
test('a non-power-of-two batch size snaps down, and the panel describes it correctly', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await page.goto('.');
  await page.locator('#aggregate-count').fill('7');
  await page.locator('#aggregate-run').click();
  await expect(page.locator('#aggregate-run-result')).toContainText('Batch size used:', {
    timeout: 60_000,
  });
  const run = await text(page, 'aggregate-run-result');
  const m = grab(run, /Batch size used: (\d+)/, 'batch size');
  // largest power of two ≤ 7 is 4 — NOT the nearest one, which would be 8
  expect(m).toBe(4);
  expect(Number.isInteger(Math.log2(m))).toBe(true);
  expect(m).toBeLessThanOrEqual(7);
  expect(m * 2).toBeGreaterThan(7);
  expect(run, 'the panel must not claim it rounded to the nearest power of two').toContain(
    'down to the largest power of two ≤ 7',
  );
  expect(run).not.toContain('nearest power of two');
});

// ---------------------------------------------------------------------------
// 11. The benchmark table: one extra IPA round pair per doubling of m.
// ---------------------------------------------------------------------------
test('benchmark sizes grow by exactly one IPA round pair per doubling', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('.');
  await prove(page);
  const singleBytes = grab(
    await text(page, 'introspection-content'),
    /Serialized proof size: ([\d,]+) B/,
    'measured single-proof size',
  );

  await page.locator('#bench-run').click();
  await expect(page.locator('#bench-result table')).toBeVisible({ timeout: 150_000 });
  await expect(page.locator('#bench-run')).toBeEnabled({ timeout: 150_000 });

  const rows = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#bench-result tr'))
      .slice(1)
      .map((tr) => Array.from(tr.querySelectorAll('td')).map((td) => td.textContent?.trim() ?? '')),
  );
  expect(rows.map((r) => r[0])).toEqual([
    'single value (n=64)',
    'aggregate m=1',
    'aggregate m=2',
    'aggregate m=4',
    'aggregate m=8',
  ]);
  const size = (i: number) => Number(rows[i][1]);

  // the benchmark's single-value row is the same proof the app just measured
  expect(size(0), 'benchmark single-value size vs the live proof').toBe(singleBytes);
  // an aggregate over one value is exactly a single-value proof
  expect(size(1)).toBe(size(0));
  // each doubling adds one IPA round = one (L, R) pair = 64 B
  expect(size(2) - size(1)).toBe(2 * POINT);
  expect(size(3) - size(2)).toBe(2 * POINT);
  expect(size(4) - size(3)).toBe(2 * POINT);
  // …which is the logarithmic claim: 8 values cost far less than 8 proofs
  expect(size(4)).toBeLessThan(8 * singleBytes);
  expect(8 * singleBytes).toBe(5376);
  expect(size(4)).toBe(864);

  // every timing is a real measurement
  for (const r of rows) {
    for (const cell of r.slice(2)) expect(Number(cell)).toBeGreaterThan(0);
  }
});

// ---------------------------------------------------------------------------
// 12. Deterministic seed mode reproduces bytes exactly, as advertised.
// ---------------------------------------------------------------------------
test('the same seed reproduces the commitment and the proof bit-for-bit', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto('.');
  await expect(page.locator('#seed-status')).toContainText('crypto.getRandomValues');

  const runWithSeed = async (seed: string) => {
    await page.locator('#seed-value').fill(seed);
    await page.locator('#seed-apply').click();
    await expect(page.locator('#seed-status')).toContainText(`seed = ${seed}`);
    await prove(page);
    await page.locator('#export-proof').click();
    return {
      commitment: await page.locator('#commitment-hex').inputValue(),
      proof: await page.locator('#export-output').inputValue(),
    };
  };

  const a = await runWithSeed('claims-spec-seed');
  const b = await runWithSeed('claims-spec-seed');
  expect(b.commitment, 'same seed must give the same commitment').toBe(a.commitment);
  expect(b.proof, 'same seed must give the same proof bytes').toBe(a.proof);

  const c = await runWithSeed('a-different-seed');
  expect(c.commitment, 'a different seed must give different bytes').not.toBe(a.commitment);

  await page.locator('#seed-clear').click();
  await expect(page.locator('#seed-status')).toContainText('crypto.getRandomValues');
  await page.locator('#export-proof').click();
  await expect(page.locator('#portable-result')).toContainText('Generate a proof first.');
});

// ---------------------------------------------------------------------------
// 13. A new commitment invalidates everything downstream of it.
// ---------------------------------------------------------------------------
test('changing the value tears down the stale proof and its exhibits', async ({ page }) => {
  await page.goto('.');
  await prove(page);
  await page.locator('#verify-button').click();
  await expect(page.locator('#verify-result')).toContainText('✓ reference verifier accepted');
  await page.locator('#export-proof').click();
  expect((await page.locator('#export-output').inputValue()).length).toBeGreaterThan(0);

  await page.locator('.preset-chip[data-preset="255"]').click();

  await expect(page.locator('#verify-result')).toHaveText('No verification has been run yet.');
  await expect(page.locator('#introspection-content')).toHaveText('No proof has been generated yet.');
  await expect(page.locator('#equation-eval')).toContainText('Generate a proof');
  await expect(page.locator('#folding-content')).toContainText('Generate a proof');
  await expect(page.locator('#bridge-content')).toContainText('Generate a proof');
  await expect(page.locator('li.transcript-entry')).toHaveCount(0);
  // the stale bytes are gone, so a later "verify pasted proof" cannot silently
  // re-check the proof for the previous value
  expect(await page.locator('#export-output').inputValue()).toBe('');
  expect(await page.locator('#commitment-hex').inputValue()).toBe('');

  const steps = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.stepper-step')).map((s) => ({
      done: s.classList.contains('done'),
      active: s.classList.contains('active'),
    })),
  );
  expect(steps[1].done, 'Prove is undone by a new commitment').toBe(false);
  expect(steps[1].active).toBe(true);
  expect(steps[2].done).toBe(false);
});
