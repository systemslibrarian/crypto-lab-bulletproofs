/**
 * Copy-to-clipboard wiring for the demo's hex fields.
 *
 * A button opts in with either:
 *   data-copy-el="#selector"   — copy that element's .value or textContent, or
 *   data-copy-text="…"         — copy a literal string (kept fresh by callers).
 * Falls back gracefully where the async clipboard API is unavailable.
 */

async function copyText(text: string): Promise<boolean> {
  try {
    const clip = (globalThis as { navigator?: Navigator }).navigator?.clipboard;
    if (clip?.writeText) {
      await clip.writeText(text);
      return true;
    }
  } catch {
    /* fall through to failure */
  }
  return false;
}

/** Attach click handlers to every [data-copy-el]/[data-copy-text] button under `root`. */
export function attachCopyButtons(root: ParentNode): void {
  root.querySelectorAll<HTMLElement>('[data-copy-el],[data-copy-text]').forEach((btn) => {
    if (btn.dataset.copyWired) return;
    btn.dataset.copyWired = '1';
    btn.addEventListener('click', async () => {
      let text = btn.getAttribute('data-copy-text') ?? '';
      const sel = btn.getAttribute('data-copy-el');
      if (sel) {
        const el = document.querySelector(sel);
        if (el) {
          text = 'value' in el ? (el as HTMLInputElement).value : el.textContent ?? '';
        }
      }
      const label = btn.textContent;
      const ok = await copyText(text);
      btn.textContent = ok ? 'Copied!' : 'Press ⌘/Ctrl+C';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = label;
        btn.classList.remove('copied');
      }, 1300);
    });
  });
}
