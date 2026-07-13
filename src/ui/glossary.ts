/**
 * Inline glossary tooltips for jargon.
 *
 * Lets the prose use the real vocabulary (Fiat–Shamir, blinder, MSM…) without
 * stranding a newcomer: each term carries a hover/focus definition and an
 * accessible label, so the page stays rigorous and readable at once.
 */

const TERMS: Record<string, string> = {
  'Pedersen commitment':
    'A hiding, binding commitment V = v·g + γ·h. It reveals nothing about v, yet v can never be opened two different ways.',
  blinder:
    'A random scalar γ (the blinding factor) that hides the value inside a commitment.',
  'Fiat–Shamir':
    'A transform that makes an interactive proof non-interactive by deriving the verifier’s “random” challenges from a hash of the transcript.',
  ROM: 'Random Oracle Model — the idealized-hash assumption under which Fiat–Shamir soundness is proven.',
  'inner-product argument':
    'A recursive protocol proving ⟨l, r⟩ = t̂ in O(log n) rounds instead of sending the full vectors.',
  MSM: 'Multi-scalar multiplication — computing Σ sᵢ·Pᵢ as one batched operation. The single-MSM verifier folds every check into one such sum.',
  'range proof':
    'A proof that a committed value lies in an interval — here [0, 2⁶⁴) — without revealing the value.',
  transcript:
    'The running record of every public value exchanged; hashing it yields the Fiat–Shamir challenges y, z, x.',
  'T₁':
    'A commitment to t₁, the linear coefficient of the prover’s secret quadratic t(X) = t₀ + t₁·X + t₂·X². It lets the verifier check t(x) without learning the polynomial.',
  'T₂':
    'A commitment to t₂, the quadratic coefficient of t(X). Together with T₁ it binds the prover to the whole polynomial before the challenge x is revealed.',
  'τₓ':
    'tau_x — the blinding scalar that opens the polynomial-identity equation. It bundles the blinders of T₁, T₂ and the value commitment V so equation (1) balances.',
  μ:
    'mu — the blinding scalar that opens the vector commitment A + x·S, so the verifier can cancel the h-term and isolate the inner-product statement.',
  'δ(y,z)':
    'delta(y,z) — a public scalar the verifier computes itself from the challenges y, z. It absorbs all the cross-terms so both sides of equation (1) line up.',
  't̂':
    't-hat — the single scalar the prover claims equals ⟨l, r⟩ = t(x). Collapsing the whole range claim into this one number is what the inner-product argument certifies.',
  'single-MSM verifier':
    'An equivalent verifier that folds every check into one multi-scalar multiplication Σ sᵢ·Pᵢ. Same accept/reject decision, one big batched operation instead of many.',
};

const escapeAttr = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** Wrap `term` (or `display`) in an accessible tooltip carrying its definition. */
export function gloss(term: string, display?: string): string {
  const def = TERMS[term] ?? '';
  const text = display ?? term;
  return `<span class="gloss" tabindex="0" role="note" aria-label="${escapeAttr(`${term}: ${def}`)}"><span class="gloss-term">${text}</span><span class="gloss-pop" role="tooltip">${def}</span></span>`;
}
