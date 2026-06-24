/**
 * "You are here" progress stepper.
 *
 * Gives the guided journey a visible spine: Commit → Prove → Verify → Explore.
 * Completed steps show a check, the next action is highlighted, so a first-time
 * visitor always knows what to do next.
 */

export interface JourneyState {
  committed: boolean;
  proved: boolean;
  verified: boolean;
}

const STEPS = [
  { key: 'committed', label: 'Commit', hint: 'hide the value' },
  { key: 'proved', label: 'Prove', hint: 'build the proof' },
  { key: 'verified', label: 'Verify', hint: 'check it holds' },
  { key: 'explore', label: 'Explore', hint: 'attack & aggregate' },
] as const;

/** Render the stepper markup for the given journey state. */
export function renderStepper(s: JourneyState): string {
  const done: Record<string, boolean> = {
    committed: s.committed,
    proved: s.proved,
    verified: s.verified,
    explore: s.verified,
  };
  // The "current" step is the first not-yet-done action.
  const active = !s.proved ? 'proved' : !s.verified ? 'verified' : 'explore';

  const items = STEPS.map((st, i) => {
    const isDone = done[st.key];
    const isActive = st.key === active;
    const mark = isDone ? '✓' : String(i + 1);
    return `
      <li class="stepper-step${isDone ? ' done' : ''}${isActive ? ' active' : ''}" aria-current="${isActive ? 'step' : 'false'}">
        <span class="stepper-dot" aria-hidden="true">${mark}</span>
        <span class="stepper-text">
          <span class="stepper-label">${st.label}</span>
          <span class="stepper-hint">${st.hint}</span>
        </span>
      </li>`;
  }).join('');

  return `<ol class="stepper" aria-label="Progress through the demo">${items}</ol>`;
}
