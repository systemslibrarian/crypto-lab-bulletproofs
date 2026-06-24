/**
 * Entry point for the Bulletproofs demo application.
 *
 * Theming is owned by the shared Crypto Lab header (see index.html), which
 * renders the only theme toggle and persists the choice to localStorage. This
 * module just boots the demo UI once the DOM is ready.
 */

import { initializeApp } from './app';
import './style.css';

document.addEventListener('DOMContentLoaded', () => {
  const appContainer = document.getElementById('app');
  if (!appContainer) {
    throw new Error('App container not found');
  }

  initializeApp(appContainer);
});
