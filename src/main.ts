/**
 * Entry point for the Bulletproofs demo application.
 */

import { initializeApp } from './app';
import './style.css';

/**
 * Initialize the application on DOM ready.
 */
document.addEventListener('DOMContentLoaded', () => {
  const appContainer = document.getElementById('app');
  if (!appContainer) {
    throw new Error('App container not found');
  }

  // Initialize the main UI
  initializeApp(appContainer);

  // Setup theme toggle
  const themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const html = document.documentElement;
      const currentTheme = html.getAttribute('data-theme') || 'dark';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

      html.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);

      updateThemeToggle(themeToggle, newTheme);
    });

    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    updateThemeToggle(themeToggle, currentTheme);
  }
});

function updateThemeToggle(button: HTMLElement, theme: string): void {
  const isDark = theme === 'dark';
  button.textContent = isDark ? '🌙' : '☀️';
  button.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
  button.setAttribute('aria-pressed', String(!isDark));
  button.setAttribute('title', isDark ? 'Switch to light mode' : 'Switch to dark mode');
}
