/**
 * Light/dark theme toggle. The actual switch happens via a single
 * `data-theme` attribute on <html> — see themes/omenwatch.css for the
 * variable overrides. This file just handles the two toggle controls
 * (header button + Settings row) and persistence.
 *
 * Applied early (see the inline script in dashboard.html's <head>) so
 * there's no flash of the wrong theme on load.
 */

function getTheme() {
  return document.documentElement.getAttribute('data-theme') || 'dark';
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('omenwatch-theme', theme);
  syncThemeControls();
}

function syncThemeControls() {
  const isLight = getTheme() === 'light';
  const headerBtn = document.getElementById('themeToggle');
  const settingsToggle = document.getElementById('themeToggleSettings');
  // Shows the theme you would switch to.
  if (headerBtn) headerBtn.innerHTML = isLight
    ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></svg>'
    : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/></svg>';
  if (settingsToggle) settingsToggle.classList.toggle('on', isLight);
}

function initThemeControls() {
  syncThemeControls();
  document.getElementById('themeToggle').onclick = () => {
    setTheme(getTheme() === 'light' ? 'dark' : 'light');
  };
  document.getElementById('themeToggleSettings').onclick = () => {
    setTheme(getTheme() === 'light' ? 'dark' : 'light');
  };
}
