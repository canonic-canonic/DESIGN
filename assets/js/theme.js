/**
 * theme.js — Dark/light toggle + localStorage
 * DESIGN.md 255 Map | Client JS | ~20 lines
 */
(function () {
  var KEY = 'canonic-theme';
  var root = document.documentElement;
  var saved = localStorage.getItem(KEY);
  if (saved) root.setAttribute('data-theme', saved);

  var btn = document.getElementById('theme-btn');
  if (!btn) return;
  btn.addEventListener('click', function () {
    var current = root.getAttribute('data-theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    localStorage.setItem(KEY, next);
  });
})();
