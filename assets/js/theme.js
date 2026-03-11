/**
 * theme.js — Dark/light toggle + localStorage
 * DESIGN.md 255 Map | Client JS | ~20 lines
 */
(function () {
  var KEY = 'canonic-theme';
  var root = document.documentElement;
  function setTheme(t) {
    root.setAttribute('data-theme', t);
    if (document.body) document.body.setAttribute('data-theme', t);
  }
  var saved = localStorage.getItem(KEY);
  if (saved) setTheme(saved);
  /* Body may not exist yet at parse time — mirror once DOM ready */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      var t = root.getAttribute('data-theme');
      if (t && document.body) document.body.setAttribute('data-theme', t);
    });
  }

  var btn = document.getElementById('theme-btn');
  if (!btn) return;
  btn.addEventListener('click', function () {
    var current = root.getAttribute('data-theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem(KEY, next);
  });
})();
