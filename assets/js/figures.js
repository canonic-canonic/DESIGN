/**
 * figures.js — SVG chart renderer for complex figures
 * DESIGN.md 255 Map
 * Only the figures that require JS math (area-chart, donut, gauge, balance, pipeline, audit-trail, flow-chain).
 * Simple figures (timeline, hero-stats, architecture, funnel, tier-cards, bars, score, app-grid) are pre-rendered by Jekyll.
 */
(function () {
  'use strict';
  var A = 'rgba(var(--accent-rgb,59,130,246),';
  function isLight() { return document.documentElement.dataset.theme === 'light'; }
  function fg(a) { return isLight() ? 'rgba(0,0,0,' + a + ')' : 'rgba(255,255,255,' + a + ')'; }

  var FIGURES = {
    'pipeline': function (el) {
      var steps = JSON.parse(el.dataset.steps || '[]');
      var n = steps.length; if (!n) return;
      var w = 420, h = 180, padX = 50, stepW = (w - padX * 2) / n, cy = h / 2;
      var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" xmlns="http://www.w3.org/2000/svg">';
      svg += '<rect x="0" y="0" width="' + w + '" height="' + h + '" rx="16" fill="' + fg(0.02) + '"/>';
      steps.forEach(function (s, i) {
        var cx = padX + stepW * i + stepW / 2;
        var fill = i === n - 1 ? A + '0.25)' : fg(0.04);
        var stroke = i === n - 1 ? A + '0.7)' : fg(0.15);
        svg += '<circle cx="' + cx + '" cy="' + cy + '" r="28" fill="' + fill + '" stroke="' + stroke + '" stroke-width="1.5"/>';
        svg += '<text x="' + cx + '" y="' + (cy + 4) + '" text-anchor="middle" font-size="11" fill="' + fg(0.75) + '" font-family="var(--mono)">' + s + '</text>';
        if (i < n - 1) {
          var x1 = cx + 30, x2 = padX + stepW * (i + 1) + stepW / 2 - 30;
          svg += '<line x1="' + x1 + '" y1="' + cy + '" x2="' + x2 + '" y2="' + cy + '" stroke="' + A + '0.35)" stroke-width="1.5"/>';
          svg += '<polygon points="' + x2 + ',' + (cy - 4) + ' ' + (x2 + 6) + ',' + cy + ' ' + x2 + ',' + (cy + 4) + '" fill="' + A + '0.5)"/>';
        }
      });
      svg += '</svg>';
      el.innerHTML = svg;
    },

    'audit-trail': function (el) {
      var items = JSON.parse(el.dataset.items || '[]');
      var n = items.length; if (!n) return;
      var w = 420, h = 240, blockH = 36, gap = 10;
      var totalH = n * (blockH + gap) - gap, startY = (h - totalH) / 2;
      var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" xmlns="http://www.w3.org/2000/svg">';
      svg += '<rect x="0" y="0" width="' + w + '" height="' + h + '" rx="16" fill="' + fg(0.02) + '"/>';
      items.forEach(function (item, i) {
        var y = startY + i * (blockH + gap);
        var alpha = (0.08 + (i / n) * 0.12).toFixed(2);
        svg += '<rect x="100" y="' + y + '" width="220" height="' + blockH + '" rx="8" fill="' + fg(alpha) + '" stroke="' + A + (0.15 + i * 0.1).toFixed(2) + ')" stroke-width="1"/>';
        svg += '<text x="210" y="' + (y + blockH / 2 + 4) + '" text-anchor="middle" font-size="12" fill="' + fg(0.7) + '" font-family="var(--mono)">' + item + '</text>';
        if (i < n - 1) svg += '<line x1="210" y1="' + (y + blockH) + '" x2="210" y2="' + (y + blockH + gap) + '" stroke="' + A + '0.3)" stroke-width="1.5" stroke-dasharray="3 2"/>';
        svg += '<text x="86" y="' + (y + blockH / 2 + 4) + '" text-anchor="end" font-size="10" fill="' + A + '0.4)" font-family="var(--mono)">#' + (i + 1) + '</text>';
      });
      svg += '</svg>';
      el.innerHTML = svg;
    },

    'flow-chain': function (el) {
      var nodes = JSON.parse(el.dataset.nodes || '[]');
      var n = nodes.length; if (!n) return;
      var w = 420, h = 180, padX = 40, segW = (w - padX * 2) / (n - 1 || 1), cy = h / 2;
      var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" xmlns="http://www.w3.org/2000/svg">';
      svg += '<rect x="0" y="0" width="' + w + '" height="' + h + '" rx="16" fill="' + fg(0.02) + '"/>';
      if (n > 1) {
        var d = 'M' + padX + ' ' + cy;
        for (var i = 1; i < n; i++) {
          var px = padX + segW * (i - 1), nx = padX + segW * i, mx = (px + nx) / 2;
          d += ' C' + mx + ' ' + (cy - 40) + ',' + mx + ' ' + (cy - 40) + ',' + nx + ' ' + cy;
        }
        svg += '<path d="' + d + '" stroke="' + A + '0.35)" stroke-width="2" fill="none"/>';
      }
      nodes.forEach(function (nd, i) {
        var x = padX + segW * i;
        svg += '<circle cx="' + x + '" cy="' + cy + '" r="22" fill="' + A + '0.2)" stroke="' + A + '0.5)" stroke-width="1.5"/>';
        svg += '<text x="' + x + '" y="' + (cy + 42) + '" text-anchor="middle" font-size="10" fill="' + fg(0.6) + '" font-family="var(--mono)">' + nd + '</text>';
      });
      svg += '</svg>';
      el.innerHTML = svg;
    },

    'area-chart': function (el) {
      var points = JSON.parse(el.dataset.points || '[]');
      if (!points.length) return;
      var prefix = el.dataset.prefix || '', suffix = el.dataset.suffix || '';
      var w = 420, h = 240, padL = 50, padR = 20, padT = 30, padB = 40;
      var cW = w - padL - padR, cH = h - padT - padB;
      var maxY = 0;
      points.forEach(function (p) { if (p.y > maxY) maxY = p.y; });
      maxY *= 1.15;
      function px(i) { return padL + (i / (points.length - 1)) * cW; }
      function py(v) { return padT + cH - (v / maxY) * cH; }
      var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" xmlns="http://www.w3.org/2000/svg">';
      svg += '<defs><linearGradient id="ag" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="' + A + '0.4)"/><stop offset="100%" stop-color="' + A + '0.02)"/></linearGradient></defs>';
      svg += '<rect x="0" y="0" width="' + w + '" height="' + h + '" rx="16" fill="' + fg(0.02) + '"/>';
      var aD = 'M' + px(0).toFixed(1) + ' ' + py(points[0].y).toFixed(1);
      for (var i = 1; i < points.length; i++) {
        var cp = (px(i - 1) + px(i)) / 2;
        aD += ' C' + cp.toFixed(1) + ' ' + py(points[i - 1].y).toFixed(1) + ',' + cp.toFixed(1) + ' ' + py(points[i].y).toFixed(1) + ',' + px(i).toFixed(1) + ' ' + py(points[i].y).toFixed(1);
      }
      var lD = aD;
      aD += ' L' + px(points.length - 1).toFixed(1) + ' ' + (padT + cH) + ' L' + px(0).toFixed(1) + ' ' + (padT + cH) + ' Z';
      svg += '<path d="' + aD + '" fill="url(#ag)"/>';
      svg += '<path d="' + lD + '" stroke="' + A + '0.9)" stroke-width="2.5" fill="none" stroke-linecap="round"/>';
      points.forEach(function (p, i) {
        var x = px(i), y = py(p.y);
        svg += '<circle cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="4" fill="' + A + '1)"/>';
        svg += '<text x="' + x.toFixed(1) + '" y="' + (y - 10).toFixed(1) + '" text-anchor="middle" font-size="10" font-weight="700" fill="' + fg(0.8) + '" font-family="var(--mono)">' + prefix + p.y + suffix + '</text>';
        svg += '<text x="' + x.toFixed(1) + '" y="' + (h - 8) + '" text-anchor="middle" font-size="10" fill="' + fg(0.4) + '" font-family="var(--mono)">' + p.x + '</text>';
      });
      svg += '</svg>';
      el.innerHTML = svg;
    },

    'gauge': function (el) {
      var value = parseFloat(el.dataset.value) || 50, max = parseFloat(el.dataset.max) || 100;
      var label = el.dataset.label || '', unit = el.dataset.unit || '';
      var pct = Math.min(value / max, 1);
      var w = 420, h = 240, cx = w / 2, cy = 160, r = 100;
      var sa = (225 * Math.PI) / 180, ts = (270 * Math.PI) / 180;
      function ap(a) { return [(cx + r * Math.cos(a)).toFixed(1), (cy - r * Math.sin(a)).toFixed(1)]; }
      var sp = ap(sa), ep = ap(sa - ts), fp = ap(sa - ts * pct);
      var la = pct > 0.5 ? 1 : 0;
      var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" xmlns="http://www.w3.org/2000/svg">';
      svg += '<rect x="0" y="0" width="' + w + '" height="' + h + '" rx="16" fill="' + fg(0.02) + '"/>';
      svg += '<path d="M' + sp[0] + ' ' + sp[1] + ' A' + r + ' ' + r + ' 0 1 1 ' + ep[0] + ' ' + ep[1] + '" stroke="' + fg(0.08) + '" stroke-width="14" fill="none" stroke-linecap="round"/>';
      if (pct > 0.001) svg += '<path d="M' + sp[0] + ' ' + sp[1] + ' A' + r + ' ' + r + ' 0 ' + la + ' 1 ' + fp[0] + ' ' + fp[1] + '" stroke="' + A + '0.85)" stroke-width="14" fill="none" stroke-linecap="round"/>';
      svg += '<text x="' + cx + '" y="' + (cy - 16) + '" text-anchor="middle" font-size="40" font-weight="800" fill="' + A + '0.95)">' + value + unit + '</text>';
      svg += '<text x="' + cx + '" y="' + (cy + 8) + '" text-anchor="middle" font-size="10" fill="' + fg(0.4) + '" font-family="var(--mono)" letter-spacing="0.15em">' + label + '</text>';
      svg += '</svg>';
      el.innerHTML = svg;
    },

    'donut': function (el) {
      var segments = JSON.parse(el.dataset.segments || '[]');
      var total = parseFloat(el.dataset.total) || 0;
      var label = el.dataset.label || '';
      if (!segments.length) return;
      if (!total) segments.forEach(function (s) { total += s.value; });
      var w = 420, h = 300, cx = w / 2, cy = 130, r = 80, ir = 50;
      var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" xmlns="http://www.w3.org/2000/svg">';
      svg += '<rect x="0" y="0" width="' + w + '" height="' + h + '" rx="16" fill="' + fg(0.02) + '"/>';
      var angle = -Math.PI / 2;
      segments.forEach(function (seg, i) {
        var pct = total > 0 ? seg.value / total : 0;
        var sweep = pct * Math.PI * 2 - 0.03;
        if (sweep < 0.01) return;
        var alpha = Math.max(0.25, 1 - i * 0.12);
        var sa = angle + 0.015, ea = sa + sweep;
        var x1 = cx + r * Math.cos(sa), y1 = cy + r * Math.sin(sa);
        var x2 = cx + r * Math.cos(ea), y2 = cy + r * Math.sin(ea);
        var ix1 = cx + ir * Math.cos(ea), iy1 = cy + ir * Math.sin(ea);
        var ix2 = cx + ir * Math.cos(sa), iy2 = cy + ir * Math.sin(sa);
        var lg = sweep > Math.PI ? 1 : 0;
        svg += '<path d="M' + x1.toFixed(1) + ' ' + y1.toFixed(1) + ' A' + r + ' ' + r + ' 0 ' + lg + ' 1 ' + x2.toFixed(1) + ' ' + y2.toFixed(1) + ' L' + ix1.toFixed(1) + ' ' + iy1.toFixed(1) + ' A' + ir + ' ' + ir + ' 0 ' + lg + ' 0 ' + ix2.toFixed(1) + ' ' + iy2.toFixed(1) + ' Z" fill="' + A + alpha.toFixed(2) + ')"/>';
        angle += pct * Math.PI * 2;
      });
      svg += '<text x="' + cx + '" y="' + (cy - 6) + '" text-anchor="middle" font-size="20" font-weight="800" fill="' + fg(0.9) + '">' + total + '</text>';
      svg += '<text x="' + cx + '" y="' + (cy + 12) + '" text-anchor="middle" font-size="9" fill="' + fg(0.4) + '" font-family="var(--mono)" letter-spacing="0.15em">' + label + '</text>';
      var ly = cy + r + 28;
      segments.slice(0, 8).forEach(function (seg, i) {
        var lx = i % 2 === 0 ? 30 : w / 2 + 10;
        var y = ly + Math.floor(i / 2) * 18;
        var a2 = Math.max(0.25, 1 - i * 0.12);
        svg += '<rect x="' + lx + '" y="' + (y - 6) + '" width="8" height="8" rx="2" fill="' + A + a2.toFixed(2) + ')"/>';
        svg += '<text x="' + (lx + 14) + '" y="' + y + '" font-size="10" fill="' + fg(0.6) + '" font-family="var(--mono)">' + seg.label + '</text>';
      });
      svg += '</svg>';
      el.innerHTML = svg;
    },

    'balance': function (el) {
      var left = el.dataset.left || 'Spec', right = el.dataset.right || 'Hype';
      var tilt = parseFloat(el.dataset.tilt) || -8;
      var w = 420, h = 200, cx = w / 2, baseY = 160;
      var rad = tilt * Math.PI / 180, bLen = 140;
      var lx = cx - bLen * Math.cos(rad), ly = (baseY - 20) + bLen * Math.sin(rad);
      var rx = cx + bLen * Math.cos(rad), ry = (baseY - 20) - bLen * Math.sin(rad);
      var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" xmlns="http://www.w3.org/2000/svg">';
      svg += '<rect x="0" y="0" width="' + w + '" height="' + h + '" rx="16" fill="' + fg(0.02) + '"/>';
      svg += '<polygon points="' + (cx - 12) + ',' + baseY + ' ' + (cx + 12) + ',' + baseY + ' ' + cx + ',' + (baseY - 16) + '" fill="' + fg(0.1) + '" stroke="' + fg(0.2) + '" stroke-width="1"/>';
      svg += '<line x1="' + lx.toFixed(1) + '" y1="' + ly.toFixed(1) + '" x2="' + rx.toFixed(1) + '" y2="' + ry.toFixed(1) + '" stroke="' + fg(0.25) + '" stroke-width="2.5" stroke-linecap="round"/>';
      svg += '<circle cx="' + lx.toFixed(1) + '" cy="' + ly.toFixed(1) + '" r="18" fill="' + A + '0.2)" stroke="' + A + '0.5)" stroke-width="1.5"/>';
      svg += '<text x="' + lx.toFixed(1) + '" y="' + (ly + 4).toFixed(1) + '" text-anchor="middle" font-size="9" fill="' + fg(0.7) + '" font-family="var(--mono)">' + left + '</text>';
      svg += '<circle cx="' + rx.toFixed(1) + '" cy="' + ry.toFixed(1) + '" r="18" fill="' + fg(0.04) + '" stroke="' + fg(0.15) + '" stroke-width="1.5"/>';
      svg += '<text x="' + rx.toFixed(1) + '" y="' + (ry + 4).toFixed(1) + '" text-anchor="middle" font-size="9" fill="' + fg(0.4) + '" font-family="var(--mono)">' + right + '</text>';
      svg += '</svg>';
      el.innerHTML = svg;
    }
  };

  // Auto-render all figure elements on DOM ready
  function renderAll() {
    document.querySelectorAll('[data-figure]').forEach(function (el) {
      var type = el.dataset.figure;
      if (FIGURES[type]) FIGURES[type](el);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renderAll);
  } else {
    renderAll();
  }

  // Re-render when theme toggles
  new MutationObserver(function (mutations) {
    mutations.forEach(function (m) {
      if (m.attributeName === 'data-theme') renderAll();
    });
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
})();

