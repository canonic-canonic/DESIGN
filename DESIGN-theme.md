# DESIGN-theme

inherits: canonic-canonic/MAGIC/SURFACE/JEKYLL

---

## Scope

DESIGN-theme IS the JEKYLL service runtime. `remote_theme: canonic-canonic/DESIGN`. Fleet sites consume this theme — it contains no content.

## Hierarchy

```
MAGIC
└── SURFACE
    └── DESIGN
        └── JEKYLL
            └── DESIGN-theme    ← this scope (GitHub repo)
                ├── _includes/  — figures, partials
                ├── _layouts/   — page templates
                ├── _sass/      — stylesheets
                ├── assets/     — css, js
                └── demo/       — reference deck
```

## Evolution

| Date | Event |
|------|-------|
| 2025-12 | Jekyll theme established — remote_theme distribution |
| 2026-01 | DESIGN.css universal — one stylesheet, all surfaces |
| 2026-02 | Fleet sites consuming via _config.yml remote_theme |

---

*DESIGN-theme | JEKYLL | DESIGN | SURFACE | MAGIC*
