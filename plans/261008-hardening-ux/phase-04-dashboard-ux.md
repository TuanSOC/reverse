# Phase 4 — Dashboard UX upgrade + i18n (in place)

- **Home hub** (new default section): no scan → welcome + "Start first scan"
  CTA + 3-step how-to; with scan → KPI tiles (risk, findings by severity,
  endpoints, AI status) + "Next steps" list linking to sections (high
  findings, run AI, static-only endpoints, source map exposed…).
- **Nav**: groups Start (Home) · Results (Overview, AI Analysis, Findings) ·
  Surface (Attack Surface, Endpoints, JS Files, Auth Flow, Forms) · Inventory
  (Technologies, Pages, Assets, DNS/TLS, Graph) · History (Timeline, Compare,
  Reports). Badges for counts; active state; collapsible on mobile (drawer).
- **i18n**: `I18N = {en:{…}, vi:{…}}`, `t(key)`; language toggle in header;
  default from `navigator.language`, stored in localStorage (try/catch).
  Section ids stay English internally; labels translated.
- **States**: one `loading()`, `emptyState(msg, action?)`, `errorState(err,
  retry)` used everywhere; empty states explain what to do next.
- **Responsive**: ≤860px sidebar becomes off-canvas menu button; tables
  scroll horizontally inside a wrapper; 16px gutters; no page h-scroll.
- **A11y**: `:focus-visible` rings, nav as buttons/links with aria-current,
  drawer focus trap + return focus, aria-labels on icon buttons,
  prefers-reduced-motion respected, color contrast ≥ 4.5:1 on text.
- **Polish**: consistent spacing scale, table density, page headers with
  description + actions, tooltips for jargon (observed/referenced/potential).
Verification: browser pass at 1440 / 390 px in EN + VI, 0 console errors,
JS guard test, screenshots.
