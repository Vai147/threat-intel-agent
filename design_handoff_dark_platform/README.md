# Handoff: Dark "Enterprise Platform" restyle for the Threat Intel Console

## Overview
This restyles the existing **threat-intel-agent** frontend from its current dark-terminal/SOC look into a calmer, dark **Material-style enterprise platform** layout: a top app bar with search, a left navigation rail, and flat elevation cards for the investigation report.

**This is a styling + layout change only.** All data flow — the `useInvestigation()` SSE hook, `fetchFeed()`, `lib/api.ts`, and the `Report` / `FeedIOC` / `AgentEvent` types — stays exactly as it is. Do **not** rewire any fetching, parsing, or state logic.

## About the design files
`Cleanup.dc.html` in this bundle is a **design reference written in HTML** — a prototype showing the intended look, not production code to paste in. It is a pannable canvas with five frames; the target for this handoff is **Frame 5: "ENTERPRISE PLATFORM — dark"** (the bottom frame). Recreate that look inside the existing React + Vite + TypeScript app, reusing its component structure and CSS-variable token system.

## Fidelity
**High-fidelity.** Colors, typography, spacing, and radii below are final — match them. The other frames (before / clean-dark / fix list / light platform) are context only.

---

## Target architecture in the existing repo

Keep the component tree; change the shell and the styling. The biggest structural change is the **app shell**: today `App.tsx` is a centered 960px column with a pill-tab header. The new shell is a full-width app bar + a persistent left nav rail + a content area.

| Repo file | Change |
|---|---|
| `src/styles/tokens.css` | Replace the dark-slate/cyan token values with the Material dark tokens below. Keep the variable **names** so component CSS keeps working; just change values. Add the new nav/appbar tokens. |
| `src/styles/global.css` | **Remove the grid `background-image`** on `body` (the two `linear-gradient`s + `background-size`). Switch `--font-sans` usage to Roboto. Drop `::selection` glow if desired. |
| `src/App.tsx` | Replace the `app__header` (brand + pill tabs) with an **app bar** (logo chip + search field + user) and move navigation into a **left nav rail**. Wrap `main` so the rail and content sit side by side. The `tab` state and `investigateFromFeed` logic are unchanged — just render the nav items as rail rows instead of pill buttons. |
| `src/App.css` | Rewrite for the app-bar + rail + content layout (specs below). Remove `max-width:960px` centering; the platform is full-bleed. |
| `src/components/investigate/ReportView.tsx` | Keep structure. The hero `Card` becomes the **verdict card**; the bento grid becomes a `1fr 320px` two-column grid (main = verdict + MITRE; side = actions + related). |
| `src/components/investigate/investigate.css` | Restyle verdict block, MITRE table, action list, severity badge → tonal chip (specs below). Remove `pulse`/`blink` animations from the report; keep them only inside `AgentStream` while `running`. |
| `src/components/ui/Card.tsx` + `ui.css` | Flat Material card: `background: var(--surface)`, `1px solid var(--border)`, `border-radius: 8px`, no glow/gradient. `card--accent` → no gradient, just the card. `card__label` → sentence-case, no uppercase/letter-spacing/mono. |
| `src/components/investigate/SeverityBadge.tsx` | Render as a **tonal chip**: pill, `background` = severity color at 16% alpha, text/dot = severity color. No glow on the dot. |
| `src/components/feed/*` | `FeedPanel` / `FeedTable` / `feed.css` restyled to the dark Material card + table (see "Live feed" below). Data logic untouched. |

Keep untouched: `useInvestigation.ts`, `lib/api.ts`, `lib/types.ts`, `lib/format.ts`, `IocInput.tsx` logic (restyle only), `FeedPanel.tsx` / `FeedTable.tsx` logic.

---

## Design tokens (dark Material)

Drop-in replacement for `tokens.css` values (keep variable names so existing CSS resolves):

```css
:root {
  /* Surfaces */
  --bg: #202124;            /* page / content area */
  --surface: #2d2e31;       /* cards, app bar, nav rail */
  --surface-2: #292a2d;     /* table header, insets */
  --surface-3: #3c4043;     /* neutral chip bg, search field */
  --border: #3c4043;        /* hairline borders */
  --border-strong: #5f6368;

  /* Text */
  --text: #e8eaed;
  --text-dim: #bdc1c6;      /* body copy in cards */
  --text-faint: #9aa0a6;    /* secondary labels */
  --text-muted: #80868b;    /* tertiary / numerals */

  /* Primary (Material blue 300) */
  --accent: #8ab4f8;
  --accent-soft: rgba(138, 180, 248, 0.16);  /* active nav, blue chip bg */
  --accent-avatar: rgba(138, 180, 248, 0.20);

  /* Severity — Material dark 300-level hues, each paired with a 16% tonal bg */
  --sev-critical: #f28b82;  --sev-critical-bg: rgba(242,139,130,0.16);
  --sev-high:     #fcad70;  --sev-high-bg:     rgba(252,173,112,0.16);
  --sev-medium:   #fdd663;  --sev-medium-bg:   rgba(253,214,99,0.16);
  --sev-low:      #81c995;  --sev-low-bg:      rgba(129,201,149,0.16);
  --sev-info:     #8ab4f8;  --sev-info-bg:     rgba(138,180,248,0.16);

  /* Typography */
  --font-sans: "Roboto", system-ui, -apple-system, sans-serif;
  --font-mono: "Roboto Mono", ui-monospace, "SF Mono", Menlo, monospace;

  /* Shape */
  --radius-chip: 6px;
  --radius: 8px;
  --radius-pill: 999px;

  /* Chrome */
  --appbar-h: 60px;
  --rail-w: 230px;
}
```

**Fonts:** add Roboto + Roboto Mono. In `index.html` `<head>`:
```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;600&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
```

There are **no glow shadows and no gradients** anywhere. Cards use a `1px solid var(--border)` hairline and, optionally, a very subtle `box-shadow: 0 1px 2px rgba(0,0,0,.3)`.

---

## Screens / Views

### App shell (`App.tsx` + `App.css`)
- **App bar** — height `60px`, `background: var(--surface)`, `border-bottom: 1px solid var(--border)`, horizontal padding `22px`, `display:flex; align-items:center; gap:18px`.
  - **Logo chip**: 30×30, `border-radius:7px`, `background: var(--accent)`, text `#202124`, weight 600, `font-size:14px`, content `TI`. Next to it: product name `Threat Intel`, `1.05rem`, weight 500, `color: var(--text)`.
  - **Search field**: `flex:1; max-width:520px`, `background: var(--surface-3)`, `border-radius:8px`, padding `9px 14px`, `color: var(--text-faint)`, `0.9rem`, with a 16px magnifier icon (circle + line, `stroke: var(--text-faint)`). Placeholder copy: `Search indicators, reports, detections`.
  - **Right cluster** (`margin-left:auto; gap:16px`): label `SOC · Tier 2` (`0.85rem`, `var(--text-faint)`) + 34px round avatar `background: var(--accent-avatar)`, `color: var(--accent)`, weight 600, initials `AK`.
- **Left nav rail** — `width: var(--rail-w)` (230px), `flex-shrink:0`, `background: var(--surface)`, `border-right: 1px solid var(--border)`, padding `16px 12px`.
  - Section heading `Operations`: `0.72rem`, weight 600, `letter-spacing:0.06em`, uppercase, `color: var(--text-muted)`, padding `6px 14px 10px`.
  - Nav rows: `display:flex; align-items:center; gap:13px`, padding `9px 14px`, `border-radius:999px`, `0.9rem`, icon 18px on the left.
    - Inactive: `color: var(--text-dim)`, icon `stroke: var(--text-faint)`.
    - **Active** (Investigate): `background: var(--accent-soft)`, `color: var(--accent)`, weight 500, icon `stroke: var(--accent)`.
  - Items in order: **Dashboard** (4-square grid icon), **Investigate** (magnifier, active), **Live feed** (3 horizontal lines), **Detections** (warning triangle), **Rules** (rounded rect + lines). Dashboard/Detections/Rules can be placeholders; **Investigate** and **Live feed** drive the existing `tab` state.
- **Content area** — `flex:1; background: var(--bg)`, padding `24px 28px 30px`, `min-width:0`.
  - Breadcrumb: `Investigate / Report` — `0.82rem`, `var(--text-faint)`, the trailing segment `var(--text)`, slash `#5f6368`.
  - Page title `h1`: `Investigation report`, `1.4rem`, weight 500, `var(--text)`, `letter-spacing:-0.01em`, `margin:0 0 20px`.

### Report (`ReportView.tsx` + `investigate.css`)
Two-column grid: `grid-template-columns: 1fr 320px; gap:18px; align-items:start`. Collapse to one column under ~720px.

**Main column** (`display:flex; flex-direction:column; gap:18px`):
- **Verdict card** (the old hero): card surface, padding `22px 24px`.
  - Top row `space-between`, wrap: left = IOC in `var(--font-mono)` `1.18rem` `var(--text)` (break-all) + below it `{typeLabel} · first seen …` at `0.85rem` `var(--text-faint)`; right = **severity chip**.
  - Below: a row of neutral chips (`gap:10px`, wrap) for classification, `Confidence {n}%`, and source — each `padding:5px 11px`, `border-radius:6px`, `background: var(--surface-3)`, `color: var(--text-dim)`, `0.8rem`.
  - Summary `p`: `margin-top:18px`, `color: var(--text-dim)`, `line-height:1.6`, `0.95rem`, `text-wrap:pretty`.
- **MITRE card**: header bar `16px 24px`, `border-bottom: 1px solid var(--border)`, `0.95rem` weight 500. Table `width:100%; border-collapse:collapse; 0.88rem`. `thead` row `background: var(--surface-2)`, headers `0.78rem` weight 500 `var(--text-faint)` left-aligned, padding `10px 24px`. Body cells padding `13px 24px`, `border-top: 1px solid var(--border)`; ID column in `var(--font-mono)` `color: var(--accent)` (keep the existing `<a>` link to attack.mitre.org), name `var(--text-dim)`, tactic `var(--text-faint)`.

**Side column** (`gap:18px`):
- **Recommended actions card**: title `0.9rem` weight 500. `<ol>` as `list-style:none`, `gap:12px`; each `<li>` `display:flex; gap:11px`, a 2-digit mono index (`01`, `02`, …) at `0.75rem` `var(--text-muted)`, then the action text `0.88rem` `var(--text-dim)` `line-height:1.45`.
- **Related card**: label `0.78rem` `var(--text-faint)` then chips. `related_malware` → red tonal chips (`background: var(--sev-critical-bg)`, `color: var(--sev-critical)`). `related_threat_groups` → blue tonal chips (`var(--accent-soft)` / `var(--accent)`). `related_iocs` → neutral mono chips. Chip = `padding:4px 10px; border-radius:6px; 0.8rem`.

### Severity chip (`SeverityBadge.tsx`)
Pill: `display:inline-flex; align-items:center; gap:7px; padding:6px 12px; border-radius:999px`, `background: var(--sev-*-bg)`, `color: var(--sev-*)`, `0.8rem` weight 500. Leading dot 7px `border-radius:999px; background: var(--sev-*)` — **no box-shadow glow**. Map `SEVERITY_VAR` to the new `--sev-*` names. Confidence can move into the neutral chip row in the verdict card (as `Confidence {n}%`).

### Agent trace (`AgentStream.tsx`)
Keep it, restyled as a flat card. The pulsing dot + blinking cursor are fine **only while `running`** — they should not persist in the finished report view.

### Live feed (`FeedPanel.tsx` + `FeedTable.tsx` + `feed.css`)
Same content area shell (breadcrumb `Investigate / …` becomes `Live feed`, page title `Live indicator feed`). Logic in `FeedPanel` (`days` / `limit` / `load()` / `fetchFeed`) and `FeedTable` (`onInvestigate`) is **unchanged** — restyle only.

- **Control bar** (`feed__bar`): `display:flex; justify-content:space-between; align-items:flex-end; gap:24px; flex-wrap:wrap`.
  - **Lead text** (`feed__lead`): `max-width:46ch`, `color: var(--text-dim)`, `line-height:1.55`, `0.9rem`. Keep the inline `abuse.ch ThreatFox` link → `color: var(--accent)`, no underline until hover. Copy unchanged.
  - **Controls** (`feed__controls`): `display:flex; align-items:flex-end; gap:12px`.
    - **Number fields** (`days`, `limit`): label above input, label `0.72rem` uppercase `letter-spacing:0.06em` `var(--text-faint)`. Input: `width:4.5rem`, `background: var(--surface)`, `border:1px solid var(--border)`, `border-radius:6px`, `color: var(--text)`, padding `8px`, `font-family: var(--font-mono)`. On focus: `border-color: var(--accent)`, no glow.
    - **Pull IOCs button** (`feed__load`): `background: var(--accent)`, text `#202124`, weight 500, `border-radius:8px`, padding `9px 18px`. Hover `filter: brightness(1.06)`; `:disabled` `opacity:0.5`. Label `Pull IOCs` / `Loading…` (existing).
- **Error banner** (`feed__error`): red tonal — `background: var(--sev-critical-bg)`, `border:1px solid var(--sev-critical)`, `color: var(--sev-critical)`, `border-radius:8px`, padding `12px 16px`. Keep the muted `.env` hint at `var(--text-faint)`.
- **Feed table** (`feed-table`): wrap in a Material card — `background: var(--surface)`, `border:1px solid var(--border)`, `border-radius:8px`, `overflow:hidden`. `width:100%; border-collapse:collapse`.
  - **Header** (`th`): `background: var(--surface-2)`, `0.78rem` weight 500 `var(--text-faint)`, left-aligned, padding `12px 20px`. Drop the uppercase + `letter-spacing` SOC treatment — sentence case (`Indicator`, `Type`, `Malware`, `Confidence`, and an empty action header).
  - **Rows** (`td`): padding `13px 20px`, `border-top:1px solid var(--border)`, `0.88rem`. Row `:hover` → `background: var(--surface-2)` (transition `background 140ms`).
    - **Indicator** cell: `var(--font-mono)`, `color: var(--text)`, `word-break:break-all`, `max-width:22rem`.
    - **Type** cell: `var(--text-faint)` (via `typeLabel`).
    - **Malware** cell: `var(--text-dim)`, em-dash fallback `var(--text-muted)`.
    - **Confidence** cell (`ConfidenceBar`): `display:flex; align-items:center; gap:8px`. Track `width:56px; height:6px; background: var(--surface-3); border-radius:999px; overflow:hidden`. **Fill** — replace the red→amber gradient with a **single calm fill**: `background: var(--accent)` (or map by severity band if you prefer: ≥80 `--sev-critical`, ≥50 `--sev-high`, else `--sev-low`), `width:{value}%`. Number `var(--font-mono)` `0.72rem` `var(--text-faint)`.
    - **Action** cell (`feed-table__action`): the `Investigate →` button as a quiet Material text/outline button — `background:transparent`, `border:1px solid var(--border-strong)`, `color: var(--accent)`, `border-radius:6px`, padding `6px 14px`, `white-space:nowrap`. Hover: `background: var(--accent-soft)`, `border-color: var(--accent)`. Click still calls `onInvestigate(ioc.value, ioc.ioc_type, "live")`.
- **Empty state**: `No IOCs returned.` at `var(--text-faint)`.

No new state, no data changes — `FeedIOC` shape and `fetchFeed(days, limit)` stay as-is.

---

## Interactions & behavior (unchanged)
- Nav rail **Investigate / Live feed** rows set `tab` (same handler as today's pill tabs); show active state via `--accent-soft`.
- Clicking a feed row still calls `investigateFromFeed(ioc, type, "live")` → switches tab + prefills (existing logic).
- `IocInput` submit, auto-detect, backend toggle: unchanged logic, restyle controls to Material (field `var(--surface-3)`, primary button `background: var(--accent)`, text `#202124`).
- Loading/error states: keep existing; restyle error to a red tonal banner (`var(--sev-critical-bg)` / `var(--sev-critical)`).
- Respect `prefers-reduced-motion` (already handled in `global.css`).

## State management (unchanged)
`useInvestigation()` (status / events / report / error / start), `FeedPanel` local state, `App` `tab` + `prefill`. No new state required beyond what already exists.

## Assets
Nav and search **icons** are simple inline SVGs (grid of squares, magnifier, lines, warning triangle, rounded rect) — recreate as small stroke icons or swap for your existing icon set (e.g. Material Symbols). No raster assets. No brand logos.

## Files in this bundle
- `Cleanup.dc.html` — the HTML design reference (pannable canvas). The two target frames:
  - **"ENTERPRISE PLATFORM — dark"** — the investigation report view.
  - **"LIVE FEED — dark"** — the live indicator feed view.
  Other frames (before / clean-dark / fix list / light platform) are alternatives and context.
