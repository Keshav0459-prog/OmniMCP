# OmniMCP Design System

> Inspired by Linear (Dark Craft & Speed), Vercel (Minimal Precision), and Raycast (Command Density).  
> Standardized using the `awesome-design-md` specification.

---

## 1. Visual Archetype & Brand Identity

- **Archetype**: Linear Dark Craft & Speed × Vercel Minimal Precision.
- **Mood**: Fast, authoritative, high-density, engineering-first, focused, zero distraction.
- **Form Factor**: Responsive developer cockpit with collapsible navigation, tabular numbers, and hairline borders.
- **Theme Support**: Dark-first default (`#090a0f`), optimized for long developer sessions, high contrast, and visual comfort.

---

## 2. Color Palette & Semantic Tokens

### Canvas & Surfaces
| Token | Hex Value | Role |
|---|---|---|
| `canvas-default` | `#090a0f` | Deep Charcoal canvas / window background |
| `surface-subtle` | `#0e1017` | Secondary background, sidebar base, grouped lists |
| `surface-panel` | `#131620` | Primary cards, table bodies, modal surfaces |
| `surface-elevated`| `#1a1e2b` | Hovered items, active selection containers, dropdowns |
| `surface-overlay` | `#222738` | Badges, tooltips, segmented control indicators |

### Borders & Dividers
| Token | Hex Value / Opacity | Role |
|---|---|---|
| `border-subtle` | `rgba(255, 255, 255, 0.06)` | Hairline dividers between table rows and sections |
| `border-default`| `rgba(255, 255, 255, 0.12)` | Card borders, input field outlines, button borders |
| `border-strong` | `rgba(255, 255, 255, 0.22)` | Hover borders, active tab outlines |
| `border-accent` | `#7c3aed` | Focus visible rings, active selection states |

### Accent Colors
| Role | Hex Value | Semantic Meaning |
|---|---|---|
| `accent-primary` | `#7c3aed` (Electric Violet) | Primary branding, action buttons, active profile pill |
| `accent-secondary`| `#38bdf8` (Sky Blue) | Informational tags, transport indicators, link highlights |
| `accent-success` | `#10b981` (Emerald) | Online health, approved executions, exit code 0 |
| `accent-warning` | `#f59e0b` (Amber) | Pending approvals, write-protected operations |
| `accent-danger` | `#ef4444` (Rose) | Failed executions, destructive operations, disconnected state |

### Text & Typography Tokens
| Token | Hex Value | Contrast Ratio (vs `#090a0f`) | Role |
|---|---|---|---|
| `text-primary` | `#f8fafc` (Slate 50) | 18.2:1 (AAA) | Headings, active values, card titles |
| `text-secondary`| `#94a3b8` (Slate 400) | 8.1:1 (AAA) | Subheadings, descriptions, table labels |
| `text-tertiary` | `#64748b` (Slate 500) | 4.8:1 (AA) | Timestamps, placeholders, inactive icons |
| `text-accent` | `#a78bfa` (Violet 400) | 9.4:1 (AAA) | Highlighted numbers, active navigation links |

---

## 3. Typography Scale & Font Rules

- **Primary Sans Font**: `Inter`, `-apple-system`, `BlinkMacSystemFont`, `sans-serif`
- **Monospace Font**: `Geist Mono`, `ui-monospace`, `SFMono-Regular`, `Menlo`, `monospace`
- **Tabular Numerals**: Enforce `font-variant-numeric: tabular-nums` across all metrics, IDs, latencies, and execution counters.

| Scale | Size | Line Height | Weight | Letter Spacing | Usage |
|---|---|---|---|---|---|
| `text-2xs` | 10px | 14px | 500 / 600 | `+0.04em` (Uppercase) | Badges, transport tags, column category headers |
| `text-xs` | 12px | 16px | 400 / 500 | `+0.01em` | Table body cells, sidebar navigation, metadata |
| `text-sm` | 14px | 20px | 400 / 500 | Normal | Descriptions, modal bodies, button text |
| `text-base` | 16px | 24px | 500 / 600 | `-0.01em` | Section headers, card titles, drawer headings |
| `text-xl` | 20px | 28px | 600 / 700 | `-0.02em` | View title, modal headers |
| `text-2xl` | 24px | 32px | 700 | `-0.025em` | Dashboard primary statistics, counter totals |

---

## 4. Radii, Elevation & Hairline Borders

### Concentric Radius Scale
- **Small Controls (`rounded-md`)**: `6px` — Buttons, text inputs, select dropdowns, search bars.
- **Medium Panels (`rounded-lg`)**: `10px` — Metric cards, task cards, tables, popovers.
- **Large Containers (`rounded-xl`)**: `14px` — Modals, drawer containers, major dashboard sections.
- **Pills (`rounded-full`)**: `9999px` — Status indicators, active profile badge, count tags.

### Subtle Elevation & Shadows
- **Card Rest**: `0 1px 2px rgba(0, 0, 0, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.06)`
- **Card Hover**: `0 4px 16px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255, 255, 255, 0.12)`
- **Modal / Floating Panel**: `0 12px 36px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.15)`

---

## 5. Icon Conventions

- **Icon Family**: Lucide Icons.
- **Default Stroke Width**: `1.75px` (refined, consistent, crisp).
- **Icon Sizing Rules**:
  - Small badges & inline indicators: `12px` / `14px`
  - Navigation sidebar & buttons: `16px`
  - Section headers & large metrics: `20px`

---

## 6. Micro-Interactions & Motion Principles

- **Standard Transition**: `all 150ms cubic-bezier(0.16, 1, 0.3, 1)` (snappy, responsive).
- **Hover Feedback**: Boost background surface luminance by 4–6% or increase border opacity; avoid heavy transforms.
- **Active State**: Scale feedback `transform: scale(0.98)` on button clicks.
- **Modal Reveal**: Opacity `0 -> 1` with subtle vertical drift `translateY(4px) -> translateY(0)`.
- **Reduced Motion**: Automatically respect `@media (prefers-reduced-motion: reduce)` with zero animation transitions.

---

## 7. Accessibility (WCAG 2.1 AA Compliance)

- **Contrast Guarantee**: Minimum 4.5:1 text-to-background contrast on all body text, minimum 3:1 on large text and UI components.
- **Focus Rings**: `outline: 2px solid #7c3aed; outline-offset: 2px` on all interactive elements via `:focus-visible`.
- **Keyboard Navigation**: Full traversal support (`Tab`, `Shift+Tab`, `Enter`, `Escape` to close drawers/modals).
- **ARIA Semantics**: Proper `role="dialog"`, `role="tablist"`, `aria-expanded`, and `aria-label` attributes on icon-only buttons.

