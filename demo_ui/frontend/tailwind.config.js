/** @type {import('tailwindcss').Config} */
// Colour values are CSS custom properties defined in src/index.css (RGB
// triplets, one block per [data-theme]) so utility classes stay theme-aware
// AND keep Tailwind's opacity modifiers (bg-surface-panel/95 etc.) working —
// see src/design/tokens.ts for the hex source of truth and palette
// validation results.
const withOpacity = (varName) => `rgb(var(${varName}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          page: withOpacity("--c-surface-page"),
          panel: withOpacity("--c-surface-panel"),
          raised: withOpacity("--c-surface-raised"),
          hairline: withOpacity("--c-surface-hairline"),
          hairline2: withOpacity("--c-surface-hairline2"),
        },
        ink: {
          primary: withOpacity("--c-ink-primary"),
          secondary: withOpacity("--c-ink-secondary"),
          muted: withOpacity("--c-ink-muted"),
        },
        entity: {
          rsu: withOpacity("--c-entity-rsu"),
          controller: withOpacity("--c-entity-controller"),
          vehicle: withOpacity("--c-entity-vehicle"),
          ghost: withOpacity("--c-entity-ghost"),
        },
        status: {
          good: withOpacity("--c-status-good"),
          caught: withOpacity("--c-status-caught"),
          serious: withOpacity("--c-status-serious"),
          missed: withOpacity("--c-status-missed"),
        },
      },
      fontFamily: {
        // "IBM Plex Sans" first, system-ui fallback if the CDN is unreachable.
        sans: ['"IBM Plex Sans"', 'system-ui', '-apple-system', '"Segoe UI"', 'sans-serif'],
        // Reserved for numeric/tabular data — timestamps, scores, hashes,
        // IDs. Never for prose. Matches the mockup's convention: mono for
        // anything a reader needs to scan/compare, sans for anything they read.
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'Menlo', 'monospace'],
      },
      // Named scale for the SOC-dashboard redesign (Datadog/Grafana/Linear-
      // style density: fewer, bigger sizes used consistently, not a dozen
      // one-off text-[Npx] values). Applies to screens as they're rolled
      // onto this scale — older un-migrated screens keep their existing
      // text-xs/text-[Npx] usage until their turn.
      fontSize: {
        hero: ["2.5rem", { lineHeight: "1.1", fontWeight: "700" }], // 40px
        "page-title": ["1.625rem", { lineHeight: "1.25", fontWeight: "600" }], // 26px
        "section-title": ["1.0625rem", { lineHeight: "1.35", fontWeight: "600" }], // 17px
        body: ["0.875rem", { lineHeight: "1.6" }], // 14px
        badge: ["0.75rem", { lineHeight: "1.4", fontWeight: "600" }], // 12px
      },
    },
  },
  plugins: [],
};
