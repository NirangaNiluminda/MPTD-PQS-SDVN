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
    },
  },
  plugins: [],
};
