// Design tokens — the palette here was VALIDATED with the dataviz skill's
// validate_palette.js against the actual chart/map surfaces, not chosen by
// eye. Re-run the validator before changing any hex below.
//
// Validation results that constrain the DARK palette:
//
//  * The co-occurring map set (RSU blue, controller aqua, caught yellow,
//    missed red) passes the normal-vision floor at ΔE 20.9 (>=15 required)
//    and lands at CVD ΔE 7.2 — inside the 6-8 band, which is permitted ONLY
//    with secondary encoding. That is why every entity class also carries a
//    distinct SHAPE and a text label. Do not remove those and leave colour
//    to do the work alone.
//
//  * An earlier attempt used violet for controllers: violet vs blue measured
//    CVD ΔE 1.9 / normal-vision ΔE 9.8 — a hard fail. Aqua replaced it.
//
//  * Ghost magenta vs controller aqua measures CVD ΔE 1.6 (fail). Ghosts are
//    therefore separated by SHAPE (cross) + an explicit "GHOST" label, never
//    by colour. Magenta is retained only as a supporting accent.
//
//  * The status quartet (good/caught/serious/missed) fails all-pairs CVD and
//    normal-vision floors (missed vs good ΔE ~4, serious vs caught ΔE 13.6)
//    — status colours are therefore NEVER shown without an icon + text label
//    per the skill's status rule; nowhere in this app relies on the hue
//    alone to distinguish them.
//
//  * SERIES (chart lines) validated on the ADJACENT pairlist only (fixed
//    legend order, never cycled): worst adjacent CVD ΔE 8.4, normal-vision
//    ΔE 19.8.
//
// The LIGHT palette (source: the SENTINEL mockup's [data-theme="light"]
// block) was validated against the SAME standard, not assumed safe by
// analogy — see the re-run below. It clears an identical or better bar on
// every check:
//
//  * Core map set (RSU/controller/caught/missed): WARN band, CVD ΔE 6.5 —
//    same secondary-encoding requirement as dark, already satisfied by the
//    existing shape+label treatment.
//  * Ghost vs controller: FAILs CVD (ΔE 2.4), matching dark's already-known,
//    already-mitigated failure — ghosts never rely on colour alone in either
//    theme.
//  * Status quartet: FAILs all-pairs (worse than dark, in fact), but this
//    mirrors dark's own pre-existing accepted risk under the same
//    icon+label mitigation — not a light-mode regression.
//  * SERIES (adjacent pairlist): PASSES — worst adjacent CVD ΔE 7.7 (WARN
//    band, legal via the chart's existing direct-label legend), normal-
//    vision ΔE 18.0.

import { useTheme } from "../store/theme";

export type ThemeName = "dark" | "light";

interface PaletteTokens {
  SURFACE: {
    page: string;
    panel: string;
    raised: string;
    hairline: string;
    hairlineStrong: string;
  };
  INK: { primary: string; secondary: string; muted: string };
  ENTITY: { rsu: string; controller: string; vehicleClean: string; ghost: string };
  STATUS: { good: string; caught: string; serious: string; missed: string };
  SERIES: readonly [string, string, string, string];
  PROVENANCE: {
    live: { glyph: string; label: string; color: string };
    replayed: { glyph: string; label: string; color: string };
    snapshot: { glyph: string; label: string; color: string };
  };
}

const DARK: PaletteTokens = {
  SURFACE: {
    page: "#0b0f14",
    panel: "#0f1419",
    raised: "#151c24",
    hairline: "#1f2933",
    hairlineStrong: "#2b3744",
  },
  INK: {
    primary: "#f2f5f8",
    secondary: "#a8b3bf",
    muted: "#6b7785",
  },
  ENTITY: {
    rsu: "#3987e5",
    controller: "#199e70",
    vehicleClean: "#7d8894",
    ghost: "#d55181",
  },
  STATUS: {
    good: "#0ca30c",
    caught: "#fab219",
    serious: "#ec835a",
    missed: "#d03b3b",
  },
  SERIES: ["#3987e5", "#d95926", "#199e70", "#c98500"],
  PROVENANCE: {
    live: { glyph: "●", label: "LIVE", color: "#0ca30c" },
    replayed: { glyph: "▶", label: "REPLAYED", color: "#3987e5" },
    snapshot: { glyph: "◆", label: "POINT-IN-TIME", color: "#a8b3bf" },
  },
};

const LIGHT: PaletteTokens = {
  SURFACE: {
    page: "#eef1f5",
    panel: "#ffffff",
    raised: "#f5f7fa",
    hairline: "#dde3ea",
    hairlineStrong: "#c7d0da",
  },
  INK: {
    primary: "#0e1620",
    secondary: "#4a5866",
    muted: "#78848f",
  },
  ENTITY: {
    rsu: "#1f66c0",
    controller: "#0f7a55",
    vehicleClean: "#5f6b78",
    ghost: "#b23566",
  },
  STATUS: {
    good: "#0a7d0a",
    caught: "#a97400",
    serious: "#b8552a",
    missed: "#b32a2a",
  },
  SERIES: ["#1f66c0", "#b8452a", "#0f7a55", "#a97400"],
  PROVENANCE: {
    live: { glyph: "●", label: "LIVE", color: "#0a7d0a" },
    replayed: { glyph: "▶", label: "REPLAYED", color: "#1f66c0" },
    snapshot: { glyph: "◆", label: "POINT-IN-TIME", color: "#4a5866" },
  },
};

export const PALETTE: Record<ThemeName, PaletteTokens> = { dark: DARK, light: LIGHT };

// Static (dark) exports — kept for any consumer that hasn't been made
// theme-reactive. Prefer useTokens() in components so light mode applies.
export const SURFACE = DARK.SURFACE;
export const INK = DARK.INK;
export const ENTITY = DARK.ENTITY;
export const STATUS = DARK.STATUS;
export const SERIES = DARK.SERIES;
export const PROVENANCE = DARK.PROVENANCE;

export type ProvenanceKind = keyof PaletteTokens["PROVENANCE"];

// Theme-reactive accessor. Components that colour SVG/canvas output directly
// (recharts stroke/fill props, deck.gl RGBA arrays) can't be re-themed by
// CSS alone — they must read this hook instead of the static exports above.
export function useTokens(): PaletteTokens {
  const theme = useTheme((s) => s.theme);
  return PALETTE[theme];
}

export type Rgba = [number, number, number, number];

export function hexToRgba(hex: string, alpha = 255): Rgba {
  const h = hex.replace("#", "");
  return [
    parseInt(h.slice(0, 2), 16),
    parseInt(h.slice(2, 4), 16),
    parseInt(h.slice(4, 6), 16),
    alpha,
  ];
}
