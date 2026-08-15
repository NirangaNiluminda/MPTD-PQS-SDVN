// Design tokens — the palette here was VALIDATED with the dataviz skill's
// validate_palette.js against the actual dark map surface (#0f1419), not
// chosen by eye. Re-run the validator before changing any hex below.
//
// Validation results that constrain this file:
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

export const SURFACE = {
  page: "#0b0f14",
  panel: "#0f1419",
  raised: "#151c24",
  hairline: "#1f2933",
  hairlineStrong: "#2b3744", // borders that need more presence: inputs, active tabs
} as const;

// Data provenance — every number on screen is one of these three. Not a
// stylistic choice: a "live" figure can change under you, a "replayed" one
// is fixed to a recording, and a "point-in-time" one is a snapshot that may
// already be stale. Conflating them is how a demo accidentally lies.
export const PROVENANCE = {
  live: { glyph: "●", label: "LIVE", color: "#0ca30c" },
  replayed: { glyph: "▶", label: "REPLAYED", color: "#3987e5" },
  snapshot: { glyph: "◆", label: "POINT-IN-TIME", color: "#a8b3bf" },
} as const;

export type ProvenanceKind = keyof typeof PROVENANCE;

export const INK = {
  primary: "#f2f5f8",
  secondary: "#a8b3bf",
  muted: "#6b7785",
} as const;

// Entity identity (categorical). Blue/aqua validated all-pairs on dark.
export const ENTITY = {
  rsu: "#3987e5",
  controller: "#199e70",
  vehicleClean: "#7d8894",
  ghost: "#d55181",
} as const;

// Threat state — the RESERVED status palette. Fixed, never themed, and always
// shipped with an icon + label (the skill's status rule).
export const STATUS = {
  good: "#0ca30c",
  caught: "#fab219", // warning — poisoned AND detected
  serious: "#ec835a",
  missed: "#d03b3b", // critical — poisoned but NOT detected
} as const;

// Chart series — validated on the ADJACENT pairlist (lines/bars), worst
// adjacent CVD ΔE 8.4, normal-vision ΔE 19.8. Assign in fixed order, never cycle.
export const SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500"] as const;

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
