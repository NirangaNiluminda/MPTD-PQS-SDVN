import { create } from "zustand";

export type Theme = "dark" | "light";

const STORAGE_KEY = "sentinel-theme";

function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "dark" || saved === "light") return saved;
  } catch {
    // localStorage unavailable (private mode, etc.) — fall through to default.
  }
  return "dark";
}

interface ThemeState {
  theme: Theme;
  toggleTheme: () => void;
}

export const useTheme = create<ThemeState>((set, get) => ({
  theme: initialTheme(),
  toggleTheme: () => {
    const next: Theme = get().theme === "dark" ? "light" : "dark";
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // best effort — theme still switches for this session
    }
    set({ theme: next });
  },
}));
