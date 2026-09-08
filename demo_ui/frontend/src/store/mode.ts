import { create } from "zustand";

export type CopyMode = "plain" | "expert";

interface ModeState {
  mode: CopyMode;
  setMode: (m: CopyMode) => void;
}

// Global, not per-screen: a viewer picks one register and expects the whole
// app to speak it, not just the screen they happened to toggle it on.
export const useMode = create<ModeState>((set) => ({
  mode: "plain",
  setMode: (mode) => set({ mode }),
}));
