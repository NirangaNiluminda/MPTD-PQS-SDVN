import { useEffect, useRef } from "react";
import { usePlayback } from "./store/playback";
import ScenarioPicker from "./components/ScenarioPicker";
import NetworkMap from "./components/NetworkMap";
import DetectionFeed from "./components/DetectionFeed";
import PlaybackControls from "./components/PlaybackControls";

export default function App() {
  const loadScenarios = usePlayback((s) => s.loadScenarios);
  const tick = usePlayback((s) => s.tick);
  const playing = usePlayback((s) => s.playing);
  const lastFrameRef = useRef<number | null>(null);

  useEffect(() => {
    loadScenarios();
  }, [loadScenarios]);

  // Real-time-driven playback loop: each animation frame advances sim time
  // by the elapsed wall-clock delta * speed multiplier (see store.tick).
  useEffect(() => {
    if (!playing) {
      lastFrameRef.current = null;
      return;
    }
    let raf: number;
    const step = (now: number) => {
      if (lastFrameRef.current != null) {
        const dt = (now - lastFrameRef.current) / 1000;
        tick(dt);
      }
      lastFrameRef.current = now;
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [playing, tick]);

  return (
    <div className="flex h-screen flex-col">
      <header className="border-b border-slate-800 bg-slate-950 px-4 py-2">
        <h1 className="text-sm font-semibold tracking-wide text-slate-200">
          SENTINEL — MPTD-PQS-SDVN attack &amp; defence replay
        </h1>
      </header>

      <ScenarioPicker />

      <div className="flex flex-1 overflow-hidden">
        <div className="relative flex-1 bg-slate-950">
          <NetworkMap />
        </div>
        <div className="w-80 shrink-0">
          <DetectionFeed />
        </div>
      </div>

      <PlaybackControls />
    </div>
  );
}
