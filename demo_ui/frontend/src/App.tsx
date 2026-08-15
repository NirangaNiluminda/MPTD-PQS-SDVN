import { useEffect, useRef } from "react";
import { usePlayback } from "./store/playback";
import ScenarioPicker from "./components/ScenarioPicker";
import NetworkMap from "./components/NetworkMap";
import MapLegend from "./components/MapLegend";
import DetectionFeed from "./components/DetectionFeed";
import PlaybackControls from "./components/PlaybackControls";
import StatBar from "./components/StatBar";
import VehicleDrawer from "./components/VehicleDrawer";

export default function App() {
  const loadScenarios = usePlayback((s) => s.loadScenarios);
  const tick = usePlayback((s) => s.tick);
  const playing = usePlayback((s) => s.playing);
  const error = usePlayback((s) => s.error);
  const lastFrameRef = useRef<number | null>(null);

  useEffect(() => {
    loadScenarios();
  }, [loadScenarios]);

  // Wall-clock-driven playback: each frame advances sim time by the real
  // elapsed delta × the speed multiplier.
  useEffect(() => {
    if (!playing) {
      lastFrameRef.current = null;
      return;
    }
    let raf = 0;
    const step = (now: number) => {
      if (lastFrameRef.current != null) {
        tick((now - lastFrameRef.current) / 1000);
      }
      lastFrameRef.current = now;
      raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [playing, tick]);

  return (
    <div className="flex h-screen flex-col bg-surface-page">
      <header className="flex items-baseline gap-3 border-b border-surface-hairline bg-surface-page px-4 py-2.5">
        <h1 className="text-sm font-semibold tracking-wide text-ink-primary">
          SENTINEL
        </h1>
        <span className="text-xs text-ink-muted">
          Trajectory-poisoning defence for software-defined vehicle networks
        </span>
        <span className="ml-auto rounded bg-surface-raised px-2 py-1 text-[10px] text-ink-muted">
          replaying recorded simulation
        </span>
      </header>

      {error && (
        <div className="border-b border-status-missed/40 bg-status-missed/10 px-4 py-2 text-xs text-status-missed">
          {error}
        </div>
      )}

      <ScenarioPicker />
      <StatBar />

      <div className="flex flex-1 overflow-hidden">
        <div className="relative flex-1 bg-surface-page">
          <NetworkMap />
          <MapLegend />
        </div>
        <div className="w-80 shrink-0">
          <DetectionFeed />
        </div>
        <VehicleDrawer />
      </div>

      <PlaybackControls />
    </div>
  );
}
