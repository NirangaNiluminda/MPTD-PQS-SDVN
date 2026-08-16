import { useEffect, useRef } from "react";
import { usePlayback } from "../store/playback";
import ScenarioPicker from "../components/ScenarioPicker";
import NetworkMap from "../components/NetworkMap";
import MapControls from "../components/MapControls";
import DetectionFeed from "../components/DetectionFeed";
import PlaybackControls from "../components/PlaybackControls";
import StatBar from "../components/StatBar";
import VehicleDrawer from "../components/VehicleDrawer";

export default function NetworkReplayScreen() {
  // loadScenarios() is called once at the app root (App.tsx), not here.
  // This screen only mounts when its tab is active, but the Attack
  // Explainer's "Show me this attack" needs to call selectScenario()
  // BEFORE this screen has ever mounted — if the scenario list were only
  // loaded here, that jump would silently no-op (selectScenario looks up
  // the id in an empty array and returns early, no error surfaced).
  const tick = usePlayback((s) => s.tick);
  const playing = usePlayback((s) => s.playing);
  const error = usePlayback((s) => s.error);
  const lastFrameRef = useRef<number | null>(null);

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
    <div className="flex h-full flex-col">
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
          <MapControls />
          {/* Floats over the map rather than docking as a side panel — the
              map keeps its full width, and the overlays this vehicle draws
              (rubber band, LSTM-AE expected path, GAT attention lines) stay
              visible right next to the detail that explains them. */}
          <VehicleDrawer />
        </div>
        <div className="w-80 shrink-0">
          <DetectionFeed />
        </div>
      </div>

      <PlaybackControls />
    </div>
  );
}
