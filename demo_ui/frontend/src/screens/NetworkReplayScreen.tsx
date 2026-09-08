import { useEffect, useRef, useState } from "react";
import { Maximize, Minimize } from "lucide-react";
import { usePlayback } from "../store/playback";
import ScenarioPicker from "../components/ScenarioPicker";
import NetworkMap from "../components/NetworkMap";
import MapControls from "../components/MapControls";
import DetectionFeed from "../components/DetectionFeed";
import PlaybackControls from "../components/PlaybackControls";
import StatBar from "../components/StatBar";

function FullscreenToggle({ targetRef }: { targetRef: React.RefObject<HTMLElement> }) {
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    const onChange = () => setIsFullscreen(document.fullscreenElement === targetRef.current);
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, [targetRef]);

  const toggle = () => {
    if (document.fullscreenElement) document.exitFullscreen();
    else targetRef.current?.requestFullscreen();
  };

  return (
    <button
      onClick={toggle}
      title={isFullscreen ? "Exit full screen" : "Full screen"}
      className="pointer-events-auto absolute right-3 top-3 z-10 flex items-center gap-1.5 rounded-md border border-surface-hairline2 bg-surface-panel/95 px-2.5 py-1.5 font-mono text-[10px] font-medium text-ink-secondary shadow-lg backdrop-blur transition-colors hover:text-ink-primary"
    >
      {isFullscreen ? <Minimize size={12} aria-hidden /> : <Maximize size={12} aria-hidden />}
      {isFullscreen ? "Exit full screen" : "Full screen"}
    </button>
  );
}

export default function NetworkReplayScreen() {
  const rootRef = useRef<HTMLDivElement>(null);
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
    <div ref={rootRef} className="flex h-full flex-col bg-surface-page">
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
          <FullscreenToggle targetRef={rootRef} />
        </div>
        {/* One persistent, synchronized detection panel — a selected event
            expands inline within this same list rather than swapping to a
            separate screen, and the map stays fully visible at all times. */}
        <div className="w-[360px] shrink-0">
          <DetectionFeed />
        </div>
      </div>

      <PlaybackControls />
    </div>
  );
}
