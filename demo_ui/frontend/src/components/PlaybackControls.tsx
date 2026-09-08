import { Repeat } from "lucide-react";
import { usePlayback } from "../store/playback";

const SPEEDS = [1, 5, 20];

export default function PlaybackControls() {
  const { t, tMin, tMax, playing, speed, loop, play, pause, setSpeed, seek, toggleLoop } =
    usePlayback();

  const ready = tMax > tMin;

  return (
    <div className="flex items-center gap-4 border-t border-surface-hairline bg-surface-panel px-4 py-2.5">
      <button
        className="flex h-8 w-8 items-center justify-center rounded-md bg-entity-rsu text-sm text-white transition-opacity hover:opacity-90 disabled:opacity-30"
        disabled={!ready}
        onClick={() => (playing ? pause() : play())}
        aria-label={playing ? "Pause" : "Play"}
      >
        {playing ? "❚❚" : "▶"}
      </button>

      <span className="w-28 shrink-0 font-mono text-xs tabular-nums text-ink-secondary">
        {t.toFixed(1)}s / {tMax.toFixed(1)}s
      </span>

      <input
        type="range"
        className="h-1 flex-1 cursor-pointer accent-entity-rsu"
        min={tMin}
        max={tMax || 1}
        step={0.1}
        value={t}
        disabled={!ready}
        onChange={(e) => seek(parseFloat(e.target.value))}
      />

      <div className="flex gap-1">
        {SPEEDS.map((s) => (
          <button
            key={s}
            className={`rounded px-2.5 py-1 text-xs transition-colors ${
              speed === s
                ? "bg-entity-rsu text-white"
                : "bg-surface-raised text-ink-muted hover:text-ink-primary"
            }`}
            onClick={() => setSpeed(s)}
          >
            {s}×
          </button>
        ))}
      </div>

      <button
        className={`flex items-center gap-1.5 rounded px-2.5 py-1 text-xs transition-colors ${
          loop ? "bg-entity-rsu text-white" : "bg-surface-raised text-ink-muted hover:text-ink-primary"
        }`}
        onClick={toggleLoop}
        aria-pressed={loop}
        title={loop ? "Looping — restarts automatically at the end" : "Loop off — stops at the end"}
      >
        <Repeat size={13} /> Loop
      </button>
    </div>
  );
}
