import { usePlayback } from "../store/playback";

const SPEEDS = [1, 5, 20];

export default function PlaybackControls() {
  const { t, tMin, tMax, playing, speed, play, pause, setSpeed, seek } =
    usePlayback();

  const pct = tMax > tMin ? ((t - tMin) / (tMax - tMin)) * 100 : 0;

  return (
    <div className="flex items-center gap-3 border-t border-slate-800 bg-slate-900 px-4 py-2 text-sm">
      <button
        className="rounded bg-slate-800 px-3 py-1 hover:bg-slate-700 disabled:opacity-40"
        disabled={tMax <= tMin}
        onClick={() => (playing ? pause() : play())}
      >
        {playing ? "⏸" : "▶"}
      </button>

      <span className="w-24 font-mono text-slate-400">
        {t.toFixed(1)} / {tMax.toFixed(1)}s
      </span>

      <input
        type="range"
        className="flex-1"
        min={tMin}
        max={tMax}
        step={0.1}
        value={t}
        onChange={(e) => seek(parseFloat(e.target.value))}
      />

      <div className="flex gap-1">
        {SPEEDS.map((s) => (
          <button
            key={s}
            className={`rounded px-2 py-1 text-xs ${
              speed === s
                ? "bg-cyan-700 text-white"
                : "bg-slate-800 text-slate-400 hover:bg-slate-700"
            }`}
            onClick={() => setSpeed(s)}
          >
            {s}x
          </button>
        ))}
      </div>

      <span className="hidden w-10 text-right text-[10px] text-slate-600 sm:inline">
        {pct.toFixed(0)}%
      </span>
    </div>
  );
}
