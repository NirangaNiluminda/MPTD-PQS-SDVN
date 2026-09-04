import { useEffect, useState } from "react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, CsvColumnsDto, CsvSourceDto } from "../api";
import { useTokens } from "../design/tokens";

/**
 * Generic "pick a CSV, pick two columns, plot it" panel — not bound to any
 * one known chart shape. Headerless sources (E1/E2's raw sweep CSVs) are
 * labelled "Column N", never a guessed metric name — see
 * csv_explorer.py's docstring for why: a past attempt to re-derive those
 * columns' meaning without the original generating script was judged too
 * risky to ship, so this tool stays honestly generic instead.
 */
export default function CsvExplorer() {
  const { SERIES, INK, SURFACE } = useTokens();
  const [sources, setSources] = useState<CsvSourceDto[] | null>(null);
  const [sourceId, setSourceId] = useState<string | null>(null);
  const [cols, setCols] = useState<CsvColumnsDto | null>(null);
  const [xCol, setXCol] = useState<string | null>(null);
  const [yCol, setYCol] = useState<string | null>(null);
  const [points, setPoints] = useState<{ x: number; y: number }[] | null>(null);
  const [nTotal, setNTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .csvSources()
      .then((s) => {
        setSources(s);
        const first = s.find((x) => x.exists);
        if (first) setSourceId(first.id);
      })
      .catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (!sourceId) return;
    setCols(null);
    setXCol(null);
    setYCol(null);
    setPoints(null);
    api
      .csvColumns(sourceId)
      .then((c) => {
        setCols(c);
        if (c.columns.length >= 2) {
          setXCol(c.columns[0]);
          setYCol(c.columns[1]);
        }
      })
      .catch((e) => setError(String(e)));
  }, [sourceId]);

  useEffect(() => {
    if (!sourceId || !xCol || !yCol) return;
    setError(null);
    api
      .csvData(sourceId, xCol, yCol)
      .then((d) => {
        setPoints(d.x.map((x, i) => ({ x, y: d.y[i] })).sort((a, b) => a.x - b.x));
        setNTotal(d.n_total);
      })
      .catch((e) => setError(String(e)));
  }, [sourceId, xCol, yCol]);

  return (
    <div className="rounded-lg border border-surface-hairline bg-surface-raised p-4">
      <h3 className="mb-1 text-body font-semibold text-ink-primary">CSV explorer</h3>
      <p className="mb-3 text-[11px] leading-relaxed text-ink-muted">
        Pick a real CSV and two of its columns to plot — nothing pre-baked. Columns from a source with no header
        row are labelled positionally ("Column N"), never guessed, since this project's own E1/E2 sweep CSVs
        have no surviving generating script to confirm what each column means.
      </p>

      {error && <p className="mb-2 text-[11px] text-status-missed">{error}</p>}
      {!sources && !error && <p className="text-[11px] text-ink-muted">Loading sources…</p>}

      {sources && (
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-[11px] text-ink-secondary">
            Source
            <select
              className="mt-1 block w-56 rounded border border-surface-hairline bg-surface-page px-2 py-1.5 text-[11px] text-ink-primary outline-none focus:border-entity-rsu"
              value={sourceId ?? ""}
              onChange={(e) => setSourceId(e.target.value)}
            >
              {sources.map((s) => (
                <option key={s.id} value={s.id} disabled={!s.exists}>
                  {s.label}
                  {!s.exists && " (not found)"}
                </option>
              ))}
            </select>
          </label>

          {cols && cols.columns.length > 0 && (
            <>
              <label className="text-[11px] text-ink-secondary">
                X
                <select
                  className="mt-1 block w-36 rounded border border-surface-hairline bg-surface-page px-2 py-1.5 text-[11px] text-ink-primary outline-none focus:border-entity-rsu"
                  value={xCol ?? ""}
                  onChange={(e) => setXCol(e.target.value)}
                >
                  {cols.columns.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-[11px] text-ink-secondary">
                Y
                <select
                  className="mt-1 block w-36 rounded border border-surface-hairline bg-surface-page px-2 py-1.5 text-[11px] text-ink-primary outline-none focus:border-entity-rsu"
                  value={yCol ?? ""}
                  onChange={(e) => setYCol(e.target.value)}
                >
                  {cols.columns.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
              </label>
              <span className="text-[10px] text-ink-muted">
                {cols.row_count.toLocaleString()} rows{!cols.has_header && " · headerless source"}
              </span>
            </>
          )}
        </div>
      )}

      {points && points.length > 0 && (
        <div className="mt-4 h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={points} margin={{ top: 8, right: 16, bottom: 8, left: 8 }}>
              <CartesianGrid stroke={SURFACE.hairline} />
              <XAxis
                dataKey="x"
                type="number"
                tick={{ fill: INK.muted, fontSize: 10 }}
                stroke={SURFACE.hairlineStrong}
                label={{ value: xCol, position: "insideBottom", offset: -4, fill: INK.muted, fontSize: 10 }}
              />
              <YAxis
                tick={{ fill: INK.muted, fontSize: 10 }}
                stroke={SURFACE.hairlineStrong}
                label={{ value: yCol, angle: -90, position: "insideLeft", fill: INK.muted, fontSize: 10 }}
              />
              <Tooltip
                contentStyle={{ background: SURFACE.raised, border: `1px solid ${SURFACE.hairline}`, borderRadius: 6, fontSize: 11 }}
                labelStyle={{ color: INK.secondary }}
              />
              <Line type="monotone" dataKey="y" stroke={SERIES[0]} strokeWidth={2} dot={{ r: 2 }} isAnimationActive={false} name={yCol ?? "y"} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
      {points && points.length === 0 && (
        <p className="mt-4 text-[11px] text-ink-muted">No numeric rows found for this column pair.</p>
      )}
      {points && nTotal > points.length && (
        <p className="mt-1 text-[10px] text-ink-muted">
          Showing {points.length.toLocaleString()} of {nTotal.toLocaleString()} points (evenly decimated, not a
          random sample — the sweep's shape is preserved).
        </p>
      )}
    </div>
  );
}
