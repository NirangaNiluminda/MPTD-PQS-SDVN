# SENTINEL demo UI

Browser UI for the MPTD-PQS-SDVN attack/defence demo. Design rationale, data
inventory, and the full 6-screen plan live in
`../DEMO_UI_PLAN_2026-08-14.md` — read that first if you're picking this up
cold. This file is just "how do I run it."

## What's built so far (2026-08-14, overnight pass)

- **Backend** (`backend/`): FastAPI app + 5 parser modules, each individually
  validated against real data before being wired into the API (see the git
  log on this branch for the validation transcripts). Confirmed:
  - `parsers/sigmask.py` — 9-bit rule-signature decoder. Cross-checked
    against all 4001 rows of a real `beacon_log.csv`: **0 mismatches**
    between the decoded weights and the simulator's own `psi_score` column.
  - `parsers/fusion.py` — `[FUSION-RSU*]` stdout line parser. Parsed 2361
    real lines from a live smoke-test run with an exact match against an
    independent grep count (1796 `full_anom=YES` / 565 `full_anom=no`).
    Case-sensitivity trap from `RUN_CONFIG.md` handled correctly.
  - `parsers/beacon.py` — `beacon_log.csv` reader; ghost-identity handling
    (`vehicle_id >= 10000`) confirmed against the header comment in
    `10_metrics_csv.h`.
  - `parsers/geometry.py` — RSU positions + ns-2 `.tcl` mobility trace
    parser. Reproduced the simulator's own `[MAP-BOUNDS]` output byte-exact,
    including the documented 100 m headroom margin (`12_main.h:636`).
  - `parsers/catalog.py` — scans the replay corpus
    (`~/Desktop/dataset_G50-mobility/`); found all 113 real scenarios
    (urban 42, rural 42, highway 29), all with `beacon_log.csv` +
    `metrics.csv` present.
- **API** (`backend/app.py`) — scenario catalog, per-scenario metrics,
  time-windowed beacon frames (map replay), single-vehicle trajectory
  (for the Defence Stack Inspector), sig_mask decode utility, and map
  geometry (RSUs + full-fleet positions at any time t). All endpoints
  exercised against live data with curl; one real routing bug was found and
  fixed (`{scenario_id:path}`'s greedy path converter was shadowing
  `/timerange`, `/frame`, `/vehicle/{id}` because it was registered before
  them — Starlette matches route-declaration order, not specificity).
- **Frontend** (`frontend/`) — Screen 1 (Live Network Map) as a real, running
  vertical slice: scenario picker → deck.gl map (RSU coverage circles, full
  200-vehicle fleet, poisoned/detected/ghost colour coding, claimed-vs-actual
  "rubber band" lines) → detection feed (plain-English accusations from
  `sig_mask`, false-negatives surfaced first on purpose) → playback
  transport (scrub, play/pause, 1x/5x/20x). Type-checks clean, production
  build succeeds, and the built bundle is confirmed served correctly by
  FastAPI's static mount on a single port.

**Not yet built:** Screens 2-6 (Defence Stack Inspector, Blockchain panel,
Attack Explainer, Results/Ablation, Run Console), the live-run launcher, and
the WebSocket live-tail path. See the plan doc's phase breakdown.

**Not yet verified:** nobody has looked at this in an actual browser. The
map's visual correctness (does the coordinate system read right, do the
colours work, does deck.gl actually render) needs a human with a screen —
this environment has no browser to screenshot from.

## Running it

### One-time setup (see also the plan doc §6.1)

```bash
# Node.js (no sudo required)
cd ~ && curl -fsSL https://nodejs.org/dist/v20.11.1/node-v20.11.1-linux-x64.tar.xz | tar -xJ
echo 'export PATH=$HOME/node-v20.11.1-linux-x64/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Python backend env
cd /home/sdvn_mobility_flooding/Niranga/MPTD-PQS-SDVN
python3 -m venv demo_ui/.venv
source demo_ui/.venv/bin/activate
pip install -r demo_ui/backend/requirements.txt
deactivate

# Frontend deps
cd demo_ui/frontend && npm install
```

### Dev mode (two processes, hot reload)

```bash
# terminal 1 — backend
cd demo_ui/backend && source ../.venv/bin/activate
uvicorn app:app --reload --host 127.0.0.1 --port 8000

# terminal 2 — frontend
cd demo_ui/frontend
npm run dev
# open http://localhost:5173 — Vite proxies /api to :8000 automatically
```

### Production-style (one process — this is the laptop/demo-day path)

```bash
cd demo_ui/frontend && npm run build      # produces dist/
cd ../backend && source ../.venv/bin/activate
uvicorn app:app --host 0.0.0.0 --port 8000
# open http://<this-machine>:8000 — FastAPI serves the built UI AND the API
```

### From a laptop (SSH tunnel, no local installs needed)

```bash
ssh -L 8000:localhost:8000 user@10.50.20.184
# then open http://localhost:8000 in the laptop's browser
```

## Config

Both `MPTD_CORPUS_ROOT` (replay corpus) and `MPTD_REPO_ROOT` (for the
`mobility/` geometry files) are overridable via environment variables —
see `backend/config.py`. Defaults match this machine's current layout.

## Directory layout

```
demo_ui/
  backend/
    app.py              FastAPI app, all routes
    config.py            paths (env-overridable)
    requirements.txt
    parsers/
      sigmask.py          9-bit rule-signature decoder
      fusion.py           [FUSION-RSU*] stdout line parser
      beacon.py           beacon_log.csv reader
      geometry.py          RSU positions + .tcl mobility trace
      catalog.py           replay-corpus scenario scanner
    .venv/                (gitignored — recreate with the setup commands above)
  frontend/
    src/
      api.ts               typed fetch client, mirrors app.py's response shapes
      App.tsx               screen shell + playback animation loop
      store/playback.ts     zustand store: scenario/time/geometry/beacons state
      components/
        ScenarioPicker.tsx
        NetworkMap.tsx        deck.gl OrthographicView map
        DetectionFeed.tsx     plain-English accusation feed
        PlaybackControls.tsx  scrub/play/speed transport
    dist/                  (gitignored — recreate with `npm run build`)
    node_modules/           (gitignored — recreate with `npm install`)
```
