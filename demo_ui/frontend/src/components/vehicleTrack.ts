import { BeaconDto } from "../api";

/**
 * The beacon nearest the current playback time — what the map is showing
 * right now. Shared by the sidebar quick-facts panel and the full-analysis
 * modal so the two never disagree about which beacon "current" means.
 */
export function currentBeaconAt(track: BeaconDto[] | null | undefined, t: number): BeaconDto | null {
  if (!track?.length) return null;
  let best = track[0];
  for (const b of track) {
    if (Math.abs(b.sim_time - t) < Math.abs(best.sim_time - t)) best = b;
  }
  return best;
}
