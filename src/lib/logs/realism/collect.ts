/**
 * Runs every collector once (memoised per process): the one place the gate, the baseline writer
 * and the report get their rows from.
 */
import type { Collected } from "./types";
import { collectLive } from "./collectors/live";
import { collectScenarios } from "./collectors/scenarios";
import { collectTeam, collectXdr, collectForensic } from "./collectors/team";
import { collectEdr } from "./collectors/edr";
import { collectRooms } from "./collectors/rooms";

let cache: Collected | null = null;

export function collectAll(): Collected {
  if (cache) return cache;
  const out: Collected = { rows: [], feeds: [], notes: [] };
  const t = (label: string, f: () => void) => { const s = Date.now(); f(); out.notes.push(`${label} collected in ${Date.now() - s} ms`); };
  t("live", () => collectLive(out));
  let scenarios: ReturnType<typeof collectScenarios> = [];
  t("scenario", () => { scenarios = collectScenarios(out); });
  let sessions: ReturnType<typeof collectTeam> = [];
  t("team", () => { sessions = collectTeam(out); });
  t("xdr", () => collectXdr(out, sessions));
  t("forensic", () => collectForensic(out, sessions));
  t("edr", () => collectEdr(out, scenarios));
  t("room", () => collectRooms(out));
  cache = out;
  return out;
}
