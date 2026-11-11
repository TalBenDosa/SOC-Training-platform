/** Mission consoles by id (see types.ts). One per room that has console steps. */
import { CLEAR_SKY_CONSOLE } from "./clearSky";
import type { MissionConsole } from "./types";

const REGISTRY: Record<string, MissionConsole> = {
  "clear-sky": CLEAR_SKY_CONSOLE,
};

export function getConsole(id: string): MissionConsole | null {
  return Object.prototype.hasOwnProperty.call(REGISTRY, id) ? REGISTRY[id] : null;
}

export function consoleIds(): string[] {
  return Object.keys(REGISTRY);
}
