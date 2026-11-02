import type { BuildingKind } from "@/lib/rooms/experience";

export type StationStatus = "locked" | "open" | "cleared";

/** A station as the mission board shows it: status, stars and task progress. */
export interface HubStation {
  id: string;
  label: string;
  status: StationStatus;
  boss?: boolean;
  building: BuildingKind;
  stars: number;
  progress: string; // "2/3"
}
