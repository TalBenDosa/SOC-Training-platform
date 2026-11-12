/**
 * Web injection round (Tal, 2026-11-12): every family is a parametric template of two or more variants,
 * dealt in the single-player dashboard AND in Team Training (not team-only, unlike the first web catalog).
 */
import { WEB_INJECTION_CMD_STORIES } from "./injection-cmd";
import { WEB_INJECTION_DATA_STORIES } from "./injection-data";
import { WEB_INJECTION_CLIENT_STORIES } from "./injection-client";
import type { WebStoryDef } from "./entry";

export const WEB_INJECTION_STORIES: WebStoryDef[] = [
  ...WEB_INJECTION_CMD_STORIES,
  ...WEB_INJECTION_DATA_STORIES,
  ...WEB_INJECTION_CLIENT_STORIES,
];
