/** The core attack catalog, gathered for attackStories.ts. */
import { AD_STORIES } from "./ad";
import { CLOUD_STORIES } from "./cloud";
import { ENDPOINT_STORIES } from "./endpoint";
import { IDENTITY_STORIES } from "./identity";
import { MISC_STORIES } from "./misc";
import type { CoreStoryDef } from "./_kit";

export const CORE_STORIES: CoreStoryDef[] = [...IDENTITY_STORIES, ...AD_STORIES, ...ENDPOINT_STORIES, ...CLOUD_STORIES, ...MISC_STORIES];
