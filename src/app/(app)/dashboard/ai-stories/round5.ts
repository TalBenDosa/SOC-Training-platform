/**
 * AI round (Tal's approved order, step 4, 2026-11-12): six attack families, each a parametric template with one
 * single-player variant (mode "solo") and one Team Training variant (mode "team"), never the same story or data.
 *
 *  - round5-malware.ts : LLM-querying malware (LameHug / PromptLock pattern); a local AI coding agent hijacked by a
 *                        poisoned package (s1ngularity pattern, Aug 2025)
 *  - round5-agents.ts  : toxic agent flow (an agent with a GitHub connector steered by a public issue); improper
 *                        output handling (OWASP LLM05: model output executed or rendered as-is)
 *  - round5-people.ts  : crescendo multi-turn jailbreak; fraudulent remote IT worker (DPRK IT-worker pattern)
 *
 * Payloads are effects-only: the logs show what happened (processes, connections, records, sizes, verdicts),
 * never a working prompt, script or exploit string.
 */
import type { AiStoryDef } from "./wave2";
import { AI_R5_MALWARE_STORIES } from "./round5-malware";
import { AI_R5_AGENT_STORIES } from "./round5-agents";
import { AI_R5_PEOPLE_STORIES } from "./round5-people";

export const AI_ROUND5_STORIES: AiStoryDef[] = [...AI_R5_MALWARE_STORIES, ...AI_R5_AGENT_STORIES, ...AI_R5_PEOPLE_STORIES];
