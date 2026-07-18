/**
 * Log Generator Engine — public API.
 * Replaces the static shuffle-deck in useLiveEvents with algorithmic generation.
 */

export { initWorldState, COMPANY_META } from "./worldState";
export { generateBenignEvent }          from "./generators/index";
export { pickPlaybook, startAttack, advanceAttack, attackDue } from "./attacks/index";
export type { WorldState, CompanyMeta, CompanyUser, GeneratedEvent, AttackCtx } from "./types";
