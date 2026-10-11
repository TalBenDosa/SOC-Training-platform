/**
 * ECS (Elastic Common Schema) helpers for the normalised SIEM view a `raw` block carries
 * next to a vendor's own fields — one spelling for MITRE ids and code-signing state on
 * every surface, read back by one reader.
 *
 * MITRE: ECS keeps the parent technique in `threat.technique.id` and the sub-technique in
 * `threat.technique.subtechnique.id` ("T1059" + "T1059.001"), never "T1059.001" in
 * `threat.technique.id`. https://www.elastic.co/docs/reference/ecs/ecs-threat
 *
 * Code signing: ECS `*.code_signature.exists` (is there a signature) and `.trusted` (does
 * it chain to a trusted root), both booleans; `.status` holds only an error/diagnostic
 * string when validation failed. That is exactly how Elastic's CrowdStrike integration
 * maps Falcon's signature info (unsigned → exists false; signed-untrusted → exists true,
 * trusted false; trusted → both true). https://www.elastic.co/docs/reference/ecs/ecs-code_signature
 */

const SUB = /^(T\d{4})\.\d{3}$/i;

/** `threat.technique.id` (+ `threat.technique.subtechnique.id` when `id` is a sub-technique). */
export function ecsTechnique(id: string | undefined): Record<string, string> {
  if (!id) return {};
  const m = id.trim().match(SUB);
  return m ? { "threat.technique.id": m[1].toUpperCase(), "threat.technique.subtechnique.id": id.trim() } : { "threat.technique.id": id.trim() };
}

/** The most specific MITRE technique id an ECS block states (sub-technique first). */
export function ecsTechniqueId(raw: Record<string, unknown> | undefined): string | undefined {
  for (const k of ["threat.technique.subtechnique.id", "threat.technique.id"]) {
    const v = raw?.[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return undefined;
}

/**
 * The signing states the platform's stories distinguish. `untrusted` = a signature exists
 * but does not chain to a trusted publisher (a macOS ad-hoc signature, subject "-");
 * `revoked` = the publisher's certificate was revoked (ECS `.status` carries the error).
 */
export type SignState = "trusted" | "untrusted" | "revoked" | "unsigned";

/** macOS Security framework error for a revoked signing certificate. */
export const REVOKED_STATUS = "errSecCertificateRevoked";

/** ECS `<prefix>.code_signature.*` fields for a signing state (prefix: process / process.parent / file). */
export function ecsCodeSignature(prefix: string, state: SignState | undefined): Record<string, boolean | string> {
  if (!state) return {};
  const p = `${prefix}.code_signature`;
  if (state === "unsigned") return { [`${p}.exists`]: false, [`${p}.trusted`]: false };
  if (state === "trusted") return { [`${p}.exists`]: true, [`${p}.trusted`]: true };
  return { [`${p}.exists`]: true, [`${p}.trusted`]: false, ...(state === "revoked" ? { [`${p}.status`]: REVOKED_STATUS } : {}) };
}

const bool = (v: unknown): boolean | undefined =>
  v === true || v === "true" ? true : v === false || v === "false" ? false : undefined;

/** Read the signing state back from ECS `<prefix>.code_signature.*` (undefined when the block is silent). */
export function signState(raw: Record<string, unknown> | undefined, prefix = "process"): SignState | undefined {
  const p = `${prefix}.code_signature`;
  const exists = bool(raw?.[`${p}.exists`]);
  const trusted = bool(raw?.[`${p}.trusted`]);
  const status = String(raw?.[`${p}.status`] ?? "");
  if (/revoked/i.test(status)) return "revoked";
  if (exists === false) return "unsigned";
  if (trusted === true) return "trusted";
  if (exists === true || trusted === false) return "untrusted";
  return undefined;
}
