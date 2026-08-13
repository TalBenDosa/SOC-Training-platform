/**
 * The ROOT of the super-admin's environment tree.
 *
 * The platform has one system organization — "Internal / Default", the fixed id
 * below — that is the super-admin's HOME base: where they land, and from which
 * they enter every client environment (the children). Framing it as the tree
 * root (rather than one row in a flat list) is the whole point of the
 * super-admin environment model: you sit at the top and drill into each org.
 *
 * The id is a well-known constant that predates this file (it already lived,
 * duplicated, in a few routes). This is the single source of truth going
 * forward; new code should import ROOT_ORG_ID from here.
 */
export const ROOT_ORG_ID = "d0d0d0d0-0000-4000-8000-000000000000";

/** The label shown for the root slot in the UI, regardless of the org's raw name. */
export const ROOT_ENVIRONMENT_LABEL = "Main environment";

export function isRootOrg(orgId: string | null | undefined): boolean {
  return orgId === ROOT_ORG_ID;
}
