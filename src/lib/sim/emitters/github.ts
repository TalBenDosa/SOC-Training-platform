/**
 * GitHub Audit Log EMITTER.
 *
 * The source-control / CI control-plane audit trail — repository, org, Actions,
 * token, webhook and branch-protection events an analyst reads for supply-chain
 * compromise (a maliciously edited workflow, a self-hosted runner, a minted PAT,
 * an out-of-band webhook). GitHub audit actions are highly heterogeneous, so the
 * emitter renders the COMMON envelope (action, actor, actor.ip, org, repo, geo,
 * event.*) and takes every action-specific `github.*` field through `extra` —
 * every key checked to be one the registry allows (the github. / data.github.
 * prefixes + shared fields).
 *
 * GitHub is source:"vcs" and carries no process.
 */
import type { TelemetryEvent, Severity, EventType } from "../types";
import type { Ctx } from "./_core";

const VENDOR = "GitHub Audit Log";

export interface GitHubAuditOpts extends Ctx {
  action: string;                   // github.action (e.g. "protected_branch.policy_override")
  actor: string;                    // github.actor (login)
  actorIp?: string;                 // github.actor.ip (also the event src_ip)
  userAgent?: string;               // github.actor.user_agent
  org?: string;
  repo?: string;
  visibility?: string;              // github.visibility
  category?: string;                // event.category (web|authentication|configuration)
  outcome?: "success" | "failure";
  geoCountryCode?: string;          // github.geo.country_code
  geoCity?: string;
  userTitle?: string;
  eventType?: EventType;            // default cloud_api_call
  /** action-specific github.* fields (pull_request.*, token.*, runner.*, hook.*, workflow_run.*, …) */
  extra?: Record<string, string | number>;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
export function githubAudit(o: GitHubAuditOpts): TelemetryEvent {
  const outcome = o.outcome ?? "success";
  return {
    id: o.id, ts: o.ts, source: "vcs", vendor: VENDOR, event_type: o.eventType ?? "cloud_api_call",
    severity: o.severity ?? "medium", src_ip: o.actorIp, user_email: o.user ?? undefined, user_title: o.userTitle,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    ...(o.geoCountryCode || o.geoCity ? { geo: { country: o.geoCountryCode, city: o.geoCity } } : {}),
    description: o.description ?? `${o.actor} performed ${o.action} on ${o.repo ?? o.org ?? "GitHub"}`,
    raw: {
      "github.action": o.action,
      "github.actor": o.actor,
      ...(o.actorIp ? { "github.actor.ip": o.actorIp } : {}),
      ...(o.userAgent ? { "github.actor.user_agent": o.userAgent } : {}),
      ...(o.org ? { "github.org": o.org } : {}),
      ...(o.repo ? { "github.repo": o.repo } : {}),
      ...(o.visibility ? { "github.visibility": o.visibility } : {}),
      ...(o.geoCountryCode ? { "github.geo.country_code": o.geoCountryCode } : {}),
      ...(o.geoCity ? { "github.geo.city": o.geoCity } : {}),
      "github.at": o.ts,
      "github.transport_protocol_name": "https",
      "event.category": o.category ?? "web",
      "event.action": o.action,
      "event.outcome": outcome,
      ...(o.actorIp ? { "source.ip": o.actorIp } : {}),
      ...(o.extra ?? {}),
    },
  };
}
