/**
 * AI-related attack stories — foundation + advanced additions (live feed & team training).
 *
 *  2. ai-claude-shared-secret         (foundation, rocketstack) — a developer uploads a deployment
 *     .env file to Claude Enterprise, then changes the resulting artifact's sharing settings and
 *     publishes it. Claude Enterprise audit (Wazuh) only.
 *  3. ai-claude-compliance-key-harvest (advanced, rocketstack)   — a hijacked Okta session of the
 *     Claude Enterprise organisation owner removes the org IP restriction and creates an API key;
 *     the key then calls the Compliance API in bulk from a hosting provider, and an org data
 *     export is started.
 *
 * Every Claude Enterprise event is built by the shared emitter (real customer log shape:
 * Wazuh envelope + data.* from the Compliance API; activity types and actor fields as in
 * Anthropic's Compliance API reference) — it carries NO prompt or file content.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { oktaSignIn, oktaMfa } from "@/lib/sim/emitters/okta";
import { claudeActivity, claudeId, type ClaudeOrg } from "@/lib/sim/emitters/claudeEnterprise";

export interface AiStoryDef {
  id: string;
  title: string;
  complexity: "foundation" | "core" | "advanced";
  companies: string[];
  events: TelemetryEvent[];
}

const CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const CHROME_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const RS_OFFICE_IP = "94.188.12.44";
const RS_OFFICE_GEO = { country: "Israel", city: "Tel Aviv", lat: 32.0853, lon: 34.7818 };   // RocketStack HQ

// ══════════════════════════════════════════════════════════════════════════════
// 2. ai-claude-shared-secret — RocketStack, Claude Enterprise only
// ══════════════════════════════════════════════════════════════════════════════
function buildClaudeSharedSecret(): TelemetryEvent[] {
  const org: ClaudeOrg = { key: "rocketstack" };
  const user = "r.cohen@rocketstack.io";
  const base = { org, email: user, ip: RS_OFFICE_IP, geo: RS_OFFICE_GEO, userAgent: CHROME_MAC, hostname: "LAP-DEV-12" };
  return [
    claudeActivity({ ...base, id: "aicas1", ts: "2026-09-23T10:12:05.310Z", type: "sso_login_succeeded", firedTimes: 212,
      description: "r.cohen signed in to Claude Enterprise through Okta SSO from the office egress address. Sign-in activities are not tied to an organization, so organization_id is empty." }),
    claudeActivity({ ...base, id: "aicas2", ts: "2026-09-23T10:13:41.022Z", type: "claude_project_viewed", projectSeed: "rs-platform-oncall", firedTimes: 58,
      description: "r.cohen's Claude app loaded a project." }),
    claudeActivity({ ...base, id: "aicas3", ts: "2026-09-23T10:15:26.884Z", type: "claude_file_uploaded", projectSeed: "rs-platform-oncall", fileSeed: "prod-deploy-env", filename: "prod-deploy.env", firedTimes: 9,
      severity: "medium", mitre: "T1552.001", tactic: "Credential Access",
      description: "r.cohen uploaded prod-deploy.env in the project. The file name matches the production deployment environment file of the payments service." }),
    claudeActivity({ ...base, id: "aicas4", ts: "2026-09-23T10:16:02.519Z", type: "claude_chat_created", projectSeed: "rs-platform-oncall", chatSeed: "oncall-debug-0923", firedTimes: 77,
      description: "r.cohen started a chat in the project." }),
    claudeActivity({ ...base, id: "aicas5", ts: "2026-09-23T10:24:48.130Z", type: "claude_artifact_created", projectSeed: "rs-platform-oncall", artifactSeed: "deploy-checklist", firedTimes: 14,
      description: "An artifact was created in r.cohen's chat." }),
    claudeActivity({ ...base, id: "aicas6", ts: "2026-09-23T10:26:15.774Z", type: "claude_artifact_sharing_updated", artifactSeed: "deploy-checklist", firedTimes: 3,
      severity: "medium", mitre: "T1567", tactic: "Exfiltration",
      description: "r.cohen changed the artifact's sharing settings — the first sharing change by this user in the last 90 days." }),
    claudeActivity({ ...base, id: "aicas7", ts: "2026-09-23T10:26:41.402Z", type: "claude_artifact_published", artifactSeed: "deploy-checklist", firedTimes: 1,
      severity: "high", mitre: "T1552.001", tactic: "Credential Access",
      description: "r.cohen published a version of the artifact, 11 minutes after prod-deploy.env was uploaded in the same project. A published artifact is reachable by link; the audit record carries the artifact id only, not its content." }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. ai-claude-compliance-key-harvest — RocketStack, Okta + Claude Enterprise
// ══════════════════════════════════════════════════════════════════════════════
function buildClaudeComplianceKeyHarvest(): TelemetryEvent[] {
  const cx = "rocketstack";
  const org: ClaudeOrg = { key: "rocketstack" };
  const owner = "a.kim@rocketstack.io";
  const vpnIp = "146.70.117.35";       // commercial VPN exit (M247)
  const vpnGeo = { country: "Netherlands", city: "Amsterdam", lat: 52.3676, lon: 4.9041 };
  const hostIp = "5.188.206.18";       // hosting provider
  const collectorKey = claudeId("apikey", "rs-wazuh-collector");
  const newKey = claudeId("apikey", "rs-key-0924");
  const ownerCtx = { org, email: owner, ip: vpnIp, geo: vpnGeo, userAgent: CHROME_WIN };
  const newKeyCtx = { org, apiKeyId: newKey, ip: hostIp, userAgent: "python-requests/2.32.3" };

  return [
    // Baseline: the SIEM collector's own key polling the Activity Feed from the office egress.
    claudeActivity({ id: "aicak0", ts: "2026-09-24T02:10:00.412Z", org, type: "compliance_api_accessed", apiKeyId: collectorKey,
      ip: RS_OFFICE_IP, geo: RS_OFFICE_GEO, userAgent: "python-httpx/0.27.2", firedTimes: 48_211, isBaseline: true, expectedVerdict: "fp",
      fpExplanation: "The Wazuh collector's own Compliance Access Key, polling the Activity Feed every minute from the office egress — the organisation's only API key until tonight.",
      description: "A Compliance API call by the SIEM collector's key from the RocketStack office egress address, part of its once-a-minute Activity Feed poll." }),
    oktaSignIn({
      id: "aicak1", ts: "2026-09-24T02:14:37.220Z", companyId: cx, user: owner, srcIp: vpnIp,
      userAgent: CHROME_WIN, os: "Windows 10", browser: "CHROME", isProxy: true, threatSuspected: true,
      asOrg: "M247 Europe SRL", mfaUsed: true, factor: "OKTA_VERIFY_PUSH", severity: "high",
      geo: { country: vpnGeo.country, city: vpnGeo.city, latitude: vpnGeo.lat, longitude: vpnGeo.lon },
      mitre: "T1078.004", tactic: "Initial Access",
      description: "Okta sign-in for a.kim (Claude Enterprise organization owner) at 02:14 from 146.70.117.35, a commercial VPN exit (M247). a.kim's sign-ins in the last 30 days all came from the office or the home ISP; Okta ThreatInsight marked the request as suspected.",
    }),
    oktaMfa({
      id: "aicak2", ts: "2026-09-24T02:14:52.901Z", companyId: cx, user: owner, srcIp: vpnIp,
      result: "approved", userAgent: CHROME_WIN, severity: "medium",
      description: "The Okta Verify push for that sign-in was approved 15 seconds later.",
    }),
    claudeActivity({ ...ownerCtx, id: "aicak3", ts: "2026-09-24T02:16:10.448Z", type: "sso_login_succeeded", firedTimes: 41,
      mitre: "T1078.004", tactic: "Initial Access",
      description: "a.kim signed in to Claude Enterprise through SSO from the same VPN exit address." }),
    claudeActivity({ ...ownerCtx, id: "aicak4", ts: "2026-09-24T02:17:22.905Z", type: "org_ip_restriction_deleted", firedTimes: 1,
      severity: "high", mitre: "T1562.007", tactic: "Defense Evasion",
      description: "a.kim deleted the organization's IP restriction — the allow-list that limited Claude Enterprise access to RocketStack's office and VPN address ranges." }),
    claudeActivity({ ...ownerCtx, id: "aicak5", ts: "2026-09-24T02:18:33.605Z", type: "api_key_created", firedTimes: 2,
      severity: "high", mitre: "T1098.001", tactic: "Persistence",
      description: "a.kim created a new API key in the organization settings. The only other key in the organization belongs to the SIEM collector." }),
    claudeActivity({ ...newKeyCtx, id: "aicak6", ts: "2026-09-24T02:24:02.118Z", type: "compliance_api_accessed", firedTimes: 48_229,
      severity: "medium", mitre: "T1213", tactic: "Collection",
      description: `A Compliance API call by api_key_id ${newKey} — the key created at 02:18 — from 5.188.206.18 (hosting provider) with a python-requests client. The key had never been used before.` }),
    claudeActivity({ ...newKeyCtx, id: "aicak7", ts: "2026-09-24T02:31:48.207Z", type: "compliance_api_accessed", firedTimes: 49_413,
      severity: "high", mitre: "T1213", tactic: "Collection",
      description: "Between 02:24 and 02:31 the same key produced 1,184 compliance_api_accessed activities from 5.188.206.18, against about 7 per minute from the SIEM collector's key." }),
    claudeActivity({ ...ownerCtx, id: "aicak8", ts: "2026-09-24T02:33:15.660Z", type: "org_data_export_started", firedTimes: 1,
      severity: "high", mitre: "T1530", tactic: "Collection",
      description: "An organization data export was started from a.kim's session on the VPN exit address — the first data export in the organization's history." }),
  ];
}

export const AI_EXTRA_STORIES: AiStoryDef[] = [
  { id: "ai-claude-shared-secret", title: "Deployment Secrets Published from Claude Enterprise", complexity: "foundation", companies: ["rocketstack"], events: buildClaudeSharedSecret() },
  { id: "ai-claude-compliance-key-harvest", title: "Hijacked Owner Session Mints a Claude Compliance Key and Pulls Org Data", complexity: "advanced", companies: ["rocketstack"], events: buildClaudeComplianceKeyHarvest() },
];
