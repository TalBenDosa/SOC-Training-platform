/**
 * AI-related attack stories — foundation + advanced additions (live feed & team training).
 *
 *  2. ai-claude-shared-secret    (foundation, rocketstack)  — a developer uploads a deployment
 *     .env file to Claude Enterprise and shares the resulting artifact by link; an
 *     unauthenticated viewer opens it. Claude Enterprise audit (Wazuh) only.
 *  3. ai-claude-admin-key-harvest (advanced, rocketstack)   — a hijacked Okta admin session
 *     mints a Claude Enterprise admin API key; the key then pulls chats and files across the
 *     organisation from a hosting provider and deletes platform memory.
 *
 * Every Claude Enterprise event is built by the shared emitter (real customer log shape:
 * Wazuh envelope + data.* from the Compliance API) — it carries NO prompt or file content.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { oktaSignIn, oktaMfa } from "@/lib/sim/emitters/okta";
import { claudeActivity, type ClaudeOrg } from "@/lib/sim/emitters/claudeEnterprise";

export interface AiStoryDef {
  id: string;
  title: string;
  complexity: "foundation" | "core" | "advanced";
  companies: string[];
  events: TelemetryEvent[];
}

const CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const CHROME_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

// ══════════════════════════════════════════════════════════════════════════════
// 2. ai-claude-shared-secret — RocketStack, Claude Enterprise only
// ══════════════════════════════════════════════════════════════════════════════
function buildClaudeSharedSecret(): TelemetryEvent[] {
  const org: ClaudeOrg = { key: "rocketstack" };
  const user = "r.cohen@rocketstack.io";
  const officeIp = "94.188.12.44";
  const viewerIp = "185.107.56.212";
  const officeGeo = { country: "Israel", city: "Tel Aviv", lat: 32.0853, lon: 34.7818 };   // RocketStack HQ
  const base = { org, email: user, ip: officeIp, geo: officeGeo, userAgent: CHROME_MAC, hostname: "LAP-DEV-12" };
  return [
    claudeActivity({ ...base, id: "aicas1", ts: "2026-09-23T10:12:05.310Z", type: "sso_login_succeeded", firedTimes: 212,
      description: "r.cohen signed in to Claude Enterprise through Okta SSO from the office egress address." }),
    claudeActivity({ ...base, id: "aicas2", ts: "2026-09-23T10:13:41.022Z", type: "claude_project_viewed", projectSeed: "rs-platform-oncall", firedTimes: 58,
      description: "r.cohen opened a Claude Enterprise project." }),
    claudeActivity({ ...base, id: "aicas3", ts: "2026-09-23T10:15:26.884Z", type: "claude_file_uploaded", projectSeed: "rs-platform-oncall", fileSeed: "prod-deploy-env", filename: "prod-deploy.env", firedTimes: 9,
      severity: "medium", mitre: "T1552.001", tactic: "Credential Access",
      description: "r.cohen uploaded prod-deploy.env to the Claude Enterprise project. The file name matches the production deployment environment file of the payments service." }),
    claudeActivity({ ...base, id: "aicas4", ts: "2026-09-23T10:16:02.519Z", type: "claude_chat_created", projectSeed: "rs-platform-oncall", chatSeed: "oncall-debug-0923", firedTimes: 77,
      description: "r.cohen started a chat in the project." }),
    claudeActivity({ ...base, id: "aicas5", ts: "2026-09-23T10:24:48.130Z", type: "claude_artifact_created", projectSeed: "rs-platform-oncall", artifactSeed: "deploy-checklist", firedTimes: 14,
      description: "A Claude Enterprise artifact was created in r.cohen's chat." }),
    claudeActivity({ ...base, id: "aicas6", ts: "2026-09-23T10:26:15.774Z", type: "claude_artifact_shared", projectSeed: "rs-platform-oncall", artifactSeed: "deploy-checklist", firedTimes: 2,
      severity: "medium", mitre: "T1567", tactic: "Exfiltration",
      description: "r.cohen shared the artifact by link — the only artifact share by this user in the last 90 days." }),
    claudeActivity({ id: "aicas7", ts: "2026-09-23T13:41:09.402Z", org, type: "claude_artifact_viewed", actorType: "unauthenticated_user_actor",
      ip: viewerIp, userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0", artifactSeed: "deploy-checklist", firedTimes: 1,
      severity: "high", mitre: "T1552.001", tactic: "Credential Access",
      description: "The shared artifact was opened by an unauthenticated viewer from 185.107.56.212, an address with no prior activity in the organisation." }),
  ];
}

// ══════════════════════════════════════════════════════════════════════════════
// 3. ai-claude-admin-key-harvest — RocketStack, Okta + Claude Enterprise
// ══════════════════════════════════════════════════════════════════════════════
function buildClaudeAdminKeyHarvest(): TelemetryEvent[] {
  const cx = "rocketstack";
  const org: ClaudeOrg = { key: "rocketstack" };
  const admin = "a.kim@rocketstack.io";
  const vpnIp = "146.70.117.35";       // commercial VPN exit
  const hostIp = "5.188.206.18";       // hosting provider
  const keySeed = "rs-admin-key-0924";
  const apiBase = { org, actorType: "admin_api_key_actor" as const, ip: hostIp, apiKeyId: undefined as string | undefined };
  const apiKeyId = `apikey_01${"Qh7VbN2mKt9XwR4cLp8DzF3s"}`;
  apiBase.apiKeyId = apiKeyId;

  return [
    oktaSignIn({
      id: "aicak1", ts: "2026-09-24T02:14:37.220Z", companyId: cx, user: admin, srcIp: vpnIp,
      userAgent: CHROME_WIN, os: "Windows 10", browser: "CHROME", isProxy: true, threatSuspected: true,
      asOrg: "M247 Europe SRL", mfaUsed: true, factor: "OKTA_VERIFY_PUSH", severity: "high",
      mitre: "T1078.004", tactic: "Initial Access",
      description: "Okta sign-in for a.kim (Claude Enterprise organisation admin) at 02:14 from 146.70.117.35, a commercial VPN exit (M247). a.kim's sign-ins in the last 30 days all came from the office or the home ISP; Okta ThreatInsight marked the request as suspected.",
    }),
    oktaMfa({
      id: "aicak2", ts: "2026-09-24T02:14:52.901Z", companyId: cx, user: admin, srcIp: vpnIp,
      result: "approved", userAgent: CHROME_WIN, severity: "medium",
      description: "The Okta Verify push for that sign-in was approved 15 seconds later.",
    }),
    claudeActivity({ id: "aicak3", ts: "2026-09-24T02:16:10.448Z", org, type: "sso_login_succeeded", email: admin, ip: vpnIp, userAgent: CHROME_WIN, firedTimes: 41,
      mitre: "T1078.004", tactic: "Initial Access",
      description: "a.kim signed in to Claude Enterprise through SSO from the same VPN exit address." }),
    claudeActivity({ id: "aicak4", ts: "2026-09-24T02:18:33.605Z", org, type: "admin_api_key_created", email: admin, ip: vpnIp, userAgent: CHROME_WIN, apiKeyId, firedTimes: 1,
      severity: "high", mitre: "T1098.001", tactic: "Persistence",
      description: "a.kim created a new Claude Enterprise admin API key — the first admin key created in the organisation since the tenant was set up." }),
    claudeActivity({ ...apiBase, id: "aicak5", ts: "2026-09-24T02:24:02.118Z", type: "claude_chat_viewed", chatSeed: "exec-board-prep", firedTimes: 1,
      mitre: "T1213", tactic: "Collection",
      description: "The new admin API key read a chat, from 5.188.206.18 (hosting provider)." }),
    claudeActivity({ ...apiBase, id: "aicak6", ts: "2026-09-24T02:24:04.551Z", type: "claude_project_viewed", projectSeed: "security-architecture", firedTimes: 2,
      mitre: "T1213", tactic: "Collection",
      description: "The admin API key read a project." }),
    claudeActivity({ ...apiBase, id: "aicak7", ts: "2026-09-24T02:24:06.973Z", type: "claude_file_viewed", projectSeed: "security-architecture", fileSeed: "iam-design", filename: "AWS_IAM_Role_Design_v4.pdf", firedTimes: 3,
      severity: "medium", mitre: "T1213", tactic: "Collection",
      description: "The admin API key read AWS_IAM_Role_Design_v4.pdf from a project." }),
    claudeActivity({ ...apiBase, id: "aicak8", ts: "2026-09-24T02:31:48.207Z", type: "claude_file_viewed", projectSeed: "fundraising-2027", fileSeed: "cap-table", filename: "Cap_Table_Series_C_Draft.xlsx", firedTimes: 1_184,
      severity: "high", mitre: "T1213", tactic: "Collection",
      description: "The admin API key read Cap_Table_Series_C_Draft.xlsx. Between 02:24 and 02:31 the same key made 1,184 read calls across chats, projects and files of 37 users." }),
    claudeActivity({ ...apiBase, id: "aicak9", ts: "2026-09-24T02:33:15.660Z", type: "platform_memory_deleted", firedTimes: 6,
      severity: "high", mitre: "T1070", tactic: "Defense Evasion",
      description: "The admin API key deleted six platform memory entries." }),
  ];
}

export const AI_EXTRA_STORIES: AiStoryDef[] = [
  { id: "ai-claude-shared-secret", title: "Deployment Secrets Shared from Claude Enterprise by Link", complexity: "foundation", companies: ["rocketstack"], events: buildClaudeSharedSecret() },
  { id: "ai-claude-admin-key-harvest", title: "Hijacked Admin Mints a Claude Enterprise API Key and Harvests Chats", complexity: "advanced", companies: ["rocketstack"], events: buildClaudeAdminKeyHarvest() },
];
