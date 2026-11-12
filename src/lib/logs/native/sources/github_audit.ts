/**
 * GitHub Enterprise Cloud audit log, as streamed (card: docs/log-schemas/vcs-github-audit.md).
 *
 * One record is one streamed audit event: `@timestamp` / `created_at` in epoch ms, `_document_id`, `action`,
 * `operation_type`, the actor (`actor`, `actor_id`, `actor_ip`, `actor_location.country_code`, `user_agent`), the
 * enterprise and organization (`business`, `org` and their ids), the repository, the token that made the call
 * (`programmatic_access_type`, `hashed_token`, `token_id`, `token_scopes`) and the action's own fields. Git events
 * (`git.clone` / `git.fetch` / `git.push`) are their own kind: they always name the repository and the transport.
 *
 * GitHub is the company's source control in every stack: its record never changes with the session's products.
 * Webhook payloads (`issues.opened`, `pull_request.merged`, `push`) and GitHub Advanced Security alerts are other
 * products and keep their own view.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, UseCase } from "../types";

type Rec = Record<string, unknown>;

const BASE = ["@timestamp", "_document_id", "action", "actor", "actor_id", "created_at", "operation_type", "business", "business_id"];
const SHARED = [
  "actor_ip", "actor_location", "actor_location.country_code", "actor_is_bot", "actor_is_agent", "agent_session_id", "user_agent", "request_id",
  "org", "org_id", "repo", "repo_id", "external_identity_nameid", "external_identity_username",
  "programmatic_access_type", "hashed_token", "token_id", "token_scopes", "user_programmatic_access_name", "oauth_application_id",
];
const AUDIT: KindSchema = {
  required: BASE,
  optional: [
    ...SHARED,
    "visibility", "previous_visibility", "public_repo",
    "pull_request_id", "pull_request_title", "pull_request_url",
    "fingerprint", "title", "read_only",
    "user", "user_id", "permission", "invitee_email", "team",
    "repositories", "repository_selection",
    "hook_id", "name", "events", "active",
    "branch", "reasons", "overridden_codes",
    "runner_id", "runner_name", "runner_labels", "runner_group_name",
    "workflow_id", "workflow_run_id", "head_branch", "head_sha", "run_number", "run_attempt", "event", "conclusion", "started_at", "completed_at",
    "secret_type", "publicly_leaked",
  ],
};
const GIT: KindSchema = {
  required: [...BASE, "repo", "repository", "repository_public", "transport_protocol", "transport_protocol_name"],
  optional: SHARED.filter(f => f !== "repo"),
};

export function kindOf(r: Rec): string | null {
  if (typeof r.action !== "string" || typeof r["@timestamp"] !== "number" || typeof r._document_id !== "string") return null;
  return r.action.startsWith("git.") ? "git" : "audit";
}

const str = (v: unknown) => (typeof v === "string" && v !== "" ? v : typeof v === "number" ? String(v) : undefined);
const bool = (v: unknown) => (typeof v === "boolean" ? v : v === "true" ? true : v === "false" ? false : undefined);
const int = (v: unknown) => (typeof v === "number" ? v : typeof v === "string" && /^\d+$/.test(v) ? Number(v) : undefined);

/** Webhook event names: another product's payload, never an audit action. */
const WEBHOOK = /\.(opened|merged|closed|reopened|edited|labeled|synchronize|created|deleted|completed|requested)$/;

function actionOf(ev: TelemetryEvent): string | undefined {
  const r = (ev.raw ?? {}) as Rec;
  return str(r.action) ?? str(r["github.action"]) ?? str(r["github.audit.action"]);
}

/** An audit-log record of GitHub: the vendor names GitHub (not Advanced Security) and the action is an audit action. */
export function isGithubAudit(ev: TelemetryEvent): boolean {
  if (!/^github( audit log)?$/i.test((ev.vendor ?? "").trim())) return false;
  const a = actionOf(ev);
  return !!a && /^[a-z_]+(\.[a-z_]+)+$/.test(a) && !WEBHOOK.test(a);
}
/** A GitHub event this module does not render (a webhook payload under a GitHub vendor). */
export function isGithubOther(ev: TelemetryEvent): boolean {
  return /^github/i.test(ev.vendor ?? "") && !isGithubAudit(ev);
}

function operationOf(action: string): string {
  const verb = action.split(".").pop() ?? "";
  if (action === "git.push") return "modify";
  if (action.startsWith("git.") || /download|access_granted$/.test(verb) && action !== "repo.access") return "access";
  if (/login|logout|sign_in|two_factor/.test(verb)) return "authentication";
  if (/transfer/.test(verb)) return "transfer";
  if (/restore/.test(verb)) return "restore";
  if (/^(destroy|delete|remove|remove_member|revoke|unregister|disable)/.test(verb)) return "remove";
  if (/^(create|add|add_member|invite_member|register|request_created|enable|grant)/.test(verb)) return "create";
  return "modify";
}

/** base64 of the bytes a hex string spells. */
const b64 = (hex: string) => btoa(String.fromCharCode(...(hex.match(/../g) ?? []).map(h => parseInt(h, 16))));
const b64url = (hex: string) => b64(hex).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** An Enterprise Managed User login from a corporate address: m.cohen@nexacorp.com -> m-cohen_nexacorp. */
export function emuLogin(email: string, shortcode: string): string {
  return `${email.split("@")[0].toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "")}_${shortcode}`;
}

const DEFAULT_SCOPES: Record<string, string> = {
  "Personal access token (classic)": "repo,workflow",
  "OAuth access token": "gist,read:org,repo,workflow",
};

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  if (!isGithubAudit(ev)) return null;
  const r = (ev.raw ?? {}) as Rec;
  const pick = (...keys: string[]) => { for (const k of keys) { const v = str(r[k]); if (v !== undefined) return v; } return undefined; };
  const action = actionOf(ev)!;
  const timeMs = int(r["@timestamp"]) ?? Date.parse(ev.ts);
  if (!Number.isFinite(timeMs)) return null;
  const git = action.startsWith("git.");

  const shortcode = ctx.org;
  const actor = pick("actor", "github.actor", "github.audit.actor") ?? (ev.user_email ? emuLogin(ev.user_email, shortcode) : undefined);
  if (!actor) return null;
  const repo = pick("repo", "repository", "github.repo", "github.audit.repo", "github.actions.repository");
  if (git && !repo) return null;
  const owner = repo?.split("/")[0];
  const org = pick("org", "github.org") ?? (owner && owner !== actor ? owner : undefined);
  const ip = pick("actor_ip", "github.actor.ip", "source.ip") ?? ev.src_ip;
  const cc = pick("actor_location.country_code", "github.geo.country_code") ?? (str((r.actor_location as Rec | undefined)?.country_code)) ?? (ev.geo?.country && /^[A-Z]{2}$/.test(ev.geo.country) ? ev.geo.country : undefined);
  const access = pick("programmatic_access_type", "github.programmatic_access_type");
  const bot = bool(r.actor_is_bot) ?? (/\[bot\]$|^github-/.test(actor) ? true : undefined);
  const ua = pick("user_agent", "github.actor.user_agent") ?? ev.network?.user_agent ?? (git ? "git/2.47.1" : access ? "GitHub CLI 2.63.0" : undefined);
  const visibility = pick("visibility", "github.visibility");

  const record: Rec = {
    "@timestamp": timeMs,
    _document_id: pick("_document_id") ?? b64url(ctx.hex(`${ev.id}:gh-doc`, 32)),
    action,
    actor,
    actor_id: int(r.actor_id) ?? ctx.int(`${ctx.companyId}:gh-actor:${actor}`, 100_000_000, 199_999_999),
    ...(ip ? { actor_ip: ip } : {}),
    ...(cc ? { actor_location: { country_code: cc } } : {}),
    ...(bot !== undefined ? { actor_is_bot: bot } : {}),
    ...(bool(r.actor_is_agent) !== undefined ? { actor_is_agent: bool(r.actor_is_agent) } : {}),
    ...(pick("agent_session_id") ? { agent_session_id: pick("agent_session_id") } : {}),
    business: pick("business") ?? shortcode,
    business_id: int(r.business_id) ?? ctx.int(`${ctx.companyId}:gh-business`, 1_000, 9_999),
    created_at: int(r.created_at) ?? timeMs,
    operation_type: pick("operation_type") ?? operationOf(action),
    ...(org ? { org, org_id: int(r.org_id) ?? ctx.int(`${ctx.companyId}:gh-org:${org}`, 90_000_000, 99_999_999) } : {}),
    ...(repo ? { repo, repo_id: int(r.repo_id) ?? ctx.int(`${ctx.companyId}:gh-repo:${repo}`, 700_000_000, 799_999_999) } : {}),
  };
  if (git) {
    const proto = pick("transport_protocol_name", "github.transport_protocol_name");
    const name = proto === "ssh" ? "ssh" : "http";
    record.repository = repo;
    record.repository_public = bool(r.repository_public) ?? (visibility ? visibility === "public" : false);
    record.transport_protocol = name === "ssh" ? 2 : 1;
    record.transport_protocol_name = name;
  } else {
    record.request_id = pick("request_id") ?? `${ctx.hex(`${ev.id}:rq1`, 4)}:${ctx.hex(`${ev.id}:rq2`, 4)}:${ctx.hex(`${ev.id}:rq3`, 6)}:${ctx.hex(`${ev.id}:rq4`, 6)}:${ctx.hex(`${ev.id}:rq5`, 8)}`.toUpperCase();
    if (visibility) record.visibility = visibility;
    const prev = pick("previous_visibility");
    if (prev) record.previous_visibility = prev;
    const pub = bool(r.public_repo) ?? (visibility ? visibility === "public" : undefined);
    if (pub !== undefined && repo) record.public_repo = pub;
  }
  if (ua) record.user_agent = ua;
  if (ev.user_email && !bot) record.external_identity_nameid = ev.user_email;

  if (access) {
    record.programmatic_access_type = access;
    // One token per account and kind: every call it makes carries the same hash and id.
    const tokenSeed = pick("hashed_token") ? "" : `${ctx.companyId}:gh-token:${actor}:${access}:${pick("github.token.name", "user_programmatic_access_name") ?? ""}`;
    record.hashed_token = pick("hashed_token") ?? b64(ctx.hex(tokenSeed, 64));
    record.token_id = int(r.token_id) ?? ctx.int(`${tokenSeed}:id`, 50_000_000, 59_999_999);
    const scopes = pick("token_scopes", "github.oauth_scopes") ?? DEFAULT_SCOPES[access];
    if (scopes && !/fine-grained|server-to-server/i.test(access)) record.token_scopes = scopes;
    const tokenName = pick("user_programmatic_access_name", "github.token.name");
    if (tokenName) record.user_programmatic_access_name = tokenName;
  }

  // The action's own fields, native names first, then the older authored keys.
  const carry = (field: string, ...legacy: string[]) => { const v = pick(field, ...legacy); if (v !== undefined) record[field] = v; };
  if (!git) {
    const prNumber = pick("github.pull_request.number");
    carry("pull_request_title", "github.pull_request.title");
    carry("pull_request_url");
    if (!record.pull_request_url && prNumber && repo) record.pull_request_url = `https://github.com/${repo}/pull/${prNumber}`;
    if (record.pull_request_title || r.pull_request_id !== undefined) record.pull_request_id = int(r.pull_request_id) ?? ctx.int(`${ev.id}:pr`, 2_000_000_000, 2_999_999_999);
    for (const f of ["fingerprint", "title", "user", "permission", "invitee_email", "team", "repository_selection", "name", "head_branch", "head_sha", "event", "conclusion", "reasons", "overridden_codes", "secret_type"]) carry(f);
    carry("branch", "github.protected_branch.name");
    carry("runner_name", "github.runner.name");
    carry("runner_group_name", "github.runner.group");
    carry("secret_type", "github.secret_type");
    for (const f of ["user_id", "hook_id", "workflow_id", "workflow_run_id", "run_number", "run_attempt"]) { const n = int(r[f]); if (n !== undefined) record[f] = n; }
    const runnerId = int(r.runner_id) ?? int(r["github.runner.id"]);
    if (runnerId !== undefined) record.runner_id = runnerId;
    const labels = pick("runner_labels", "github.runner.labels");
    if (labels) record.runner_labels = labels.split(",").map(s => s.trim());
    for (const f of ["read_only", "active"]) { const b = bool(r[f]); if (b !== undefined) record[f] = b; }
    const leaked = bool(r.publicly_leaked) ?? bool(r["github.publicly_leaked"]);
    if (leaked !== undefined) record.publicly_leaked = leaked;
    if (Array.isArray(r.repositories)) record.repositories = r.repositories;
    if (Array.isArray(r.events)) record.events = r.events;
    if (record.user && record.user_id === undefined) record.user_id = ctx.int(`${ctx.companyId}:gh-actor:${String(record.user)}`, 100_000_000, 199_999_999);
  }
  return { sourceId: "github_audit", kind: git ? "git" : "audit", format: "json", record, timeMs };
}

const useCases: UseCase[] = [
  {
    id: "github_audit.bulk-clone", title: "One account clones many repositories in minutes",
    sourceId: "github_audit", kinds: ["git"], severity: "high", mitre: ["T1213.003", "T1530"],
    description: "A developer clones the few repositories they work on. Ten or more different repositories in a quarter of an hour from one account is a stolen token or an insider taking the code base: look at the address, the user agent and the token hash against that account's history.",
    logic: "// KQL (GitHubAuditLogsV2_CL)\nGitHubAuditLogsV2_CL\n| where Action == \"git.clone\"\n| summarize repos = dcount(Repo), ips = make_set(ActorIp) by Actor, bin(TimeGenerated, 15m)\n| where repos >= 10",
    match: { field: "action", op: "eq", value: "git.clone" },
    threshold: { groupBy: ["actor"], count: 10, windowSec: 900, distinct: "repo" },
    falsePositives: ["A new machine set up from a bootstrap script that clones the team's repositories", "A migration or backup job running under a person's token instead of a GitHub App"],
  },
  {
    id: "github_audit.public-repo-by-token", title: "Public repository created through a token",
    sourceId: "github_audit", kinds: ["audit"], severity: "high", mitre: ["T1567.001", "T1552.001"],
    description: "Supply-chain malware that steals a developer's GitHub token publishes what it harvested to a new PUBLIC repository in the developer's own account (the s1ngularity campaign, August 2025). A public repository created by a token, not in the browser, deserves a look at its name and at what was pushed next.",
    logic: "// KQL (GitHubAuditLogsV2_CL)\nGitHubAuditLogsV2_CL\n| where Action == \"repo.create\" and Visibility == \"public\" and isnotempty(ProgrammaticAccessType)\n| project TimeGenerated, Actor, Repo, ActorIp, UserAgent, ProgrammaticAccessType, HashedToken",
    match: { all: [{ field: "action", op: "eq", value: "repo.create" }, { field: "visibility", op: "eq", value: "public" }, { field: "programmatic_access_type", op: "exists" }] },
    falsePositives: ["An open-source maintainer who creates repositories from the CLI (gh repo create --public)"],
  },
  {
    id: "github_audit.repo-made-public", title: "Private repository made public",
    sourceId: "github_audit", kinds: ["audit"], severity: "high", mitre: ["T1567.001"],
    description: "Flipping a private repository to public publishes its whole history, secrets in old commits included. It is rare, and every one should have an approved reason.",
    logic: "// KQL (GitHubAuditLogsV2_CL)\nGitHubAuditLogsV2_CL\n| where Action == \"repo.access\" and Visibility == \"public\" and PreviousVisibility != \"public\"",
    match: { all: [{ field: "action", op: "eq", value: "repo.access" }, { field: "visibility", op: "eq", value: "public" }] },
    falsePositives: ["A planned open-source release with a change ticket"],
  },
  {
    id: "github_audit.pr-to-public-by-agent-client", title: "Pull request to a public repository from an agent or API client",
    sourceId: "github_audit", kinds: ["audit"], severity: "medium", mitre: ["T1567", "T1213.003"],
    description: "An AI agent connected to GitHub (an MCP server) acts with the person's token. If it reads an attacker's issue in a public repository, it can be steered to copy private code into a pull request on that public repository. A pull request on a public repository whose client is an MCP server or the API, right after reads of private repositories, is the trail of that toxic agent flow.",
    logic: "// KQL (GitHubAuditLogsV2_CL)\nGitHubAuditLogsV2_CL\n| where Action == \"pull_request.create\" and PublicRepo == true\n| where UserAgent has_any (\"mcp\", \"octokit\", \"python-requests\") or isnotempty(ProgrammaticAccessType)\n| project TimeGenerated, Actor, Repo, PullRequestTitle, PullRequestUrl, UserAgent, ProgrammaticAccessType",
    match: { all: [{ field: "action", op: "eq", value: "pull_request.create" }, { field: "public_repo", op: "eq", value: true }, { field: "programmatic_access_type", op: "exists" }] },
    falsePositives: ["Release automation and dependency bots that open pull requests on the company's open-source projects"],
  },
  {
    id: "github_audit.pat-all-repos", title: "Fine-grained token granted access to every repository",
    sourceId: "github_audit", kinds: ["audit"], severity: "medium", mitre: ["T1098.001", "T1528"],
    description: "A fine-grained token is meant to reach the repositories one job needs. A grant over ALL of an organization's repositories is the broad, long-lived credential an attacker or a careless automation wants.",
    logic: "// KQL (GitHubAuditLogsV2_CL)\nGitHubAuditLogsV2_CL\n| where Action == \"personal_access_token.access_granted\" and RepositorySelection == \"all\"",
    match: { all: [{ field: "action", op: "eq", value: "personal_access_token.access_granted" }, { field: "repository_selection", op: "eq", value: "all" }] },
    falsePositives: ["An organization-wide tooling token approved by the platform team"],
  },
  {
    id: "github_audit.ssh-key-new-country", title: "SSH key added from outside the company's countries",
    sourceId: "github_audit", kinds: ["audit"], severity: "medium", mitre: ["T1098.004"],
    description: "An SSH key gives Git access that survives a password reset and SSO. One added from a country the company does not work from is a persistence step, or a remote worker who is not where they claim to be.",
    logic: "// KQL (GitHubAuditLogsV2_CL)\nGitHubAuditLogsV2_CL\n| where Action == \"public_key.create\"\n| extend cc = tostring(ActorLocation.country_code)\n| where cc !in (\"IL\")",
    match: { all: [{ field: "action", op: "eq", value: "public_key.create" }, { field: "actor_location.country_code", op: "nin", value: ["IL"] }] },
    falsePositives: ["Staff travelling, or a branch office abroad (keep the list of company countries current)"],
  },
  {
    id: "github_audit.branch-protection-override", title: "Branch protection overridden",
    sourceId: "github_audit", kinds: ["audit"], severity: "high", mitre: ["T1195.002", "T1562"],
    description: "An administrator pushed or merged past a required review or check. On a branch that deploys, that is code in production nobody reviewed.",
    logic: "// KQL (GitHubAuditLogsV2_CL)\nGitHubAuditLogsV2_CL\n| where Action == \"protected_branch.policy_override\"\n| project TimeGenerated, Actor, Repo, Branch, ActorIp",
    match: { field: "action", op: "eq", value: "protected_branch.policy_override" },
    falsePositives: ["A documented emergency fix during an incident"],
  },
  {
    id: "github_audit.self-hosted-runner", title: "Self-hosted Actions runner registered",
    sourceId: "github_audit", kinds: ["audit"], severity: "medium", mitre: ["T1078", "T1195.002"],
    description: "A self-hosted runner executes workflow jobs, secrets included, on a machine the registrant controls. A new one labelled for deploy jobs, registered by a person and not the platform team, can read every secret those jobs use.",
    logic: "// KQL (GitHubAuditLogsV2_CL)\nGitHubAuditLogsV2_CL\n| where Action == \"self_hosted_runner.register\"\n| project TimeGenerated, Actor, Repo, Org, RunnerName, RunnerLabels, ActorIp",
    match: { field: "action", op: "eq", value: "self_hosted_runner.register" },
    falsePositives: ["Platform engineering adding build capacity under a change"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "github_audit",
    category: "vcs",
    card: "vcs-github-audit.md",
    product: "GitHub Enterprise audit log",
    format: "json",
    vendorMatch: ["github audit log", "github"],
    telemetrySources: ["vcs", "cloudtrail"],
    kinds: { audit: AUDIT, git: GIT },
  },
  fromTelemetry,
  useCases,
};
