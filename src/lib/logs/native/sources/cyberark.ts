/**
 * CyberArk Privileged Access Manager (Self-Hosted) — Vault audit via syslog, native module
 * (card: docs/log-schemas/pam-cyberark.md).
 *
 * Record: ONE Vault audit line as the shipped `Arcsight.sample.xsl` writes it — BSD syslog
 * header + CEF — flattened the card's way: `timestamp` (Vault-local "Mmm dd HH:MM:SS"),
 * `hostname` (the Vault), the CEF header (`CEFVersion`, `DeviceVendor` "Cyber-Ark",
 * `DeviceProduct` "Vault", `DeviceVersion`, `SignatureID` = the Vault action code, `Name`,
 * `Severity` 5/7), then the extension keys verbatim in XSL order (`act, suser, fname, shost,
 * dhost, duser, externalId, app, reason, cs1Label … cn2Label, msg`). Every value is a string;
 * the `…Label` keys are always printed, their paired values only when present. `rawLine` = the
 * syslog line rebuilt from the same values.
 *
 * Input: `source:"iam"` events whose vendor is CyberArk (category "pam"). The authored raw maps
 * use several legacy namespaces — `ca.*`, `cyberark.*`, `pam.*`, `access.request.*`,
 * `event.action` — and may already carry native CEF keys (`act`, `suser`, `cs2`, `reason` …),
 * which win. Evidence carried verbatim: the Vault user (suser), the station address (shost), the
 * privileged account + target (duser / dhost / fname), the safe (cs2), the reason text, the
 * access-request id (cn1). Missing values are deterministic per company / entity: the Vault
 * version, the CPM / PSM component addresses, the PSM session GUID (one per user + account + day,
 * so 300 → 302 of one session share it).
 *
 * Action mapping: a checkout / reveal → 295 Retrieve password; a PSM session start / end →
 * 300 / 302; a check-in of an exclusive account → 24 CPM Change Password by PasswordManager (the
 * one-time-password rotation on release — the Vault writes no separate "check-in" code); the
 * other card codes (4, 7, 8, 22, 31, 38, 57, 60, 180, 265, 294, 301, 303, 308, 309, 319, 359, 361,
 * 411, 427, 428) by name. Non-CyberArk "iam" events (Okta, Entra) are identity-provider records → null.
 */
import type { NativeSource, NativeLog, KindSchema, UseCase, NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import { syslogStamp } from "./_dnsShared";

// ── schema ───────────────────────────────────────────────────────────────────
const HEADER = ["timestamp", "hostname", "CEFVersion", "DeviceVendor", "DeviceProduct", "DeviceVersion", "SignatureID", "Name", "Severity"];
const LABELS = ["cs1Label", "cs2Label", "cs3Label", "cs4Label", "cs5Label", "cn1Label", "cn2Label"];
/** Extension keys in the order Arcsight.sample.xsl prints them. */
const EXT_ORDER = ["act", "suser", "fname", "shost", "dhost", "duser", "externalId", "app", "reason",
  "cs1Label", "cs1", "cs2Label", "cs2", "cs3Label", "cs3", "cs4Label", "cs4", "cs5Label", "cs5", "cn1Label", "cn1", "cn2Label", "cn2", "msg"];
const LABEL_TEXT: Record<string, string> = {
  cs1Label: "Affected User Name", cs2Label: "Safe Name", cs3Label: "Device Type", cs4Label: "Database", cs5Label: "Other info",
  cn1Label: "Request Id", cn2Label: "Ticket Id",
};

/** Vault action codes the card documents: Name / act text and CEF severity (Error → 7, Info → 5). */
const CODES: Record<string, { name: string; sev: "5" | "7" }> = {
  "4": { name: "User Authentication Failure", sev: "7" },
  "7": { name: "Logon", sev: "5" },
  "8": { name: "Logoff", sev: "5" },
  "22": { name: "CPM Verify Password", sev: "5" },
  "24": { name: "CPM Change Password", sev: "5" },
  "31": { name: "CPM Reconcile Password", sev: "5" },
  "38": { name: "CPM Verify Password Failure", sev: "7" },
  "57": { name: "CPM Change Password Failure", sev: "7" },
  "60": { name: "CPM Reconcile Password Failure", sev: "7" },
  "180": { name: "Add User", sev: "5" },
  "265": { name: "Add Group Member", sev: "5" },
  "294": { name: "Store password", sev: "5" },
  "295": { name: "Retrieve password", sev: "5" },
  "300": { name: "PSM Connect", sev: "5" },
  "301": { name: "PSM Connect Failed", sev: "7" },
  "302": { name: "PSM Disconnect", sev: "5" },
  "303": { name: "PSM Disconnect Failed", sev: "7" },
  "308": { name: "Use Password", sev: "5" },
  "309": { name: "Undefined User Logon", sev: "7" },   // severity UNVERIFIED on the card (failure-class → Error)
  "319": { name: "Retrieve password (From Provider)", sev: "5" },
  "359": { name: "SQL command", sev: "5" },
  "361": { name: "SSH command", sev: "5" },            // the docs' second table labels it "PSM Keystrokes"
  "411": { name: "Window Title", sev: "5" },
  "427": { name: "Store SSH Key", sev: "5" },
  "428": { name: "Retrieve SSH Key", sev: "5" },
};
/** Codes recorded in a PSM session (they carry the session GUID in externalId). */
const PSM_CODES = new Set(["300", "301", "302", "303", "359", "361", "411"]);
/** Codes the CPM component performs (suser PasswordManager, shost = the CPM server). */
const CPM_CODES = new Set(["22", "24", "31", "38", "57", "60"]);

const kind = (): KindSchema => ({
  required: [...HEADER, "act", "suser", "fname", "shost", "dhost", "duser", "app", "reason", ...LABELS, "msg"],
  optional: ["externalId", "cs1", "cs2", "cs3", "cs4", "cs5", "cn1", "cn2", "raw" /* card representation carries the raw line too */],
});
const kinds: Record<string, KindSchema> = Object.fromEntries(Object.keys(CODES).map(c => [c, kind()]));

export function kindOf(record: Record<string, unknown>): string | null {
  if (record.DeviceVendor !== "Cyber-Ark" || record.DeviceProduct !== "Vault") return null;
  const id = String(record.SignatureID ?? "");
  return kinds[id] ? id : null;
}

// ── helpers ──────────────────────────────────────────────────────────────────
type Raw = Record<string, unknown>;
const str = (v: unknown): string | undefined => (v === undefined || v === null || v === "" ? undefined : String(v));
const pick = (raw: Raw, ...keys: string[]) => { for (const k of keys) { const v = str(raw[k]); if (v !== undefined) return v; } return undefined; };
const COMPONENT_USER = /^(PasswordManager|PSMApp_|PSMGw_|Prov_|PVWAGWUser|PVWAAppUser|AIMWebService)/i;
const VERSIONS = ["14.2.0002", "14.6.0002", "13.2.0002"];

/** A Vault action named in the authored event → its action code. */
function codeOf(ev: TelemetryEvent, raw: Raw): string | null {
  const sig = pick(raw, "SignatureID");
  if (sig && CODES[sig]) return sig;
  const named = pick(raw, "act", "Name", "cyberark.event_type", "ca.event_type", "cyberark.action", "event.action");
  const a = (named ?? "").toLowerCase().replace(/[_-]+/g, " ").trim();
  if (a) {
    const byName = Object.entries(CODES).find(([, c]) => c.name.toLowerCase() === a);
    if (byName) return byName[0];
    if (/^(credential )?check ?out$|^retrieve password$|^show password$|^copy password$|^reveal password$/.test(a)) return "295";
    if (/^(psm )?session start$|^psm connect$/.test(a)) return "300";
    if (/^(psm )?session (end|stop|disconnect)$/.test(a)) return "302";
    if (/^(session )?check ?in$|^release( password)?$/.test(a)) return "24";
    if (/keystroke/.test(a)) return "361";
    if (/^(user )?(logon|login) fail(ed|ure)?$|^authentication failure$/.test(a)) return "4";
    if (/^(logon|login)$/.test(a)) return "7";
    if (/^(logoff|logout)$/.test(a)) return "8";
  }
  // No action named: a successful authentication that names a vaulted account is a retrieval.
  if (ev.event_type === "auth_failure") return "4";
  if (ev.event_type === "auth_success") return accountOf(raw) ? "295" : "7";
  return null;
}

interface Account { platform: string; policy: string; address: string; user: string }
/** The vaulted account: an authored object name ("WinDomain-nexacorp.com-adm-x") or "user@address". */
function accountOf(raw: Raw): { object?: string; name?: string } | null {
  const object = pick(raw, "cyberark.object", "ca.object");
  const name = pick(raw, "duser", "pam.account.name", "ca.account", "cyberark.account", "cyberark.target_account", "target.user.name");
  return object || name ? { object, name } : null;
}
const PLATFORM_OF: [RegExp, string][] = [[/^(MSSql|Oracle|MySQL|PostgreSQL|DB2)/i, "Database"], [/^(Win|Unix|Linux|AIX|AS400)/i, "Operating System"], [/^(Cisco|Juniper|F5|Fortinet)/i, "Network Device"]];
function resolveAccount(raw: Raw, ctx: NativeCtx): Account | null {
  const a = accountOf(raw);
  if (!a) return null;
  const fname = pick(raw, "fname");
  const fromObject = (obj: string, userHint?: string): Account | null => {
    // "<PolicyID>-<Address>-<UserName>": the user name is the authored account name when known.
    const body = obj.replace(/^Root\\/, "").replace(/^(Operating System|Database|Application|Network Device)-/, "");
    const policy = body.split("-")[0];
    let rest = body.slice(policy.length + 1);
    let user = userHint && rest.endsWith(`-${userHint}`) ? userHint : undefined;
    if (!user) { const i = rest.lastIndexOf("-"); user = i > 0 ? rest.slice(i + 1) : rest; }
    rest = rest.slice(0, rest.length - user.length - 1);
    const platform = PLATFORM_OF.find(([re]) => re.test(policy))?.[1] ?? "Application";
    return policy && rest ? { platform, policy, address: rest, user } : null;
  };
  if (fname) { const r = fromObject(fname, a.name?.split("@")[0]); if (r) return r; }
  if (a.object) { const r = fromObject(a.object, a.name?.split("@")[0]); if (r) return r; }
  const name = a.name!;
  const at = name.indexOf("@");
  if (at > 0) {
    const user = name.slice(0, at), address = name.slice(at + 1);
    const db = /sql/i.test(address);
    return { platform: db ? "Database" : "Operating System", policy: db ? "MSSql" : "WinServerLocal", address, user };
  }
  // A bare name is a domain account.
  return { platform: "Operating System", policy: "WinDomain", address: ctx.domain, user: name.replace(/^[^\\]+\\/, "") };
}

/** Infrastructure addresses on the company's own /16 (site servers live in x.y.0.0/24). */
function infraIp(ctx: NativeCtx, last: number): string {
  const subnet = COMPANY_ASSETS[ctx.companyId]?.subnet ?? "10.0.1";
  const [a, b] = subnet.split(".");
  return `${a}.${b}.0.${last}`;
}

const ALWAYS_QUOTED = new Set(["act", "cs1", "cs2", "cs3", "cs4", ...LABELS]);
/** The CEF extension the shipped XSL prints: labels / act / cs1-4 quoted, other multi-word values quoted, fname bare. */
export function cefLine(r: Record<string, string>): string {
  const ext = EXT_ORDER.filter(k => k in r).map(k => {
    const v = r[k].replace(/=/g, "\\=");
    if (v === "") return `${k}=`;
    const q = k !== "fname" && (ALWAYS_QUOTED.has(k) || /\s/.test(v));
    return q ? `${k}="${v.replace(/"/g, '\\"')}"` : `${k}=${v}`;
  }).join(" ");
  return `${r.timestamp} ${r.hostname} CEF:${r.CEFVersion}|${r.DeviceVendor}|${r.DeviceProduct}|${r.DeviceVersion}|${r.SignatureID}|${r.Name}|${r.Severity}|${ext}`;
}

// ── conversion ───────────────────────────────────────────────────────────────
function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw = (ev.raw ?? {}) as Raw;
  const vendorPam = /cyberark|cyber-ark/i.test(ev.vendor ?? "");
  if (!vendorPam) return null;
  const code = codeOf(ev, raw);
  if (!code) return null;
  const meta = CODES[code];
  const timeMs = Date.parse(ev.ts);
  const acct = resolveAccount(raw, ctx);
  // Account-object codes need the vaulted object; a retrieval without one is not representable.
  if (!acct && !["4", "7", "8", "180", "265", "309"].includes(code)) return null;

  const email = ev.user_email ?? ev.user?.email ?? pick(raw, "user.email");
  const human = pick(raw, "suser", "cyberark.user", "ca.user", "user.name") ?? (email ? email.split("@")[0] : undefined);
  const suser = CPM_CODES.has(code) ? (pick(raw, "suser") ?? "PasswordManager") : human;
  if (!suser) return null;   // the Vault always names the issuer
  const station = pick(raw, "shost", "cyberark.station", "ca.station", "source.ip") ?? ev.src_ip;
  // PSM records name the PSM server as the station; CPM records the CPM server.
  const shost = CPM_CODES.has(code) ? (pick(raw, "shost") ?? infraIp(ctx, 42))
    : PSM_CODES.has(code) ? (pick(raw, "shost", "cyberark.station") ?? infraIp(ctx, 45))
    : station ?? "";
  const safe = pick(raw, "cs2", "cyberark.safe", "ca.safe", "cyberark.safe_name", "pam.safe.name", "pam.vault.name") ?? "";
  const ticketRef = pick(raw, "reason", "cyberark.reason", "ca.reason", "cyberark.ticket.id", "ca.ticket_id");
  const reason = CPM_CODES.has(code) ? (ticketRef ?? (code === "24" ? "ImmediateTask" : code === "22" || code === "38" ? "VerifyTask" : code === "31" || code === "60" ? "ReconcileTask" : "")) : (ticketRef ?? "");
  // Dual control: the access-request id is numeric in the Vault (cn1); "AR-NEXA-77120" → 77120.
  const reqRaw = pick(raw, "cn1", "access.request.id", "cyberark.request_id", "ca.request_id");
  const reqId = reqRaw && reqRaw !== "-" ? reqRaw.match(/\d+/)?.[0] : undefined;
  const ticketNum = pick(raw, "cn2");

  const r: Record<string, string> = {
    timestamp: syslogStamp(timeMs, ctx.companyId),
    hostname: "VAULT01",
    CEFVersion: "0",
    DeviceVendor: "Cyber-Ark",
    DeviceProduct: "Vault",
    DeviceVersion: VERSIONS[ctx.int(`${ctx.companyId}:cyberark:version`, 0, VERSIONS.length - 1)],
    SignatureID: code,
    Name: meta.name,
    Severity: meta.sev,
    act: meta.name,
    suser,
    fname: acct ? `Root\\${acct.platform}-${acct.policy}-${acct.address}-${acct.user}` : "",
    shost,
    dhost: pick(raw, "dhost") ?? (acct?.address ?? ""),
    duser: acct?.user ?? "",
  };
  if (PSM_CODES.has(code) && acct) {
    const authored = pick(raw, "externalId", "pam.session.id", "cyberark.session_id");
    r.externalId = authored && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(authored) ? authored.toLowerCase()
      : ctx.uuid(`cyberark:psm:${authored ?? `${suser}|${acct.address}|${acct.user}|${ev.ts.slice(0, 10)}`}`);
  }
  const sessionType = pick(raw, "app", "pam.session.type", "cyberark.connection_component");
  r.app = PSM_CODES.has(code) || code === "308"
    ? (sessionType && sessionType.toLowerCase() !== "none" ? sessionType : acct?.policy.startsWith("Unix") ? "SSH" : "RDP")
    : "";
  r.reason = reason;
  r.cs1Label = LABEL_TEXT.cs1Label;
  const affected = pick(raw, "cs1", "cyberark.affected_user");
  if (affected && (code === "180" || code === "265")) r.cs1 = affected;
  r.cs2Label = LABEL_TEXT.cs2Label;
  r.cs2 = safe;
  r.cs3Label = LABEL_TEXT.cs3Label;
  r.cs3 = acct?.platform ?? "";
  r.cs4Label = LABEL_TEXT.cs4Label;
  const db = pick(raw, "cs4");
  if (db) r.cs4 = db;
  r.cs5Label = LABEL_TEXT.cs5Label;
  // Other info: the window title / command a PSM session recorded (mapping UNVERIFIED on the card — only when authored).
  const other = pick(raw, "cs5", "cyberark.window_title", "cyberark.command");
  if (other && (code === "411" || code === "359" || code === "361")) r.cs5 = other;
  r.cn1Label = LABEL_TEXT.cn1Label;
  if (reqId) r.cn1 = reqId;
  r.cn2Label = LABEL_TEXT.cn2Label;
  if (ticketNum && /^\d+$/.test(ticketNum)) r.cn2 = ticketNum;
  r.msg = pick(raw, "msg") ?? "";

  return { sourceId: "cyberark", kind: code, format: "cef", record: r, rawLine: cefLine(r), timeMs };
}

// ── use cases ────────────────────────────────────────────────────────────────
const HUMAN = { not: { field: "suser", op: "regex", value: COMPONENT_USER.source } } as const;
const TIER0 = "(^|[^a-z])(t0|tier-?0)([^a-z]|$)|domain.?admins?|enterprise.?admins?";
const useCases: UseCase[] = [
  {
    id: "cyberark.tier0_retrieve_no_dual_control", title: "Tier-0 password revealed without a dual-control approval", sourceId: "cyberark", kinds: ["295"],
    severity: "high", mitre: ["T1078.002", "T1555"],
    description: "A human Vault user revealed or copied (code 295) the password of an account in a Tier-0 safe (domain / enterprise admins) and the record carries no Request Id (cn1) — the dual-control approval that policy requires for these safes was never granted. After a 295 the password is outside CyberArk's control until the CPM rotates it.",
    logic: "SPL: sourcetype=cyberark:epv:cef signature_id=295 cs2=\"*Domain*Admin*\" OR cs2=\"T0-*\" NOT suser IN (PasswordManager, PSMApp_*, Prov_*) | where isnull(cn1) | table _time suser shost cs2 duser dhost reason",
    match: { all: [HUMAN, { field: "cs2", op: "regex", value: TIER0 }, { field: "cn1", op: "missing" }] },
    falsePositives: ["Break-glass accounts whose safe is configured without dual control — confirm against the PAM policy and the on-call roster"],
  },
  {
    id: "cyberark.retrieve_no_reason_or_ticket", title: "Privileged password retrieved with no reason, ticket or request", sourceId: "cyberark", kinds: ["295", "428"],
    severity: "medium", mitre: ["T1078.002"],
    description: "A person (not a CyberArk component) retrieved a privileged password or SSH key with an empty or placeholder reason, no Ticket Id (cn2) and no Request Id (cn1). Ask for the change or incident it belongs to; an unexplained retrieval is the start of most PAM-abuse cases.",
    logic: "SPL: sourcetype=cyberark:epv:cef signature_id IN (295,428) NOT suser IN (PasswordManager, PSMApp_*, Prov_*) | where (isnull(reason) OR reason=\"\" OR match(reason,\"(?i)^(adhoc|n/?a|-|test)$\")) AND isnull(cn1) AND isnull(cn2)",
    match: { all: [HUMAN, { any: [{ field: "reason", op: "eq", value: "" }, { field: "reason", op: "regex", value: "^(adhoc|n/?a|-|test|none)$" }] }, { field: "cn1", op: "missing" }, { field: "cn2", op: "missing" }] },
    falsePositives: ["Safes that do not enforce 'reason required' — the finding is the policy gap, not necessarily the person"],
  },
  {
    id: "cyberark.retrieve_offhours", title: "Privileged password retrieved outside business hours", sourceId: "cyberark", kinds: ["295", "428"],
    severity: "medium", mitre: ["T1078.002"],
    description: "A human retrieval between 22:00 and 06:00 Vault-local time. Compare with the change calendar (an approved maintenance window explains it) and with the user's normal hours and stations; a night retrieval from a new station is the classic PAM anomaly.",
    logic: "SPL: sourcetype=cyberark:epv:cef signature_id IN (295,428) NOT suser IN (PasswordManager, PSMApp_*, Prov_*) | eval h=tonumber(strftime(_time,\"%H\")) | where h>=22 OR h<6",
    match: { all: [HUMAN, { field: "timestamp", op: "regex", value: " (2[2-3]|0[0-5]):\\d{2}:\\d{2}$" }] },
    falsePositives: ["On-call engineers and approved night-time change windows"],
  },
  {
    id: "cyberark.vault_access_external_ip", title: "Vault logon or retrieval from a public address", sourceId: "cyberark", kinds: ["7", "295", "428", "300"],
    severity: "high", mitre: ["T1078", "T1133"],
    description: "The station (shost) of a Vault logon or password retrieval is a public IP. PVWA is normally reachable only from the corporate network or the VPN pool — a public station means the portal is exposed or a hijacked session is being replayed from outside. Pivot to the identity provider's sign-in for the same user and minute.",
    logic: "SPL: sourcetype=cyberark:epv:cef signature_id IN (7,295,428,300) | where NOT cidrmatch(\"10.0.0.0/8\",shost) AND NOT cidrmatch(\"172.16.0.0/12\",shost) AND NOT cidrmatch(\"192.168.0.0/16\",shost)",
    match: { all: [HUMAN, { field: "shost", op: "regex", value: "^\\d{1,3}(\\.\\d{1,3}){3}$" }, { field: "shost", op: "notCidr", value: "10.0.0.0/8" }, { field: "shost", op: "notCidr", value: "172.16.0.0/12" }, { field: "shost", op: "notCidr", value: "192.168.0.0/16" }] },
    falsePositives: ["A PVWA deliberately published to the internet behind an SSO portal"],
  },
  {
    id: "cyberark.bulk_retrievals", title: "One user retrieving many privileged passwords", sourceId: "cyberark", kinds: ["295", "428"],
    severity: "high", mitre: ["T1555", "T1078.002"],
    description: "Five or more different account objects (fname) retrieved by the same Vault user within an hour — credential harvesting from the Vault, either by an insider or by whoever holds the user's session.",
    logic: "SPL: sourcetype=cyberark:epv:cef signature_id IN (295,428) | bin _time span=1h | stats dc(fname) AS objects values(cs2) AS safes BY _time suser | where objects>=5",
    match: HUMAN,
    threshold: { groupBy: ["suser"], count: 5, windowSec: 3600, distinct: "fname" },
    falsePositives: ["Migration or audit projects that legitimately touch many accounts — these should run under a ticket"],
  },
  {
    id: "cyberark.vault_auth_failures", title: "Repeated Vault authentication failures from one station", sourceId: "cyberark", kinds: ["4"],
    severity: "high", mitre: ["T1110"],
    description: "Three or more User Authentication Failure (code 4) records from the same station within five minutes — password guessing against the Vault. If a Logon (7) from the same shost follows, the guess or a reused password worked.",
    logic: "SPL: sourcetype=cyberark:epv:cef signature_id=4 | bin _time span=5m | stats count dc(suser) AS users BY _time shost | where count>=3",
    match: { field: "SignatureID", op: "eq", value: "4" },
    threshold: { groupBy: ["shost"], count: 3, windowSec: 300 },
    falsePositives: ["A user with an expired password retrying, or a script with a stale credential"],
  },
  {
    id: "cyberark.psm_session_critical_target", title: "PSM session to a Tier-0 account or critical server (context)", sourceId: "cyberark", kinds: ["300"],
    severity: "low", mitre: ["T1021.001"],
    description: "Context: a brokered PSM session (code 300) to a Tier-0 safe or a domain controller. The session GUID (externalId) joins its window titles / commands and the closing 302, and names the recording; the target logs the logon from the PSM server, not from the user's workstation.",
    logic: "SPL: sourcetype=cyberark:epv:cef signature_id=300 (cs2=\"T0-*\" OR cs2=\"*Domain*Admin*\" OR dhost=\"DC*\") | table _time suser dhost duser externalId app",
    match: { any: [{ field: "cs2", op: "regex", value: TIER0 }, { field: "dhost", op: "regex", value: "(^|[-.])dc[-0-9]" }] },
    falsePositives: ["Routine Tier-0 administration — exactly what PSM is for; use it to reconstruct the session"],
  },
  {
    id: "cyberark.vault_membership_change", title: "Vault user created or added to a Vault group", sourceId: "cyberark", kinds: ["180", "265"],
    severity: "medium", mitre: ["T1098", "T1136"],
    description: "Add User (180) or Add Group Member (265) in the Vault. A new member of a Vault admin or safe-owner group gains access to every account those safes hold — persistence that survives a domain password reset. Check who did it (suser), from where (shost) and whether a ticket exists.",
    logic: "SPL: sourcetype=cyberark:epv:cef signature_id IN (180,265) | table _time suser shost cs1 msg",
    match: { field: "SignatureID", op: "in", value: ["180", "265"] },
    falsePositives: ["Onboarding of new administrators through the access-request process"],
  },
  {
    id: "cyberark.cpm_out_of_band_change", title: "CPM verify / change / reconcile failure on a managed account", sourceId: "cyberark", kinds: ["38", "57", "60"],
    severity: "medium", mitre: ["T1098", "T1531"],
    description: "The CPM could not verify, change or reconcile a managed password (38 / 57 / 60): the real password no longer matches the Vault — someone changed it outside CyberArk. Check the directory for a password reset (4723/4724) of the same account (duser) in the preceding hours.",
    logic: "SPL: sourcetype=cyberark:epv:cef signature_id IN (38,57,60) suser=PasswordManager | table _time duser dhost cs2 msg",
    match: { field: "SignatureID", op: "in", value: ["38", "57", "60"] },
    falsePositives: ["Accounts whose password an administrator rotated by hand during an outage", "Target host unreachable during the CPM task"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "cyberark", category: "pam", card: "pam-cyberark.md", product: "CyberArk Privileged Access Manager",
    format: "cef", vendorMatch: ["cyberark", "cyber-ark"], telemetrySources: ["iam"], kinds,
  },
  fromTelemetry,
  useCases,
};

