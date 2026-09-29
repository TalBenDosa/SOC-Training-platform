/**
 * AI-related attack stories, FOUNDATION tier: one user, one workstation, no lateral
 * movement, no credential theft beyond a single disclosed password.
 *
 * These are training telemetry: what the SOC's own log sources record when AI tools
 * are part of the incident. Every observation below is something a real product
 * writes; no source here logs more than its product does. The only sources that carry
 * prompt text are Zscaler (`prompt_req`); the EDR, DNS, mail-gateway and Entra records
 * carry none.
 *
 *  1. ai-shadow-chat-upload      Zscaler ZIA + EDR   (a spreadsheet uploaded to a personal chat account)
 *  2. ai-chat-harvest-extension  Zscaler ZIA + EDR + Infoblox DNS   (a free extension update copies AI chats)
 *  3. ai-svg-invoice-lure        Defender for Office 365 + EDR + Zscaler ZIA + Entra ID   (SVG posing as a PDF)
 *
 * Authored against nexacorp identities (host, subnet, domain, victim). instantiateStory()
 * rewrites victim, hosts, private IPs and the email domain for every other company, so
 * the only company-specific text kept inside descriptions is the host/user/IP that the
 * remap already handles. Other-organisation names (the supplier) are deliberately not
 * the victim domain so the remap leaves them alone.
 *
 * Event ids: ai + story tag + number. Times are UTC.
 */

import type { TelemetryEvent, Severity } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";
import { zscalerWeb } from "@/lib/sim/emitters/zscaler";
import { csFile, csProcess } from "@/lib/sim/emitters/crowdstrike";
import { entraSignIn } from "@/lib/sim/emitters/entra";

export interface AiStoryDef {
  id: string;
  title: string;
  complexity: "foundation" | "core" | "advanced";
  companies: string[];
  events: TelemetryEvent[];
}

const CX = "nexacorp" as const;

// ── Field-fidelity helpers (identifiers and envelopes the real products add) ─────────────

/** Deterministic version-4-shaped GUID (Falcon event id). */
function guid(seed: string): string {
  const h = makeSha256(`aifound:${seed}`);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

/** ISO instant a fixed number of milliseconds after ts (event.created, the SIEM ingest time). */
const ingested = (ts: string, ms: number): string => new Date(Date.parse(ts) + ms).toISOString();

/** A Windows path as the Falcon sensor records it: an NT device path. */
const ntPath = (p: string): string => `\\Device\\HarddiskVolume3\\${p.slice(3)}`;

/** Falcon sensor envelope carried by every event of one tenant (customer id, sensor build, config). */
const CS_CID = "3f7e2a1b9c8d4e5f6a7b8c9d0e1f2a3b";
const csEnvelope = (id: string): Record<string, string> => ({
  "crowdstrike.event_platform": "Win",
  "crowdstrike.cid": CS_CID,
  "crowdstrike.id": guid(`cs:${id}`),
  "crowdstrike.ConfigBuild": "1007.3.0019807.11",
  "crowdstrike.ConfigStateHash": "2163484712",
  "crowdstrike.EffectiveTransmissionClass": "2",
  "crowdstrike.Entitlements": "15",
  "event.module": "crowdstrike",
  "event.dataset": "crowdstrike.fdr",
});

/** Extra raw fields for a csFile() event: the Falcon envelope, the NT target path and the ECS mapping. */
function csFileExtra(o: {
  id: string; ts: string; host: string; user: string; path: string; type: "creation" | "deletion";
  actor: string; actorPid: number; actorPath: string; actorParent?: string; actorParentPid?: number;
}): Record<string, string> {
  return {
    ...csEnvelope(o.id),
    "crowdstrike.TargetFileName": ntPath(o.path),
    "host.name": o.host,
    "user.name": o.user.split("@")[0],
    "event.category": "file",
    "event.type": o.type,
    "event.outcome": "success",
    "event.created": ingested(o.ts, 2_300),
    "process.name": o.actor,
    "process.pid": String(o.actorPid),
    "process.executable": o.actorPath,
    ...(o.actorParent ? { "process.parent.name": o.actorParent, "process.parent.pid": String(o.actorParentPid) } : {}),
  };
}

const UA_CHROME =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const UA_EDGE = `${UA_CHROME} Edg/141.0.0.0`;

// ── Shared builders ───────────────────────────────────────────────────────────────────

interface WorkCtx { host: string; ip: string; user: string; ua: string; location: string; incident: string }

interface ZiaIn {
  id: string; ts: string; url: string; domain: string;
  method?: "GET" | "POST"; action?: "allowed" | "blocked";
  category?: string; status?: number; sent?: number; recv?: number; appName?: string;
  severity: Severity; mitre?: string; tactic?: string; description: string;
  dstIp?: string;
  extra?: Record<string, unknown>;
  top?: Partial<TelemetryEvent>;
}

/** Zscaler Internet Access web record with the extra NSS fields merged in (all zscaler.* prefixed). */
function makeZia(c: WorkCtx) {
  return (o: ZiaIn): TelemetryEvent => {
    const method = o.method ?? "GET";
    const action = o.action ?? "allowed";
    const status = o.status ?? (action === "blocked" ? 403 : 200);
    const ev = zscalerWeb({
      companyId: CX, id: o.id, ts: o.ts, host: c.host, srcIp: c.ip, user: c.user,
      url: o.url, domain: o.domain, method, action, category: o.category, status,
      bytesSent: o.sent, bytesReceived: o.recv, userAgent: c.ua, appName: o.appName,
      location: c.location, mitre: o.mitre, tactic: o.tactic, severity: o.severity,
      description: o.description, incidentId: c.incident,
    });
    return {
      ...ev,
      ...(o.dstIp ? { dst_ip: o.dstIp } : {}),
      ...(o.top ?? {}),
      raw: {
        ...ev.raw,
        "zscaler.cip": c.ip,
        "zscaler.reqmethod": method,
        "zscaler.respcode": String(status),
        "zscaler.useragent": c.ua,
        ...(o.dstIp ? { "zscaler.sip": o.dstIp } : {}),
        ...(o.extra ?? {}),
      },
    };
  };
}

/** NSS cloud-app classification fields for a generative-AI destination. */
const aiApp = (status: "Sanctioned" | "Unsanctioned") => ({
  "zscaler.appclass": "AI & ML Applications",
  "zscaler.app_status": status,
  "zscaler.app_risk_score": "3",
});

const baseline = { is_baseline: true, expected_verdict: "informational" } as const;

// ═════════════════════════════════════════════════════════════════════════════════════
// 1. ai-shadow-chat-upload
// ═════════════════════════════════════════════════════════════════════════════════════
function buildShadowChatUpload(): TelemetryEvent[] {
  const INC = "inc:aishd:1";
  const c: WorkCtx = {
    host: "WS-SALES-1876", ip: "10.10.20.76", user: "a.kaplan@nexacorp.com",
    ua: UA_CHROME, location: "London-HQ", incident: INC,
  };
  const zia = makeZia(c);

  const xlsxName = "Customer_Contacts_Q3_Master.xlsx";
  const csvName = "Customer_Contacts_Q3_Master.csv";
  const xlsxPath = `C:\\Users\\a.kaplan\\Downloads\\${xlsxName}`;
  const csvPath = `C:\\Users\\a.kaplan\\Downloads\\${csvName}`;
  const xlsxHash = makeSha256("aishd_customer_contacts_q3_master_xlsx_2026");
  const csvHash = makeSha256("aishd_customer_contacts_q3_master_csv_2026");
  const XLSX_SIZE = 2_418_944;
  const CSV_SIZE = 1_731_088;
  const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
  const EXCEL = "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE";

  const events: TelemetryEvent[] = [
    // Reference point: the same domain, but the company's sanctioned workspace.
    zia({
      id: "aishd1", ts: "2026-09-22T08:41:17.336Z",
      url: "https://chatgpt.com/backend-api/conversation", domain: "chatgpt.com", method: "POST",
      category: "Internet Services", appName: "ChatGPT", sent: 968, recv: 5_412, severity: "informational",
      description:
        "At 08:41 a.kaplan's browser on WS-SALES-1876 posted a short prompt to chatgpt.com and Zscaler classified the session Sanctioned: the company's enterprise ChatGPT workspace, reached through corporate single sign-on. Ordinary work-related use, and the reference point for the later sessions on the same domain.",
      extra: {
        ...aiApp("Sanctioned"),
        "zscaler.prompt_req": "give me three subject lines for the Q4 partner newsletter",
      },
      top: { ...baseline },
    }),

    // A customer export lands on disk.
    csFile({
      companyId: CX, id: "aishd2", ts: "2026-09-22T09:22:46.581Z", host: c.host, srcIp: c.ip, user: c.user,
      extra: csFileExtra({
        id: "aishd2", ts: "2026-09-22T09:22:46.581Z", host: c.host, user: c.user, path: xlsxPath, type: "creation",
        actor: "chrome.exe", actorPid: 6204, actorPath: CHROME, actorParent: "explorer.exe", actorParentPid: 3844,
      }),
      path: xlsxPath, sha256: xlsxHash, size: XLSX_SIZE, action: "file_create",
      actorProcess: "chrome.exe", actorPid: 6204, actorPath: CHROME,
      actorParentName: "explorer.exe", actorParentPid: 3844, actorSigned: "trusted", actorIntegrity: "medium",
      severity: "low", incidentId: INC,
      description:
        `chrome.exe wrote ${xlsxName} (2.3 MB) into a.kaplan's Downloads folder on WS-SALES-1876 at 09:22: a report exported from a browser session, not a file created locally.`,
    }),

    // Same domain, different classification: not the company workspace.
    zia({
      id: "aishd3", ts: "2026-09-22T09:30:08.127Z",
      url: "https://chatgpt.com/", domain: "chatgpt.com", method: "GET",
      category: "Internet Services", appName: "ChatGPT", sent: 742, recv: 118_204, severity: "low",
      description:
        "At 09:30 the same browser requested chatgpt.com again. This time Zscaler classified the session Unsanctioned, on the same domain that was Sanctioned at 08:41, which means this session is not signed in to the company workspace.",
      extra: { ...aiApp("Unsanctioned") },
    }),

    // DLP stops the spreadsheet.
    zia({
      id: "aishd4", ts: "2026-09-22T09:33:54.640Z",
      url: "https://chatgpt.com/backend-api/files", domain: "chatgpt.com", method: "POST", action: "blocked", status: 403,
      category: "Internet Services", appName: "ChatGPT", sent: 2_419_377, recv: 312,
      severity: "medium", mitre: "T1567", tactic: "Exfiltration",
      description:
        `At 09:33 Zscaler blocked a POST of ${xlsxName} to chatgpt.com/backend-api/files in the Unsanctioned session. The DLP rule Block PII to GenAI (Files) matched the Credit Cards dictionary (9 hits) and the Email Addresses dictionary (1,204 hits).`,
      extra: {
        ...aiApp("Unsanctioned"),
        "zscaler.activity": "Upload",
        "zscaler.upload_filename": xlsxName,
        "zscaler.upload_filetype": "xlsx",
        "zscaler.ruletype": "Data Loss Prevention",
        "zscaler.rulelabel": "GenAI-DLP-Block",
        "zscaler.dlpeng": "PII",
        "zscaler.dlpdict": "Credit Cards|Email Addresses",
        "zscaler.dlpdicthitcount": "9|1204",
        "zscaler.trig_dlprulename": "Block PII to GenAI (Files)",
      },
      top: { is_detection: true, edr_scope: "edr" },
    }),

    // The same data, re-saved in another format.
    csFile({
      companyId: CX, id: "aishd5", ts: "2026-09-22T09:35:22.905Z", host: c.host, srcIp: c.ip, user: c.user,
      extra: csFileExtra({
        id: "aishd5", ts: "2026-09-22T09:35:22.905Z", host: c.host, user: c.user, path: csvPath, type: "creation",
        actor: "EXCEL.EXE", actorPid: 7284, actorPath: EXCEL, actorParent: "explorer.exe", actorParentPid: 3844,
      }),
      path: csvPath, sha256: csvHash, size: CSV_SIZE, action: "file_create",
      actorProcess: "EXCEL.EXE", actorPid: 7284, actorPath: EXCEL,
      actorParentName: "explorer.exe", actorParentPid: 3844, actorSigned: "trusted", actorIntegrity: "medium",
      severity: "medium", mitre: "T1074.001", tactic: "Collection", incidentId: INC,
      description:
        `About ninety seconds after the block, EXCEL.EXE (started from explorer.exe) wrote ${csvName} (1.7 MB) into the same Downloads folder on WS-SALES-1876: the same customer data saved again in a different file format.`,
    }),

    // The CSV goes up and nothing fires.
    zia({
      id: "aishd6", ts: "2026-09-22T09:36:41.318Z",
      url: "https://chatgpt.com/backend-api/files", domain: "chatgpt.com", method: "POST", action: "allowed", status: 200,
      category: "Internet Services", appName: "ChatGPT", sent: 1_731_522, recv: 486,
      severity: "high", mitre: "T1567", tactic: "Exfiltration",
      description:
        `At 09:36 Zscaler allowed a POST of ${csvName} to chatgpt.com/backend-api/files in the Unsanctioned session. DLP inspection returned nothing for the CSV, although it holds the same records the rule matched in the xlsx under three minutes earlier.`,
      extra: {
        ...aiApp("Unsanctioned"),
        "zscaler.activity": "Upload",
        "zscaler.upload_filename": csvName,
        "zscaler.upload_filetype": "csv",
        "zscaler.dlpeng": "None",
        "zscaler.dlpdict": "None",
      },
    }),

    // The prompt that goes with it (Zscaler is the one source that logs it).
    zia({
      id: "aishd7", ts: "2026-09-22T09:36:46.752Z",
      url: "https://chatgpt.com/backend-api/conversation", domain: "chatgpt.com", method: "POST", action: "allowed", status: 200,
      category: "Internet Services", appName: "ChatGPT", sent: 1_486, recv: 7_903,
      severity: "high", mitre: "T1567", tactic: "Exfiltration",
      description:
        "Five seconds later a POST to the conversation endpoint carried the user's prompt, which Zscaler logged in prompt_req: the full customer list with account owners and annual spend, to be grouped by region, ranked and turned into renewal emails. Customer records have now been disclosed to a public model service outside company control (ATLAS AML.T0048).",
      extra: {
        ...aiApp("Unsanctioned"),
        "zscaler.prompt_req":
          "Here is our full customer list with account owners and annual spend. Group the accounts by region, rank the top 20 by spend, and write a personalised renewal email for each of the top 5.",
      },
    }),

    // The upload copy is removed from disk.
    csFile({
      companyId: CX, id: "aishd8", ts: "2026-09-22T09:44:03.271Z", host: c.host, srcIp: c.ip, user: c.user,
      extra: csFileExtra({
        id: "aishd8", ts: "2026-09-22T09:44:03.271Z", host: c.host, user: c.user, path: csvPath, type: "deletion",
        actor: "explorer.exe", actorPid: 3844, actorPath: "C:\\Windows\\explorer.exe",
      }),
      path: csvPath, sha256: csvHash, size: CSV_SIZE, action: "file_delete",
      actorProcess: "explorer.exe", actorPid: 3844, actorPath: "C:\\Windows\\explorer.exe",
      actorSigned: "trusted", actorIntegrity: "medium",
      severity: "medium", mitre: "T1070.004", tactic: "Defense Evasion", incidentId: INC,
      description:
        `At 09:44 explorer.exe deleted ${csvName} from Downloads on WS-SALES-1876, seven minutes after the upload. No matching delete was logged for the xlsx export.`,
    }),
  ];

  for (const e of events) e.incident_id = INC;
  return events;
}

// ═════════════════════════════════════════════════════════════════════════════════════
// 2. ai-chat-harvest-extension
// ═════════════════════════════════════════════════════════════════════════════════════
function buildChatHarvestExtension(): TelemetryEvent[] {
  const INC = "inc:aiext:1";
  const c: WorkCtx = {
    host: "WS-MKT-3301", ip: "10.10.20.61", user: "s.patel@nexacorp.com",
    ua: UA_CHROME, location: "London-HQ", incident: INC,
  };
  const zia = makeZia(c);

  const extId = "hkgmfnpelcbjoadkdanmghcplobjhegk";
  const statsHost = "stats.surfguard-vpn.com";
  const statsIp = "80.94.95.213";
  const statsQuery = `ext=${extId}&ver=5.5.0`;
  const statsUrl = `https://${statsHost}/v2/events?${statsQuery}`;
  const crxUrl = `https://clients2.googleusercontent.com/crx/blobs/Acy5rT0q8XvL3nWk2dUe1hQmZ7JpAaVfN4YtR6sGxKb9oCwDiE5uLhBMg2PzHnQ/${extId}_5_5_0_0.crx`;
  const manifestPath = `C:\\Users\\s.patel\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\${extId}\\5.5.0_0\\manifest.json`;
  const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

  const events: TelemetryEvent[] = [
    // Before the update: chats to the sanctioned workspace, nothing else follows.
    zia({
      id: "aiext1", ts: "2026-09-23T08:57:29.412Z",
      url: "https://chatgpt.com/backend-api/conversation", domain: "chatgpt.com", method: "POST",
      category: "Internet Services", appName: "ChatGPT", sent: 1_204, recv: 4_880, severity: "informational",
      description:
        "At 08:57 s.patel posted a short editing prompt to the sanctioned ChatGPT workspace from WS-MKT-3301. No request to any other domain followed it: this is the browser's traffic pattern before the extension update.",
      extra: {
        ...aiApp("Sanctioned"),
        "zscaler.prompt_req": "shorten this intro paragraph for the partner one-pager",
      },
      top: { ...baseline },
    }),

    // Chrome auto-updates an installed extension.
    zia({
      id: "aiext2", ts: "2026-09-23T09:38:47.093Z",
      url: crxUrl, domain: "clients2.googleusercontent.com", method: "GET",
      category: "Internet Services", appName: "General Browsing", sent: 611, recv: 1_882_417,
      severity: "low", mitre: "T1176", tactic: "Persistence",
      description:
        `At 09:38 Chrome on WS-MKT-3301 downloaded a 1.8 MB extension package, version 5.5.0, for extension ID ${extId} from the Chrome Web Store update service: a routine automatic update of an extension already installed in the browser.`,
    }),

    // The new version is unpacked into the profile.
    csFile({
      companyId: CX, id: "aiext3", ts: "2026-09-23T09:38:51.664Z", host: c.host, srcIp: c.ip, user: c.user,
      extra: csFileExtra({
        id: "aiext3", ts: "2026-09-23T09:38:51.664Z", host: c.host, user: c.user, path: manifestPath, type: "creation",
        actor: "chrome.exe", actorPid: 7132, actorPath: CHROME, actorParent: "explorer.exe", actorParentPid: 3844,
      }),
      path: manifestPath, sha256: makeSha256("aiext_surfguard_manifest_json_5_5_0"), size: 2_731, action: "file_create",
      actorProcess: "chrome.exe", actorPid: 7132, actorPath: CHROME,
      actorParentName: "explorer.exe", actorParentPid: 3844, actorSigned: "trusted", actorIntegrity: "medium",
      severity: "low", mitre: "T1176", tactic: "Persistence", incidentId: INC,
      description:
        `At 09:38, about five seconds after the package download, chrome.exe wrote manifest.json into a new 5.5.0_0 folder under Extensions\\${extId} in s.patel's Chrome profile. The folder name is the extension's Chrome Web Store ID, and it now runs at version 5.5.0.`,
    }),

    // First lookup of a name that has never appeared for this host.
    {
      id: "aiext4", ts: "2026-09-23T09:39:58.207Z",
      source: "dns", vendor: "Infoblox DNS", event_type: "dns_query", severity: "low",
      hostname: c.host, user_email: c.user, src_ip: c.ip, dst_ip: "10.10.20.5", dst_port: 53, protocol: "udp",
      dns: { query: statsHost, query_type: "A", response: statsIp, rcode: "NOERROR" },
      network: { domain: statsHost },
      description:
        `At 09:39, 67 seconds after the new version was written, WS-MKT-3301 asked the internal Infoblox resolver for ${statsHost} and received one A record, ${statsIp} (a hosting range in Bucharest, Romania). This is the first lookup of that name in this sequence of events.`,
      raw: {
        "infoblox.client_ip": c.ip,
        "infoblox.query_name": statsHost,
        "infoblox.query_type": "A",
        "infoblox.rcode": "NOERROR",
        "infoblox.answer": statsIp,
        "infoblox.ttl": 300,
        "infoblox.view": "internal",
        "infoblox.member": "ns-01.nexacorp.com",
        "infoblox.transport": "UDP",
        "dns.question.name": statsHost,
        "dns.question.type": "A",
        "dns.question.class": "IN",
        "dns.answers.data": statsIp,
        "dns.answers.ttl": 300,
        "dns.resolved_ip": statsIp,
        "dns.response_code": "NOERROR",
        "network.protocol": "dns",
        "source.ip": c.ip,
        "host.name": "ns-01.nexacorp.com",
        "message": `client @0x7f2b1c04a3d0 ${c.ip}#51422 (${statsHost}): query: ${statsHost} IN A + (10.10.20.5)`,
        "log.level": "info",
        "event.action": "dns-query",
        "event.outcome": "success",
        "event.module": "infoblox_nios",
        "event.dataset": "infoblox_nios.log",
        "event.provider": "named",
        "event.created": "2026-09-23T09:39:58.512Z",
      },
    },

    // First contact.
    zia({
      id: "aiext5", ts: "2026-09-23T09:40:01.338Z",
      url: statsUrl, domain: statsHost, method: "POST", action: "allowed", status: 200,
      category: "Miscellaneous or Unknown", appName: "General Browsing", sent: 1_186, recv: 46, dstIp: statsIp,
      severity: "medium", mitre: "T1071.001", tactic: "Command and Control",
      description:
        `At 09:40 a 1.2 KB POST reached ${statsHost}/v2/events with ext=${extId}&ver=5.5.0 in the query string and was answered with 46 bytes. Zscaler had no category for the domain and allowed it. The ext parameter is the same 32-character ID as the extension folder written at 09:38.`,
      extra: {},
    }),

    // Chat 1: a normal prompt to the sanctioned workspace.
    zia({
      id: "aiext6", ts: "2026-09-23T09:52:14.719Z",
      url: "https://chatgpt.com/backend-api/conversation", domain: "chatgpt.com", method: "POST",
      category: "Internet Services", appName: "ChatGPT", sent: 1_412, recv: 6_204, severity: "informational",
      description:
        "At 09:52 s.patel sent a 1.4 KB prompt to the sanctioned ChatGPT workspace asking for an announcement paragraph to be rewritten; the answer was 6.2 KB. prompt_req shows the text, which includes unreleased pricing.",
      extra: {
        ...aiApp("Sanctioned"),
        "zscaler.prompt_req":
          "Rewrite this paragraph from our Q4 launch announcement so it sounds more confident, keep it under 90 words: Our new Atlas analytics tier ships on 11 November and we are pricing it 18% below Meridian to win the mid-market accounts.",
      },
    }),

    // ...and the copy leaves for the extension vendor's domain.
    zia({
      id: "aiext7", ts: "2026-09-23T09:52:24.318Z",
      url: statsUrl, domain: statsHost, method: "POST", action: "allowed", status: 200,
      category: "Miscellaneous or Unknown", appName: "General Browsing", sent: 8_004, recv: 46, dstIp: statsIp,
      severity: "high", mitre: "T1041", tactic: "Exfiltration",
      description:
        `About ten seconds after that request, a 7.8 KB POST went to ${statsHost}/v2/events with the same ext and ver parameters: about the size of the prompt and the answer together (1,412 + 6,204 bytes plus roughly 390 bytes of overhead). Conversation content is being copied to a domain that belongs to the extension vendor, not to the AI service (ATLAS AML.T0048).`,
      top: { edr_scope: "edr" },
    }),

    // Chat 2: a long paste.
    zia({
      id: "aiext8", ts: "2026-09-23T10:31:40.885Z",
      url: "https://chatgpt.com/backend-api/conversation", domain: "chatgpt.com", method: "POST",
      category: "Internet Services", appName: "ChatGPT", sent: 21_344, recv: 9_876, severity: "informational",
      description:
        "At 10:31 s.patel pasted about 21 KB of notes into the sanctioned workspace to draft a board update; the answer was 9.9 KB. prompt_req shows notes about a revenue shortfall and acquisition talks (truncated by the log).",
      extra: {
        ...aiApp("Sanctioned"),
        "zscaler.prompt_req":
          "Turn these notes into a two-paragraph board update. Notes: Q3 revenue landed 6% under plan, mostly EMEA; talks with Halden Systems on an acquisition are at term-sheet stage; legal wants the announcement held until…",
      },
    }),

    // The copy is proportional to what was typed and answered.
    zia({
      id: "aiext9", ts: "2026-09-23T10:31:58.204Z",
      url: statsUrl, domain: statsHost, method: "POST", action: "allowed", status: 200,
      category: "Miscellaneous or Unknown", appName: "General Browsing", sent: 31_622, recv: 46, dstIp: statsIp,
      severity: "high", mitre: "T1041", tactic: "Exfiltration",
      description:
        `About 17 seconds after the request, a 31 KB POST went to ${statsHost}/v2/events: again the size of prompt plus answer (21,344 + 9,876 bytes plus roughly 400 bytes of overhead). The volume sent to that domain scales with what the user typed and received, not with a fixed heartbeat, and it follows each chat exchange by seconds.`,
    }),
  ];

  for (const e of events) e.incident_id = INC;
  return events;
}

// ═════════════════════════════════════════════════════════════════════════════════════
// 3. ai-svg-invoice-lure
// ═════════════════════════════════════════════════════════════════════════════════════
function buildSvgInvoiceLure(): TelemetryEvent[] {
  const INC = "inc:aisvg:1";
  const c: WorkCtx = {
    host: "WS-ACC-4477", ip: "10.10.20.47", user: "j.chen@nexacorp.com",
    ua: UA_EDGE, location: "London-HQ", incident: INC,
  };
  const zia = makeZia(c);
  const victim = c.user;
  // A second hidden recipient who is deliberately NOT on any company roster, so the victim
  // swap in instantiateStory() can never collapse the two mailboxes into one person.
  const second = "p.whitfield@nexacorp.com";

  // The supplier's mailbox is the sender; the supplier is a victim too.
  const supplier = "d.holloway@brightwaterfreight.co.uk";
  const supplierName = "Daniel Holloway";
  const eopIp = "40.107.21.62";           // Exchange Online outbound: same for the supplier's normal mail
  const usualClientIp = "81.2.69.160";    // the supplier's office (UK), as seen on the earlier mail
  const lureClientIp = "196.251.73.140";  // where the mailbox client connected from for the lure (Lagos)

  const svgName = "Invoice_INV-20418 - PDF - 4 pages.svg";
  const svgSize = 12_846;
  const svgHash = makeSha256("aisvg_invoice_inv_20418_pdf_4_pages_svg_2026");
  const pdfName = "Invoice_INV-20377.pdf";
  const pdfSize = 148_226;
  const pdfHash = makeSha256("aisvg_invoice_inv_20377_pdf_2026");

  const lureInternetId = "<LO2P265MB4471B8D3E9A0C51F7A26D94E1B3C7A@LO2P265MB4471.GBRP265.PROD.OUTLOOK.COM>";
  const baseInternetId = "<LO2P265MB4102A6C7F3B81D0E5942AC17D8E6F2@LO2P265MB4102.GBRP265.PROD.OUTLOOK.COM>";

  const gateHost = "docview.northgate-billing.com";
  const gateIp = "45.142.214.77";        // resolves to Kyiv in the platform's geo table
  const cacheDir = "C:\\Users\\j.chen\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\KP3T9A2M";
  const svgPath = `${cacheDir}\\${svgName}`;
  const OUTLOOK = "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE";
  const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

  // Defender for Office 365 delivery record (same conventions as the platform's other MDO events).
  const mail = (o: {
    id: string; ts: string; rcpt: string; headerTo: string; subject: string; internetId: string; networkId: string;
    attName: string; attMime: string; attExt: string; attSize: number; attHash: string; clientIp: string; scl: string;
    severity: Severity; description: string; top?: Partial<TelemetryEvent>;
  }): TelemetryEvent => ({
    id: o.id, ts: o.ts, source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_received",
    user_email: o.rcpt, src_ip: eopIp, severity: o.severity, description: o.description, incident_id: INC,
    raw: {
      "email.from.address": supplier,
      "email.from.display_name": supplierName,
      "email.sender.address": supplier,
      "email.to.address": o.headerTo,
      "email.subject": o.subject,
      "email.direction": "inbound",
      "email.message_id": o.internetId,
      "email.attachments.file.name": o.attName,
      "email.attachments.file.mime_type": o.attMime,
      "email.attachments.file.extension": o.attExt,
      "email.attachments.file.size": o.attSize,
      "email.attachments.file.hash.sha256": o.attHash,
      "email.spf": "pass",
      "email.dkim": "pass",
      "email.dmarc": "pass",
      "email.auth.compauth": "pass",
      "email.headers.x-originating-ip": `[${o.clientIp}]`,
      "data.office365.Directionality": "Inbound",
      "data.office365.DeliveryAction": "Delivered",
      "data.office365.DeliveryLocation": "Inbox",
      "data.office365.ThreatType": "None",
      "data.office365.PhishConfidenceLevel": "None",
      "data.office365.SpamConfidenceLevel": o.scl,
      "data.office365.Sender": supplier,
      "data.office365.SenderIp": eopIp,
      "data.office365.NetworkMessageId": o.networkId,
      "data.office365.InternetMessageId": o.internetId,
      "data.office365.MailboxOwnerUPN": o.rcpt,
      "data.office365.Subject": o.subject,
      "data.office365.AttachmentName": o.attName,
      "data.office365.AttachmentCount": "1",
      "data.office365.AttachmentSha256": o.attHash,
      "source.ip": eopIp,
      "action_result": "allowed",
    },
    ...o.top,
  });

  const signInPolicy = [{
    id: "1f0b6c93-7d24-4a5e-8b90-c3f27a641e58", displayName: "Require MFA for all users",
    result: "failure", enforcedGrantControls: ["Mfa"], enforcedSessionControls: [],
  }];

  const events: TelemetryEvent[] = [
    // Reference point: this supplier's ordinary invoice mail, the day before.
    mail({
      id: "aisvg1", ts: "2026-09-23T14:06:12.480Z", rcpt: victim, headerTo: victim,
      subject: "Invoice INV-20377 - August freight services", internetId: baseInternetId,
      networkId: "3c7a91f2-58d4-4e06-b1a9-0d2e6f47c815",
      attName: pdfName, attMime: "application/pdf", attExt: "pdf", attSize: pdfSize, attHash: pdfHash,
      clientIp: usualClientIp, scl: "0", severity: "informational",
      description:
        "On Wednesday afternoon d.holloway of Brightwater Freight, an existing supplier, sent j.chen invoice INV-20377 as a PDF (145 KB). SPF, DKIM and DMARC passed, the message was addressed to j.chen and the mailbox client connected from the supplier's usual UK office IP. This is the sender's normal pattern.",
      top: { ...baseline },
    }),

    // The lure, delivered to the victim.
    mail({
      id: "aisvg2", ts: "2026-09-24T08:13:22.317Z", rcpt: victim, headerTo: supplier,
      subject: "Invoice INV-20418 - September freight services and remittance details", internetId: lureInternetId,
      networkId: "e94b06d1-2f73-4a8c-9c15-7b30a1d8f462",
      attName: svgName, attMime: "image/svg+xml", attExt: "svg", attSize: svgSize, attHash: svgHash,
      clientIp: lureClientIp, scl: "1", severity: "low",
      description:
        "At 08:13 a message from the same supplier mailbox reached j.chen with an attachment named 'Invoice_INV-20418 - PDF - 4 pages.svg' (12.5 KB, image/svg+xml). SPF, DKIM and DMARC passed and it was delivered to the inbox with SCL 1, but the To header names d.holloway himself and j.chen received the copy only by envelope, so the real recipients were hidden (Bcc). The mailbox client connected from an IP in Lagos, not the supplier's usual UK office. The subject and wording are fluent, generic business English of the kind an LLM produces at no cost (ATLAS AML.T0052.000).",
      top: { mitre_technique: "T1566.001", mitre_tactic: "Initial Access" },
    }),

    // Same message, second hidden recipient.
    mail({
      id: "aisvg3", ts: "2026-09-24T08:13:25.041Z", rcpt: second, headerTo: supplier,
      subject: "Invoice INV-20418 - September freight services and remittance details", internetId: lureInternetId,
      networkId: "1a5d78c3-b902-47e6-8f4a-c60e93b2d517",
      attName: svgName, attMime: "image/svg+xml", attExt: "svg", attSize: svgSize, attHash: svgHash,
      clientIp: lureClientIp, scl: "1", severity: "low",
      description:
        "Under three seconds later the same message (identical Internet message ID) was delivered to p.whitfield, again with d.holloway in the To header. One message reached both mailboxes as hidden recipients.",
      top: { mitre_technique: "T1566.001", mitre_tactic: "Initial Access" },
    }),

    // The attachment is opened from Outlook.
    csFile({
      companyId: CX, id: "aisvg4", ts: "2026-09-24T08:26:38.552Z", host: c.host, srcIp: c.ip, user: victim,
      extra: csFileExtra({
        id: "aisvg4", ts: "2026-09-24T08:26:38.552Z", host: c.host, user: victim, path: svgPath, type: "creation",
        actor: "OUTLOOK.EXE", actorPid: 5148, actorPath: OUTLOOK, actorParent: "explorer.exe", actorParentPid: 3844,
      }),
      path: svgPath, sha256: svgHash, size: svgSize, action: "file_create",
      actorProcess: "OUTLOOK.EXE", actorPid: 5148, actorPath: OUTLOOK,
      actorParentName: "explorer.exe", actorParentPid: 3844, actorSigned: "trusted", actorIntegrity: "medium",
      severity: "low", incidentId: INC,
      description:
        "At 08:26 OUTLOOK.EXE wrote 'Invoice_INV-20418 - PDF - 4 pages.svg' into the INetCache\\Content.Outlook folder in j.chen's profile on WS-ACC-4477, the copy Outlook makes when an attachment is opened from a message. The SHA-256 equals the hash of the attachment delivered at 08:13.",
    }),

    // Edge, not a PDF reader, renders it.
    csProcess({
      companyId: CX, id: "aisvg5", ts: "2026-09-24T08:26:40.907Z", host: c.host, srcIp: c.ip, user: victim,
      processName: "msedge.exe", processPath: EDGE,
      cmdline: `"${EDGE}" --single-argument "${svgPath}"`,
      parentName: "OUTLOOK.EXE", parentPid: 5148, pid: 9236,
      extra: {
        ...csEnvelope("aisvg5"),
        "crowdstrike.UserSid": "S-1-5-21-3623811015-3361044348-30300820-1113",
        "crowdstrike.ImageSubsystem": "2",
        "host.name": c.host,
        "user.name": victim.split("@")[0],
        "user.domain": "NEXACORP",
        "event.category": "process",
        "event.type": "start",
        "event.created": ingested("2026-09-24T08:26:40.907Z", 2_100),
        "process.name": "msedge.exe",
        "process.pid": "9236",
        "process.executable": EDGE,
        "process.command_line": `"${EDGE}" --single-argument "${svgPath}"`,
        "process.parent.name": "OUTLOOK.EXE",
        "process.parent.pid": "5148",
      },
      sha256: makeSha256("aisvg_microsoft_edge_msedge_exe_141_clean"),
      signed: true, signatureSubject: "Microsoft Corporation", integrity: "medium",
      mitre: "T1204.002", tactic: "Execution", severity: "medium", incidentId: INC,
      description:
        "About two seconds later OUTLOOK.EXE started msedge.exe with the SVG as its only argument. The file opened in the browser, not in a PDF reader: an SVG is a web document that can carry script.",
    }),

    // The SVG sends the browser to a gate page.
    zia({
      id: "aisvg6", ts: "2026-09-24T08:26:47.213Z",
      url: `https://${gateHost}/r/Xq7Lp2Vt9`, domain: gateHost, method: "GET",
      category: "Newly Registered Domains", appName: "General Browsing", sent: 902, recv: 41_336, dstIp: gateIp,
      severity: "medium", mitre: "T1566.002", tactic: "Initial Access",
      description:
        `Six seconds after Edge opened the file, WS-ACC-4477 requested https://${gateHost}/r/Xq7Lp2Vt9 (${gateIp}). Zscaler categorised the domain as Newly Registered Domains and allowed it. The host had made no earlier request to this domain.`,
    }),

    // The CAPTCHA.
    zia({
      id: "aisvg7", ts: "2026-09-24T08:27:09.774Z",
      url: "https://challenges.cloudflare.com/turnstile/v0/api.js", domain: "challenges.cloudflare.com", method: "GET",
      category: "Internet Services", appName: "General Browsing", sent: 1_014, recv: 47_905,
      severity: "informational",
      description:
        "About 23 seconds later the page loaded the Cloudflare Turnstile script, the CAPTCHA that gates the next step. The destination is a legitimate CDN; what matters is that it was requested by the page on the newly registered domain.",
    }),

    // The credential page.
    zia({
      id: "aisvg8", ts: "2026-09-24T08:27:56.339Z",
      url: `https://${gateHost}/auth/signin?d=INV-20418`, domain: gateHost, method: "GET",
      category: "Newly Registered Domains", appName: "General Browsing", sent: 1_188, recv: 33_118, dstIp: gateIp,
      severity: "medium",
      description:
        `At 08:27, 47 seconds after the CAPTCHA script, the browser loaded https://${gateHost}/auth/signin?d=INV-20418, a sign-in page on the same newly registered domain.`,
    }),

    // The form is submitted.
    zia({
      id: "aisvg9", ts: "2026-09-24T08:28:44.126Z",
      url: `https://${gateHost}/api/session`, domain: gateHost, method: "POST", action: "allowed", status: 200,
      category: "Newly Registered Domains", appName: "General Browsing", sent: 3_214, recv: 204, dstIp: gateIp,
      severity: "high", mitre: "T1056", tactic: "Credential Access",
      description:
        `At 08:28 a 3.2 KB POST to https://${gateHost}/api/session was allowed: the submission of the sign-in form, about the size of a username, a password and some page metadata. Zscaler does not log the body.`,
    }),

    // A sign-in follows from the address that served the page; MFA holds.
    {
      ...entraSignIn({
        companyId: CX, id: "aisvg10", ts: "2026-09-24T08:29:12.583Z", srcIp: gateIp, user: victim,
        result: "failure", errorCode: "500121",
        app: "Office 365 Exchange Online", appId: "00000002-0000-0ff1-ce00-000000000000", resource: "Office 365 Exchange Online",
        mfa: true, isInteractive: true, managed: false, compliant: false, deviceId: "",
        os: "Windows 10", browser: "Chrome 126.0.0",
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        userId: "6b2f9d40-8e13-4c57-a1d6-3f0c7e8b5a92",
        correlationId: "d4a81c36-5f92-4e07-b3c8-2a9e6f1d7b40", sessionId: "c9e2a705-1f84-4b36-a927-6d0e5c3f819a",
        riskLevel: "none", conditionalAccess: "failure",
        severity: "high", mitre: "T1078.004", tactic: "Initial Access", incidentId: INC,
        extra: {
          "azure.signinlogs.resultDescription": "Authentication failed during strong authentication request.",
          "azure.signinlogs.properties.authenticationDetails": [
            { authenticationStepDateTime: "2026-09-24T08:29:11.940Z", authenticationMethod: "Password", authenticationMethodDetail: "Password in the cloud", succeeded: true, authenticationStepResultDetail: "Correct password", authenticationStepRequirement: "Primary authentication" },
            { authenticationStepDateTime: "2026-09-24T08:29:12.583Z", authenticationMethod: "Mobile app notification", authenticationMethodDetail: "Microsoft Authenticator", succeeded: false, authenticationStepResultDetail: "MFA denied; user did not respond to mobile app notification", authenticationStepRequirement: "Multifactor authentication" },
          ],
          "azure.signinlogs.properties.appliedConditionalAccessPolicies": signInPolicy,
        },
        description:
          `At 08:29, 28 seconds after the form POST, Entra ID logged a sign-in attempt for j.chen from ${gateIp} in Kyiv, the same address that served the page. The password step succeeded, but the multifactor step failed (500121) because no Authenticator prompt was approved, and Conditional Access blocked the session. The password is disclosed even though nobody got in.`,
      }),
      is_detection: true,
      edr_scope: "hybrid" as const,
    },

    // The mail product catches up after delivery.
    {
      id: "aisvg11", ts: "2026-09-24T08:33:51.077Z",
      source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_quarantined",
      severity: "medium", user_email: victim, incident_id: INC,
      description:
        "At 08:33 Defender for Office 365 removed the message from j.chen's mailbox after delivery (zero-hour auto purge, alert \"Email messages containing malicious file removed after delivery\"), 20 minutes after it arrived and about five minutes after the credentials were submitted. The removal came after the attachment had been opened and the form submitted.",
      raw: {
        "email.from.address": supplier,
        "email.subject": "Invoice INV-20418 - September freight services and remittance details",
        "email.message_id": lureInternetId,
        "email.attachments.file.name": svgName,
        "email.attachments.file.hash.sha256": svgHash,
        "data.office365.ActionType": "Moved to quarantine",
        "data.office365.ActionTrigger": "ZAP",
        "data.office365.ActionResult": "Success",
        "data.office365.DeliveryLocation": "Quarantine",
        "data.office365.ThreatTypes": "Phish",
        "data.office365.NetworkMessageId": "e94b06d1-2f73-4a8c-9c15-7b30a1d8f462",
        "data.office365.InternetMessageId": lureInternetId,
        "data.office365.MailboxOwnerUPN": victim,
        "data.office365.Subject": "Invoice INV-20418 - September freight services and remittance details",
        "data.office365.Sender": supplier,
        "data.office365.AttachmentName": svgName,
        "data.office365.AttachmentSha256": svgHash,
        "email.from.display_name": supplierName,
        "email.sender.address": supplier,
        "email.to.address": victim,
        "email.direction": "inbound",
        "data.office365.CreationTime": "2026-09-24T08:33:51.077Z",
        "data.office365.Workload": "Exchange",
        "data.office365.Directionality": "Inbound",
        "data.office365.SenderIp": eopIp,
        "data.office365.SenderFromDomain": "brightwaterfreight.co.uk",
        "data.office365.RecipientEmailAddress": victim,
        "data.office365.AttachmentCount": "1",
        "action_result": "quarantined",
      },
    },
  ];

  for (const e of events) e.incident_id = INC;
  return events;
}

// ── Registry ──────────────────────────────────────────────────────────────────────────

export const AI_FOUNDATION_STORIES: AiStoryDef[] = [
  {
    id: "ai-shadow-chat-upload",
    title: "Shadow AI — Customer List Uploaded to a Personal Chatbot Account",
    complexity: "foundation",
    companies: ["nexacorp", "globallogis", "quantumbank"],
    events: buildShadowChatUpload(),
  },
  {
    id: "ai-chat-harvest-extension",
    title: "Popular Free VPN Extension Starts Copying AI Chat Conversations",
    complexity: "foundation",
    companies: ["nexacorp", "medcore", "globallogis", "quantumbank"],
    events: buildChatHarvestExtension(),
  },
  {
    id: "ai-svg-invoice-lure",
    title: "Invoice SVG Posing as a PDF — Credential Page After a CAPTCHA",
    complexity: "foundation",
    companies: ["nexacorp", "medcore", "globallogis"],
    events: buildSvgInvoiceLure(),
  },
];
