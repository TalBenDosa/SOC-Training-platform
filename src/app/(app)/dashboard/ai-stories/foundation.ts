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
 *  1. ai-shadow-chat-upload      Zscaler ZIA + EDR   (a DLP-blocked spreadsheet pasted into an unsanctioned chatbot)
 *  2. ai-chat-harvest-extension  Zscaler ZIA + EDR + DNS + Sentinel TI   (a free extension update copies AI chats)
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
import { csFile, csProcess, csNetwork } from "@/lib/sim/emitters/crowdstrike";
import { entraSignIn } from "@/lib/sim/emitters/entra";
import { sentinelAlert } from "@/lib/sim/emitters/sentinel";

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
const CS_CID = "a214f4f4fa1ab768a188dd17a1c89e85";
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

/** Zscaler URL category of generative-AI destinations. */
const GENAI_CATEGORY = "Generative AI and ML Applications";

/** A file event carrying the file's MD5 too (the hash a proxy logs for the same file). */
const withMd5 = (ev: TelemetryEvent, md5: string): TelemetryEvent =>
  ({ ...ev, file: { ...(ev.file ?? { path: "" }), md5 }, raw: { ...ev.raw, "crowdstrike.MD5HashData": md5 } });

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
  const xlsxPath = `C:\\Users\\a.kaplan\\Downloads\\${xlsxName}`;
  const xlsxHash = makeSha256("aishd_customer_contacts_q3_master_xlsx_2026");
  const xlsxMd5 = makeSha256("aishd_customer_contacts_q3_master_xlsx_md5").slice(0, 32);
  const XLSX_SIZE = 2_418_944;
  // The CRM report export the spreadsheet came from (Mark-of-the-Web origin on the download).
  const crmExportUrl = "https://eu47.salesforce.com/00O5g000004XyZ1EAK?export=1&enc=UTF-8&xf=xlsx";
  const CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
  const EXCEL = "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE";
  const DS = "chat.deepseek.com";
  const deepseek = { category: GENAI_CATEGORY, appName: "DeepSeek" };
  // The prompt rule only monitors: the DLP engine scans the request body and the transaction is allowed.
  const promptDlp = { "zscaler.activity": "Chat", "zscaler.dlpeng": "PII", "zscaler.dlpdict": "Email Addresses", ...aiApp("Unsanctioned") };

  const events: TelemetryEvent[] = [
    // Reference point: the company's approved AI assistant.
    zia({
      id: "aishd1", ts: "2026-09-22T08:41:17.336Z",
      url: "https://chatgpt.com/backend-api/conversation", domain: "chatgpt.com", method: "POST",
      category: GENAI_CATEGORY, appName: "ChatGPT", sent: 968, recv: 5_412, severity: "informational",
      description:
        "At 08:41 a.kaplan's browser on WS-SALES-1876 posted a 968-byte request to chatgpt.com (appname ChatGPT, the company's approved AI assistant). This is the user's usual AI traffic before the later sessions.",
      extra: {
        ...aiApp("Sanctioned"),
        "zscaler.prompt_req": "give me three subject lines for the Q4 partner newsletter",
      },
      top: { ...baseline },
    }),

    // A CRM report export lands on disk.
    withMd5(csFile({
      companyId: CX, id: "aishd2", ts: "2026-09-22T09:22:46.581Z", host: c.host, srcIp: c.ip, user: c.user,
      extra: {
        ...csFileExtra({
          id: "aishd2", ts: "2026-09-22T09:22:46.581Z", host: c.host, user: c.user, path: xlsxPath, type: "creation",
          actor: "chrome.exe", actorPid: 6204, actorPath: CHROME, actorParent: "explorer.exe", actorParentPid: 3844,
        }),
        "file.origin_url": crmExportUrl,
        "file.origin_referrer_url": "https://eu47.salesforce.com/00O5g000004XyZ1EAK",
      },
      path: xlsxPath, sha256: xlsxHash, size: XLSX_SIZE, action: "file_create",
      actorProcess: "chrome.exe", actorPid: 6204, actorPath: CHROME,
      actorParentName: "explorer.exe", actorParentPid: 3844, actorSigned: "trusted", actorIntegrity: "medium",
      severity: "low", mitre: "T1213", tactic: "Collection", incidentId: INC,
      description:
        `At 09:22 chrome.exe wrote ${xlsxName} (2.3 MB) into a.kaplan's Downloads folder on WS-SALES-1876. FileOriginUrl is a Salesforce report export (export=1, xf=xlsx).`,
    }), xlsxMd5),

    // First contact with an AI service that is not the approved one.
    zia({
      id: "aishd3", ts: "2026-09-22T09:30:08.127Z",
      url: `https://${DS}/api/v0/users/login`, domain: DS, method: "POST",
      ...deepseek, sent: 1_142, recv: 2_918, severity: "low",
      description:
        `At 09:30 the same browser posted to https://${DS}/api/v0/users/login (appname DeepSeek). It is the first request from WS-SALES-1876 to that host in these logs; the company has no DeepSeek tenant, so any account signed in here is a personal one.`,
      extra: { ...aiApp("Unsanctioned") },
    }),

    // DLP stops the spreadsheet — the first alert.
    {
      ...zia({
        id: "aishd4", ts: "2026-09-22T09:33:54.640Z",
        url: `https://${DS}/api/v0/file/upload_file`, domain: DS, method: "POST", action: "blocked", status: 403,
        ...deepseek, sent: 2_419_377, recv: 312,
        severity: "medium", mitre: "T1567", tactic: "Exfiltration",
        description:
          `At 09:33 Zscaler blocked a 2.4 MB POST to ${DS}/api/v0/file/upload_file (reason Blocked by DLP, filetype Microsoft Excel, dlpengine PII, dlpdictionaries Credit Cards and Email Addresses). The md5 in the record is the md5 of ${xlsxName} written at 09:22.`,
        extra: {
          ...aiApp("Unsanctioned"),
          "zscaler.activity": "Upload",
          "zscaler.upload_filename": xlsxName,
          "zscaler.upload_filetype": "xlsx",
          "zscaler.ruletype": "Data Loss Prevention",
          "zscaler.rulelabel": "GenAI-DLP-Block-Files",
          "zscaler.dlpeng": "PII",
          "zscaler.dlpdict": "Credit Cards|Email Addresses",
          "zscaler.dlpdicthitcount": "9|1204",
          "zscaler.trig_dlprulename": "Block PII to GenAI (Files)",
        },
        top: { is_detection: true, edr_scope: "hybrid" },
      }),
      file: { name: xlsxName, path: xlsxPath, md5: xlsxMd5, size: XLSX_SIZE, extension: "xlsx" },
    },

    // The blocked file is opened locally.
    csProcess({
      companyId: CX, id: "aishd5", ts: "2026-09-22T09:34:41.905Z", host: c.host, srcIp: c.ip, user: c.user,
      processName: "EXCEL.EXE", processPath: EXCEL,
      cmdline: `"${EXCEL}" "${xlsxPath}"`,
      parentName: "explorer.exe", parentPid: 3844, pid: 7284,
      extra: {
        ...csEnvelope("aishd5"),
        "host.name": c.host,
        "user.name": "a.kaplan",
        "event.category": "process",
        "event.type": "start",
        "event.created": ingested("2026-09-22T09:34:41.905Z", 2_200),
        "process.name": "EXCEL.EXE",
        "process.pid": "7284",
        "process.executable": EXCEL,
        "process.command_line": `"${EXCEL}" "${xlsxPath}"`,
        "process.parent.name": "explorer.exe",
        "process.parent.pid": "3844",
      },
      sha256: makeSha256("aishd_excel_exe_16_0_clean"),
      signed: true, signatureSubject: "Microsoft Corporation", integrity: "medium",
      mitre: "T1005", tactic: "Collection", severity: "low", incidentId: INC,
      description:
        `At 09:34, 47 seconds after the block, explorer.exe started EXCEL.EXE with ${xlsxName} from Downloads as its argument on WS-SALES-1876.`,
    }),

    // Rows go in as prompt text instead of a file.
    zia({
      id: "aishd6", ts: "2026-09-22T09:36:12.318Z",
      url: `https://${DS}/api/v0/chat/completion`, domain: DS, method: "POST", action: "allowed", status: 200,
      ...deepseek, sent: 64_218, recv: 7_904,
      severity: "high", mitre: "T1567", tactic: "Exfiltration",
      description:
        `At 09:36 Zscaler allowed a 64 KB POST to ${DS}/api/v0/chat/completion, the prompt endpoint. The DLP engine scanned the body (dlpengine PII, dlpdictionaries Email Addresses) and the action is Allowed: the rule that blocked the file at 09:33 does not cover prompt text.`,
      extra: {
        ...promptDlp,
        "zscaler.prompt_req": "Here is our customer list (part 1 of 3) with account owners, contact emails and annual spend. Group the accounts by region and rank them by spend…",
      },
    }),
    zia({
      id: "aishd7", ts: "2026-09-22T09:38:05.752Z",
      url: `https://${DS}/api/v0/chat/completion`, domain: DS, method: "POST", action: "allowed", status: 200,
      ...deepseek, sent: 71_904, recv: 6_211,
      severity: "high", mitre: "T1567", tactic: "Exfiltration",
      description:
        `At 09:38 a second 72 KB POST to the same prompt endpoint was allowed with the same DLP result (dlpengine PII, dlpdictionaries Email Addresses).`,
      extra: {
        ...promptDlp,
        "zscaler.prompt_req": "Part 2 of 3 of the customer list, same columns…",
      },
    }),
    zia({
      id: "aishd8", ts: "2026-09-22T09:40:31.044Z",
      url: `https://${DS}/api/v0/chat/completion`, domain: DS, method: "POST", action: "allowed", status: 200,
      ...deepseek, sent: 58_377, recv: 11_486,
      severity: "high", mitre: "T1567", tactic: "Exfiltration",
      description:
        `At 09:40 a third 58 KB POST was allowed with the same DLP result. Between 09:36 and 09:40 the three prompt requests carried about 194 KB to ${DS}, each flagged by the PII engine and none blocked.`,
      extra: {
        ...promptDlp,
        "zscaler.prompt_req": "Part 3 of 3. Now write a personalised renewal email for each of the top 5 accounts by spend.",
      },
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
  const statsIp = "212.87.204.61";
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
      category: GENAI_CATEGORY, appName: "ChatGPT", sent: 1_204, recv: 4_880, severity: "informational",
      description:
        "At 08:57 s.patel posted a 1.2 KB request to chatgpt.com (appname ChatGPT, the company's approved AI assistant) from WS-MKT-3301 and received 4.9 KB. This is the browser's traffic before the extension update.",
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
        `At 09:38 Chrome on WS-MKT-3301 downloaded a 1.8 MB extension package from the Chrome Web Store update host; the file name in the URL is ${extId}_5_5_0_0.crx (extension ID ${extId}, version 5.5.0).`,
      extra: { "data.http.content_type": "application/x-chrome-extension" },
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
        `At 09:38, about five seconds after the package download, chrome.exe wrote manifest.json into a new 5.5.0_0 folder under Extensions\\${extId} in s.patel's Chrome profile on WS-MKT-3301.`,
    }),

    // First lookup of the new name.
    {
      id: "aiext4", ts: "2026-09-23T09:39:58.207Z",
      source: "dns", vendor: "Infoblox DNS", event_type: "dns_query", severity: "low",
      hostname: c.host, user_email: c.user, src_ip: c.ip, dst_ip: "10.10.20.5", dst_port: 53, protocol: "udp",
      dns: { query: statsHost, query_type: "A", response: statsIp, rcode: "NOERROR" },
      network: { domain: statsHost },
      description:
        `At 09:39, 67 seconds after the new version was written, WS-MKT-3301 asked the internal DNS resolver for ${statsHost} and received one A record, ${statsIp}.`,
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
        `At 09:40 a 1.2 KB POST reached ${statsHost}/v2/events (${statsIp}) with ext=${extId}&ver=5.5.0 in the query string and was answered with 46 bytes. Zscaler had no category for the domain (Miscellaneous or Unknown) and allowed it. The ext value is the extension ID of the folder written at 09:38.`,
      extra: {},
    }),

    // The threat-intelligence match on that lookup — the first alert.
    {
      ...sentinelAlert({
        companyId: CX, id: "aiext10", ts: "2026-09-23T09:46:20.000Z", host: c.host, user: c.user, srcIp: c.ip, incidentId: INC,
        alertName: "TI map Domain entity to DnsEvents",
        ruleId: "85aca4d1-5d15-4001-abd9-acb86ca1786a",
        detail: "Identifies a match in DNS events from any Domain IOC from threat intelligence.",
        severity: "medium", eventType: "threat_intel_match", mitre: "T1176", tactic: "Persistence",
        extendedProperties: {
          DomainName: statsHost,
          ClientIP: c.ip,
          Computer: c.host,
          DnsQueryTime: "2026-09-23T09:39:58.207Z",
          IndicatorId: "indicator--6e1b9c42-7f30-4d8a-a5c2-0b93e4f17d58",
          ThreatType: "malicious-activity",
          ConfidenceScore: 80,
          IndicatorDescription: "Collection endpoint contacted by the SurfGuard VPN browser extension from version 5.5.0 (extension ID hkgmfnpelcbjoadkdanmghcplobjhegk)",
          IndicatorFirstSeen: "2026-09-23T06:12:00Z",
          SourceSystem: "Microsoft Defender Threat Intelligence",
        },
        description:
          `Microsoft Sentinel raised TI map Domain entity to DnsEvents at 09:46: the 09:39 lookup of ${statsHost} by WS-MKT-3301 matched a threat-intelligence domain indicator (confidence 80) whose description names the SurfGuard VPN extension 5.5.0 and the extension ID seen in the profile folder.`,
      }),
      is_detection: true,
      edr_scope: "hybrid" as const,
    },

    // Chat 1: a normal prompt to the sanctioned workspace.
    zia({
      id: "aiext6", ts: "2026-09-23T09:52:14.719Z",
      url: "https://chatgpt.com/backend-api/conversation", domain: "chatgpt.com", method: "POST",
      category: GENAI_CATEGORY, appName: "ChatGPT", sent: 1_412, recv: 6_204, severity: "informational",
      description:
        "At 09:52 s.patel sent a 1,412-byte request to the approved ChatGPT workspace and received a 6,204-byte answer.",
      extra: {
        ...aiApp("Sanctioned"),
        "zscaler.prompt_req":
          "Rewrite this paragraph from our Q4 launch announcement so it sounds more confident, keep it under 90 words: Our new Atlas analytics tier ships on 11 November and we are pricing it 18% below Meridian to win the mid-market accounts.",
      },
    }),

    // ...and a POST of matching size goes to the extension's domain.
    zia({
      id: "aiext7", ts: "2026-09-23T09:52:24.318Z",
      url: statsUrl, domain: statsHost, method: "POST", action: "allowed", status: 200,
      category: "Miscellaneous or Unknown", appName: "General Browsing", sent: 8_004, recv: 46, dstIp: statsIp,
      severity: "high", mitre: "T1041", tactic: "Exfiltration",
      description:
        `About ten seconds after that request, an 8,004-byte POST went to ${statsHost}/v2/events with the same ext and ver parameters: about the size of the prompt and the answer together (1,412 + 6,204 bytes plus roughly 390 bytes).`,
      top: { edr_scope: "edr" },
    }),

    // Chat 2: a long paste.
    zia({
      id: "aiext8", ts: "2026-09-23T10:31:40.885Z",
      url: "https://chatgpt.com/backend-api/conversation", domain: "chatgpt.com", method: "POST",
      category: GENAI_CATEGORY, appName: "ChatGPT", sent: 21_344, recv: 9_876, severity: "informational",
      description:
        "At 10:31 s.patel sent a 21,344-byte request to the approved ChatGPT workspace and received a 9,876-byte answer.",
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
        `About 17 seconds after the request, a 31,622-byte POST went to ${statsHost}/v2/events: again about the size of prompt plus answer (21,344 + 9,876 bytes plus roughly 400 bytes). The bytes sent to that domain track each chat exchange within seconds rather than following a fixed heartbeat.`,
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

  // Each recipient's copy of the lure has its own NetworkMessageId (one InternetMessageId).
  const lureNetworkId = "e94b06d1-2f73-4a8c-9c15-7b30a1d8f462";
  const secondNetworkId = "1a5d78c3-b902-47e6-8f4a-c60e93b2d517";
  const lureSubject = "Invoice INV-20418 - September freight services and remittance details";

  // The EmailAttachmentInfo companion of j.chen's copy: same message, so the same ids and time.
  const attRow = mail({
    id: "aisvg12", ts: "2026-09-24T08:13:22.317Z", rcpt: victim, headerTo: supplier,
    subject: lureSubject, internetId: lureInternetId, networkId: lureNetworkId,
    attName: svgName, attMime: "image/svg+xml", attExt: "svg", attSize: svgSize, attHash: svgHash,
    clientIp: lureClientIp, scl: "1", severity: "low",
    description:
      "The attachment row of j.chen's copy of the lure (same NetworkMessageId): FileName 'Invoice_INV-20418 - PDF - 4 pages.svg', FileType svg, 12,846 bytes, with its SHA256. The name says PDF; the file is an SVG, a web document that can carry script.",
    top: { mitre_technique: "T1566.001", mitre_tactic: "Initial Access" },
  });

  // Zero-hour auto purge of one recipient's copy (Defender EmailPostDeliveryEvents).
  const zapRow = (id: string, ts: string, rcpt: string, networkId: string, description: string): TelemetryEvent => ({
    id, ts, source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_quarantined",
    severity: "medium", user_email: rcpt, incident_id: INC, description,
    raw: {
      "email.from.address": supplier,
      "email.from.display_name": supplierName,
      "email.sender.address": supplier,
      "email.to.address": rcpt,
      "email.direction": "inbound",
      "email.subject": lureSubject,
      "email.message_id": lureInternetId,
      "email.attachments.file.name": svgName,
      "email.attachments.file.hash.sha256": svgHash,
      "data.office365.ActionType": "Moved to quarantine",
      "data.office365.ActionTrigger": "ZAP",
      "data.office365.ActionResult": "Success",
      "data.office365.DeliveryLocation": "Quarantine",
      "data.office365.ThreatTypes": "Phish",
      "data.office365.DetectionMethods": "File detonation reputation",
      "data.office365.NetworkMessageId": networkId,
      "data.office365.InternetMessageId": lureInternetId,
      "data.office365.MailboxOwnerUPN": rcpt,
      "data.office365.RecipientEmailAddress": rcpt,
      "data.office365.Subject": lureSubject,
      "data.office365.Sender": supplier,
      "data.office365.SenderFromDomain": "brightwaterfreight.co.uk",
      "data.office365.SenderIp": eopIp,
      "data.office365.AttachmentName": svgName,
      "data.office365.AttachmentSha256": svgHash,
      "data.office365.AttachmentCount": "1",
      "data.office365.CreationTime": ts,
      "data.office365.Workload": "Exchange",
      "data.office365.Directionality": "Inbound",
      "action_result": "quarantined",
    },
  });

  const events: TelemetryEvent[] = [
    // Reference point: this supplier's ordinary invoice mail, the day before.
    mail({
      id: "aisvg1", ts: "2026-09-23T14:06:12.480Z", rcpt: victim, headerTo: victim,
      subject: "Invoice INV-20377 - August freight services", internetId: baseInternetId,
      networkId: "3c7a91f2-58d4-4e06-b1a9-0d2e6f47c815",
      attName: pdfName, attMime: "application/pdf", attExt: "pdf", attSize: pdfSize, attHash: pdfHash,
      clientIp: usualClientIp, scl: "0", severity: "informational",
      description:
        "On Wednesday afternoon d.holloway of Brightwater Freight, an existing supplier, sent j.chen invoice INV-20377 as a PDF (145 KB). SPF, DKIM and DMARC passed and the To header is j.chen. This is the sender's normal pattern.",
      top: { ...baseline },
    }),

    // The lure, delivered to the victim.
    mail({
      id: "aisvg2", ts: "2026-09-24T08:13:22.317Z", rcpt: victim, headerTo: supplier,
      subject: "Invoice INV-20418 - September freight services and remittance details", internetId: lureInternetId,
      networkId: lureNetworkId,
      attName: svgName, attMime: "image/svg+xml", attExt: "svg", attSize: svgSize, attHash: svgHash,
      clientIp: lureClientIp, scl: "1", severity: "low",
      description:
        "At 08:13 a message from the same supplier mailbox reached j.chen with one attachment. SPF, DKIM and DMARC passed and it was delivered to the inbox with SCL 1, but the To header names d.holloway himself while the recipient is j.chen, so the real recipients were hidden (Bcc).",
      top: { mitre_technique: "T1566.001", mitre_tactic: "Initial Access" },
    }),

    // The attachment of that message (Defender's EmailAttachmentInfo row: name, type and hash).
    // (EmailAttachmentInfo has no sender-IP column, so the row carries no src_ip.)
    { ...attRow, src_ip: undefined, raw: { ...attRow.raw, category: "AdvancedHunting-EmailAttachmentInfo" } },

    // Same message, second hidden recipient.
    mail({
      id: "aisvg3", ts: "2026-09-24T08:13:25.041Z", rcpt: second, headerTo: supplier,
      subject: "Invoice INV-20418 - September freight services and remittance details", internetId: lureInternetId,
      networkId: secondNetworkId,
      attName: svgName, attMime: "image/svg+xml", attExt: "svg", attSize: svgSize, attHash: svgHash,
      clientIp: lureClientIp, scl: "1", severity: "low",
      description:
        "Under three seconds later the same message (identical InternetMessageId) was delivered to p.whitfield, again with d.holloway in the To header. One message reached both mailboxes as hidden recipients.",
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
        "At 08:26 OUTLOOK.EXE wrote 'Invoice_INV-20418 - PDF - 4 pages.svg' into the INetCache\\Content.Outlook folder in j.chen's profile on WS-ACC-4477, the copy Outlook makes when an attachment is opened from a message. The SHA256 equals the attachment hash of the lure delivered at 08:13.",
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
        "About two seconds later OUTLOOK.EXE started msedge.exe with the cached SVG as its only argument, so the file opened in the browser rather than in a PDF reader.",
    }),

    // That Edge process connects out.
    csNetwork({
      companyId: CX, id: "aisvg13", ts: "2026-09-24T08:26:46.871Z", host: c.host, srcIp: c.ip, user: victim,
      remoteIp: gateIp, remotePort: 443, domain: gateHost,
      processName: "msedge.exe", processPath: EDGE, pid: 9236, parentName: "OUTLOOK.EXE", parentPid: 5148,
      cmdline: `"${EDGE}" --single-argument "${svgPath}"`,
      extra: csEnvelope("aisvg13"),
      mitre: "T1204.002", tactic: "Execution", severity: "medium", incidentId: INC,
      description:
        `Six seconds after it started, the msedge.exe process opened with the SVG (parent OUTLOOK.EXE) connected to ${gateIp}:443 (${gateHost}).`,
    }),

    // The SVG sends the browser to a gate page.
    zia({
      id: "aisvg6", ts: "2026-09-24T08:26:47.213Z",
      url: `https://${gateHost}/r/Xq7Lp2Vt9`, domain: gateHost, method: "GET",
      category: "Newly Registered Domains", appName: "General Browsing", sent: 902, recv: 41_336, dstIp: gateIp,
      severity: "medium", mitre: "T1566.002", tactic: "Initial Access",
      description:
        `At 08:26 WS-ACC-4477 requested https://${gateHost}/r/Xq7Lp2Vt9 (${gateIp}) with no referer. Zscaler categorised the domain as Newly Registered Domains and allowed it. The host had made no earlier request to this domain.`,
    }),

    // The CAPTCHA.
    zia({
      id: "aisvg7", ts: "2026-09-24T08:27:09.774Z",
      url: "https://challenges.cloudflare.com/turnstile/v0/api.js", domain: "challenges.cloudflare.com", method: "GET",
      category: "Internet Services", appName: "General Browsing", sent: 1_014, recv: 47_905,
      severity: "informational",
      description:
        `About 23 seconds later the browser loaded the Cloudflare Turnstile CAPTCHA script; refererURL is the page on ${gateHost}. The destination itself is a legitimate CDN.`,
      extra: { "zscaler.referer": `https://${gateHost}/r/Xq7Lp2Vt9`, "data.http.content_type": "application/javascript" },
    }),

    // The credential page.
    zia({
      id: "aisvg8", ts: "2026-09-24T08:27:56.339Z",
      url: `https://${gateHost}/auth/signin?d=INV-20418`, domain: gateHost, method: "GET",
      category: "Newly Registered Domains", appName: "General Browsing", sent: 1_188, recv: 33_118, dstIp: gateIp,
      severity: "medium",
      description:
        `At 08:27, 47 seconds after the CAPTCHA script, the browser loaded https://${gateHost}/auth/signin?d=INV-20418, a sign-in page on the same newly registered domain.`,
      extra: { "zscaler.referer": `https://${gateHost}/r/Xq7Lp2Vt9` },
    }),

    // The form is submitted.
    zia({
      id: "aisvg9", ts: "2026-09-24T08:28:44.126Z",
      url: `https://${gateHost}/api/session`, domain: gateHost, method: "POST", action: "allowed", status: 200,
      category: "Newly Registered Domains", appName: "General Browsing", sent: 3_214, recv: 204, dstIp: gateIp,
      severity: "high", mitre: "T1598.003", tactic: "Reconnaissance",
      description:
        `At 08:28 a 3.2 KB POST from the sign-in page to https://${gateHost}/api/session was allowed: about the size of a username, a password and some page metadata. Zscaler does not log the body.`,
      extra: { "zscaler.referer": `https://${gateHost}/auth/signin?d=INV-20418` },
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
        riskLevel: "medium", riskDetail: "none", riskEventTypes: ["unfamiliarFeatures"], conditionalAccess: "failure",
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
          `At 08:29, 28 seconds after the form POST, Entra ID logged a sign-in attempt for j.chen from ${gateIp} (Kyiv), the address that served the sign-in page. Identity Protection rated it medium risk (unfamiliarFeatures). The password step succeeded ("Correct password"); the Authenticator step was not approved (500121) and Conditional Access did not grant the session.`,
      }),
      is_detection: true,
      edr_scope: "hybrid" as const,
    },

    // The mail product catches up after delivery.
    zapRow("aisvg11", "2026-09-24T08:33:51.077Z", victim, lureNetworkId,
      "At 08:33 zero-hour auto purge moved the lure delivered at 08:13 (same NetworkMessageId) from j.chen's inbox to quarantine (Phish ZAP), 20 minutes after delivery and about five minutes after the 08:28 form POST."),
    zapRow("aisvg14", "2026-09-24T08:33:52.410Z", second, secondNetworkId,
      "One second later the same purge moved p.whitfield's copy of the message to quarantine (Phish ZAP, same InternetMessageId)."),
  ];

  for (const e of events) e.incident_id = INC;
  return events;
}

// ── Registry ──────────────────────────────────────────────────────────────────────────

export const AI_FOUNDATION_STORIES: AiStoryDef[] = [
  {
    id: "ai-shadow-chat-upload",
    title: "Shadow AI — Customer List Pasted into an Unsanctioned Chatbot After a DLP Block",
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
