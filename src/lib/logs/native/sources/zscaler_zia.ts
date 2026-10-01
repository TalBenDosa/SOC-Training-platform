/**
 * Zscaler Internet Access (ZIA) — NSS Web log, Zscaler-published Splunk JSON feed template.
 * Card: docs/log-schemas/proxy-zscaler-zia.md
 *
 * JSON-native once the template is fixed: `{"sourcetype":"zscalernss-web","event":{…}}`,
 * every value a string, "empty" rendered as the literal "None" (card §6). `url` carries no
 * scheme; `refererURL` keeps it.
 *
 * Renders every platform proxy event — Zscaler-authored (legacy zscaler.* raw keys),
 * Palo Alto URL-filtering-authored (pan.* / url.*), and Squid-authored (data.http.*) — as the
 * ZIA web transaction. Returns null when ZIA would never see the transaction:
 *   - inbound internet traffic to the company (unauthenticated public client, e.g. WAF / OWA
 *     brute-force events): ZIA is a FORWARD proxy for the company's own users;
 *   - east-west traffic to internal hosts (*.local, RFC1918 destinations), which never leaves
 *     for the Zscaler cloud;
 *   - events with no destination host at all (nothing to put in url/hostname).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { company, identity, emailDomain, isIPv4, isPrivateIp, rawStr, rawNum, testNetIp, digits } from "./remote-access-shared";

export const ZIA_EVENT_KEYS = [
  "datetime", "reason", "event_id", "protocol", "action", "transactionsize", "responsesize", "requestsize", "urlcategory",
  "serverip", "clienttranstime", "requestmethod", "refererURL", "useragent", "product", "location", "ClientIP", "status",
  "user", "url", "vendor", "hostname", "clientpublicIP", "threatcategory", "threatname", "filetype", "appname", "pagerisk",
  "department", "urlsupercategory", "appclass", "dlpengine", "urlclass", "threatclass", "dlpdictionaries", "fileclass",
  "bwthrottle", "servertranstime", "contenttype", "ssldecrypted", "unscannabletype", "md5", "deviceowner", "devicehostname",
];

const schema: SourceSchema = {
  sourceId: "zscaler_zia",
  category: "proxy",
  card: "proxy-zscaler-zia.md",
  product: "Zscaler Internet Access",
  format: "json",
  vendorMatch: ["zscaler internet access", "zscaler zia", "zia"],
  telemetrySources: ["proxy"],
  kinds: { web: { required: ["sourcetype", ...ZIA_EVENT_KEYS.map(k => `event.${k}`)], optional: [] } },
};

export function kindOf(record: Record<string, unknown>): string | null {
  return record.sourcetype === "zscalernss-web" && record.event && typeof record.event === "object" ? "web" : null;
}

// ── Vocabulary tables (labels the card marks UNVERIFIED are used as the card shows them) ──

const NRD = ["Newly Registered and Observed Domains", "Newly Registered Domains"];
const FILE_SHARING_CATS = ["File Host", "Online and Cloud Storage", "Personal Cloud Storage"];
const GENAI_CAT = "Generative AI and ML Applications";

const CATEGORY: Record<string, [string, string]> = {
  "Newly Registered and Observed Domains": ["Miscellaneous", "Security Risk"],
  "Newly Registered Domains": ["Miscellaneous", "Security Risk"],
  "Miscellaneous or Unknown": ["Miscellaneous", "General Surfing"],
  "Other Suspicious Destination": ["Security", "Advanced Security Risk"],
  [GENAI_CAT]: ["Information Technology", "Business Use"],
  "Internet Services": ["Information Technology", "Business Use"],
  "Web Search": ["Information Technology", "Business Use"],
  "Professional Services": ["Business and Economy", "Business Use"],
  "Corporate Marketing": ["Business and Economy", "Business Use"],
  Finance: ["Business and Economy", "Business Use"],
  "News and Media": ["News and Media", "General Surfing"],
  "Social Networking": ["Social Networking", "Productivity Loss"],
  "Job Search": ["Job/Employment Search", "Productivity Loss"],
  "Webmail - Personal": ["Internet Communication", "General Surfing"],
  "Web Conferencing": ["Internet Communication", "Business Use"],
  "File Host": ["Internet Communication", "Bandwidth Loss"],
  "Online and Cloud Storage": ["Internet Communication", "Bandwidth Loss"],
  "Personal Cloud Storage": ["Internet Communication", "Bandwidth Loss"],
};
/** Non-ZIA category spellings found in authored events (PAN URL categories, legacy labels) → ZIA category. */
const CATEGORY_ALIAS: Record<string, string> = {
  news: "News and Media", "computer-and-internet-info": "Internet Services", "business-and-economy": "Professional Services",
  "social-networking": "Social Networking", "financial-services": "Finance", "Banking/Finance": "Finance",
  "Financial-Services": "Finance", Uncategorized: "Miscellaneous or Unknown", "unknown": "Miscellaneous or Unknown",
};
const PAN_APP: Record<string, string> = {
  "web-browsing": "General Browsing", ssl: "General Browsing", npm: "General Browsing", docusign: "DocuSign",
  "atlassian-jira": "Jira", servicenow: "ServiceNow", github: "GitHub", linkedin: "LinkedIn", intercom: "Intercom",
};
const APP_CLASS: Record<string, string> = {
  "General Browsing": "General Browsing", ChatGPT: "AI & ML Applications", Claude: "AI & ML Applications", "Google Gemini": "AI & ML Applications",
  WeTransfer: "File Sharing", Dropbox: "File Sharing", "Google Drive": "File Sharing", "Google Cloud Storage": "File Sharing",
  LinkedIn: "Social Networking", "Microsoft Teams": "Collaboration & Online Meetings", "Microsoft Office 365": "Business Productivity",
};
const HOST_APP: [RegExp, string, string?][] = [
  [/(^|\.)chatgpt\.com$|(^|\.)openai\.com$/, "ChatGPT", GENAI_CAT],
  [/(^|\.)claude\.ai$/, "Claude", GENAI_CAT],
  [/^gemini\.google\.com$/, "Google Gemini", GENAI_CAT],
  [/(^|\.)wetransfer\.com$/, "WeTransfer", "File Host"],
  [/(^|\.)dropbox(usercontent)?\.com$/, "Dropbox", "Online and Cloud Storage"],
  [/^drive\.google\.com$/, "Google Drive", "Online and Cloud Storage"],
  [/^transfer\.sh$/, "General Browsing", "File Host"],
];
const EXT: Record<string, [string, string, string]> = {
  exe: ["Windows Executables", "Executable", "application/octet-stream"],
  dll: ["Windows Executables", "Executable", "application/octet-stream"],
  msi: ["Windows Executables", "Executable", "application/octet-stream"],
  zip: ["ZIP Files", "Archive", "application/zip"],
  gz: ["GZIP Files", "Archive", "application/gzip"],
  "7z": ["7-Zip Files", "Archive", "application/x-7z-compressed"],
  xlsx: ["Microsoft Excel", "Document", "multipart/form-data"],
  csv: ["CSV Files", "Document", "multipart/form-data"],
  pdf: ["PDF Documents", "Document", "application/pdf"],
  docx: ["Microsoft Word", "Document", "multipart/form-data"],
};
const DEPT_BY_HOST: [RegExp, string][] = [
  [/-FIN-/i, "Finance"], [/-HR-/i, "HR"], [/-SALES-/i, "Sales"], [/-MKT-/i, "Marketing"], [/-ACC-/i, "Accounting"],
  [/-(ENG|DEV)-/i, "Engineering"], [/-IT-/i, "IT"], [/-RISK-/i, "Risk"], [/-LEGAL-/i, "Legal"],
];
const HQ: Record<string, string> = { nexacorp: "London-HQ", medcore: "Amsterdam-HQ", globallogis: "Hamburg-HQ", quantumbank: "Zurich-HQ", rocketstack: "SF-HQ" };
/** Company application hosts for authored events that logged only a URL path (e.g. "/swift/api/v3/transfers"). */
const APP_HOST: Record<string, string> = { quantumbank: "corebanking.quantumbank.ch" };
const CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";

const stripScheme = (u: string) => u.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
function hostOf(u: string | undefined): string | undefined {
  if (!u) return undefined;
  const m = /^(?:[a-z][a-z0-9+.-]*:\/\/)?([^/?#:]+)/i.exec(u);
  return m && !u.startsWith("/") ? m[1] : undefined;
}

interface Tx {
  url: string; host: string; scheme: "http" | "https"; method: string; status: string; blocked: boolean;
  req: number; resp: number; category: string; app: string; appClass: string; threat?: string; threatCat?: string;
  dlpEngine?: string; dlpDict?: string; ext?: string; srcIp?: string; cip?: string; serverIp?: string; referer?: string;
  ua?: string; contentType?: string; reasonRaw?: string; location?: string; department?: string; supercat?: string; urlclass?: string;
}

function transaction(ev: TelemetryEvent, ctx: NativeCtx): Tx | null {
  const id = identity(ev);
  const srcIp = [ev.src_ip, rawStr(ev, "source.ip", "zscaler.cip", "pan.src")].find(isIPv4);
  // Inbound internet client with no authenticated user: not a forward-proxy transaction.
  if (!id.email && !rawStr(ev, "zscaler.login") && srcIp && !isPrivateIp(srcIp)) return null;

  let full = ev.network?.url ?? rawStr(ev, "zscaler.url", "url.full", "data.http.url", "http.url", "pan.misc", "network.url");
  const rawDomain = ev.network?.domain ?? rawStr(ev, "zscaler.hostname", "url.domain", "destination.domain");
  if (!full && rawDomain) {
    const path = rawStr(ev, "url.path") ?? "/";
    const q = rawStr(ev, "url.query");
    full = `https://${rawDomain}${path}${q ? `?${q}` : ""}`;
  }
  if (full && full.startsWith("/")) {
    const h = rawDomain ?? APP_HOST[ctx.companyId];
    if (!h) return null;
    full = `https://${h}${full}`;
  }
  if (!full) {
    // Last resort: the analyst-facing description names the destination (e.g. "upload … to transfer.sh").
    const m = /\b((?:[a-z0-9-]+\.)+(?:sh|biz|com|net|io|org|top|online|xyz|info|ru|cn))\b/i.exec(ev.description ?? "");
    if (!m || m[1].includes("@")) return null;
    full = `https://${m[1]}/`;
  }
  const host = rawDomain ?? hostOf(full);
  if (!host) return null;
  const dst = ev.dst_ip ?? rawStr(ev, "pan.dst", "destination.ip");
  if (/\.local$/i.test(host) || (isIPv4(host) && isPrivateIp(host)) || (dst && isIPv4(dst) && isPrivateIp(dst))) return null; // east-west

  const scheme = /^http:\/\//i.test(full) || ev.dst_port === 80 ? "http" : "https";
  const blocked = rawStr(ev, "zscaler.action") === "Blocked" || /^(block|deny|drop|reset)/i.test(rawStr(ev, "pan.action") ?? "")
    || /^(blocked|deny)$/i.test(rawStr(ev, "action_result") ?? "") || rawStr(ev, "session.blocked") === "true"
    || ev.event_type === "http_blocked" || ev.event_type === "net_blocked";
  const dlpHint = /dlp/i.test(`${rawStr(ev, "zscaler.dlp_scan", "zscaler.dlpeng", "zscaler.reason", "policy.name") ?? ""}`) || (!!rawStr(ev, "zscaler.dlp_scan") && rawStr(ev, "zscaler.dlp_scan") !== "no_violation");
  // A DLP verdict is only ever produced for content leaving the client: an authored DLP event without a method is an upload.
  const method = (ev.network?.method ?? rawStr(ev, "zscaler.reqmethod", "http.request.method", "http.method", "data.http.method") ?? (dlpHint ? "POST" : "GET")).toUpperCase();
  const status = String(ev.network?.status ?? rawStr(ev, "zscaler.respcode", "http.response.status_code", "http.status", "data.http.response.code") ?? (blocked ? 403 : 200));

  const hostApp = HOST_APP.find(([re]) => re.test(host));
  const authoredCat = rawStr(ev, "zscaler.urlcategory", "zscaler.category", "url.category", "pan.url.category", "pan.category");
  const category = authoredCat ? (CATEGORY[authoredCat] ? authoredCat : CATEGORY_ALIAS[authoredCat] ?? authoredCat) : hostApp?.[2] ?? "Miscellaneous or Unknown";
  const panApp = rawStr(ev, "pan.app");
  const app = rawStr(ev, "zscaler.appname") ?? hostApp?.[1] ?? (panApp ? PAN_APP[panApp] ?? panApp : undefined) ?? "General Browsing";
  const appClass = rawStr(ev, "zscaler.appclass") ?? (FILE_SHARING_CATS.includes(category) ? "File Sharing" : APP_CLASS[app] ?? "Business Productivity");

  const threatRaw = rawStr(ev, "zscaler.threatname", "pan.threat_name");
  const threat = threatRaw && threatRaw !== "None" ? threatRaw : undefined;
  const dlpScan = rawStr(ev, "zscaler.dlp_scan");
  const dlpSignal = !!rawStr(ev, "zscaler.dlpeng") && rawStr(ev, "zscaler.dlpeng") !== "None"
    || (!!dlpScan && dlpScan !== "no_violation") || /dlp/i.test(`${rawStr(ev, "zscaler.reason", "event.reason") ?? ""} ${rawStr(ev, "policy.name") ?? ""} ${rawStr(ev, "zscaler.ruletype") ?? ""}`);
  const dlpEngineRaw = rawStr(ev, "zscaler.dlpeng");
  const dlpEngine = dlpEngineRaw && dlpEngineRaw !== "None" ? dlpEngineRaw
    : dlpSignal ? (dlpScan && !/^(blocked|no_violation)$/.test(dlpScan) ? dlpScan.split("_").map(w => w[0].toUpperCase() + w.slice(1)).join(" ") : "Custom DLP Engine") : undefined;
  const dictRaw = rawStr(ev, "zscaler.dlpdict", "zscaler.dlp_dict_matches");
  const dlpDict = dictRaw && dictRaw !== "None" ? dictRaw : undefined;

  const fileName = rawStr(ev, "zscaler.upload_filename", "zscaler.filename") ?? ev.file?.name ?? stripScheme(full).split(/[?#]/)[0].split("/").pop();
  const extM = /\.([a-z0-9]{1,5})$/i.exec(fileName ?? "");
  const ext = (rawStr(ev, "zscaler.upload_filetype") ?? extM?.[1])?.toLowerCase();

  const req = rawNum(ev, "zscaler.reqsize") ?? ev.network?.bytes_out ?? rawNum(ev, "network.bytes_out")
    ?? (dlpHint ? ctx.int(`${ev.id}:zia-req`, 200_000, 5_000_000) : ctx.int(`${ev.id}:zia-req`, method === "GET" ? 400 : 1500, method === "GET" ? 2500 : 9000));
  const resp = rawNum(ev, "zscaler.respsize") ?? ev.network?.bytes_in ?? rawNum(ev, "data.http.response.bytes", "network.bytes_in", "network.bytes")
    ?? (blocked ? ctx.int(`${ev.id}:zia-resp`, 1200, 2400) : ctx.int(`${ev.id}:zia-resp`, 2000, 90000));

  return {
    url: stripScheme(full), host, scheme, method, status, blocked, req, resp, category, app, appClass, threat,
    threatCat: rawStr(ev, "zscaler.malwarecategory"), dlpEngine: dlpEngineRaw && dlpEngineRaw !== "None" ? dlpEngineRaw : blocked ? dlpEngine : undefined, dlpDict, ext,
    srcIp, cip: rawStr(ev, "zscaler.cip"), serverIp: [rawStr(ev, "zscaler.sip", "zscaler.serverip"), ev.dst_ip, rawStr(ev, "destination.ip")].find(isIPv4),
    referer: rawStr(ev, "zscaler.referer"), ua: ev.network?.user_agent ?? rawStr(ev, "zscaler.useragent", "http.user_agent", "user_agent"),
    contentType: rawStr(ev, "data.http.content_type"), reasonRaw: rawStr(ev, "zscaler.reason"),
    location: rawStr(ev, "zscaler.location"), department: rawStr(ev, "zscaler.department"),
    supercat: rawStr(ev, "zscaler.urlsupercategory"), urlclass: rawStr(ev, "zscaler.urlclass"),
  };
}

function build(ev: TelemetryEvent, ctx: NativeCtx): Record<string, unknown> | null {
  const t = transaction(ev, ctx);
  if (!t) return null;
  const id = identity(ev);
  const login = rawStr(ev, "zscaler.login");
  // Unauthenticated location traffic: the feed prints the template's empty value (UNVERIFIED for `user`).
  const user = id.email ?? (login ? (login.includes("@") ? login : `${login}@${emailDomain(ev, ctx)}`) : "None");
  const ms = Date.parse(ev.ts);
  const d = new Date(ms).toISOString();
  const clientIp = t.cip ?? t.srcIp ?? testNetIp(ctx, `${ctx.companyId}:zia-client:${user}`);
  const publicIp = t.srcIp && !isPrivateIp(t.srcIp) ? t.srcIp : testNetIp(ctx, `${ctx.companyId}:egress`);
  const roadWarrior = !isPrivateIp(clientIp);
  const [superDefault, classDefault] = CATEGORY[t.category] ?? ["Miscellaneous", "General Surfing"];
  const file = t.ext ? EXT[t.ext] : undefined;
  const dlpBlock = t.blocked && !!t.dlpEngine;
  const reason = !t.blocked ? "Allowed"
    : t.threat ? "Virus/Malware detected"
      : dlpBlock ? "Blocked by DLP"
        : t.reasonRaw && !/dlp/i.test(t.reasonRaw) ? t.reasonRaw : "Not allowed to browse this category";
  const host = ev.hostname ?? rawStr(ev, "source.hostname", "host.name");
  const dept = t.department ?? ev.user?.department ?? DEPT_BY_HOST.find(([re]) => re.test(host ?? ""))?.[1] ?? "None";
  const pagerisk = t.threat ? ctx.int(`${ev.id}:risk`, 85, 95) : NRD.includes(t.category) ? ctx.int(`${ev.id}:risk`, 55, 75)
    : t.category === "Miscellaneous or Unknown" ? ctx.int(`${ev.id}:risk`, 35, 60) : ctx.int(`${ev.id}:risk`, 0, 15);
  const ctimeMs = rawNum(ev, "zscaler.clienttranstime") ?? ctx.int(`${ev.id}:ctime`, 60, 900) + Math.floor(t.req / 4000);
  const contentType = t.contentType ?? (file && (t.method === "POST" || t.method === "PUT") ? (file[1] === "Document" ? "multipart/form-data" : "application/octet-stream")
    : file ? file[2] : /\/api\//.test(t.url) ? "application/json" : t.method === "POST" ? (t.req > 100_000 ? "application/octet-stream" : "application/x-www-form-urlencoded") : "text/html");
  const event: Record<string, string> = {
    datetime: `${d.slice(0, 10)} ${d.slice(11, 19)}`,
    reason,
    event_id: `7392018475561${digits(ctx, `${ev.id}:zia-recid`, 6)}`,
    protocol: t.scheme === "https" ? "HTTPS" : "HTTP",
    action: t.blocked ? "Blocked" : "Allowed",
    transactionsize: String(t.req + t.resp),
    responsesize: String(t.resp),
    requestsize: String(t.req),
    urlcategory: t.category,
    serverip: t.serverIp ?? testNetIp(ctx, `zia-server:${t.host}`),
    clienttranstime: String(ctimeMs),
    requestmethod: t.method,
    refererURL: t.referer ?? "None",
    useragent: t.ua ?? CHROME_UA,
    product: "NSS",
    location: t.location ?? (roadWarrior ? "Road Warrior" : HQ[ctx.companyId] ?? `${company(ctx).short}-HQ`),
    ClientIP: clientIp,
    status: t.status,
    user,
    url: t.url,
    vendor: "Zscaler",
    hostname: t.host,
    clientpublicIP: publicIp,
    threatcategory: t.threat ? (t.threatCat && t.threatCat !== "None" ? t.threatCat : "Trojan") : "None",
    threatname: t.threat ?? "None",
    filetype: file?.[0] ?? "None",
    appname: t.app,
    pagerisk: String(pagerisk),
    department: dept,
    urlsupercategory: t.supercat ?? superDefault,
    appclass: t.appClass,
    dlpengine: t.dlpEngine ?? "None",
    urlclass: t.urlclass ?? classDefault,
    threatclass: t.threat ? "Virus" : "None",
    dlpdictionaries: t.dlpDict ?? "None",
    fileclass: file?.[1] ?? "None",
    bwthrottle: "No",
    servertranstime: t.blocked ? "0" : String(Math.max(1, ctimeMs - ctx.int(`${ev.id}:stime`, 5, 60))),
    contenttype: contentType,
    ssldecrypted: t.scheme === "https" ? "Yes" : "No",
    unscannabletype: "None",
    md5: ev.file?.md5 ?? ev.process?.hash?.md5 ?? "None",
    deviceowner: user !== "None" ? user.split("@")[0] : "None",
    devicehostname: host ?? "None",
  };
  return { sourcetype: "zscalernss-web", event };
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const record = build(ev, ctx);
  if (!record) return null;
  return { sourceId: "zscaler_zia", kind: "web", format: "json", record, timeMs: Date.parse(ev.ts) };
}

const E = (k: string) => `event.${k}`;

const useCases: UseCase[] = [
  {
    id: "zscaler_zia.malware_download_blocked",
    title: "Malware download blocked by ZIA",
    sourceId: "zscaler_zia",
    severity: "high",
    mitre: ["T1204.002", "T1105"],
    description: "ZIA blocked a download because the file matched malware (action=Blocked, threatname set). The block worked, but the user was lured to the URL — check refererURL for the lure, search other users who hit the same hostname, and pivot md5 to EDR to make sure the file did not arrive another way.",
    logic: "SPL: index=zscaler sourcetype=zscalernss-web action=Blocked threatname!=None | table datetime user devicehostname url refererURL threatname threatcategory md5",
    match: { all: [{ field: E("action"), op: "eq", value: "Blocked" }, { field: E("threatname"), op: "neq", value: "None" }] },
    falsePositives: ["Security staff deliberately downloading samples (should use an isolated analysis network)"],
  },
  {
    id: "zscaler_zia.newly_registered_domain_allowed",
    title: "Allowed traffic to a newly registered domain",
    sourceId: "zscaler_zia",
    severity: "medium",
    mitre: ["T1566.002", "T1583.001"],
    description: "A user reached a domain in the 'Newly Registered and Observed Domains' category and ZIA allowed it. Phishing kits and C2 live on days-old domains; look at the hostname for look-alikes of your brand or SSO.",
    logic: "SPL: index=zscaler sourcetype=zscalernss-web action=Allowed urlcategory IN (\"Newly Registered and Observed Domains\", \"Newly Registered Domains\") | stats count values(url) BY user hostname",
    match: { all: [{ field: E("action"), op: "eq", value: "Allowed" }, { field: E("urlcategory"), op: "in", value: NRD }] },
    falsePositives: ["Marketing launching a new campaign domain", "Brand-new SaaS vendor"],
  },
  {
    id: "zscaler_zia.credential_post_to_new_domain",
    title: "Form POST to a newly registered domain (likely credential submission)",
    sourceId: "zscaler_zia",
    severity: "high",
    mitre: ["T1566.002", "T1056.003", "T1557"],
    description: "requestmethod=POST to a newly registered domain that ZIA allowed. On a look-alike login page this is the moment the password (or session) was handed to the attacker — reset the user's credentials and check the IdP for sign-ins right after this time.",
    logic: "SPL: index=zscaler sourcetype=zscalernss-web action=Allowed requestmethod=POST urlcategory IN (\"Newly Registered and Observed Domains\", \"Newly Registered Domains\") | table datetime user devicehostname hostname url refererURL",
    match: { all: [{ field: E("action"), op: "eq", value: "Allowed" }, { field: E("requestmethod"), op: "eq", value: "POST" }, { field: E("urlcategory"), op: "in", value: NRD }] },
    falsePositives: ["Legitimate new vendor portal used for the first time"],
  },
  {
    id: "zscaler_zia.large_upload_file_sharing",
    title: "Large upload (>100 MB) to a file-sharing / personal cloud service",
    sourceId: "zscaler_zia",
    severity: "high",
    mitre: ["T1567.002", "T1048"],
    description: "requestsize (client→server bytes) over 100 MB to a File Sharing app or file-hosting / cloud-storage category. Exfiltration shows up in requestsize, not transactionsize. Check the time of day, the file type, and whether the session came from an unusual clientpublicIP.",
    logic: "SPL: index=zscaler sourcetype=zscalernss-web requestmethod IN (POST, PUT) requestsize>100000000 (appclass=\"File Sharing\" OR urlcategory IN (\"File Host\", \"Online and Cloud Storage\", \"Personal Cloud Storage\")) | eval MB=round(requestsize/1048576,1) | table datetime user appname hostname MB filetype unscannabletype",
    match: { all: [
      { field: E("requestsize"), op: "gt", value: 100_000_000 },
      { any: [{ field: E("appclass"), op: "eq", value: "File Sharing" }, { field: E("urlcategory"), op: "in", value: FILE_SHARING_CATS }] },
    ] },
    falsePositives: ["Approved transfers to partners via a sanctioned file-sharing app (check the app's sanction status)"],
  },
  {
    id: "zscaler_zia.encrypted_archive_upload",
    title: "Upload of an encrypted (unscannable) file",
    sourceId: "zscaler_zia",
    severity: "high",
    mitre: ["T1560.001", "T1567"],
    description: "unscannabletype='Encrypted File' on an upload above 10 MB. A password-protected archive cannot be inspected by DLP — a classic way to move sensitive data past content inspection. Pivot to EDR for archive creation (7z/rar with -p) on devicehostname.",
    logic: "SPL: index=zscaler sourcetype=zscalernss-web unscannabletype=\"Encrypted File\" requestmethod IN (POST, PUT) requestsize>10000000 | table datetime user devicehostname hostname requestsize filetype",
    match: { all: [{ field: E("unscannabletype"), op: "eq", value: "Encrypted File" }, { field: E("requestmethod"), op: "in", value: ["POST", "PUT"] }, { field: E("requestsize"), op: "gt", value: 10_000_000 }] },
    falsePositives: ["Legal/finance sending encrypted archives to auditors by policy"],
  },
  {
    id: "zscaler_zia.genai_file_upload",
    title: "File or large prompt uploaded to a generative-AI app",
    sourceId: "zscaler_zia",
    severity: "medium",
    mitre: ["T1567"],
    description: "POST to a generative-AI application (urlcategory 'Generative AI and ML Applications' or appclass 'AI & ML Applications') that uploads a file (/backend-api/files) or more than 1 MB. Company data pasted into an unsanctioned AI tool leaves your control; dlpengine/dlpdictionaries show whether sensitive data was detected.",
    logic: "SPL: index=zscaler sourcetype=zscalernss-web requestmethod=POST (urlcategory=\"Generative AI and ML Applications\" OR appclass=\"AI & ML Applications\") (url=\"*/backend-api/files*\" OR requestsize>1000000) | table datetime user appname url requestsize filetype action dlpengine",
    match: { all: [
      { field: E("requestmethod"), op: "eq", value: "POST" },
      { any: [{ field: E("urlcategory"), op: "eq", value: GENAI_CAT }, { field: E("appclass"), op: "eq", value: "AI & ML Applications" }] },
      { any: [{ field: E("url"), op: "contains", value: "/backend-api/files" }, { field: E("requestsize"), op: "gt", value: 1_000_000 }] },
    ] },
    falsePositives: ["Sanctioned enterprise AI tenant used per policy"],
  },
  {
    id: "zscaler_zia.dlp_block",
    title: "Upload blocked by ZIA DLP",
    sourceId: "zscaler_zia",
    severity: "medium",
    mitre: ["T1567", "T1048"],
    description: "action=Blocked with a DLP engine hit (dlpengine/dlpdictionaries name what was found: PCI, PII, confidential records). The control worked, but intent matters: repeated attempts, renamed files or a switch to another channel right after the block are signs of deliberate exfiltration.",
    logic: "SPL: index=zscaler sourcetype=zscalernss-web action=Blocked dlpengine!=None | stats count values(hostname) values(dlpdictionaries) values(filetype) BY user | sort -count",
    match: { all: [{ field: E("action"), op: "eq", value: "Blocked" }, { field: E("dlpengine"), op: "neq", value: "None" }] },
    falsePositives: ["Users unaware of policy uploading a report with customer data to a personal tool"],
  },
  {
    id: "zscaler_zia.repeated_post_uncategorised",
    title: "Repeated POSTs from one device to an uncategorised site (beaconing / data harvest)",
    sourceId: "zscaler_zia",
    severity: "medium",
    mitre: ["T1071.001", "T1041"],
    description: "Three or more allowed POSTs from the same user and device to the same 'Miscellaneous or Unknown' hostname within an hour. Browsers rarely POST repeatedly to unknown sites on their own — a malicious extension or implant reporting home does.",
    logic: "SPL: index=zscaler sourcetype=zscalernss-web action=Allowed requestmethod=POST urlcategory=\"Miscellaneous or Unknown\" | bin _time span=1h | stats count sum(requestsize) BY user devicehostname hostname _time | where count>=3",
    match: { all: [{ field: E("action"), op: "eq", value: "Allowed" }, { field: E("requestmethod"), op: "eq", value: "POST" }, { field: E("urlcategory"), op: "eq", value: "Miscellaneous or Unknown" }] },
    threshold: { groupBy: [E("user"), E("devicehostname"), E("hostname")], count: 3, windowSec: 3600 },
    falsePositives: ["Niche SaaS or telemetry endpoints not yet categorised by Zscaler"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
