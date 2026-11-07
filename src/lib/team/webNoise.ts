/**
 * Ordinary web traffic for the team feed: the access log and WAF rows a public site writes all day.
 *
 * Web logs that exist only inside a web story give the story away: filter the source and the incident
 * is what is left. So every session carries these rows, on the estate's own sites and on the sites a
 * web story of the session uses, in the same vendor-neutral shape (emitters/web.ts), the same products
 * and the same policy mode. Rule hits on normal traffic are alerts an analyst closes by reading them.
 * Clients are documentation addresses the session's attacks do not use.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { CompanyAssets } from "@/lib/sim/companyProfilesMeta";
import { wafRequest, webAccess, type WafDecision, type WebSite } from "@/lib/sim/emitters/web";

const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const SAFARI = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
const EDGE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0";
const BOT = "Mozilla/5.0 (compatible; SiteAuditBot/2.1; +https://audit.example/bot)";
const UAS = [CHROME, CHROME, SAFARI, EDGE];

interface Ctx { w: WebSite; id: string; ts: string; ip: string; rnd: () => number }
const pick = <T,>(arr: T[], rnd: () => number): T => arr[Math.floor(rnd() * arr.length) % arr.length];
const size = (rnd: () => number, lo: number, hi: number) => lo + Math.floor(rnd() * (hi - lo));

/** Requests any public site answers. */
const ACCESS: ((c: Ctx) => TelemetryEvent)[] = [
  c => webAccess(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, path: "/", bytes: size(c.rnd, 18000, 42000), ua: pick(UAS, c.rnd), isBaseline: true, description: "Web server answered a page request" }),
  c => webAccess(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, path: "/assets/app.min.js", bytes: size(c.rnd, 90000, 240000), ua: pick(UAS, c.rnd), referer: `https://${c.w.site}/`, isBaseline: true, description: "Web server answered a script request" }),
  c => webAccess(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, path: "/assets/site.css", status: 304, bytes: 0, ua: pick(UAS, c.rnd), referer: `https://${c.w.site}/`, isBaseline: true, description: "Web server answered a stylesheet request" }),
  c => webAccess(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, path: "/favicon.ico", status: 404, bytes: 1245, ua: pick(UAS, c.rnd), isBaseline: true, description: "Web server answered a page request" }),
  c => webAccess(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, path: "/robots.txt", bytes: 212, ua: BOT, isBaseline: true, description: "Web server answered a page request" }),
  c => webAccess(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, method: "POST", path: "/account/login", status: 302, bytes: 0, ua: pick(UAS, c.rnd), isBaseline: true, description: "Web server answered a sign-in" }),
  c => webAccess(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, method: "POST", path: "/account/login", status: 401, bytes: 391, ua: pick(UAS, c.rnd), isBaseline: true, description: "Web server answered a sign-in" }),
  c => webAccess(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, path: "/account/profile", bytes: size(c.rnd, 4000, 9000), ua: pick(UAS, c.rnd), isBaseline: true, description: "Web server answered a profile request" }),
  c => webAccess(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, path: "/old/brochure.pdf", status: 404, bytes: 1245, ua: pick(UAS, c.rnd), isBaseline: true, description: "Web server answered a page request" }),
  c => webAccess(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, path: "/download", query: "file=price-list-2026.pdf", bytes: size(c.rnd, 300000, 2400000), ua: pick(UAS, c.rnd), isBaseline: true, description: "Web server answered a download" }),
];

/** What a rule does to a matching request on this site: a Detection policy logs, a Prevention policy blocks. */
const onSite = (w: WebSite): "block" | "count" => (w.wafMode === "Detection" ? "count" : "block");
const fp = (o: WafDecision, why: string): WafDecision => ({ ...o, severity: "medium", isDetection: true, verdict: "fp", fpExplanation: why });

/** Rows a WAF writes on traffic nobody attacked with. */
const WAF: ((c: Ctx) => TelemetryEvent)[] = [
  c => wafRequest(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, path: "/", action: "allow", ua: pick(UAS, c.rnd), bytes: size(c.rnd, 18000, 42000), isBaseline: true, description: "WAF passed a request" }),
  c => wafRequest(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, path: "/account/profile", action: "allow", ua: pick(UAS, c.rnd), bytes: size(c.rnd, 4000, 9000), isBaseline: true, description: "WAF passed a request" }),
  c => wafRequest(c.w, fp({ id: c.id, ts: c.ts, srcIp: c.ip, path: "/search", query: "q=O%27Brien+OR+Sons+Ltd", action: onSite(c.w), rule: "sqli_query", matched: "O'Brien OR", location: "ARGS:q", ua: pick(UAS, c.rnd), mitre: "T1190", tactic: "Initial Access", description: "WAF rule matched SQL syntax in the q parameter of /search" },
    "A customer searching for a company name with an apostrophe in it: one request, a plain word search, nothing else from the address.")),
  c => wafRequest(c.w, fp({ id: c.id, ts: c.ts, srcIp: c.ip, method: "POST", path: "/contact", action: onSite(c.w), rule: "xss_body", matched: "<b>", location: "ARGS:message", ua: pick(UAS, c.rnd), mitre: "T1059.007", tactic: "Execution", description: "WAF rule matched HTML in a form body" },
    "A customer pasting formatted text into the contact form: bold tags and no script, and one request.")),
  c => wafRequest(c.w, fp({ id: c.id, ts: c.ts, srcIp: c.ip, path: "/download", query: "file=..%2Fimages%2Flogo.png", action: onSite(c.w), rule: "lfi_query", matched: "../", location: "ARGS:file", ua: BOT, mitre: "T1190", tactic: "Initial Access", description: "WAF rule matched a path sequence in the file parameter of /download" },
    "A link checker following an old relative link to a logo in the site's own images folder: its declared user agent, and one request.")),
  c => wafRequest(c.w, { id: c.id, ts: c.ts, srcIp: c.ip, method: "POST", path: "/account/documents", action: "count", rule: "size_body", ua: pick(UAS, c.rnd), sent: size(c.rnd, 24000, 96000), bytes: 244, severity: "low", isBaseline: true, description: "WAF rule evaluated a large request body" }),
];

/** The sites a story of this session uses, as it wrote them: same host, address, product and mode. */
function sitesOf(events: TelemetryEvent[]): WebSite[] {
  const out = new Map<string, WebSite>();
  for (const e of events) {
    const site = e.network?.domain;
    if ((e.source !== "web_server" && e.source !== "waf") || !site) continue;
    const cur = out.get(site) ?? ({ site, host: "", ip: "" } as WebSite);
    if (e.source === "web_server") {
      cur.host = e.hostname ?? cur.host;
      cur.ip = e.dst_ip ?? cur.ip;
      if (/iis/i.test(e.vendor ?? "")) cur.server = "iis";
      if (/nginx/i.test(e.vendor ?? "")) cur.server = "nginx";
    }
    if (e.raw?.["waf.mode"] === "Detection") cur.wafMode = "Detection";
    out.set(site, cur);
  }
  return [...out.values()].filter(w => w.host && w.ip);
}

export function webNoise(o: { assets: CompanyAssets; storyEvents: TelemetryEvent[]; avoidIps: Set<string>; count: number; rnd: () => number; ts: string }): TelemetryEvent[] {
  const { assets, rnd, ts } = o;
  const estate: WebSite[] = ["www", "portal", "api"].map((name, i) => ({ site: `${name}.${assets.domain}`, host: `web-${name}-01.${assets.domain}`, ip: `${assets.subnet}.${241 + i}` }));
  const own = sitesOf(o.storyEvents);
  const sites = [...own, ...estate.filter(w => !own.some(s => s.site === w.site))];
  const clients = Array.from({ length: 30 }, (_, i) => `${i % 2 ? "198.51.100" : "203.0.113"}.${221 + (i >> 1)}`).filter(ip => !o.avoidIps.has(ip));
  const rows: TelemetryEvent[] = [];
  for (let n = 0; n < o.count; n++) {
    // The sites a story of this session runs on get half the traffic: their rows must not stand alone.
    const w = own.length && n % 2 === 0 ? pick(own, rnd) : pick(sites, rnd);
    const make = n % 3 === 2 ? pick(WAF, rnd) : pick(ACCESS, rnd);
    rows.push(make({ w, id: `wn_${n}`, ts, ip: pick(clients, rnd), rnd }));
  }
  return rows;
}
