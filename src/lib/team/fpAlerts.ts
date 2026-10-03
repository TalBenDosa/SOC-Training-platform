/**
 * Benign-positive alerts for the team feed (expert review P0-1): the everyday alerts a SOC closes
 * as false positives — an authorised vulnerability scan, a management script, an admin's
 * patching session, approved travel, the nightly backup. Without them every high-severity
 * row in the feed was an attack and a Tier-1 could score by badge alone.
 *
 * Each alert carries an fp_explanation that cites an approved ticket, so the timeline's ITSM
 * step drops the matching ServiceNow record a few logs earlier — the analyst can PROVE the
 * false positive from the feed, as on a real shift. Hosts and people are the company's own.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { CompanyAssets } from "@/lib/sim/companyProfilesMeta";

interface Ctx { assets: CompanyAssets; companyId: string; rnd: () => number; ts: string }
type Make = (c: Ctx, n: number) => TelemetryEvent;

const pick = <T,>(arr: T[], rnd: () => number): T => arr[Math.floor(rnd() * arr.length) % arr.length];
const workstations = (a: CompanyAssets) => a.hosts.filter(h => h !== a.dc && h !== a.fileServer && !/^(SRV|SVR)-|-SRV-|prod-srv/i.test(h));
const servers = (a: CompanyAssets) => [a.fileServer, ...a.hosts.filter(h => /^(SRV|SVR)-|-SRV-/i.test(h) && h !== a.dc)].filter(Boolean);
const mail = (a: CompanyAssets, name: string) => `${name}@${a.domain}`;
const itUser = (a: CompanyAssets) => a.roster.find(r => /it|devops|admin|infra|engineer|security/i.test(r.title ?? ""))?.name ?? a.roster[0]?.name ?? "it.admin";
const ticket = (prefix: string, n: number, rnd: () => number) => `${prefix}00${41000 + n * 97 + Math.floor(rnd() * 90)}`;

function alert(o: { id: string; ts: string; name: string; product: string; severity: "high" | "medium"; host?: string; user?: string; ip?: string;
  props: Record<string, string>; fp: string; mitre?: string }): TelemetryEvent {
  const raw: Record<string, unknown> = { AlertName: o.name, ProductName: o.product, AlertSeverity: o.severity === "high" ? "High" : "Medium", Status: "New", TimeGenerated: o.ts, "event.action": "alert" };
  if (o.host) raw["Entities.Host.HostName"] = o.host;
  if (o.user) { const [n, d] = o.user.split("@"); raw["Entities.Account.Name"] = n; raw["Entities.Account.UPNSuffix"] = d; }
  if (o.ip) raw["Entities.IP.Address"] = o.ip;
  for (const [k, v] of Object.entries(o.props)) raw[`ExtendedProperties.${k}`] = v;
  return {
    id: o.id, ts: o.ts, source: "siem", vendor: "Microsoft Sentinel", event_type: "risk_score_change", severity: o.severity,
    is_detection: true, expected_verdict: "fp", fp_explanation: o.fp, ...(o.mitre ? { mitre_technique: o.mitre } : {}),
    ...(o.host ? { hostname: o.host } : {}), ...(o.user ? { user_email: o.user } : {}), ...(o.ip ? { src_ip: o.ip } : {}),
    description: `Sentinel raised "${o.name}"`, raw,
  } as TelemetryEvent;
}

const MAKERS: Make[] = [
  // An authorised vulnerability scan trips the internal port-scan analytic.
  (c, n) => {
    const host = pick(servers(c.assets), c.rnd), t = ticket("CHG", n, c.rnd), ip = `${c.assets.subnet}.${200 + Math.floor(c.rnd() * 40)}`;
    return alert({ id: `fpa_scan_${n}`, ts: c.ts, name: "Port scan from an internal host", product: "Azure Sentinel", severity: "high", host, ip,
      props: { "Distinct Ports": String(900 + Math.floor(c.rnd() * 400)), "Distinct Hosts": String(40 + Math.floor(c.rnd() * 60)), "Scanner Account": c.assets.serviceAccounts.find(s => /scan/.test(s)) ?? "svc-scan" },
      fp: `Authorised weekly vulnerability scan run by the security team from the scanner host, under change ticket ${t}.`, mitre: "T1046" });
  },
  // A configuration-management compliance script looks like an encoded PowerShell launch.
  (c, n) => {
    const host = pick(workstations(c.assets), c.rnd), t = ticket("CHG", n, c.rnd);
    return alert({ id: `fpa_ps_${n}`, ts: c.ts, name: "Suspicious PowerShell command line", product: "Microsoft Defender for Endpoint", severity: "high", host,
      props: { "Parent Process": "CcmExec.exe", "Process": "powershell.exe", "Command Line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\CCM\\SystemTemp\\Compliance.ps1", "Signer": "Configuration Manager (internal)" },
      fp: `Configuration Manager compliance baseline deployed by IT under change ticket ${t}; the script is the signed baseline package.`, mitre: "T1059.001" });
  },
  // An administrator's patching run fires the remote-service-execution rule.
  (c, n) => {
    const admin = itUser(c.assets), host = pick(servers(c.assets), c.rnd), t = ticket("CHG", n, c.rnd);
    return alert({ id: `fpa_psexec_${n}`, ts: c.ts, name: "Remote service execution (PsExec)", product: "Microsoft Defender for Endpoint", severity: "high", host, user: mail(c.assets, admin),
      props: { "Service Name": "PSEXESVC", "Initiating Account": admin, "Target Host": host },
      fp: `IT administrator ${admin} patching servers during the maintenance window approved under change ticket ${t}.`, mitre: "T1569.002" });
  },
  // Approved business travel looks like atypical travel.
  (c, n) => {
    const person = pick(c.assets.roster, c.rnd).name, t = ticket("RITM", n, c.rnd);
    const [city, cc, ip] = pick([["Munich", "DE", "84.128.33.17"], ["Lisbon", "PT", "85.243.52.88"], ["Warsaw", "PL", "83.24.117.9"]], c.rnd);
    return alert({ id: `fpa_travel_${n}`, ts: c.ts, name: "Atypical travel", product: "Azure Active Directory Identity Protection", severity: "medium", user: mail(c.assets, person), ip,
      props: { "Previous Location": "Head office", "Current Location": `${city}, ${cc}`, "Device": "Compliant, company-managed" },
      fp: `${person} is on approved business travel to ${city} (travel request ${t}); the sign-in is from the managed laptop with MFA.` });
  },
  // The nightly backup reads many files and trips the mass-access analytic.
  (c, n) => {
    const svc = c.assets.serviceAccounts.find(s => /backup/.test(s)) ?? "svc-backup", t = ticket("CHG", n, c.rnd);
    return alert({ id: `fpa_backup_${n}`, ts: c.ts, name: "Mass file access by a single account", product: "Azure Sentinel", severity: "high", host: c.assets.fileServer, user: mail(c.assets, svc),
      props: { "Files Accessed": String(18000 + Math.floor(c.rnd() * 9000)), "Window": "60 minutes", "Account": svc },
      fp: `Scheduled nightly backup job of the file server by ${svc}, registered under change ticket ${t}.` });
  },
];

/** `count` benign-positive alerts for a session, varied and seed-stable. */
export function fpAlerts(assets: CompanyAssets | undefined, companyId: string, count: number, rnd: () => number, ts: string): TelemetryEvent[] {
  if (!assets || count <= 0) return [];
  const order = MAKERS.map((m, k) => ({ m, k, r: rnd() })).sort((a, b) => a.r - b.r);
  return Array.from({ length: count }, (_, i) => order[i % order.length].m({ assets, companyId, rnd, ts }, i));
}
