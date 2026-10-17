/**
 * Benign-positive alerts for the team feed (expert review P0-1): the everyday alerts a SOC closes
 * as false positives — an authorised vulnerability scan, a management script, an admin's
 * patching session, approved travel, the nightly backup. Without them every high-severity
 * row in the feed was an attack and a Tier-1 could score by badge alone.
 *
 * Each alert carries an fp_explanation that cites an approved ticket, so the timeline's ITSM
 * step drops the matching ServiceNow record a few logs earlier — the analyst can PROVE the
 * false positive from the feed, as on a real shift. Hosts and people are the company's own.
 *
 * Every alert comes from the product that really raises it, so the feed only shows what the
 * session runs (2026-10-18: a team exercise without Azure showed "Microsoft Sentinel" alerts):
 * the script and PsExec detections are EDR process events and the travel alert is an
 * identity-provider sign-in (both relabelled to the session's chosen products by applyStack);
 * only the two SIEM analytics (internal port scan, mass file access) are Sentinel alerts, and
 * only when the organization runs Azure (`siem`). `fits` drops an event the chosen product
 * has no record for.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { CompanyAssets } from "@/lib/sim/companyProfilesMeta";

interface Ctx { assets: CompanyAssets; companyId: string; rnd: () => number; ts: string }
interface Maker { siemOnly: boolean; make: (c: Ctx, n: number) => TelemetryEvent }

const pick = <T,>(arr: T[], rnd: () => number): T => arr[Math.floor(rnd() * arr.length) % arr.length];
const workstations = (a: CompanyAssets) => a.hosts.filter(h => h !== a.dc && h !== a.fileServer && !/^(SRV|SVR)-|-SRV-|prod-srv/i.test(h));
const servers = (a: CompanyAssets) => [a.fileServer, ...a.hosts.filter(h => /^(SRV|SVR)-|-SRV-/i.test(h) && h !== a.dc)].filter(Boolean);
const mail = (a: CompanyAssets, name: string) => `${name}@${a.domain}`;
const itUser = (a: CompanyAssets) => a.roster.find(r => /it|devops|admin|infra|engineer|security/i.test(r.title ?? ""))?.name ?? a.roster[0]?.name ?? "it.admin";
const ticket = (prefix: string, n: number, rnd: () => number) => `${prefix}00${41000 + n * 97 + Math.floor(rnd() * 90)}`;

/** A Microsoft Sentinel analytics alert (SecurityAlert schema). */
function sentinelAlert(o: { id: string; ts: string; name: string; severity: "high" | "medium"; host?: string; user?: string; ip?: string;
  props: Record<string, string>; fp: string; mitre?: string }): TelemetryEvent {
  const raw: Record<string, unknown> = { AlertName: o.name, ProductName: "Azure Sentinel", AlertSeverity: o.severity === "high" ? "High" : "Medium", Status: "New", TimeGenerated: o.ts, "event.action": "alert" };
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

/** An EDR process detection, authored as Defender for Endpoint and relabelled to the session's EDR. */
function edrDetection(o: { id: string; ts: string; host: string; user: string; userEmail?: string; severity: "high" | "medium";
  process: NonNullable<TelemetryEvent["process"]>; category: string; description: string; fp: string; mitre: string; extra?: Record<string, unknown> }): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "edr", event_type: "process_create", severity: o.severity, vendor: "Microsoft Defender for Endpoint",
    hostname: o.host, ...(o.userEmail ? { user_email: o.userEmail } : {}), is_detection: true,
    expected_verdict: "fp", fp_explanation: o.fp, mitre_technique: o.mitre, description: o.description,
    process: o.process,
    raw: { Category: o.category, action_result: "allowed", "process.name": o.process.name, ...(o.extra ?? {}) },
  } as TelemetryEvent;
}

const MAKERS: Maker[] = [
  // An authorised vulnerability scan trips the internal port-scan analytic (a SIEM correlation).
  { siemOnly: true, make: (c, n) => {
    const host = pick(servers(c.assets), c.rnd), t = ticket("CHG", n, c.rnd), ip = `${c.assets.subnet}.${200 + Math.floor(c.rnd() * 40)}`;
    return sentinelAlert({ id: `fpa_scan_${n}`, ts: c.ts, name: "Port scan from an internal host", severity: "high", host, ip,
      props: { "Distinct Ports": String(900 + Math.floor(c.rnd() * 400)), "Distinct Hosts": String(40 + Math.floor(c.rnd() * 60)), "Scanner Account": c.assets.serviceAccounts.find(s => /scan/.test(s)) ?? "svc-scan" },
      fp: `Authorised weekly vulnerability scan run by the security team from the scanner host, under change ticket ${t}.`, mitre: "T1046" });
  } },
  // A configuration-management compliance script looks like a PowerShell policy bypass.
  { siemOnly: false, make: (c, n) => {
    const host = pick(workstations(c.assets), c.rnd), t = ticket("CHG", n, c.rnd);
    return edrDetection({ id: `fpa_ps_${n}`, ts: c.ts, host, user: "SYSTEM", severity: "high", category: "SuspiciousScriptExecution", mitre: "T1059.001",
      process: { name: "powershell.exe", pid: 5000 + n * 37, parent_name: "CcmExec.exe", parent_pid: 3100 + n * 11, user: "SYSTEM",
        cmdline: "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\CCM\\SystemTemp\\Compliance.ps1" },
      description: `PowerShell with -ExecutionPolicy Bypass launched by CcmExec.exe on ${host}`,
      fp: `Configuration Manager compliance baseline deployed by IT under change ticket ${t}; the script is the signed baseline package.`,
      extra: { "process.code_signature.trusted": true } });
  } },
  // An administrator's patching run fires the remote-service-execution rule.
  { siemOnly: false, make: (c, n) => {
    const admin = itUser(c.assets), adminHost = pick(workstations(c.assets), c.rnd), target = pick(servers(c.assets), c.rnd), t = ticket("CHG", n, c.rnd);
    return edrDetection({ id: `fpa_psexec_${n}`, ts: c.ts, host: adminHost, user: admin, userEmail: mail(c.assets, admin), severity: "high", category: "LateralMovementTool", mitre: "T1569.002",
      process: { name: "PsExec.exe", pid: 7000 + n * 41, parent_name: "cmd.exe", parent_pid: 6900 + n * 13, user: admin,
        cmdline: `PsExec.exe \\\\${target} -s cmd /c "wusa.exe C:\\Patches\\KB5034441.msu /quiet /norestart"` },
      description: `PsExec.exe on ${adminHost} started a remote service on ${target}`,
      fp: `IT administrator ${admin} patching servers during the maintenance window approved under change ticket ${t}.` });
  } },
  // Approved business travel looks like atypical travel: an identity-provider sign-in from abroad.
  { siemOnly: false, make: (c, n) => {
    const person = pick(c.assets.roster, c.rnd).name, t = ticket("RITM", n, c.rnd);
    const [city, country, ip, lat, lon] = pick([["Munich", "Germany", "84.128.33.17", 48.1351, 11.582], ["Lisbon", "Portugal", "85.243.52.88", 38.7223, -9.1393], ["Warsaw", "Poland", "83.24.117.9", 52.2297, 21.0122]] as const, c.rnd);
    const user = mail(c.assets, person);
    return {
      id: `fpa_travel_${n}`, ts: c.ts, source: "o365", event_type: "auth_success", severity: "medium", vendor: "Microsoft Entra ID",
      user_email: user, src_ip: ip, is_detection: true, expected_verdict: "fp",
      fp_explanation: `${person} is on approved business travel to ${city} (travel request ${t}); the sign-in is from the managed laptop with MFA.`,
      description: `${user} signed in from ${city}, ${country} (${ip}), first sign-in from this country`,
      raw: {
        "data.office365.Operation": "UserLoggedIn", "data.office365.Workload": "AzureActiveDirectory",
        "data.office365.AzureActiveDirectoryEventType": "AccountLogon", "data.office365.UserId": user,
        "data.office365.ActorIpAddress": ip, "data.office365.ClientIP": ip, "data.office365.ResultStatus": "Succeeded",
        "GeoLocation.country_name": country, "GeoLocation.city_name": city, "GeoLocation.location.lat": lat, "GeoLocation.location.lon": lon,
        action_result: "allowed",
      },
    } as TelemetryEvent;
  } },
  // The nightly backup reads many files and trips the mass-access analytic (a SIEM correlation).
  { siemOnly: true, make: (c, n) => {
    const svc = c.assets.serviceAccounts.find(s => /backup/.test(s)) ?? "svc-backup", t = ticket("CHG", n, c.rnd);
    return sentinelAlert({ id: `fpa_backup_${n}`, ts: c.ts, name: "Mass file access by a single account", severity: "high", host: c.assets.fileServer, user: mail(c.assets, svc),
      props: { "Files Accessed": String(18000 + Math.floor(c.rnd() * 9000)), "Window": "60 minutes", "Account": svc },
      fp: `Scheduled nightly backup job of the file server by ${svc}, registered under change ticket ${t}.` });
  } },
];

/**
 * `count` benign-positive alerts for a session, varied and seed-stable. `siem`: the organization
 * runs Microsoft Sentinel (Azure); `fits`: the session's products have a record for the event.
 */
export function fpAlerts(assets: CompanyAssets | undefined, companyId: string, count: number, rnd: () => number, ts: string,
  opts: { siem?: boolean; fits?: (e: TelemetryEvent) => boolean } = {}): TelemetryEvent[] {
  if (!assets || count <= 0) return [];
  const siem = opts.siem ?? true, fits = opts.fits ?? (() => true);
  const order = MAKERS.map((m, k) => ({ m, k, r: rnd() })).sort((a, b) => a.r - b.r).filter(x => siem || !x.m.siemOnly);
  if (!order.length) return [];
  return Array.from({ length: count }, (_, i) => order[i % order.length].m.make({ assets, companyId, rnd, ts }, i)).filter(fits);
}
