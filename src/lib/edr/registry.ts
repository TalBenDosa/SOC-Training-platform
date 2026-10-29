/**
 * The RTR shell's registry: `reg query <key> [/v <name>] [/s]` answers from the keys an
 * analyst actually checks on a suspect Windows host (ASEPs and the settings attackers
 * flip), each with the values a clean host carries, merged with what the story's own
 * telemetry wrote (registry events, `reg add`, Set-MpPreference). A planted value sits
 * among the benign ones and is never labelled: the analyst has to know what normal is.
 *
 * Deterministic from the host (no randomness), and the output follows reg.exe: a blank
 * line, the full key, values as `    name    TYPE    data`, then subkeys as full paths.
 */
import type { EdrInvestigation } from "./investigations";
import { baselineRunKeys, baselineServices, isServerHost, RUN_HKCU, RUN_HKLM } from "./hostBaseline";

export interface RegValue { name: string; type: string; data: string; malicious?: boolean }
interface RegKey { values: RegValue[]; subkeys: string[] }

const HKLM = "HKEY_LOCAL_MACHINE";
export const WINLOGON = `${HKLM}\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon`;
export const NT_WINDOWS = `${HKLM}\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows`;
export const IFEO = `${HKLM}\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options`;
export const DEFENDER_EXCLUSIONS = `${HKLM}\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions`;
export const WDIGEST = `${HKLM}\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest`;
export const TERMINAL_SERVER = `${HKLM}\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server`;
export const LSA = `${HKLM}\\SYSTEM\\CurrentControlSet\\Control\\Lsa`;
export const SERVICES = `${HKLM}\\SYSTEM\\CurrentControlSet\\Services`;
export const HKCU_CLSID = "HKEY_CURRENT_USER\\SOFTWARE\\Classes\\CLSID";
const RUNONCE_HKLM = `${HKLM}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce`;
const RUNONCE_HKCU = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";

// The DLL a svchost-hosted service loads (Parameters\ServiceDll), as on Windows 10/11.
const SERVICE_DLL: Record<string, string> = {
  dnscache: "%SystemRoot%\\System32\\dnsrslvr.dll",
  lanmanserver: "%SystemRoot%\\system32\\srvsvc.dll",
  lanmanworkstation: "%SystemRoot%\\System32\\wkssvc.dll",
  rpcss: "%SystemRoot%\\system32\\rpcss.dll",
  schedule: "%systemroot%\\system32\\schedsvc.dll",
  w32time: "%systemroot%\\system32\\w32time.dll",
  wuauserv: "%systemroot%\\system32\\wuaueng.dll",
  bits: "%SystemRoot%\\System32\\qmgr.dll",
  eventlog: "%SystemRoot%\\System32\\wevtsvc.dll",
  winrm: "%SystemRoot%\\system32\\WsmSvc.dll",
};
const START_CODE: Record<string, string> = { BOOT_START: "0x0", SYSTEM_START: "0x1", AUTO_START: "0x2", DEMAND_START: "0x3", DISABLED: "0x4" };

/** A registry path from any telemetry spelling to reg.exe's: HKLM/HKCU/HKU\SID/\REGISTRY\… → full hive names. */
export function canonicalKey(k: string): string {
  return k.trim().replace(/^"|"$/g, "").replace(/\\+$/, "")
    .replace(/^\\REGISTRY\\MACHINE(?=\\|$)/i, HKLM)
    .replace(/^\\REGISTRY\\USER\\S-1-5-21-[\d-]+(?:_Classes)?(?=\\|$)/i, "HKEY_CURRENT_USER")
    .replace(/^HKU\\S-1-5-21-[\d-]+(?=\\|$)/i, "HKEY_CURRENT_USER")
    .replace(/^HKEY_USERS\\S-1-5-21-[\d-]+(?=\\|$)/i, "HKEY_CURRENT_USER")
    .replace(/^HKLM(?=\\|$)/i, HKLM)
    .replace(/^HKCU(?=\\|$)/i, "HKEY_CURRENT_USER")
    .replace(/^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\software(?=\\|$)/i, "$1\\SOFTWARE")
    .replace(/^HKEY_LOCAL_MACHINE\\system(?=\\|$)/i, `${HKLM}\\SYSTEM`)
    .replace(/\\ControlSet00\d(?=\\|$)/i, "\\CurrentControlSet");
}
const norm = (k: string) => canonicalKey(k).toUpperCase();

/** The keys a clean host carries, with their values and (named) subkeys. */
function baselineKeys(inv: EdrInvestigation): Map<string, { key: string; body: RegKey }> {
  const m = new Map<string, { key: string; body: RegKey }>();
  const put = (key: string, values: RegValue[], subkeys: string[] = []) => m.set(norm(key), { key, body: { values, subkeys } });
  const server = isServerHost(inv.host);

  const runs = baselineRunKeys(inv.host);
  put(RUN_HKLM, runs.filter(r => r.key === RUN_HKLM).map(({ name, type, data }) => ({ name, type, data })));
  put(RUN_HKCU, runs.filter(r => r.key === RUN_HKCU).map(({ name, type, data }) => ({ name, type, data })));
  put(RUNONCE_HKLM, []);
  put(RUNONCE_HKCU, []);
  put(WINLOGON, [
    { name: "AutoRestartShell", type: "REG_DWORD", data: "0x1" },
    { name: "AutoAdminLogon", type: "REG_SZ", data: "0" },
    { name: "LegalNoticeCaption", type: "REG_SZ", data: "" },
    { name: "Shell", type: "REG_SZ", data: "explorer.exe" },
    { name: "Userinit", type: "REG_SZ", data: "C:\\Windows\\system32\\userinit.exe," },
    { name: "WinStationsDisabled", type: "REG_SZ", data: "0" },
  ], ["AlternateShells", "GPExtensions", "UserDefaults", "AutoLogonChecked", "VolatileUserMgrKey"]);
  put(NT_WINDOWS, [
    { name: "AppInit_DLLs", type: "REG_SZ", data: "" },
    { name: "LoadAppInit_DLLs", type: "REG_DWORD", data: "0x0" },
    { name: "RequireSignedAppInit_DLLs", type: "REG_DWORD", data: "0x1" },
    { name: "Spooler", type: "REG_SZ", data: "yes" },
  ]);
  put(IFEO, [], ["DllNXOptions", "MsMpEng.exe", "MsSense.exe", "PresentationHost.exe", "SystemSettings.exe"]);
  put(`${DEFENDER_EXCLUSIONS}`, [], ["Extensions", "IpAddresses", "Paths", "Processes", "TemporaryPaths"]);
  for (const sub of ["Extensions", "IpAddresses", "Paths", "Processes", "TemporaryPaths"]) put(`${DEFENDER_EXCLUSIONS}\\${sub}`, []);
  put(WDIGEST, [
    { name: "DigestEncryptionAlgorithms", type: "REG_SZ", data: "3des,rc4" },
    { name: "Negotiate", type: "REG_DWORD", data: "0x0" },
    { name: "UTF8HTTPAuth", type: "REG_DWORD", data: "0x0" },
  ]);
  put(TERMINAL_SERVER, [
    { name: "AllowRemoteRPC", type: "REG_DWORD", data: "0x0" },
    // RDP is normally on for servers and off for workstations.
    { name: "fDenyTSConnections", type: "REG_DWORD", data: server ? "0x0" : "0x1" },
    { name: "fSingleSessionPerUser", type: "REG_DWORD", data: "0x1" },
  ], ["WinStations", "Wds"]);
  put(LSA, [
    { name: "Authentication Packages", type: "REG_MULTI_SZ", data: "msv1_0" },
    { name: "LimitBlankPasswordUse", type: "REG_DWORD", data: "0x1" },
    { name: "NoLmHash", type: "REG_DWORD", data: "0x1" },
    { name: "Notification Packages", type: "REG_MULTI_SZ", data: "scecli" },
    { name: "RunAsPPL", type: "REG_DWORD", data: server ? "0x1" : "0x2" },
    { name: "Security Packages", type: "REG_MULTI_SZ", data: "\"\"" },
  ]);
  put(HKCU_CLSID, []);

  const svc = baselineServices(inv.host, inv.edrAgent);
  for (const s of svc) {
    const dll = SERVICE_DLL[s.name.toLowerCase()];
    put(`${SERVICES}\\${s.name}`, [
      { name: "DisplayName", type: "REG_SZ", data: s.display },
      { name: "ErrorControl", type: "REG_DWORD", data: "0x1" },
      { name: "ImagePath", type: "REG_EXPAND_SZ", data: s.binPath },
      { name: "ObjectName", type: "REG_SZ", data: s.account },
      { name: "Start", type: "REG_DWORD", data: START_CODE[s.start] ?? "0x3" },
      { name: "Type", type: "REG_DWORD", data: dll ? "0x20" : "0x10" },
    ], dll ? ["Parameters", "Security"] : ["Security"]);
    if (dll) put(`${SERVICES}\\${s.name}\\Parameters`, [{ name: "ServiceDll", type: "REG_EXPAND_SZ", data: dll }, { name: "ServiceDllUnloadOnStop", type: "REG_DWORD", data: "0x1" }]);
  }
  put(SERVICES, [], svc.map(s => s.name));
  return m;
}

/** What the case's telemetry wrote, by key (autoruns carry "name    TYPE    data"). */
function storyValues(inv: EdrInvestigation): Map<string, { key: string; values: RegValue[] }> {
  const m = new Map<string, { key: string; values: RegValue[] }>();
  const add = (rawKey: string, v: RegValue) => {
    let key = canonicalKey(rawKey);
    // Sysmon's TargetObject ends with the value name: …\Run\Updater → key …\Run, value Updater.
    if (v.name && key.toUpperCase().endsWith(`\\${v.name.toUpperCase()}`)) key = key.slice(0, -(v.name.length + 1));
    const e = m.get(norm(key)) ?? { key, values: [] };
    const i = e.values.findIndex(x => x.name.toLowerCase() === v.name.toLowerCase());
    if (i >= 0) e.values[i] = v; else e.values.push(v);
    m.set(norm(key), e);
  };
  for (const a of inv.autoruns ?? []) {
    const mm = a.value.match(/^(.+?)\s{2,}(REG_\w+)\s{2,}(.*)$/);
    add(a.key, mm ? { name: mm[1].trim(), type: mm[2], data: mm[3], malicious: true } : { name: "(Default)", type: "REG_SZ", data: a.value, malicious: true });
  }
  for (const s of inv.persistence?.services ?? []) {
    add(`${SERVICES}\\${s.name}`, { name: "ImagePath", type: "REG_EXPAND_SZ", data: s.binPath, malicious: true });
    add(`${SERVICES}\\${s.name}`, { name: "ObjectName", type: "REG_SZ", data: s.account ?? "LocalSystem", malicious: true });
    add(`${SERVICES}\\${s.name}`, { name: "Start", type: "REG_DWORD", data: START_CODE[s.start ?? "DEMAND_START"] ?? "0x3", malicious: true });
    add(`${SERVICES}\\${s.name}`, { name: "Type", type: "REG_DWORD", data: "0x10", malicious: true });
  }
  return m;
}

/** Every key on the host: baseline merged with the story (a story value replaces a benign one of the same name). */
export function hostRegistry(inv: EdrInvestigation): Map<string, { key: string; body: RegKey }> {
  const reg = baselineKeys(inv);
  for (const [k, s] of storyValues(inv)) {
    const e = reg.get(k) ?? { key: s.key, body: { values: [], subkeys: [] } };
    for (const v of s.values) {
      const i = e.body.values.findIndex(x => x.name.toLowerCase() === v.name.toLowerCase());
      if (i >= 0) e.body.values[i] = v; else e.body.values.push(v);
    }
    reg.set(k, e);
  }
  // A key that exists has a parent that lists it.
  for (const { key } of [...reg.values()]) {
    const cut = key.lastIndexOf("\\");
    if (cut <= 0) continue;
    const parent = reg.get(norm(key.slice(0, cut)));
    const leaf = key.slice(cut + 1);
    if (parent && !parent.body.subkeys.some(s => s.toLowerCase() === leaf.toLowerCase())) parent.body.subkeys.push(leaf);
  }
  return reg;
}

const NOT_FOUND = "ERROR: The system was unable to find the specified registry key or value.";
const valueLine = (v: RegValue) => `    ${v.name || "(Default)"}    ${v.type}    ${v.data}`;

function render(key: string, body: RegKey, onlyValue?: string): string[] {
  const vals = onlyValue ? body.values.filter(v => v.name.toLowerCase() === onlyValue.toLowerCase()) : body.values;
  const out = ["", key, ...vals.map(valueLine)];
  if (!onlyValue && body.subkeys.length) out.push("", ...body.subkeys.map(s => `${key}\\${s}`));
  return out;
}

/** `reg query` after the verb: e.g. `"HKLM\...\Winlogon" /v Userinit`, `HKLM\...\Exclusions /s`. */
export function regQuery(inv: EdrInvestigation, argLine: string): string {
  const v = argLine.match(/\s\/v\s+("([^"]+)"|\S+)/i);
  const onlyValue = v ? (v[2] ?? v[1]) : undefined;
  const recursive = /\s\/s(\s|$)/i.test(` ${argLine}`);
  const keyArg = argLine.replace(/\s\/v\s+("[^"]+"|\S+)/i, "").replace(/(^|\s)\/(s|f)(?=\s|$)/gi, "").trim().replace(/^"|"$/g, "");
  if (!keyArg) return "ERROR: Invalid syntax.\nType \"REG QUERY /?\" for usage.";
  const reg = hostRegistry(inv);
  const hit = reg.get(norm(keyArg));
  if (!hit) return NOT_FOUND;
  if (!recursive) {
    const lines = render(hit.key, hit.body, onlyValue);
    if (onlyValue && lines.length <= 2) return NOT_FOUND;
    return lines.join("\n").replace(/^\n/, "");
  }
  // /s: this key then every key below it, in reg.exe's depth-first order.
  const prefix = norm(hit.key) + "\\";
  const below = [...reg.values()].filter(e => norm(e.key).startsWith(prefix)).sort((a, b) => a.key.localeCompare(b.key));
  const blocks = [hit, ...below].flatMap(e => {
    const vals = onlyValue ? e.body.values.filter(x => x.name.toLowerCase() === onlyValue.toLowerCase()) : e.body.values;
    if (onlyValue && !vals.length) return [];
    return ["", e.key, ...vals.map(valueLine)];
  });
  if (!blocks.length) return NOT_FOUND;
  const count = onlyValue ? blocks.filter(l => l.startsWith("    ")).length : null;
  return [...blocks, ...(count != null ? ["", `End of search: ${count} match(es) found.`] : [])].join("\n").replace(/^\n/, "");
}
