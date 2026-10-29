/**
 * Loaded modules (DLLs) of a process, as the EDR's image-load telemetry shows them
 * (Sysmon Event 7 ImageLoaded / Signed / Signature, Defender DeviceImageLoadEvents,
 * Sysinternals ListDLLs). Every user-mode Windows process loads the same core system
 * DLLs; what the process does adds more (a process that talks to the network loads the
 * socket and TLS stack, PowerShell loads the CLR and AMSI). The case's own suspicious
 * DLL is layered on top from the process's `modules` field.
 *
 * Nothing is labelled malicious. The tell the analyst has to find is an UNSIGNED module
 * loaded from a user-writable path (AppData/Temp), or a system DLL name loaded from the
 * application's own folder instead of System32 (DLL side-loading). Base addresses and
 * sizes are deterministic per host + process + path, never random, and are simulated
 * placeholders — like the rest of the console, realistic, not real.
 */
import type { EdrModule, EdrProcess } from "./investigations";

function fnv(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  return h >>> 0;
}
/** A plausible, deterministic 64-bit image base for a DLL in a process. */
function imageBase(seed: string): string {
  const hi = 0x7ff8 + (fnv(seed) % 0x6ff);                 // user-space high range, like real ASLR bases
  const lo = (fnv(seed + "lo") % 0xf0000) & 0xffff0000 >>> 0;
  return `0x${hi.toString(16)}${(lo >>> 0).toString(16).padStart(8, "0")}`;
}
function sizeOf(seed: string): string {
  const kb = 40 + (fnv(seed) % 2600);                      // 40 KB .. ~2.6 MB
  return `${(kb * 1024).toLocaleString("en-US")}`;
}

const S32 = "C:\\Windows\\System32\\";
const MSWIN = "Microsoft Windows";
const MSWPUB = "Microsoft Windows Publisher";

// The modules essentially every user-mode process has mapped.
const CORE = ["ntdll.dll", "KERNEL32.DLL", "KERNELBASE.dll", "msvcrt.dll", "ucrtbase.dll", "RPCRT4.dll",
  "combase.dll", "sechost.dll", "ADVAPI32.dll", "bcryptPrimitives.dll"];
// Added by anything with a window / shell integration.
const UI = ["USER32.dll", "win32u.dll", "GDI32.dll", "gdi32full.dll", "SHELL32.dll", "SHCORE.dll", "shlwapi.dll", "IMM32.DLL"];
// Added by anything that talks to the network.
const NET = ["WS2_32.dll", "mswsock.dll", "DNSAPI.dll", "IPHLPAPI.DLL", "NSI.dll", "CRYPT32.dll", "CRYPTSP.dll", "rsaenh.dll", "WININET.dll", "WINHTTP.dll", "SCHANNEL.DLL", "ncrypt.dll"];
// Added by a .NET / PowerShell host.
const CLR = ["clr.dll", "clrjit.dll", "mscoreei.dll", "mscoree.dll", "System.Management.Automation.dll", "amsi.dll"];

const isNetworky = (p: EdrProcess) => /powershell|pwsh|rundll32|regsvr32|curl|chrome|msedge|firefox|outlook|svchost|mshta|wscript|cscript|certutil|bitsadmin/i.test(p.name);
const isUi = (p: EdrProcess) => !/^(svchost|services|lsass|smss|csrss|wininit|wmiprvse|conhost)\.exe$/i.test(p.name);
const isDotNet = (p: EdrProcess) => /powershell|pwsh/i.test(p.name) || (p.modules ?? []).some(m => /\.(net|clr)|System\./i.test(m.path));

/** The normal system DLLs a process of this kind has mapped, newest Windows signer. */
function baselineModules(p: EdrProcess): EdrModule[] {
  const names = new Set<string>(CORE);
  if (isUi(p)) UI.forEach(n => names.add(n));
  if (isNetworky(p)) NET.forEach(n => names.add(n));
  if (isDotNet(p)) CLR.forEach(n => names.add(n));
  return [...names].map(n => {
    // The CLR assemblies live under the .NET framework dir, the rest under System32.
    const path = /clr|mscore|System\.|amsi/i.test(n)
      ? (n.startsWith("System.") ? `C:\\Windows\\Microsoft.NET\\assembly\\GAC_MSIL\\${n.replace(/\.dll$/i, "")}\\v4.0_4.0.0.0__31bf3856ad364e35\\${n}` : `C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\${n}`)
      : `${S32}${n}`;
    return { path, signed: true, signer: MSWPUB, loadedAt: "—" };
  });
}

/** Every module in the process right now: the normal system set + the case's own DLLs. */
export function processModules(p: EdrProcess): EdrModule[] {
  const own = p.modules ?? [];
  const ownPaths = new Set(own.map(m => m.path.toLowerCase()));
  const base = baselineModules(p).filter(m => !ownPaths.has(m.path.toLowerCase()));
  const all = [...base, ...own];
  // Fill deterministic base/size; keep the order loader-like (ntdll first, app DLLs last).
  return all
    .map(m => ({ ...m, _base: imageBase(`${p.name}|${p.pid}|${m.path}`), _size: sizeOf(`${p.name}|${m.path}`) }))
    .sort((a, b) => {
      const sys = (m: EdrModule) => /\\System32\\ntdll\.dll$/i.test(m.path) ? 0 : /\\System32\\/i.test(m.path) ? 1 : /Microsoft\.NET/i.test(m.path) ? 2 : 3;
      return sys(a) - sys(b) || a.path.localeCompare(b.path);
    });
}

/** The same, formatted for ListDLLs-style text (used by the RTR `listdlls`/`modules` command). */
export function modulesText(p: EdrProcess): string {
  const rows = processModules(p) as (EdrModule & { _base?: string; _size?: string })[];
  const w = Math.min(70, Math.max(20, ...rows.map(r => r.path.length)));
  return [
    `${p.name} pid: ${p.pid}`,
    "Base               Size       Signed  Path",
    ...rows.map(r => `${(r._base ?? "").padEnd(18)} ${(r._size ?? "").padStart(9)}  ${(r.signed ? "Yes" : "NO ").padEnd(6)}  ${r.path}`),
  ].join("\n");
}
