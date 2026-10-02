/**
 * One process instance → one identity, for every EDR / host-telemetry module (not a module itself).
 *
 * Rendering is per event (stateless), and the authored corpus does not number processes
 * consistently: the same USB_Backup_Tool.exe is pid 7712 on its process event and 4216 on the
 * registry write it made; an installer has a pid on its own row and none on the scheduled task it
 * registered. A UPID / S1 uid / MDE ProcessUniqueId seeded from the authored pid therefore broke
 * every parent → child and actor → action pivot. The identity is instead the INSTANCE KEY below,
 * and the OS pid is derived from it — so a process's own record, its children's parent fields, its
 * DNS / network / file / registry actions and the alert about it all carry the same ids.
 *
 * Instance key = company + host + image name + lifetime scope:
 *   - boot-scoped system singletons (services.exe, lsass.exe, svchost.exe, systemd …): one per host;
 *   - session-scoped shells (explorer.exe, userinit.exe, sihost.exe …): one per host + user + day —
 *     one user's Explorer never parents another user's process, or the same user's next-day work;
 *   - everything else: one per host + incident when the event belongs to one (a clipper that runs for
 *     two days before the alert is still ONE process), else one per host + day.
 * Known trade-off: two instances of the same image on one host on one day collapse into one id
 * (one corpus story runs powershell.exe twice from cmd.exe); every reference stays self-consistent.
 *
 * Windows pids / tids are multiples of 4 (the kernel allocates handle-table indexes in steps of 4);
 * Linux / macOS pids are plain integers.
 */
import type { NativeCtx } from "../types";

export type Os = "Win" | "Lin" | "Mac";
/** Where and when a process reference is made (the host, its OS, the event time, the event's user and incident). */
export interface ProcScope { host: string; os: Os; timeMs: number; user?: string; incident?: string }
/** Whatever an event says about a process. */
export interface ProcRef { name?: string; path?: string; cmdline?: string }

const lc = (s?: string) => (s ?? "").toLowerCase();
const baseOf = (p?: string) => (p ? p.split(/[\\/]/).pop() : undefined);
/** "C:\a\X.exe\X.exe" → "C:\a\X.exe" (a legacy FolderPath that already held the file name). */
const undouble = (p?: string) => {
  if (!p) return p;
  const m = /^(.*)([\\/])([^\\/]+)\2\3$/i.exec(p);
  return m ? `${m[1]}${m[2]}${m[3]}` : p;
};

/** The image name that identifies a process: name, else the path's file name, else the command line's first token. */
export function identityName(p: ProcRef): string | undefined {
  if (p.name) return p.name;
  const fromPath = baseOf(undouble(p.path));
  if (fromPath) return fromPath;
  const tok = p.cmdline?.trim().match(/^"([^"]+)"|^(\S+)/);
  return tok ? baseOf(tok[1] ?? tok[2]) : undefined;
}

/** One instance per host for the life of the boot. */
const SINGLETON = new Set(["system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
  "lsaiso.exe", "svchost.exe", "spoolsv.exe", "msmpeng.exe", "dns.exe", "sysmon64.exe", "sysmon.exe", "wmiprvse.exe",
  "systemd", "init", "sshd", "cron", "crond", "dockerd", "containerd", "kubelet", "auditd", "rsyslogd", "launchd", "kernel_task"]);
/** One instance per user logon session. */
const SESSION = new Set(["explorer.exe", "userinit.exe", "sihost.exe", "taskhostw.exe", "runtimebroker.exe", "dwm.exe", "ctfmon.exe",
  "finder", "dock", "loginwindow", "gnome-shell"]);

const dayOf = (ms: number) => new Date(ms).toISOString().slice(0, 10);

/** The instance key every id of this process is seeded from (undefined when the event names no image at all). */
export function procKey(ctx: NativeCtx, s: ProcScope, p: ProcRef): string | undefined {
  const name = lc(identityName(p));
  if (!name) return undefined;
  const host = lc(s.host);
  if (SINGLETON.has(name)) return `${ctx.companyId}:${host}:proc:boot:${name}`;
  if (SESSION.has(name)) return `${ctx.companyId}:${host}:proc:session:${lc(s.user) || "-"}:${dayOf(s.timeMs)}:${name}`;
  return `${ctx.companyId}:${host}:proc:${s.incident ? `inc:${s.incident}` : dayOf(s.timeMs)}:${name}`;
}

/** Round to the Windows allocation granularity (multiples of 4, never 0). */
export const win4 = (n: number) => Math.max(4, n - (n % 4));

/** The OS pid of the process — derived from its instance key, so every reference agrees. */
export function procPid(ctx: NativeCtx, s: ProcScope, p: ProcRef): number | undefined {
  const key = procKey(ctx, s, p);
  if (!key) return undefined;
  const name = lc(identityName(p));
  // The numbering follows the image itself (an .exe is a Windows process), never the event's OS
  // guess — which varies between events of one host when some carry no platform hint.
  const windows = name === "system" || name === "registry" || (/\.(exe|com|scr)$/i.test(name) && !(p.path ?? "").startsWith("/"));
  if (windows) {
    if (name === "system") return 4;
    if (name === "registry") return 92;
    return SINGLETON.has(name) ? ctx.int(`${key}:pid`, 100, 320) * 4 : ctx.int(`${key}:pid`, 250, 5000) * 4;
  }
  if (name === "systemd" || name === "init" || name === "launchd") return 1;
  return SINGLETON.has(name) ? ctx.int(`${key}:pid`, 300, 2000) : ctx.int(`${key}:pid`, 1000, 65000);
}

/**
 * The process that wrote a file when the event names none: a file a user drops into a profile
 * folder (Desktop, Documents …) by hand — a copy from a USB stick, a drag-and-drop out of a ZIP —
 * is written by that user's Explorer. Downloads / AppData / Temp writes are not inferred (a browser,
 * an installer or a script writes there, and the event would have to say which).
 */
export function inferredFileWriter(path: string | undefined, os: Os, systemUser: boolean): ProcRef | undefined {
  if (!path || os !== "Win" || systemUser) return undefined;
  if (/^[A-Za-z]:\\Users\\(?!Public\\)[^\\]+\\(Desktop|Documents|Pictures|Music|Videos)\\/i.test(path)) return { name: "explorer.exe", path: "C:\\Windows\\explorer.exe" };
  return undefined;
}

/** Command lines the OS itself starts these images with — the only parent command lines that can be stated without the event saying so. */
export const OS_COMMAND_LINE: Record<string, string> = {
  "explorer.exe": "C:\\WINDOWS\\Explorer.EXE",
  "userinit.exe": "C:\\WINDOWS\\system32\\userinit.exe",
  "services.exe": "C:\\WINDOWS\\system32\\services.exe",
  "wininit.exe": "wininit.exe",
  "winlogon.exe": "winlogon.exe",
  "lsass.exe": "C:\\WINDOWS\\system32\\lsass.exe",
};
/** The fixed parent of an OS image (explorer.exe is started by userinit.exe, services.exe by wininit.exe …). */
export const OS_PARENT: Record<string, string> = {
  "explorer.exe": "userinit.exe", "userinit.exe": "winlogon.exe", "services.exe": "wininit.exe", "lsass.exe": "wininit.exe",
  "svchost.exe": "services.exe", "spoolsv.exe": "services.exe", "msmpeng.exe": "services.exe", "wmiprvse.exe": "svchost.exe",
};
