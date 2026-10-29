import { describe, it, expect } from "vitest";
import { processModules, modulesText } from "./modules";
import type { EdrProcess } from "./investigations";

const proc = (over: Partial<EdrProcess> = {}): EdrProcess => ({
  pid: 6388, ppid: 6240, name: "rundll32.exe", cmdline: "rundll32.exe x.dll,Start",
  user: "CORP\\r.bakker", path: "C:\\Windows\\System32\\rundll32.exe", signed: true, startedAt: "09:42:01", verdict: "malicious", ...over,
});

describe("processModules", () => {
  it("includes the normal system DLLs every process has mapped", () => {
    const paths = processModules(proc()).map(m => m.path.toLowerCase());
    for (const core of ["ntdll.dll", "kernel32.dll", "kernelbase.dll"]) expect(paths.some(p => p.endsWith("\\" + core))).toBe(true);
    expect(processModules(proc()).every(m => m.signed)).toBe(true); // nothing malicious without a planted module
  });

  it("surfaces the case's own unsigned module and keeps the baseline signed", () => {
    const evil = "C:\\Users\\r.bakker\\AppData\\Roaming\\svc\\update.dll";
    const mods = processModules(proc({ modules: [{ path: evil, signed: false, loadedAt: "09:42:01" }] }));
    const bad = mods.find(m => m.path === evil)!;
    expect(bad).toBeDefined();
    expect(bad.signed).toBe(false);
    // it is the ONLY unsigned module; the system DLLs stay signed
    expect(mods.filter(m => !m.signed)).toHaveLength(1);
  });

  it("does not duplicate a module the baseline and the case both name", () => {
    const ntdll = "C:\\Windows\\System32\\ntdll.dll";
    const mods = processModules(proc({ modules: [{ path: ntdll, signed: true }] }));
    expect(mods.filter(m => m.path.toLowerCase() === ntdll.toLowerCase())).toHaveLength(1);
  });

  it("is deterministic (same process -> same module list and text)", () => {
    expect(modulesText(proc())).toBe(modulesText(proc()));
  });

  it("gives a .NET host the CLR and AMSI; a plain exe does not load the socket stack", () => {
    const ps = processModules(proc({ name: "powershell.exe", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" }));
    expect(ps.some(m => /amsi\.dll$/i.test(m.path))).toBe(true);
    const notepad = processModules(proc({ name: "notepad.exe", path: "C:\\Windows\\System32\\notepad.exe" }));
    expect(notepad.some(m => /ws2_32\.dll$/i.test(m.path))).toBe(false);
  });
});
