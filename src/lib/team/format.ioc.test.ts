import { describe, expect, it } from "vitest";
import { detectIocType, isValidIoc } from "./format";

describe("manual indicators (escalation report)", () => {
  it.each([
    ["reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f", "command"],
    ["powershell.exe -nop -w hidden -enc SQBFAFgA", "command"],
    ["C:\\Windows\\System32\\rundll32.exe C:\\Users\\Public\\x.dll,Start", "command"],
    ["curl -fsSL http://198.51.100.7/i.sh", "command"],
    ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "registry"],
    ["C:\\Users\\Public\\Documents\\svc.exe", "file_path"],
    ["/tmp/.ml/.sync/agentd", "file_path"],
    ["AnyDesk.exe", "process"],
    ["https://login.example.com/oauth?x=1", "url"],
    ["198.51.100.7", "ip"],
    ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"],
    ["a.cohen@nexacorp.com", "email"],
    ["evil-cdn.example", "domain"],
    ["WS-FIN-2847", "host"],
  ])("%s → %s, accepted", (v, type) => {
    expect(detectIocType(v)).toBe(type);
    expect(isValidIoc(v)).toBe(true);
  });

  it.each(["asdf", "Admin", "lateral movement?", "upon further actions", ""])("rejects free text: %j", v => {
    expect(isValidIoc(v)).toBe(false);
  });
});
