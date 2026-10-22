import type { TelemetryEvent } from "@/lib/sim/types";

/** Windows Security records whose IpAddress is the REMOTE peer: a network / RDP logon, the
 *  privileges of that logon, explicit credentials, NTLM / Kerberos validation, share access. */
const PEER_CODES = /^(4624|4625|4648|4672|4776|4768|4769|4771|5140|5145)$/;

/** A row whose src_ip is the other end of a logon or share access, not this computer's own address. */
export function isPeerAddressedRecord(e: Pick<TelemetryEvent, "source" | "raw" | "src_ip">): boolean {
  if (e.source !== "windows_security" || !e.src_ip) return false;
  const code = String(e.raw?.["event.code"] ?? e.raw?.["winlog.event_id"] ?? "");
  return PEER_CODES.test(code);
}
