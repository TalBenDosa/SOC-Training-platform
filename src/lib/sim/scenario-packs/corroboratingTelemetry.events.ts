/**
 * Typed record builders for the corroborating sources of the endpoint-malware stories.
 *
 * The packs that use them (multi-host intrusion, ISO container, ClickFix, SEO-poisoned installer)
 * keep every vendor block out of the pack file itself: a mail-gateway delivery and click, the
 * Sysmon Zone.Identifier stream (Event 15), a Falcon in-memory script scan and a threat-intel
 * lookup are rendered here, once, from typed arguments. Each builder returns a complete
 * TelemetryEvent whose raw block uses only fields the vendor documents (docs/log-schemas).
 *
 * Events-only module: no scenario text, safe for the live feed's client bundle.
 */
import type { TelemetryEvent, Severity } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

// ── Proofpoint TAP: a message delivered, and the click on its rewritten URL ───────────────
export interface MailDeliveredOpts {
  id: string; ts: string; incidentId: string;
  user: string; userTitle?: string;
  sender: string; headerFrom: string; subject: string; messageId: string; senderIp: string; qid: string;
  url: string; urlRewritten: string; domain: string;
  spf: string; dkim: string; dmarc: string; phishScore: number; spamScore: number;
  severity?: Severity; mitre?: string; tactic?: string; description: string;
}
export function mailDelivered(o: MailDeliveredOpts): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "email_gateway", vendor: "Proofpoint",
    event_type: "email_received", severity: o.severity ?? "low",
    mitre_technique: o.mitre, mitre_tactic: o.tactic,
    user_email: o.user, user_title: o.userTitle, incident_id: o.incidentId,
    network: { url: o.url, domain: o.domain },
    description: o.description,
    raw: {
      "pps.QID": o.qid,
      "pps.messageID": o.messageId,
      "pps.sender": o.sender,
      "pps.headerFrom": o.headerFrom,
      "pps.recipient": o.user,
      "pps.subject": o.subject,
      "pps.senderIP": o.senderIp,
      "pps.spf": o.spf,
      "pps.dkim": o.dkim,
      "pps.dmarc": o.dmarc,
      "pps.phishScore": o.phishScore,
      "pps.spamScore": o.spamScore,
      "pps.policyRoutes": ["default_inbound"],
      "pps.urls[0]": o.url,
      "pps.urls[0].rewritten": o.urlRewritten,
      "pps.action": "delivered",
    },
  };
}

export interface MailClickOpts {
  id: string; ts: string; incidentId: string;
  user: string; userTitle?: string; sender: string; messageId: string; qid: string;
  url: string; domain: string; clickIp: string; userAgent: string;
  severity?: Severity; description: string;
}
export function mailClick(o: MailClickOpts): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "email_gateway", vendor: "Proofpoint",
    event_type: "email_clicked", severity: o.severity ?? "medium",
    user_email: o.user, user_title: o.userTitle, incident_id: o.incidentId, src_ip: o.clickIp,
    network: { url: o.url, domain: o.domain, user_agent: o.userAgent },
    description: o.description,
    raw: {
      "pps.clickTime": o.ts,
      "pps.QID": o.qid,
      "pps.messageID": o.messageId,
      "pps.recipient": o.user,
      "pps.url": o.url,
      "pps.clickIP": o.clickIp,
      "pps.userAgent": o.userAgent,
      "pps.clickStatus": "permitted",
      "pps.sender": o.sender,
    },
  };
}

// ── Sysmon Event 15: FileCreateStreamHash (the Zone.Identifier alternate data stream) ────
export interface ZoneStreamOpts {
  id: string; ts: string; incidentId: string;
  host: string; user: string; userDomainName: string;
  target: string;               // e.g. C:\Users\x\Downloads\f.iso:Zone.Identifier
  image: string; pid: number;
  contents: string;             // the stream text ([ZoneTransfer] …)
  description: string;
}
export function zoneStream(o: ZoneStreamOpts): TelemetryEvent {
  const name = o.target.split("\\").pop() ?? o.target;
  return {
    id: o.id, ts: o.ts, source: "sysmon", vendor: "Microsoft Sysmon", event_type: "file_create", severity: "low",
    hostname: o.host, user_email: o.user, incident_id: o.incidentId,
    file: { name, path: o.target },
    description: o.description,
    raw: {
      "winlog.channel": "Microsoft-Windows-Sysmon/Operational",
      "winlog.provider_name": "Microsoft-Windows-Sysmon",
      "winlog.computer_name": o.host,
      "winlog.event_id": "15",
      "winlog.event_data.RuleName": "-",
      "winlog.event_data.UtcTime": o.ts,
      "winlog.event_data.Image": o.image,
      "winlog.event_data.ProcessId": String(o.pid),
      "winlog.event_data.TargetFilename": o.target,
      "winlog.event_data.CreationUtcTime": o.ts,
      "winlog.event_data.Hash": `SHA256=${makeSha256(`zone:${o.target.split(":").slice(0, 2).join(":")}:${o.contents}`).toUpperCase()}`,
      "winlog.event_data.Contents": o.contents,
      "winlog.event_data.User": o.userDomainName,
      "event.code": "15",
      "event.action": "file-stream-created",
      "host.name": o.host,
    },
  };
}

// ── CrowdStrike Falcon ScriptControlScanTelemetry: script text run in memory ─────────────
export interface ScriptScanOpts {
  id: string; ts: string; incidentId: string;
  host: string; user: string; userEmail: string; srcIp: string; sensorId: string; userDomainName: string;
  content: string; cmdline: string; parentPath: string;
  hostProcessPath: string;      // the NT device path of the interpreter
  description: string;
}
export function scriptScan(o: ScriptScanOpts): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "edr", vendor: "CrowdStrike Falcon", event_type: "file_access", severity: "medium",
    hostname: o.host, user_email: o.userEmail, src_ip: o.srcIp, incident_id: o.incidentId, description: o.description,
    raw: {
      "crowdstrike.event_simpleName": "ScriptControlScanTelemetry",
      "crowdstrike.event_platform": "Win",
      "crowdstrike.aid": o.sensorId,
      "crowdstrike.ComputerName": o.host,
      "crowdstrike.UserName": o.userDomainName,
      "crowdstrike.ScriptContent": o.content,
      "crowdstrike.ScriptContentName": "-",
      "crowdstrike.ContentSHA256HashData": makeSha256(`scriptscan:${o.content}`),
      "crowdstrike.OriginalContentLength": String(o.content.length),
      "crowdstrike.ImageFileName": o.hostProcessPath,
      "crowdstrike.CommandLine": o.cmdline,
      "crowdstrike.ParentImageFileName": o.parentPath,
    },
  };
}

// ── Recorded Future: an entity lookup (risk rows) ─────────────────────────────────────────
export interface IntelRow { entity: string; type: string; riskScore: number; riskString: string; evidence: { rule: string; criticality: string }[]; registration?: { created: string; registrar: string; ageDays: number } }
export function intelLookup(o: { id: string; ts: string; incidentId: string; message: string; rows: IntelRow[]; severity?: Severity; description: string }): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "threat_intel", vendor: "Recorded Future", event_type: "threat_intel_match",
    severity: o.severity ?? "medium", incident_id: o.incidentId, description: o.description,
    raw: {
      "vendor.product": "Recorded Future Intelligence Cloud",
      "message": o.message,
      "full_log": JSON.stringify(o.rows.map(r => ({
        entity: r.entity, type: r.type, riskScore: r.riskScore, riskString: r.riskString, evidenceDetails: r.evidence,
        ...(r.registration ? { registration: r.registration } : {}),
      }))),
    },
  };
}
