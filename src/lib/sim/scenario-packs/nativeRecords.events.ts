/**
 * Native-format records for the sources that have no vendor emitter yet (Infoblox DNS,
 * Kerberos 4768/4769, Remote Desktop Services operational log, 4648, 4722/4724, ...).
 *
 * The scenario packs listed in emitter-authored.test.ts must not type `raw: { ... }`
 * blocks by hand. A record that needs a native source with no emitter is built here
 * instead, once, so every field is the product's own field name and every caller gets
 * the same shape. Field names follow docs/log-schemas/ (windows-security.md,
 * dns-infoblox.md) and are checked by `npm run validate:logs`.
 *
 * Used only by the scenario packs of the 2026-10 story audit (batch 4).
 */
import type { TelemetryEvent, EventType, Severity } from "@/lib/sim/types";

const NO_DOMAIN = "NEXACORP";

/** Infoblox DNS query/response record (internal view). */
export function infobloxDns(o: {
  id: string; ts: string; host: string; srcIp: string; query: string; answer: string;
  member?: string; zone?: string; severity?: Severity; description: string;
}): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "dns", vendor: "Infoblox DNS", event_type: "dns_query",
    hostname: o.host, src_ip: o.srcIp, severity: o.severity ?? "informational",
    dns: { query: o.query, query_type: "A", response: o.answer, rcode: "NOERROR" },
    description: o.description,
    raw: {
      "dns.question.name": o.query,
      "dns.question.type": "A",
      "dns.question.class": "IN",
      "dns.answers.data": o.answer,
      "dns.answers.ttl": "300",
      "dns.response_code": "NOERROR",
      "dns.resolved_ip": o.answer,
      "infoblox.view": "internal",
      ...(o.zone ? { "infoblox.zone": o.zone } : {}),
      "infoblox.member": o.member ?? "DNS-CORE-01",
      "infoblox.rpz_policy": "",
      "source.ip": o.srcIp,
      "event.action": "dns-query",
      "event.outcome": "success",
    },
  };
}

/** 4768 (TGT request) or 4769 (service ticket request), written by the domain controller. */
export function winKerberos(o: {
  id: string; ts: string; eventId: "4768" | "4769"; dc: { hostname: string; fqdn: string };
  account: string; accountEmail: string; accountSid?: string; clientIp: string; clientPort: string;
  service: string; serviceSid: string; recordId: string; severity?: Severity; description: string;
}): TelemetryEvent {
  const isTgt = o.eventId === "4768";
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: "Windows Security",
    event_type: isTgt ? "kerberos_tgt" : "kerberos_tgs",
    hostname: o.dc.hostname, user_email: o.accountEmail, src_ip: o.clientIp,
    severity: o.severity ?? "informational",
    description: o.description,
    raw: {
      "winlog.event_id": o.eventId,
      "winlog.channel": "Security",
      "winlog.computer_name": o.dc.fqdn,
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      "winlog.record_id": o.recordId,
      "winlog.event_data.TargetUserName": isTgt ? o.account : `${o.account}@${NO_DOMAIN}.COM`,
      "winlog.event_data.TargetDomainName": `${NO_DOMAIN}.COM`,
      ...(isTgt && o.accountSid ? { "winlog.event_data.TargetSid": o.accountSid } : {}),
      "winlog.event_data.ServiceName": o.service,
      "winlog.event_data.ServiceSid": o.serviceSid,
      "winlog.event_data.TicketOptions": isTgt ? "0x40810010" : "0x40810000",
      "winlog.event_data.TicketEncryptionType": "0x12",
      ...(isTgt ? { "winlog.event_data.PreAuthType": "2" } : {}),
      "winlog.event_data.Status": "0x0",
      "winlog.event_data.IpAddress": `::ffff:${o.clientIp}`,
      "winlog.event_data.IpPort": o.clientPort,
      "event.code": o.eventId,
      "event.action": isTgt ? "kerberos-tgt-requested" : "kerberos-service-ticket-requested",
      "event.outcome": "success",
      "source.ip": o.clientIp,
      "user.name": o.account,
      "user.domain": NO_DOMAIN,
    },
  };
}

/** Remote Desktop Services operational log: 1149 (authentication succeeded) or 21 (session logon). */
export function winTerminalServices(o: {
  id: string; ts: string; code: "1149" | "21"; host: string; account: string; accountEmail: string;
  clientIp: string; sessionId?: string; geo?: TelemetryEvent["geo"]; description: string;
}): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: "Windows TerminalServices", event_type: "auth_success",
    hostname: o.host, user_email: o.accountEmail, src_ip: o.clientIp, severity: "informational",
    ...(o.geo ? { geo: o.geo } : {}),
    description: o.description,
    raw: o.code === "1149"
      ? {
          "event.code": "1149",
          "winlog.channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
          "winlog.provider_name": "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
          "winlog.event_data.User": o.account,
          "winlog.event_data.Domain": NO_DOMAIN,
          "winlog.event_data.Param3": o.clientIp,
          "event.action": "rdp-user-authentication-succeeded",
          "event.outcome": "success",
          "source.ip": o.clientIp,
        }
      : {
          "event.code": "21",
          "winlog.channel": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
          "winlog.provider_name": "Microsoft-Windows-TerminalServices-LocalSessionManager",
          "winlog.event_data.User": `${NO_DOMAIN}\\${o.account}`,
          "winlog.event_data.SessionID": o.sessionId ?? "2",
          "winlog.event_data.Address": o.clientIp,
          "event.action": "rdp-session-logon",
          "event.outcome": "success",
          "source.ip": o.clientIp,
        },
  };
}

/** 4648: a logon was attempted using explicit credentials (written on the machine that sent them). */
export function winExplicitCredentials(o: {
  id: string; ts: string; host: string; fqdn: string; subjectUser: string; subjectSid: string; subjectLogonId: string;
  userEmail: string; targetUser: string; targetServer: string; processName: string; processId: string;
  clientIp: string; recordId: string; severity?: Severity; description: string;
}): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: "Windows Security", event_type: "auth_success",
    hostname: o.host, user_email: o.userEmail, src_ip: o.clientIp, severity: o.severity ?? "low",
    authentication: { method: "Negotiate", result: "success" },
    description: o.description,
    raw: {
      "winlog.event_id": "4648",
      "winlog.channel": "Security",
      "winlog.computer_name": o.fqdn,
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      "winlog.record_id": o.recordId,
      "winlog.event_data.SubjectUserSid": o.subjectSid,
      "winlog.event_data.SubjectUserName": o.subjectUser,
      "winlog.event_data.SubjectDomainName": NO_DOMAIN,
      "winlog.event_data.SubjectLogonId": o.subjectLogonId,
      "winlog.event_data.TargetUserName": o.targetUser,
      "winlog.event_data.TargetDomainName": NO_DOMAIN,
      "winlog.event_data.TargetServerName": o.targetServer,
      "winlog.event_data.TargetInfo": `TERMSRV/${o.targetServer}`,
      "winlog.event_data.ProcessId": o.processId,
      "winlog.event_data.ProcessName": o.processName,
      "winlog.event_data.IpAddress": o.clientIp,
      "winlog.event_data.IpPort": "-",
      "event.code": "4648",
      "event.action": "logon-explicit-credentials",
      "event.outcome": "success",
      "source.ip": o.clientIp,
      "user.name": o.subjectUser,
      "user.domain": NO_DOMAIN,
    },
  };
}

/** 4724 (password reset attempt) or 4722 (account enabled), written by the domain controller. */
export function winAccountChange(o: {
  id: string; ts: string; eventId: "4724" | "4722"; dc: { hostname: string; fqdn: string };
  subjectUser: string; subjectSid: string; subjectLogonId: string; targetUser: string; targetSid: string;
  userEmail: string; recordId: string; severity?: Severity; description: string;
}): TelemetryEvent {
  const reset = o.eventId === "4724";
  const eventType: EventType = "account_modify";
  return {
    id: o.id, ts: o.ts, source: "ad", vendor: "Windows Security", event_type: eventType,
    hostname: o.dc.hostname, user_email: o.userEmail, severity: o.severity ?? "low",
    description: o.description,
    raw: {
      "winlog.event_id": o.eventId,
      "winlog.channel": "Security",
      "winlog.computer_name": o.dc.fqdn,
      "winlog.provider_name": "Microsoft-Windows-Security-Auditing",
      "winlog.record_id": o.recordId,
      "winlog.event_data.TargetUserName": o.targetUser,
      "winlog.event_data.TargetDomainName": NO_DOMAIN,
      "winlog.event_data.TargetSid": o.targetSid,
      "winlog.event_data.SubjectUserSid": o.subjectSid,
      "winlog.event_data.SubjectUserName": o.subjectUser,
      "winlog.event_data.SubjectDomainName": NO_DOMAIN,
      "winlog.event_data.SubjectLogonId": o.subjectLogonId,
      "event.code": o.eventId,
      "event.action": reset ? "password-reset" : "user-account-enabled",
      "event.outcome": "success",
      "user.name": o.subjectUser,
      "user.domain": NO_DOMAIN,
    },
  };
}
