import type { RoomExperience, MechanicId } from "./types";
import { PHISHING_ANALYSIS } from "./phishingAnalysis";
import { INTRO_CYBERSECURITY } from "./introCybersecurity";
import { NETWORKING_FUNDAMENTALS } from "./networkingFundamentals";
import { SOC_STRUCTURE } from "./socStructure";
import { NETWORKING_PROTOCOLS } from "./networkingProtocols";
import { WINDOWS_FUNDAMENTALS } from "./windowsFundamentals";
import { LINUX_FUNDAMENTALS } from "./linuxFundamentals";
import { LOG_MANAGEMENT } from "./logManagement";
import { ENCODING_ENCRYPTION_HASHING } from "./encodingEncryptionHashing";
import { TIMESTAMPS_AND_TIMELINES } from "./timestampsAndTimelines";
import { LOG_ENTRY_ANATOMY } from "./logEntryAnatomy";
import { IDENTITY_BASICS } from "./identityBasics";
import { MALWARE_TYPES } from "./malwareTypes";
import { RISK_FUNDAMENTALS } from "./riskFundamentals";
import { VULNERABILITY_MANAGEMENT } from "./vulnerabilityManagement";
import { CYBER_KILL_CHAIN } from "./cyberKillChain";
import { FIREWALL_NETWORK_SECURITY } from "./firewallNetworkSecurity";
import { ENDPOINT_SECURITY_FUNDAMENTALS } from "./endpointSecurityFundamentals";
import { ANALYST_MINDSET } from "./analystMindset";
import { SECURITY_PRODUCTS_BEHAVIOUR } from "./securityProductsBehaviour";
import { WEB_APPLICATION_SECURITY } from "./webApplicationSecurity";
import { COMMODITY_INITIAL_ACCESS } from "./commodityInitialAccess";
import { MACOS_SECURITY_FUNDAMENTALS } from "./macosSecurityFundamentals";
import { WINDOWS_EVENT_LOGS } from "./windowsEventLogs";
import { LINUX_LOG_ANALYSIS } from "./linuxLogAnalysis";
import { SIEM_FUNDAMENTALS } from "./siemFundamentals";
import { LOG_SOURCES_INTEGRATION } from "./logSourcesIntegration";
import { EMAIL_SECURITY } from "./emailSecurity";
import { PROTOCOLS_MASTERCLASS } from "./protocolsMasterclass";
import { DLP_FUNDAMENTALS } from "./dlpFundamentals";
import { PERSISTENCE_MECHANISMS } from "./persistenceMechanisms";
import { POWERSHELL_FOR_SOC_ANALYST } from "./powershellForSocAnalyst";
import { WINDOWS_PRIVILEGE_ESCALATION } from "./windowsPrivilegeEscalation";
import { MITRE_ATTACK } from "./mitreAttack";
import { ACTIVE_DIRECTORY } from "./activeDirectory";
import { WAZUH_FUNDAMENTALS } from "./wazuhFundamentals";
import { SENTINEL_FUNDAMENTALS } from "./sentinelFundamentals";
import { DETECTION_RULES_TUNING } from "./detectionRulesTuning";
import { MICROSOFT_365_SECURITY } from "./microsoft365Security";
import { CROWDSTRIKE_FALCON } from "./crowdstrikeFalcon";
import { SENTINEL_ONE } from "./sentinelOne";
import { MALWARE_ANALYSIS_FUNDAMENTALS } from "./malwareAnalysisFundamentals";
import { ALERT_TRIAGE } from "./alertTriage";
import { DIGITAL_FORENSICS_BASICS } from "./digitalForensicsBasics";
import { VPN_MONITORING } from "./vpnMonitoring";
import { FIREWALL_LOG_ANALYSIS } from "./firewallLogAnalysis";
import { DNS_INVESTIGATION } from "./dnsInvestigation";
import { FIREWALL_MASTERCLASS } from "./firewallMasterclass";
import { AV_VS_EDR_MASTERCLASS } from "./avVsEdrMasterclass";
import { AI_ATTACKS_SOC_DETECTION } from "./aiAttacksSocDetection";
import { TCPIP_DEEP_DIVE } from "./tcpipDeepDive";
import { WEB_ATTACKS_PRACTICE } from "./webAttacksPractice";
import { ESXI_VIRTUALIZATION_SECURITY } from "./esxiVirtualizationSecurity";
import { HTML_SMUGGLING_AND_LOLBINS } from "./htmlSmugglingAndLolbins";
import { ENTRA_ID } from "./entraId";
import { EXCHANGE_ONLINE_SECURITY } from "./exchangeOnlineSecurity";
import { SHAREPOINT_TEAMS_MONITORING } from "./sharepointTeamsMonitoring";
import { DEFENDER_XDR } from "./defenderXdr";
import { IOC_ANALYSIS } from "./iocAnalysis";
import { INCIDENT_RESPONSE_METHODOLOGY } from "./incidentResponseMethodology";
import { INVESTIGATION_METHODOLOGY } from "./investigationMethodology";
import { AUTH_IDENTITY_MONITORING } from "./authIdentityMonitoring";
import { REPORTING_DOCUMENTATION } from "./reportingDocumentation";
import { CUSTOMER_COMMUNICATION } from "./customerCommunication";
import { NAC_MASTERCLASS } from "./nacMasterclass";
import { SOAR_AUTOMATION } from "./soarAutomation";

export type { RoomExperience, Station, Persona, MechanicId, ThemeId, BuildingKind, BriefingLab, StoryClip, SceneId, LayoutId, XrayIcon, EvidenceScreen } from "./types";

// Hand-authored rooms. Rooms without an entry stay Classic-only.
const EXPERIENCES: Record<string, RoomExperience> = {
  [PHISHING_ANALYSIS.roomId]: PHISHING_ANALYSIS,
  [INTRO_CYBERSECURITY.roomId]: INTRO_CYBERSECURITY,
  [NETWORKING_FUNDAMENTALS.roomId]: NETWORKING_FUNDAMENTALS,
  [SOC_STRUCTURE.roomId]: SOC_STRUCTURE,
  [NETWORKING_PROTOCOLS.roomId]: NETWORKING_PROTOCOLS,
  [WINDOWS_FUNDAMENTALS.roomId]: WINDOWS_FUNDAMENTALS,
  [LINUX_FUNDAMENTALS.roomId]: LINUX_FUNDAMENTALS,
  [LOG_MANAGEMENT.roomId]: LOG_MANAGEMENT,
  [ENCODING_ENCRYPTION_HASHING.roomId]: ENCODING_ENCRYPTION_HASHING,
  [TIMESTAMPS_AND_TIMELINES.roomId]: TIMESTAMPS_AND_TIMELINES,
  [LOG_ENTRY_ANATOMY.roomId]: LOG_ENTRY_ANATOMY,
  [IDENTITY_BASICS.roomId]: IDENTITY_BASICS,
  [MALWARE_TYPES.roomId]: MALWARE_TYPES,
  [RISK_FUNDAMENTALS.roomId]: RISK_FUNDAMENTALS,
  [VULNERABILITY_MANAGEMENT.roomId]: VULNERABILITY_MANAGEMENT,
  [CYBER_KILL_CHAIN.roomId]: CYBER_KILL_CHAIN,
  [FIREWALL_NETWORK_SECURITY.roomId]: FIREWALL_NETWORK_SECURITY,
  [ENDPOINT_SECURITY_FUNDAMENTALS.roomId]: ENDPOINT_SECURITY_FUNDAMENTALS,
  [ANALYST_MINDSET.roomId]: ANALYST_MINDSET,
  [SECURITY_PRODUCTS_BEHAVIOUR.roomId]: SECURITY_PRODUCTS_BEHAVIOUR,
  [WEB_APPLICATION_SECURITY.roomId]: WEB_APPLICATION_SECURITY,
  [COMMODITY_INITIAL_ACCESS.roomId]: COMMODITY_INITIAL_ACCESS,
  [MACOS_SECURITY_FUNDAMENTALS.roomId]: MACOS_SECURITY_FUNDAMENTALS,
  [WINDOWS_EVENT_LOGS.roomId]: WINDOWS_EVENT_LOGS,
  [LINUX_LOG_ANALYSIS.roomId]: LINUX_LOG_ANALYSIS,
  [SIEM_FUNDAMENTALS.roomId]: SIEM_FUNDAMENTALS,
  [LOG_SOURCES_INTEGRATION.roomId]: LOG_SOURCES_INTEGRATION,
  [EMAIL_SECURITY.roomId]: EMAIL_SECURITY,
  [PROTOCOLS_MASTERCLASS.roomId]: PROTOCOLS_MASTERCLASS,
  [DLP_FUNDAMENTALS.roomId]: DLP_FUNDAMENTALS,
  [PERSISTENCE_MECHANISMS.roomId]: PERSISTENCE_MECHANISMS,
  [POWERSHELL_FOR_SOC_ANALYST.roomId]: POWERSHELL_FOR_SOC_ANALYST,
  [WINDOWS_PRIVILEGE_ESCALATION.roomId]: WINDOWS_PRIVILEGE_ESCALATION,
  [MITRE_ATTACK.roomId]: MITRE_ATTACK,
  [ACTIVE_DIRECTORY.roomId]: ACTIVE_DIRECTORY,
  [WAZUH_FUNDAMENTALS.roomId]: WAZUH_FUNDAMENTALS,
  [SENTINEL_FUNDAMENTALS.roomId]: SENTINEL_FUNDAMENTALS,
  [DETECTION_RULES_TUNING.roomId]: DETECTION_RULES_TUNING,
  [MICROSOFT_365_SECURITY.roomId]: MICROSOFT_365_SECURITY,
  [CROWDSTRIKE_FALCON.roomId]: CROWDSTRIKE_FALCON,
  [SENTINEL_ONE.roomId]: SENTINEL_ONE,
  [MALWARE_ANALYSIS_FUNDAMENTALS.roomId]: MALWARE_ANALYSIS_FUNDAMENTALS,
  [ALERT_TRIAGE.roomId]: ALERT_TRIAGE,
  [DIGITAL_FORENSICS_BASICS.roomId]: DIGITAL_FORENSICS_BASICS,
  [VPN_MONITORING.roomId]: VPN_MONITORING,
  [FIREWALL_LOG_ANALYSIS.roomId]: FIREWALL_LOG_ANALYSIS,
  [DNS_INVESTIGATION.roomId]: DNS_INVESTIGATION,
  [FIREWALL_MASTERCLASS.roomId]: FIREWALL_MASTERCLASS,
  [AV_VS_EDR_MASTERCLASS.roomId]: AV_VS_EDR_MASTERCLASS,
  [AI_ATTACKS_SOC_DETECTION.roomId]: AI_ATTACKS_SOC_DETECTION,
  [TCPIP_DEEP_DIVE.roomId]: TCPIP_DEEP_DIVE,
  [WEB_ATTACKS_PRACTICE.roomId]: WEB_ATTACKS_PRACTICE,
  [ESXI_VIRTUALIZATION_SECURITY.roomId]: ESXI_VIRTUALIZATION_SECURITY,
  [HTML_SMUGGLING_AND_LOLBINS.roomId]: HTML_SMUGGLING_AND_LOLBINS,
  [ENTRA_ID.roomId]: ENTRA_ID,
  [EXCHANGE_ONLINE_SECURITY.roomId]: EXCHANGE_ONLINE_SECURITY,
  [SHAREPOINT_TEAMS_MONITORING.roomId]: SHAREPOINT_TEAMS_MONITORING,
  [DEFENDER_XDR.roomId]: DEFENDER_XDR,
  [IOC_ANALYSIS.roomId]: IOC_ANALYSIS,
  [INCIDENT_RESPONSE_METHODOLOGY.roomId]: INCIDENT_RESPONSE_METHODOLOGY,
  [INVESTIGATION_METHODOLOGY.roomId]: INVESTIGATION_METHODOLOGY,
  [AUTH_IDENTITY_MONITORING.roomId]: AUTH_IDENTITY_MONITORING,
  [REPORTING_DOCUMENTATION.roomId]: REPORTING_DOCUMENTATION,
  [CUSTOMER_COMMUNICATION.roomId]: CUSTOMER_COMMUNICATION,
  [NAC_MASTERCLASS.roomId]: NAC_MASTERCLASS,
  [SOAR_AUTOMATION.roomId]: SOAR_AUTOMATION,
};

/**
 * Returns the experience only if every station task id exists in the room and
 * the stations are contiguous and in room order — a stale config must fall
 * back to Classic, never render a broken hub.
 */
export function getRoomExperience(roomId: string, taskIds: readonly string[]): RoomExperience | null {
  const exp = EXPERIENCES[roomId];
  if (!exp) return null;
  const flat = exp.stations.flatMap(s => s.taskIds);
  if (flat.length !== taskIds.length) return null;
  if (flat.some((id, i) => id !== taskIds[i])) return null;
  return exp;
}

export function mechanicFor(type: string): MechanicId {
  switch (type) {
    case "reading":        return "intel_briefing";
    case "question":       return "lock_terminal";
    case "log_analysis":   return "evidence_board";
    case "analyst_choice": return "triage_desk";
    case "flag":           return "vault_keypad";
    default:               return "classic";
  }
}
