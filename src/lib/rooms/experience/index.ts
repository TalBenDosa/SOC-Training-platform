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
import { ASSET_CONTEXT_PRIORITISATION } from "./assetContextPrioritisation";
import { GOOGLE_WORKSPACE_SECURITY } from "./googleWorkspaceSecurity";
import { AI_ATTACKS_SOC_LLM_RISKS } from "./aiAttacksSocLlmRisks";
import { RMM_ABUSE_REMOTE_ACCESS_TOOLS } from "./rmmAbuseRemoteAccessTools";
import { DATA_STAGING_EXFILTRATION_CHANNELS } from "./dataStagingExfiltrationChannels";
import { OT_ICS_SECURITY } from "./otIcsSecurity";
import { USE_CASE_DEVELOPMENT } from "./useCaseDevelopment";
import { DNS_DEEP_DIVE } from "./dnsDeepDive";
import { TLS_ENCRYPTED_TRAFFIC } from "./tlsEncryptedTraffic";
import { WINDOWS_PROTOCOLS_LATERAL } from "./windowsProtocolsLateral";
import { EMAIL_PROTOCOLS_FORENSICS } from "./emailProtocolsForensics";
import { KERBEROS_AUTHENTICATION } from "./kerberosAuthentication";
import { MEMORY_DISK_FORENSICS } from "./memoryDiskForensics";
import { EDR_DETECTION_INVESTIGATION } from "./edrDetectionInvestigation";
import { RANSOMWARE_FULL_LIFECYCLE } from "./ransomwareFullLifecycle";
import { THREAT_INTELLIGENCE } from "./threatIntelligence";
import { CLOUD_SECURITY_MONITORING } from "./cloudSecurityMonitoring";
import { ESCALATION_PROCEDURES } from "./escalationProcedures";
import { CREDENTIAL_ATTACKS_PRACTICE } from "./credentialAttacksPractice";
import { PLAYBOOK_EXECUTION_AND_ESCALATION } from "./playbookExecutionAndEscalation";
import { REMOTE_EMAIL_COLLECTION } from "./remoteEmailCollection";
import { DEVICE_REGISTRATION_PERSISTENCE } from "./deviceRegistrationPersistence";
import { INVESTIGATE_ALERT_WORKFLOW } from "./investigateAlertWorkflow";
import { INCIDENT_REPORT_WRITING } from "./incidentReportWriting";
import { OKTA_IDENTITY_FUNDAMENTALS } from "./oktaIdentityFundamentals";
import { AI_ATTACKS_SOC_SOCIAL } from "./aiAttacksSocSocial";
import { VISHING_HELPDESK_SOCIAL_ENGINEERING } from "./vishingHelpdeskSocialEngineering";
import { THREAT_HUNTING_FUNDAMENTALS } from "./threatHuntingFundamentals";
import { PRIVILEGED_ACCESS_MONITORING } from "./privilegedAccessMonitoring";
import { DETECTION_ENGINEERING } from "./detectionEngineering";
import { EDGE_CASE_USECASES } from "./edgeCaseUsecases";
import { TUNNELING_C2_CHANNELS } from "./tunnelingC2Channels";

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
  [ASSET_CONTEXT_PRIORITISATION.roomId]: ASSET_CONTEXT_PRIORITISATION,
  [GOOGLE_WORKSPACE_SECURITY.roomId]: GOOGLE_WORKSPACE_SECURITY,
  [AI_ATTACKS_SOC_LLM_RISKS.roomId]: AI_ATTACKS_SOC_LLM_RISKS,
  [RMM_ABUSE_REMOTE_ACCESS_TOOLS.roomId]: RMM_ABUSE_REMOTE_ACCESS_TOOLS,
  [DATA_STAGING_EXFILTRATION_CHANNELS.roomId]: DATA_STAGING_EXFILTRATION_CHANNELS,
  [OT_ICS_SECURITY.roomId]: OT_ICS_SECURITY,
  [USE_CASE_DEVELOPMENT.roomId]: USE_CASE_DEVELOPMENT,
  [DNS_DEEP_DIVE.roomId]: DNS_DEEP_DIVE,
  [TLS_ENCRYPTED_TRAFFIC.roomId]: TLS_ENCRYPTED_TRAFFIC,
  [WINDOWS_PROTOCOLS_LATERAL.roomId]: WINDOWS_PROTOCOLS_LATERAL,
  [EMAIL_PROTOCOLS_FORENSICS.roomId]: EMAIL_PROTOCOLS_FORENSICS,
  [KERBEROS_AUTHENTICATION.roomId]: KERBEROS_AUTHENTICATION,
  [MEMORY_DISK_FORENSICS.roomId]: MEMORY_DISK_FORENSICS,
  [EDR_DETECTION_INVESTIGATION.roomId]: EDR_DETECTION_INVESTIGATION,
  [RANSOMWARE_FULL_LIFECYCLE.roomId]: RANSOMWARE_FULL_LIFECYCLE,
  [THREAT_INTELLIGENCE.roomId]: THREAT_INTELLIGENCE,
  [CLOUD_SECURITY_MONITORING.roomId]: CLOUD_SECURITY_MONITORING,
  [ESCALATION_PROCEDURES.roomId]: ESCALATION_PROCEDURES,
  [CREDENTIAL_ATTACKS_PRACTICE.roomId]: CREDENTIAL_ATTACKS_PRACTICE,
  [PLAYBOOK_EXECUTION_AND_ESCALATION.roomId]: PLAYBOOK_EXECUTION_AND_ESCALATION,
  [REMOTE_EMAIL_COLLECTION.roomId]: REMOTE_EMAIL_COLLECTION,
  [DEVICE_REGISTRATION_PERSISTENCE.roomId]: DEVICE_REGISTRATION_PERSISTENCE,
  [INVESTIGATE_ALERT_WORKFLOW.roomId]: INVESTIGATE_ALERT_WORKFLOW,
  [INCIDENT_REPORT_WRITING.roomId]: INCIDENT_REPORT_WRITING,
  [OKTA_IDENTITY_FUNDAMENTALS.roomId]: OKTA_IDENTITY_FUNDAMENTALS,
  [AI_ATTACKS_SOC_SOCIAL.roomId]: AI_ATTACKS_SOC_SOCIAL,
  [VISHING_HELPDESK_SOCIAL_ENGINEERING.roomId]: VISHING_HELPDESK_SOCIAL_ENGINEERING,
  [THREAT_HUNTING_FUNDAMENTALS.roomId]: THREAT_HUNTING_FUNDAMENTALS,
  [PRIVILEGED_ACCESS_MONITORING.roomId]: PRIVILEGED_ACCESS_MONITORING,
  [DETECTION_ENGINEERING.roomId]: DETECTION_ENGINEERING,
  [EDGE_CASE_USECASES.roomId]: EDGE_CASE_USECASES,
  [TUNNELING_C2_CHANNELS.roomId]: TUNNELING_C2_CHANNELS,
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
