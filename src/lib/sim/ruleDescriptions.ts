/**
 * Simple, clear rule descriptions for every event type.
 * Keyed by Windows Security Event ID (string) or event_type.
 * Format: short label, like a real SIEM rule title.
 * No Wazuh branding — pure ECS / Microsoft Sentinel style.
 */

// ── Windows Security Event ID → rule.description ──────────────────────────────
export const RULE_DESCRIPTIONS: Record<string, string> = {
  // Authentication & Account Logon
  "4624": "An account was successfully logged on",
  "4625": "Logon Failure - Unknown user or bad password",
  "4634": "An account was logged off",
  "4647": "User initiated logoff",
  "4648": "Logon attempt using explicit credentials",
  "4649": "A replay attack was detected",
  "4675": "SIDs were filtered",
  "4778": "Session reconnected to Window Station",
  "4779": "Session disconnected from Window Station",

  // Kerberos
  "4768": "Kerberos authentication ticket (TGT) requested",
  "4769": "Kerberos service ticket was requested",
  "4770": "Kerberos service ticket was renewed",
  "4771": "Kerberos pre-authentication failed",
  "4772": "Kerberos authentication ticket request failed",
  "4773": "Kerberos service ticket request failed",
  "4776": "NTLM credential validation attempted",
  "4820": "Kerberos TGT was denied - account restriction",

  // User Account Management
  "4720": "A user account was created",
  "4722": "A user account was enabled",
  "4723": "An attempt was made to change account password",
  "4724": "An attempt was made to reset account password",
  "4725": "A user account was disabled",
  "4726": "A user account was deleted",
  "4738": "A user account was changed",
  "4740": "A user account was locked out",
  "4767": "A user account was unlocked",
  "4781": "Account name was changed",

  // Group Management
  "4727": "Security-enabled global group created",
  "4728": "Member added to security-enabled global group",
  "4729": "Member removed from security-enabled global group",
  "4730": "Security-enabled global group deleted",
  "4731": "Security-enabled local group created",
  "4732": "Member added to security-enabled local group",
  "4733": "Member removed from security-enabled local group",
  "4756": "Member added to security-enabled universal group",
  "4757": "Member removed from security-enabled universal group",

  // Privilege & Policy
  "4672": "Special privileges assigned to new logon",
  "4673": "Privileged service was called",
  "4674": "Operation attempted on privileged object",
  "4688": "A new process has been created",
  "4689": "A process has exited",
  "4697": "A service was installed in the system",
  "4698": "A scheduled task was created",
  "4699": "A scheduled task was deleted",
  "4700": "A scheduled task was enabled",
  "4701": "A scheduled task was disabled",
  "4702": "A scheduled task was updated",

  // Object Access
  "4656": "Handle to an object was requested",
  "4660": "An object was deleted",
  "4663": "Attempt to access an object",
  "4670": "Permissions on an object were changed",

  // System Events
  "4608": "Windows is starting up",
  "4609": "Windows is shutting down",
  "4616": "System time was changed",
  "4618": "Monitored security event pattern occurred",
  "4621": "Administrator recovered system from CrashOnAuditFail",

  // Audit Policy
  "4719": "System audit policy was changed",
  "4907": "Auditing settings on object changed",
  "4908": "Special Groups Logon table changed",
  "4912": "Per-User Audit Policy changed",

  // Credential Access
  "4782": "Password hash of an account was accessed",
  "5379": "Credential Manager credentials read",
  "5381": "Vault credentials enumerated",

  // Windows Filtering Platform (network)
  "5140": "Network share accessed",
  "5142": "Network share added",
  "5143": "Network share modified",
  "5144": "Network share deleted",
  "5145": "Network share access check",
  "5152": "Windows Filtering Platform blocked a packet",
  "5154": "Windows Filtering Platform permitted an application",
  "5156": "Windows Filtering Platform permitted a connection",
  "5157": "Windows Filtering Platform blocked a connection",
  "5158": "Windows Filtering Platform permitted binding",
  "5159": "Windows Filtering Platform blocked binding",

  // Service Control
  "7034": "Service terminated unexpectedly",
  "7036": "Service entered running or stopped state",
  "7040": "Service start type changed",
  "7045": "A new service was installed in the system",

  // Sysmon Event IDs (provider: Microsoft-Windows-Sysmon)
  "1":  "Process creation detected",
  "2":  "Process changed file creation time",
  "3":  "Network connection detected",
  "4":  "Sysmon service state changed",
  "5":  "Process terminated",
  "6":  "Driver loaded",
  "7":  "Image loaded",
  "8":  "CreateRemoteThread detected",
  "9":  "RawAccessRead detected",
  "10": "Process memory access detected",
  "11": "File created",
  "12": "Registry object added or deleted",
  "13": "Registry value set",
  "14": "Registry object renamed",
  "15": "FileCreateStreamHash detected",
  "17": "Pipe created",
  "18": "Pipe connected",
  "19": "WMI Event filter registered",
  "20": "WMI Event consumer registered",
  "21": "WMI Event consumer-to-filter binding",
  "22": "DNS query detected",
  "23": "File deleted",
  "24": "Clipboard content captured",
  "25": "Process tampered",
  "26": "File delete logged",
  "255": "Sysmon error occurred",

  // event_type fallbacks (used when no event.code in raw)
  "auth_success":      "Logon Success",
  "auth_failure":      "Logon Failure - Unknown user or bad password",
  "mfa_challenge":     "MFA Challenge Issued to User",
  "mfa_denied":        "MFA Request Denied by User",
  "mfa_bypass":        "Sign-in completed without satisfying MFA requirement",
  "process_create":    "Process Creation Detected",
  "file_create":       "File Created on Endpoint",
  "file_modify":       "File Modified on Endpoint",
  "file_delete":       "File Deleted",
  "registry_set":      "Registry Value Modified",
  "net_connection":    "Network Connection Established",
  "net_blocked":       "Network Connection Blocked",
  "dns_query":         "DNS Query Observed",
  "vpn_login":         "VPN Session Authenticated",
  "vpn_logout":        "VPN Session Terminated",
  "email_received":    "Email Message Received",
  "email_sent":        "Email Message Sent",
  "sharepoint_access": "SharePoint Resource Accessed",
  "cloud_api_call":    "Cloud API Call Recorded",
  "account_modify":    "User Account Properties Modified",
  "account_create":    "User Account Created",
  "account_delete":    "User Account Deleted",
  "group_modify":      "Security Group Membership Changed",
  "account_lockout":   "User Account Locked Out",
  "privilege_escalation": "New privilege assigned to process access token",
  "role_assignment":   "Role Assignment Changed",
  "scheduled_task":    "Scheduled Task Created or Modified",
  "usb_connect":       "Removable Media Device Connected",
  "av_detection":      "Antivirus Threat Detected",
};

/**
 * Office 365 / Azure AD Operation → rule.description
 * Keyed by data.office365.Operation value (exact string from Microsoft audit log).
 * Format: "Service: Plain-English description."
 */
export const O365_RULE_DESCRIPTIONS: Record<string, string> = {
  // Azure Active Directory — Authentication
  "UserLoggedIn":                   "Azure Active Directory: User successfully logged in.",
  "UserLoginFailed":                "Azure Active Directory: User login failed.",
  "UserLoggedOut":                  "Azure Active Directory: User logged out.",
  "UserAccountDeleted":             "Azure Active Directory: User account was deleted.",
  "UserAccountCreated":             "Azure Active Directory: New user account created.",

  // Azure Active Directory — Password & Credentials
  "Change user password.":          "Azure Active Directory: User password was changed.",
  "Reset user password.":           "Azure Active Directory: User password was reset by admin.",
  "Set force change user password.":"Azure Active Directory: User must change password at next login.",
  "Update user.":                   "Azure Active Directory: User account properties updated.",
  "Update StsRefreshTokenValidFrom ForKey.": "Azure Active Directory: All user sessions invalidated.",

  // Azure Active Directory — MFA
  "UserStrongAuthEnrollmentInitiated": "Azure Active Directory: MFA enrollment started.",
  "UserStrongAuthEnrollmentComplete":  "Azure Active Directory: MFA enrollment completed.",
  "UserStrongAuthMethodDelete":        "Azure Active Directory: MFA method removed.",

  // Azure Active Directory — Application & Permissions
  "Consent to application.":          "Azure Active Directory: User consented to application permissions.",
  "Add service principal.":           "Azure Active Directory: Application registered in directory.",
  "Remove service principal.":        "Azure Active Directory: Application removed from directory.",
  "Add OAuth2PermissionGrant.":       "Azure Active Directory: OAuth2 permission grant added.",
  "Remove OAuth2PermissionGrant.":    "Azure Active Directory: OAuth2 permission grant removed.",
  "Add app role assignment to service principal.": "Azure Active Directory: App role assigned to service principal.",
  "Add member to group.":             "Azure Active Directory: Member added to directory group.",
  "Remove member from group.":        "Azure Active Directory: Member removed from directory group.",
  "Add owner to group.":              "Azure Active Directory: Owner added to group.",

  // Azure Active Directory — Conditional Access
  "Add named location.":              "Azure Active Directory: Named location added to Conditional Access.",
  "Delete named location.":           "Azure Active Directory: Named location removed from Conditional Access.",
  "Update conditional access policy.":"Azure Active Directory: Conditional Access policy updated.",

  // Exchange / Mail
  "MailboxLogin":                     "Exchange Online: User logged into mailbox.",
  "Create":                           "Exchange Online: Mail item created.",
  "Send":                             "Exchange Online: Email sent.",
  "HardDelete":                       "Exchange Online: Email permanently deleted.",
  "SoftDelete":                       "Exchange Online: Email moved to Deleted Items.",
  "MoveToDeletedItems":               "Exchange Online: Email moved to Deleted Items folder.",
  "UpdateInboxRules":                 "Exchange Online: Inbox rule created or modified.",
  "New-InboxRule":                    "Exchange Online: New inbox forwarding rule created.",
  "Set-InboxRule":                    "Exchange Online: Inbox rule updated.",
  "Remove-InboxRule":                 "Exchange Online: Inbox rule deleted.",
  "New-TransportRule":                "Exchange Online: Mail transport rule created.",
  "Set-Mailbox":                      "Exchange Online: Mailbox settings modified.",
  "Add-MailboxPermission":            "Exchange Online: Mailbox permissions granted.",

  // SharePoint / OneDrive
  "FileAccessed":                     "SharePoint Online: File was accessed.",
  "FileDownloaded":                   "SharePoint Online: File was downloaded.",
  "FileUploaded":                     "SharePoint Online: File was uploaded.",
  "FileModified":                     "SharePoint Online: File was modified.",
  "FileDeleted":                      "SharePoint Online: File was deleted.",
  "FileCopied":                       "SharePoint Online: File was copied.",
  "FileMoved":                        "SharePoint Online: File was moved.",
  "FileShared":                       "SharePoint Online: File was shared.",
  "AnonymousLinkCreated":             "SharePoint Online: Anonymous sharing link created.",
  "SharingInvitationCreated":         "SharePoint Online: Sharing invitation sent.",
  "SiteCollectionCreated":            "SharePoint Online: New site collection created.",

  // Defender for Office 365 — Threat Intelligence (RecordType 28)
  "TIMailData-Inline":                "Office 365: Phishing and malware events from Exchange Online Protection and Microsoft Defender for Office 365.",
  "TIMailData":                       "Office 365: Phishing and malware events from Exchange Online Protection and Microsoft Defender for Office 365.",
  "AntiPhishingOverride":             "Office 365: Anti-phishing policy override applied to message.",
  "TIUrlReputationData":              "Office 365: Malicious URL detected by Defender for Office 365.",
  "AtpDetection":                     "Office 365: Advanced Threat Protection detection triggered.",
  "SafeAttachmentZapResult":          "Office 365: Safe Attachments ZAP action completed.",
  "SafeAttachmentPolicy":             "Office 365: Safe Attachments policy applied to message.",
  "ThreatIntelligenceUrl":            "Office 365: Malicious URL clicked by user.",
  "ThreatIntelligenceAtpContent":     "Office 365: Malicious content detected in Office document.",

  // Exchange — Delegation & Permissions
  "AddMailboxDelegate":               "Exchange Online: Delegate access granted to mailbox.",
  "RemoveMailboxDelegate":            "Exchange Online: Delegate access removed from mailbox.",
  "New-ManagementRoleAssignment":     "Exchange Online: Management role assigned to user.",
  "AddMailboxPermission":             "Exchange Online: Full access permission granted to mailbox.",

  // Teams
  "MessageSent":                      "Microsoft Teams: Chat message sent.",
  "MeetingParticipantDetail":         "Microsoft Teams: Meeting attended.",
  "TeamCreated":                      "Microsoft Teams: New team created.",
  "ChannelCreated":                   "Microsoft Teams: New channel created.",

  // Azure / Cloud
  "CloudAppEvents":                   "Microsoft Defender: Cloud app activity detected.",
  "Add policy.":                      "Azure Active Directory: Policy added.",
  "Delete policy.":                   "Azure Active Directory: Policy deleted.",
};

/**
 * Attack-specific rule descriptions keyed by MITRE technique.
 * These override the generic descriptions when an attack is detected.
 */
export const MITRE_RULE_DESCRIPTIONS: Record<string, string> = {
  "T1566.001": "Inbound email with archive/macro attachment from untrusted sender",
  "T1566.002": "Inbound email with URL link to newly registered or uncategorized domain",
  "T1059.001": "PowerShell executed with -EncodedCommand or hidden window argument",
  "T1059.003": "Command shell spawned by non-standard parent process",
  "T1059.005": "Office application spawned child process via VBA macro",
  "T1204.002": "File executed shortly after download from browser or email client",
  "T1053.005": "Scheduled task created via schtasks.exe with unusual binary path",
  "T1547.001": "Registry Run key value added or modified",
  "T1543.003": "New Windows service installed",
  "T1003.001": "Process opened handle to lsass.exe with full memory access rights",
  "T1003":     "Suspicious access to LSASS process or SAM registry hive",
  "T1110.003": "Multiple authentication failures across accounts from single source IP",
  "T1110":     "Repeated authentication failures against single account exceeding threshold",
  "T1078":     "Valid account used from unusual location",
  "T1071.001": "Outbound HTTPS connection to uncategorized domain at regular interval",
  "T1071.004": "DNS queries with high-entropy subdomain labels and elevated query volume",
  "T1572":     "Unexpected protocol observed over standard port",
  "T1041":     "Sustained outbound byte volume anomaly on established session",
  "T1567.002": "Large upload to cloud storage service",
  "T1486":     "High-volume file rename/write to uncommon extension",
  "T1490":     "vssadmin or wmic invoked to delete volume shadow copies",
  "T1027":     "Encoded or obfuscated payload written to disk",
  "T1218.011": "Rundll32.exe loading unsigned or unusual DLL path",
  "T1562.001": "Security tool or service stopped, disabled, or configuration modified",
  "T1087.002": "High-volume LDAP queries against domain account objects",
  "T1018":     "Sequential connection attempts to multiple hosts across subnet",
  "T1021.001": "RDP logon session established between internal hosts",
  "T1021.002": "Admin share access via SMB",
  "T1021.006": "Windows Remote Management session established",
  "T1005":     "Bulk file read/copy from user profile or document directories",
  "T1098.001": "New credential or secret added to Azure AD application or service principal",
  "T1621":     "Multiple MFA push notifications sent to single user within short interval",
  "T1136.003": "New user or service principal provisioned in cloud tenant",
  "T1098.005": "OAuth application granted elevated permissions",
  "T1114.002": "Inbox rule created with forward or delete action on incoming mail",
  "T1530":     "Cloud storage data accessed",
  "T1552.001": "Plaintext password string pattern matched in file content",
  "T1048.003": "Outbound email with large attachment sent to external domain",
  "T1052.001": "Data copied to removable media",
  "T1070.001": "Security event logs cleared",
  "T1569.002": "PsExec or similar remote execution tool used",
};

/**
 * Exact Windows Event Viewer description text per Event ID.
 * Used as the primary DESCRIPTION column in the feed for Windows Security Events.
 * Source: Windows Security Event Log official Microsoft documentation.
 */
export const WIN_EVENT_VIEWER_DESCRIPTIONS: Record<string, string> = {
  // Authentication & Session
  "4624": "An account was successfully logged on.",
  "4625": "An account failed to log on.",
  "4634": "An account was logged off.",
  "4647": "User initiated logoff.",
  "4648": "A logon was attempted using explicit credentials.",
  "4649": "A replay attack was detected.",
  "4675": "SIDs were filtered.",
  "4778": "A session was reconnected to a Window Station.",
  "4779": "A session was disconnected from a Window Station.",

  // Kerberos
  "4768": "A Kerberos authentication ticket (TGT) was requested.",
  "4769": "A Kerberos service ticket was requested.",
  "4770": "A Kerberos service ticket was renewed.",
  "4771": "Kerberos pre-authentication failed.",
  "4772": "A Kerberos authentication ticket request failed.",
  "4773": "A Kerberos service ticket request failed.",
  "4776": "The domain controller attempted to validate the credentials for an account.",
  "4820": "A Kerberos Ticket-granting-ticket (TGT) was denied.",

  // Privileges & Special Logon
  "4672": "Special privileges assigned to new logon.",
  "4673": "A privileged service was called.",
  "4674": "An operation was attempted on a privileged object.",

  // Process Events
  "4688": "A new process has been created.",
  "4689": "A process has exited.",

  // Scheduled Tasks
  "4698": "A scheduled task was created.",
  "4699": "A scheduled task was deleted.",
  "4700": "A scheduled task was enabled.",
  "4701": "A scheduled task was disabled.",
  "4702": "A scheduled task was updated.",

  // User Account Management
  "4720": "A user account was created.",
  "4722": "A user account was enabled.",
  "4723": "An attempt was made to change an account's password.",
  "4724": "An attempt was made to reset an account's password.",
  "4725": "A user account was disabled.",
  "4726": "A user account was deleted.",
  "4738": "A user account was changed.",
  "4740": "A user account was locked out.",
  "4767": "A user account was unlocked.",
  "4781": "The name of an account was changed.",

  // Group Management
  "4727": "A security-enabled global group was created.",
  "4728": "A member was added to a security-enabled global group.",
  "4729": "A member was removed from a security-enabled global group.",
  "4730": "A security-enabled global group was deleted.",
  "4731": "A security-enabled local group was created.",
  "4732": "A member was added to a security-enabled local group.",
  "4733": "A member was removed from a security-enabled local group.",
  "4756": "A member was added to a security-enabled universal group.",
  "4757": "A member was removed from a security-enabled universal group.",

  // Object Access
  "4656": "A handle to an object was requested.",
  "4660": "An object was deleted.",
  "4663": "An attempt was made to access an object.",
  "4670": "Permissions on an object were changed.",

  // Audit Policy
  "4719": "System audit policy was changed.",

  // System Events
  "4608": "Windows is starting up.",
  "4609": "Windows is shutting down.",
  "4616": "The system time was changed.",

  // Services
  "4697": "A service was installed in the system.",
  "7045": "A new service was installed in the system.",

  // Network Share
  "5140": "A network share object was accessed.",
  "5142": "A network share object was added.",
  "5143": "A network share object was modified.",
  "5144": "A network share object was deleted.",

  // Filtering Platform (Windows Firewall)
  "5152": "The Windows Filtering Platform blocked a packet.",
  "5156": "The Windows Filtering Platform has permitted a connection.",
  "5157": "The Windows Filtering Platform has blocked a connection.",

  // Credential Access
  "4782": "The password hash of an account was accessed.",
  "5379": "Credential Manager credentials were read.",

  // Sysmon Event IDs (provider: Microsoft-Windows-Sysmon)
  "1":  "Process Create",
  "2":  "A process changed a file creation time.",
  "3":  "Network connection detected.",
  "4":  "Sysmon service state changed.",
  "5":  "Process terminated.",
  "6":  "Driver loaded.",
  "7":  "Image loaded.",
  "8":  "CreateRemoteThread detected.",
  "9":  "RawAccessRead detected.",
  "10": "Process accessed.",
  "11": "File created.",
  "12": "Registry object added or deleted.",
  "13": "Registry value set.",
  "14": "Registry object renamed.",
  "17": "Pipe created.",
  "18": "Pipe connected.",
  "22": "DNS query.",
  "23": "File deleted.",
  "25": "Process Tampering.",
};

/**
 * Look up the rule description for an event.
 * Priority: MITRE technique > O365 operation > Windows Event ID > event_type.
 */
export function getRuleDescription(
  eventType: string,
  mitreTechnique?: string,
  eventCode?: string,
  o365Operation?: string,
): string {
  if (mitreTechnique && MITRE_RULE_DESCRIPTIONS[mitreTechnique]) {
    return MITRE_RULE_DESCRIPTIONS[mitreTechnique];
  }
  if (o365Operation && O365_RULE_DESCRIPTIONS[o365Operation]) {
    return O365_RULE_DESCRIPTIONS[o365Operation];
  }
  if (eventCode && RULE_DESCRIPTIONS[eventCode]) {
    return RULE_DESCRIPTIONS[eventCode];
  }
  return RULE_DESCRIPTIONS[eventType] ?? "Security event detected";
}
