/**
 * Hunting queries: real analyst queries over the mapped tables. A query on a table the shop does not
 * feed returns no rows, as it does in a real workspace.
 */
import type { HuntingQuery } from "./types";

type Q = Omit<HuntingQuery, "id" | "dataSources"> & { tables: string[] };

const QUERIES: Record<string, Q> = {
  // ── Identity ───────────────────────────────────────────────────────────
  "identity-password-spray": {
    name: "One address failing against many accounts", description: "Password spraying leaves few failures per account and many accounts per address.",
    tactics: ["CredentialAccess"], techniques: ["T1110.003"], tables: ["SigninLogs"],
    query: `SigninLogs
| where ResultType != "0"
| summarize Failures = count(), Accounts = dcount(UserPrincipalName), Users = make_set(UserPrincipalName, 10) by IPAddress
| where Accounts >= 3
| sort by Accounts desc`,
  },
  "identity-failed-then-success": {
    name: "Sign-in success after repeated failures", description: "Accounts with several failures that then signed in from the same address.",
    tactics: ["CredentialAccess", "InitialAccess"], techniques: ["T1110", "T1078"], tables: ["SigninLogs"],
    query: `SigninLogs
| summarize Failures = countif(ResultType != "0"), Successes = countif(ResultType == "0"), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by UserPrincipalName, IPAddress
| where Failures >= 2 and Successes >= 1
| sort by Failures desc`,
  },
  "identity-countries-per-user": {
    name: "Accounts signing in from more than one country", description: "Compare the countries with what you know about the person: travel, VPN, or something else.",
    tactics: ["InitialAccess"], techniques: ["T1078.004"], tables: ["SigninLogs"],
    query: `SigninLogs
| where ResultType == "0"
| summarize Countries = make_set(Location), CountryCount = dcount(Location), Addresses = make_set(IPAddress, 10) by UserPrincipalName
| where CountryCount > 1
| sort by CountryCount desc`,
  },
  "identity-risky-signins": {
    name: "Sign-ins Identity Protection scored as risky", description: "Risk detail, the application and the address of every medium or high risk sign-in.",
    tactics: ["InitialAccess"], techniques: ["T1078"], tables: ["SigninLogs"],
    query: `SigninLogs
| where RiskLevelDuringSignIn in ("medium", "high") or RiskLevelAggregated in ("medium", "high")
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, RiskLevelDuringSignIn, RiskState, RiskDetail, ConditionalAccessStatus
| sort by TimeGenerated desc`,
  },
  "identity-directory-changes": {
    name: "Directory changes by who made them", description: "Role, group and application changes in Entra ID, grouped by the account that made them.",
    tactics: ["Persistence", "PrivilegeEscalation"], techniques: ["T1098"], tables: ["AuditLogs"],
    query: `AuditLogs
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| summarize Changes = count(), Operations = make_set(OperationName, 10), LastChange = max(TimeGenerated) by Actor, Category
| sort by Changes desc`,
  },
  "identity-okta-failures": {
    name: "Okta failures and successes per user and address", description: "Failures that end in a success deserve a look at the address and the device.",
    tactics: ["CredentialAccess"], techniques: ["T1110"], tables: ["OktaV2_CL"],
    query: `OktaV2_CL
| where EventOriginalType == "user.session.start"
| summarize Failures = countif(OriginalOutcomeResult == "FAILURE"), Successes = countif(OriginalOutcomeResult == "SUCCESS") by OriginalActorAlternateId, SrcIpAddr, SrcGeoCountry
| where Failures > 0
| sort by Failures desc`,
  },
  "identity-okta-admin-grants": {
    name: "Okta admin grants and MFA resets", description: "Privilege grants and factor changes, and who made them.",
    tactics: ["Persistence", "PrivilegeEscalation"], techniques: ["T1098", "T1556.006"], tables: ["OktaV2_CL"],
    query: `OktaV2_CL
| where EventOriginalType in ("user.account.privilege.grant", "group.user_membership.add", "user.mfa.factor.deactivate", "user.mfa.factor.reset_all")
| project TimeGenerated, EventOriginalType, Actor = OriginalActorAlternateId, SrcIpAddr, EventMessage, OriginalTarget
| sort by TimeGenerated desc`,
  },
  "identity-windows-failed-logons": {
    name: "Windows logon failures by source", description: "Failed logons per source address and target account, from the Security log.",
    tactics: ["CredentialAccess"], techniques: ["T1110"], tables: ["SecurityEvent"],
    query: `SecurityEvent
| where EventID == 4625
| summarize Failures = count(), Accounts = dcount(TargetUserName), Targets = make_set(Computer, 10) by IpAddress
| sort by Failures desc`,
  },
  "identity-kerberos-rc4": {
    name: "Kerberos service tickets requested with RC4", description: "Encryption type 0x17 on service tickets is the classic sign of Kerberoasting.",
    tactics: ["CredentialAccess"], techniques: ["T1558.003"], tables: ["SecurityEvent"],
    query: `SecurityEvent
| where EventID == 4769
| where EventData has "0x17"
| extend ServiceName = extract(@'<Data Name="ServiceName">([^<]*)', 1, EventData)
| project TimeGenerated, Computer, TargetUserName, ServiceName, IpAddress
| sort by TimeGenerated desc`,
  },
  // ── Endpoint ───────────────────────────────────────────────────────────
  "endpoint-encoded-powershell": {
    name: "PowerShell with encoded or hidden commands", description: "Encoded commands, hidden windows and policy bypass on process start.",
    tactics: ["Execution"], techniques: ["T1059.001"], tables: ["DeviceProcessEvents"],
    query: `DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "-w hidden", "bypass", "downloadstring")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc`,
  },
  "endpoint-office-child": {
    name: "Office applications starting scripts or shells", description: "A document that starts a script host or a shell.",
    tactics: ["Execution"], techniques: ["T1204.002"], tables: ["DeviceProcessEvents"],
    query: `DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
  },
  "endpoint-falcon-process-tree": {
    name: "Falcon process starts by parent", description: "Parents and children seen by the Falcon sensor, rarest first.",
    tactics: ["Execution"], techniques: ["T1059"], tables: ["ASimProcessEventLogs"],
    query: `ASimProcessEventLogs
| summarize Starts = count(), Hosts = dcount(DvcHostname), CommandLines = make_set(TargetProcessCommandLine, 5) by ActingProcessName, TargetProcessName
| sort by Starts asc`,
  },
  "endpoint-run-keys": {
    name: "Run key changes", description: "Autostart registry values written on endpoints.",
    tactics: ["Persistence"], techniques: ["T1547.001"], tables: ["DeviceRegistryEvents"],
    query: `DeviceRegistryEvents
| where RegistryKey has @"CurrentVersion\\Run"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| sort by TimeGenerated desc`,
  },
  "endpoint-lsass-access": {
    name: "Processes opening LSASS (Sysmon)", description: "Sysmon event 10 against lsass.exe, grouped by the source image.",
    tactics: ["CredentialAccess"], techniques: ["T1003.001"], tables: ["Event"],
    query: `Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 10
| where EventData has "lsass.exe"
| extend SourceImage = extract(@'<Data Name="SourceImage">([^<]*)', 1, EventData), GrantedAccess = extract(@'<Data Name="GrantedAccess">([^<]*)', 1, EventData)
| summarize Count = count() by Computer, SourceImage, GrantedAccess`,
  },
  "endpoint-new-services": {
    name: "New services installed", description: "Service installs from the System and Security logs.",
    tactics: ["Persistence"], techniques: ["T1543.003"], tables: ["SecurityEvent"],
    query: `SecurityEvent
| where EventID in (7045, 4697)
| project TimeGenerated, Computer, ServiceName, ServiceFileName, Account
| sort by TimeGenerated desc`,
  },
  "endpoint-falcon-detections": {
    name: "Falcon detections by host", description: "CrowdStrike detections received over CEF, by host and tactic.",
    tactics: ["Execution"], techniques: ["T1059"], tables: ["CommonSecurityLog"],
    query: `CommonSecurityLog
| where DeviceVendor == "CrowdStrike" and DeviceProduct == "FalconHost"
| summarize Detections = count(), Names = make_set(Activity, 10), LastSeen = max(TimeGenerated) by DestinationHostName, DeviceCustomString5
| sort by Detections desc`,
  },
  "endpoint-s1-unmitigated": {
    name: "SentinelOne threats by mitigation status", description: "Threats the agent has not mitigated come first.",
    tactics: ["Execution"], techniques: ["T1204"], tables: ["SentinelOneThreats_CL"],
    query: `SentinelOneThreats_CL
| project TimeGenerated, AgentComputerName, ThreatName, Classification, MitigationStatus, FilePath, FileSha256, Username
| sort by MitigationStatus asc, TimeGenerated desc`,
  },
  "endpoint-sophos-events": {
    name: "Sophos endpoint events by type", description: "Malware, PUA and exploit events from Sophos Central.",
    tactics: ["Execution"], techniques: ["T1204"], tables: ["SophosEPEvents_CL"],
    query: `SophosEPEvents_CL
| summarize Events = count(), Hosts = make_set(DvcHostname, 10), Threats = make_set(ThreatName, 10) by DvcAction, ThreatCategory, EventSeverity
| sort by Events desc`,
  },
  // ── Email and collaboration ────────────────────────────────────────────
  "email-threat-mail": {
    name: "Inbound mail with a threat verdict", description: "What was delivered, and what the filter thought of it.",
    tactics: ["InitialAccess"], techniques: ["T1566"], tables: ["EmailEvents"],
    query: `EmailEvents
| where EmailDirection == "Inbound" and isnotempty(ThreatTypes)
| project TimeGenerated, SenderFromAddress, SenderIPv4, RecipientEmailAddress, Subject, ThreatTypes, DeliveryAction, DeliveryLocation
| sort by TimeGenerated desc`,
  },
  "email-sender-burst": {
    name: "Senders reaching several recipients", description: "One sender domain, many recipients, the same subject.",
    tactics: ["InitialAccess"], techniques: ["T1566"], tables: ["EmailEvents"],
    query: `EmailEvents
| summarize Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 5), Actions = make_set(DeliveryAction) by SenderFromDomain
| sort by Recipients desc`,
  },
  "email-allowed-clicks": {
    name: "Links clicked through Safe Links", description: "Clicks allowed or clicked through on a warning page.",
    tactics: ["InitialAccess"], techniques: ["T1566.002"], tables: ["UrlClickEvents"],
    query: `UrlClickEvents
| where ActionType in ("ClickAllowed", "UrlErrorPage", "ClickedThrough") or IsClickedThrough == true
| project TimeGenerated, AccountUpn, Url, ActionType, IsClickedThrough, IPAddress
| sort by TimeGenerated desc`,
  },
  "email-proofpoint-clicks": {
    name: "Proofpoint permitted clicks on classified URLs", description: "A click Proofpoint let through on a URL it now classifies.",
    tactics: ["InitialAccess"], techniques: ["T1566.002"], tables: ["ProofPointTAPClicksPermittedV2_CL"],
    query: `ProofPointTAPClicksPermittedV2_CL
| project TimeGenerated, recipient, url, classification, threatStatus, clickIP
| sort by TimeGenerated desc`,
  },
  "email-inbox-rules": {
    name: "Inbox rules and forwarding changes", description: "New or changed rules and mailbox forwarding, with their parameters.",
    tactics: ["Collection"], techniques: ["T1114.003"], tables: ["OfficeActivity"],
    query: `OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox", "UpdateInboxRules")
| project TimeGenerated, UserId, Operation, ClientIP, Parameters
| sort by TimeGenerated desc`,
  },
  "email-sharepoint-downloads": {
    name: "Files downloaded per user", description: "Download and sync volume per user and client address.",
    tactics: ["Collection"], techniques: ["T1213.002"], tables: ["OfficeActivity"],
    query: `OfficeActivity
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull", "FileAccessed")
| summarize Files = count(), Sites = make_set(Site_Url, 5), Addresses = make_set(ClientIP, 5) by UserId
| sort by Files desc`,
  },
  // ── Cloud ──────────────────────────────────────────────────────────────
  "cloud-aws-console-no-mfa": {
    name: "AWS console sign-ins without MFA", description: "Console logins, the identity type and whether MFA was used.",
    tactics: ["InitialAccess"], techniques: ["T1078.004"], tables: ["AWSCloudTrail"],
    query: `AWSCloudTrail
| where EventName == "ConsoleLogin"
| where AdditionalEventData !has "\\"MFAUsed\\":\\"Yes\\""
| project TimeGenerated, UserIdentityType, UserIdentityArn, SourceIpAddress, UserAgent, AdditionalEventData`,
  },
  "cloud-aws-logging-tamper": {
    name: "AWS logging and detection switched off", description: "CloudTrail and GuardDuty changes that reduce visibility.",
    tactics: ["DefenseImpairment"], techniques: ["T1562.008"], tables: ["AWSCloudTrail"],
    query: `AWSCloudTrail
| where EventName in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors", "DeleteDetector", "UpdateDetector")
| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, AWSRegion, RequestParameters`,
  },
  "cloud-aws-iam-changes": {
    name: "AWS IAM changes by principal", description: "Keys, policies and users created or attached, by who did it.",
    tactics: ["Persistence"], techniques: ["T1098.001"], tables: ["AWSCloudTrail"],
    query: `AWSCloudTrail
| where EventSource == "iam.amazonaws.com" and ReadOnly == false
| summarize Calls = count(), Actions = make_set(EventName, 10), Addresses = make_set(SourceIpAddress, 5) by UserIdentityArn
| sort by Calls desc`,
  },
  "cloud-aws-denied": {
    name: "AWS calls denied by principal", description: "Repeated AccessDenied is what enumeration with a stolen key looks like.",
    tactics: ["Discovery"], techniques: ["T1526"], tables: ["AWSCloudTrail"],
    query: `AWSCloudTrail
| where ErrorCode in ("AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation")
| summarize Denied = count(), Actions = make_set(EventName, 10) by UserIdentityArn, SourceIpAddress
| sort by Denied desc`,
  },
  "cloud-guardduty": {
    name: "GuardDuty findings by type", description: "Findings at severity 4 and above.",
    tactics: ["Discovery"], techniques: ["T1526"], tables: ["AWSGuardDuty"],
    query: `AWSGuardDuty
| where Severity >= 4
| summarize Findings = count(), Top = max(Severity), Last = max(TimeGenerated) by ActivityType, Region
| sort by Top desc`,
  },
  "cloud-azure-role-assignments": {
    name: "Azure role assignments", description: "Who changed access, on which scope.",
    tactics: ["PrivilegeEscalation"], techniques: ["T1098.003"], tables: ["AzureActivity"],
    query: `AzureActivity
| where OperationNameValue contains "ROLEASSIGNMENTS/WRITE"
| project TimeGenerated, Caller, CallerIpAddress, ResourceId, ActivityStatusValue`,
  },
  "cloud-azure-keyvault": {
    name: "Key Vault secret reads by caller", description: "Who reads secrets, from where, and how often.",
    tactics: ["CredentialAccess"], techniques: ["T1555.006"], tables: ["AzureActivity"],
    query: `AzureActivity
| where OperationNameValue contains "KEYVAULT"
| summarize Reads = count(), Vaults = make_set(ResourceId, 5) by Caller, CallerIpAddress
| sort by Reads desc`,
  },
  "cloud-azure-openai-oversized-completions": {
    name: "Azure OpenAI completions far larger than the deployment's usual size",
    description: "Each completion against the median response size of its own deployment. A RAG answer several times its usual size can carry text the model was told to fetch: read the grounding document and the caller.",
    tactics: ["Collection", "Exfiltration"], techniques: ["T1213", "T1567"], tables: ["AzureDiagnostics"],
    query: `let calls = AzureDiagnostics
| where Category == "RequestResponse" and ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| extend Props = parse_json(properties_s)
| extend Deployment = tostring(Props.modelDeploymentName), ResponseBytes = tolong(Props.responseLength), RequestBytes = tolong(Props.requestLength);
let usual = calls
| summarize UsualBytes = percentile(ResponseBytes, 50), Calls = count() by Resource, Deployment;
calls
| join kind=inner usual on Resource, Deployment
| extend Ratio = round(todouble(ResponseBytes) / UsualBytes, 1)
| where Ratio >= 3
| project TimeGenerated, Resource, Deployment, OperationName, ResponseBytes, UsualBytes, Ratio, RequestBytes, DurationMs, CallerIPAddress, Calls
| sort by Ratio desc`,
  },
  "cloud-azure-storage-outside-uploads": {
    name: "Blob writes with a shared access signature",
    description: "Who wrote into storage with a SAS, from which address, and with which signing identity (a user delegation SAS names the identity that requested its key).",
    tactics: ["InitialAccess", "Impact"], techniques: ["T1565.001"], tables: ["StorageBlobLogs"],
    query: `StorageBlobLogs
| where Category == "StorageWrite" and AuthenticationType in ("SAS", "DelegationSas")
| extend ClientIp = extract(@"^([^:]+)", 1, CallerIpAddress)
| summarize Writes = count(), Bytes = sum(RequestBodySize), Objects = make_set(ObjectKey, 10), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by AccountName, ClientIp, AuthenticationType, RequesterObjectId
| sort by FirstSeen asc`,
  },
  "cloud-gcp-iam": {
    name: "GCP IAM policy and key changes", description: "Policy bindings set and service account keys created.",
    tactics: ["Persistence"], techniques: ["T1098.001"], tables: ["GCPAuditLogs"],
    query: `GCPAuditLogs
| where MethodName has_any ("SetIamPolicy", "CreateServiceAccountKey", "CreateServiceAccount")
| project TimeGenerated, PrincipalEmail, MethodName, GCPResourceName, ProjectId`,
  },
  // ── Network ────────────────────────────────────────────────────────────
  "network-top-talkers": {
    name: "Largest outbound transfers", description: "Bytes sent per internal source and external destination.",
    tactics: ["Exfiltration"], techniques: ["T1048"], tables: ["CommonSecurityLog"],
    query: `CommonSecurityLog
| where isnotempty(SentBytes) and SentBytes > 0
| summarize Sent = sum(SentBytes), Sessions = count() by SourceIP, DestinationIP, DeviceVendor
| sort by Sent desc
| take 25`,
  },
  "network-port-sweep": {
    name: "One source touching many ports or hosts", description: "Scanning inside or against the perimeter.",
    tactics: ["Discovery"], techniques: ["T1046"], tables: ["CommonSecurityLog"],
    query: `CommonSecurityLog
| where isnotempty(DestinationPort)
| summarize Ports = dcount(DestinationPort), Hosts = dcount(DestinationIP), Actions = make_set(DeviceAction, 5) by SourceIP
| where Ports >= 3 or Hosts >= 5
| sort by Ports desc`,
  },
  "network-blocked-by-rule": {
    name: "Traffic denied, by source and action", description: "What the firewall stopped, and what kept trying.",
    tactics: ["CommandAndControl"], techniques: ["T1071"], tables: ["CommonSecurityLog"],
    query: `CommonSecurityLog
| where DeviceAction in~ ("deny", "drop", "block", "reset-both", "Drop", "Prevent", "Reject")
| summarize Denied = count(), Destinations = make_set(DestinationIP, 10) by SourceIP, DeviceVendor
| sort by Denied desc`,
  },
  "network-web-categories": {
    name: "Web requests by category", description: "URL categories seen on the proxy or firewall, smallest first.",
    tactics: ["CommandAndControl"], techniques: ["T1071.001"], tables: ["CommonSecurityLog"],
    query: `CommonSecurityLog
| where isnotempty(RequestURL)
| summarize Requests = count(), Hosts = dcount(SourceIP), Sample = take_any(RequestURL) by DeviceVendor, DeviceEventCategory
| sort by Requests asc`,
  },
  "network-vpn-logons": {
    name: "VPN sessions per user", description: "Addresses each user connected from.",
    tactics: ["InitialAccess"], techniques: ["T1133"], tables: ["CommonSecurityLog"],
    query: `CommonSecurityLog
| where Activity == "GLOBALPROTECT" or DeviceEventClassID in ("113039", "113004", "722051")
| summarize Sessions = count(), Addresses = make_set(SourceIP, 10) by SourceUserName
| sort by Sessions desc`,
  },
  "network-dns-long-names": {
    name: "Unusually long DNS names", description: "Long, high-entropy labels point to tunneling or generated domains.",
    tactics: ["CommandAndControl"], techniques: ["T1071.004"], tables: ["DnsEvents"],
    query: `DnsEvents
| extend Length = strlen(Name)
| where Length > 40
| project TimeGenerated, ClientIP, Name, QueryType, Length
| sort by Length desc`,
  },
  "network-dns-failures": {
    name: "DNS failures per client", description: "Clients with repeated failed lookups.",
    tactics: ["CommandAndControl"], techniques: ["T1568"], tables: ["DnsEvents"],
    query: `DnsEvents
| where ResultCode != 0
| summarize Failures = count(), Names = make_set(Name, 10) by ClientIP
| sort by Failures desc`,
  },
  "network-ssh-failures": {
    name: "SSH failures on Linux hosts", description: "Failed SSH logons from Syslog, by host.",
    tactics: ["CredentialAccess"], techniques: ["T1110"], tables: ["Syslog"],
    query: `Syslog
| where ProcessName == "sshd" and SyslogMessage has "Failed"
| summarize Failures = count(), Sample = take_any(SyslogMessage) by Computer
| sort by Failures desc`,
  },
  // ── Across sources ─────────────────────────────────────────────────────
  "cross-alerts-by-entity": {
    name: "Alerts by compromised entity", description: "The entities raising the most alerts, with their tactics.",
    tactics: ["Execution"], techniques: [], tables: ["SecurityAlert"],
    query: `SecurityAlert
| summarize Alerts = count(), Names = make_set(AlertName, 10), Tactics = make_set(Tactics, 10), LastSeen = max(TimeGenerated) by CompromisedEntity
| sort by Alerts desc`,
  },
};

const LIST: HuntingQuery[] = Object.entries(QUERIES).map(([id, q]) => ({
  id, name: q.name, description: q.description, tactics: q.tactics, techniques: q.techniques, dataSources: q.tables, query: q.query,
}));

export function buildHunting(): HuntingQuery[] { return LIST; }
