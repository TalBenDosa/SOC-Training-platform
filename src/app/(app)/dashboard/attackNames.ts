/**
 * Instructor-facing names for live-feed attack stories built from a scenario's events.
 *
 * A scenario's own title is a neutral ticket line (what the SOC first sees, never the answer),
 * because the student reads it before investigating. A live-feed story's title is read by the
 * instructor who picks the attacks for a team exercise and in the debrief after the shift, so it
 * names the attack. Keyed by the scenario bundle title the story is built from.
 */
export const ATTACK_NAMES: Readonly<Record<string, string>> = {
  "EDR alert on an HR workstation": "Shipping-Notice ZIP Attachment → Disguised .pdf.exe → Workstation Infection",
  "EDR quarantine on an operations workstation": "Malicious USB Drive → Trojan Persistence → Workstation Compromise",
  "Unassigned EDR detection on a finance workstation": "Phishing Macro → AWS Key Theft → S3 Download",
  "Failed AD FS logons and a CFO call": "Password Spray → BEC Mailbox Rule",
  "Critical file server alert and an unreachable Finance share": "Ransomware Outbreak: LockBit 3.0",
  "Graph activity alert after a password reset": "OAuth App Persistence: Cloud APT",
  "DLP download alert on a finance workstation": "Insider: Bulk Finance Downloads and Removable Media",
  "Kerberos ticket volume alert for a developer account": "Kerberoasting → Service Account Compromise → xp_cmdshell",
  "DNS volume anomaly on an engineering workstation": "DNS Tunneling: C2 Channel and Data Exfiltration",
  "Rare command-line alert on an HR workstation": "Living off the Land: certutil → regsvr32 → Persistence",
  "Secret scanning alert on a public deploy repo": "Leaked AWS Key → IAM Backdoor → S3 Data Theft",
  "Late-night admin RDP logon to a domain controller": "DCSync → Golden Ticket (Domain Dominance)",
  "EDR detection on a production server after an update": "Supply Chain Attack: Malicious Vendor Update",
  "Overnight high-severity alert on an IT administrator": "MFA Fatigue → Okta Account Takeover",
  "Identity alert naming three service accounts": "AS-REP Roasting → Offline Hash Crack",
  "Tooling detection on a developer workstation": "NTLM Relay: Internal Credential Hijacking",
  "GuardDuty finding on the production EKS cluster": "Kubernetes Pod Escape → Cloud Metadata Theft",
  "DLP alert on a Finance SharePoint contract": "OAuth Consent Grant Phishing: Silent BEC",
  "Overnight behaviour alert on a production file server": "Mass File Encryption Alert: Enterprise Backup Agent",
  "Logon failures on the published Remote Desktop server": "Logon Failure Burst: Published Remote Desktop Server",
  "Late-evening privileged group change on the DC": "Out-of-Hours Account Creation: Service Desk Credentials",
  "Two-city sign-ins for an accounts payable clerk": "Impossible Travel: Accounts Payable Mailbox",
  "Behavioural EDR alert on an engineering workstation": "Dropper Behaviour Alert: Engineering Workstation",
  "WAF blocks and an EDR alert on the shop": "SQL Injection → Web Shell → Server Compromise",
  "Falcon detection on a Linux backup server": "Exposed SSH → Cron-Persisted Backdoor",
  "Sign-ins six minutes apart for a finance user": "Adversary-in-the-Middle Phishing: Session Token Theft",
  "Every guest on PROD-CLUSTER-A unreachable on Saturday night": "Hypervisor Ransomware: ESXi Datastore Encryption",
  "Overnight Okta sign-in failures for one account": "Sign-In Failure Burst: Okta Tenant, One Account",
  "Critical EDR detection on a laptop while browsing": "Fake Browser Update: Drive-by on a Trusted Site",
  "Critical alert after a free PDF tool install": "Free PDF Tool: Trojanized Installer with a Keylogger",
  "Three EDR incidents on three hosts tonight": "Multi-Host Intrusion: Foothold, Lateral Move, Staging",
  "Bedrock cost alert on QuantumBank's AWS account": "LLMjacking: Stolen CI Key Used for Bedrock Inference",
  "Critical Mac detection after a supplier invoice": "Shared Invoice: Malicious Attachment via Google Workspace",
  "High-severity Defender incident on an admin laptop": "Sponsored Result: SEO-Poisoned PuTTY Installer with an Infostealer",
  "Critical EDR detection after an overdue invoice email": "Invoice.iso: Container-Delivered LNK and LOLBin Chain",
  "Blocked outbound connection on a browsing workstation": "Verify You Are Human: ClickFix Paste-and-Run",
  "SIEM alert on an HR coordinator's laptop": "Fix My Internet: Persistence via a Scheduled Task",
  "Killed process and a new sign-in for one user": "Free Converter, Stolen Session: Infostealer Cookie Theft and Replay",
  "Routine MFA reset ticket and two sign-ins": "Help Desk MFA Reset: Social Engineering Account Takeover",
  "VPN user correlation alert on a jump host": "Edge Appliance Exploitation: FortiOS SSL-VPN Auth Bypass to Internal Foothold",
  "Threatening email to NexaCorp's security mailbox": "Exfiltration-First Extortion: Ransomware Without an Encryptor",
  "Rare privilege alert for an IIS service account": "SYSTEM in Twelve Seconds: Token Impersonation on an IIS Host",
  "Critical Falcon detection on an Ubuntu app server": "Foothold to Root: SUID find on an Ubuntu App Server",
  "Night-time privileged logons for an infrastructure admin": "Lateral Movement: Pass-the-Hash to the File Server, Second Hop to the DC",
  "Sentinel incident for a finance analyst who resigned": "Departing Insider: Exfil via USB and Personal Cloud",
  "Microsoft Graph Security incident for svc-billing-connector": "Azure App-Registration Credential Abuse",
  "Overnight federated sign-in for a Global Administrator": "Golden SAML: a Federation Token With No Matching AD FS Issuance",
  "Two SCC findings on a data-pipeline service account": "Minted Key: Service-Account Key Theft on GCP",
};

/** The name an instructor reads for a story built from this bundle title. */
export function attackName(bundleTitle: string): string {
  return ATTACK_NAMES[bundleTitle] ?? bundleTitle;
}
