/**
 * The Analysis view of a Windows Security / System event (Tal's QA, 2026-11-12: a long list of raw
 * codes - %%2313, 0xc000006d, LogonType 3 - with no grouping). Fields are grouped as Event Viewer
 * groups them (Subject, Logon Information, New Logon / Account, Failure Information, Process
 * Information, Network Information, Detailed Authentication Information ...) and every coded value
 * gets its meaning beside it. Meanings are Microsoft's own: the auditing event pages (4624, 4625,
 * 4768, 4769, 4771, 4776, 4688) and the msobjs.dll message strings behind the %%NNNN placeholders.
 */

export interface WinSection { title: string; rows: [string, string][] }

const LOGON_TYPE: Record<string, string> = {
  "2": "Interactive (at the keyboard)", "3": "Network", "4": "Batch (scheduled task)", "5": "Service", "7": "Unlock",
  "8": "NetworkCleartext", "9": "NewCredentials (runas /netonly)", "10": "RemoteInteractive (Remote Desktop)", "11": "CachedInteractive",
};
const MSG: Record<string, string> = {
  "%%1831": "Anonymous", "%%1832": "Identification", "%%1833": "Impersonation", "%%1834": "Delegation",
  "%%1842": "Yes", "%%1843": "No",
  "%%1936": "Type 1: full token, UAC off or built-in admin", "%%1937": "Type 2: elevated token", "%%1938": "Type 3: limited token",
  "%%1793": "<value not set>", "%%1794": "<never>", "%%1797": "All",
  "%%2080": "Account Disabled", "%%2082": "'Password Not Required' enabled", "%%2084": "'Normal Account' enabled",
  "%%2304": "An error occurred during logon", "%%2305": "The specified user account has expired", "%%2306": "The NetLogon component is not active",
  "%%2307": "Account locked out", "%%2308": "The user has not been granted the requested logon type at this machine",
  "%%2309": "The specified account's password has expired", "%%2310": "Account currently disabled",
  "%%2311": "Account logon time restriction violation", "%%2312": "User not allowed to logon at this computer",
  "%%2313": "Unknown user name or bad password",
  "%%4416": "ReadData (or ListDirectory)", "%%4417": "WriteData (or AddFile)", "%%7688": "Control Access",
  "%%14674": "Value Added", "%%14675": "Value Deleted", "%%14676": "Active Directory Domain Services",
};
/** NTSTATUS codes of 4625 / 4776 (Microsoft's 4625 status table). */
const NT_STATUS: Record<string, string> = {
  "0x0": "Success", "0xc000006d": "Bad user name or authentication information", "0xc000006a": "Wrong password",
  "0xc0000064": "User name does not exist", "0xc000006e": "Account restriction", "0xc0000071": "Password expired",
  "0xc0000072": "Account disabled", "0xc000006f": "Outside authorized logon hours", "0xc0000070": "Workstation restriction",
  "0xc0000193": "Account expired", "0xc0000234": "Account locked out", "0xc000015b": "Logon type not granted",
  "0xc0000224": "User must change password at next logon", "0xc0000133": "Clock out of sync with the DC", "0xc0000413": "Authentication firewall: not allowed on this computer",
};
/** Kerberos result codes of 4768 / 4769 / 4770 / 4771. */
const KERB_STATUS: Record<string, string> = {
  "0x0": "Success", "0x6": "Client not found in the directory (KDC_ERR_C_PRINCIPAL_UNKNOWN)", "0x7": "Service not found (KDC_ERR_S_PRINCIPAL_UNKNOWN)",
  "0x12": "Account disabled, expired or locked out (KDC_ERR_CLIENT_REVOKED)", "0x17": "Password expired (KDC_ERR_KEY_EXPIRED)",
  "0x18": "Pre-authentication failed: bad password (KDC_ERR_PREAUTH_FAILED)", "0x25": "Clock skew too great (KRB_AP_ERR_SKEW)",
  "0x20": "Ticket expired (KRB_AP_ERR_TKT_EXPIRED)", "0xe": "Encryption type not supported (KDC_ERR_ETYPE_NOTSUPP)",
};
const ENC_TYPE: Record<string, string> = {
  "0x1": "DES-CBC-CRC", "0x3": "DES-CBC-MD5", "0x11": "AES128-CTS-HMAC-SHA1-96", "0x12": "AES256-CTS-HMAC-SHA1-96",
  "0x17": "RC4-HMAC (weak, the Kerberoasting / AS-REP roasting signal)", "0x18": "RC4-HMAC-EXP", "0xffffffff": "No ticket issued (failure)",
};
const PREAUTH: Record<string, string> = {
  "0": "No pre-authentication (the account can be AS-REP roasted)", "2": "PA-ENC-TIMESTAMP: standard password", "15": "PA-PK-AS-REP_OLD: smart card",
  "16": "PA-PK-AS-REQ: smart card", "17": "PA-PK-AS-REP: smart card", "138": "PA-ENCRYPTED-CHALLENGE: Kerberos armoring (FAST)",
};
const WELL_KNOWN_SID: Record<string, string> = {
  "S-1-5-18": "Local System", "S-1-0-0": "NULL SID (no account)", "S-1-5-19": "Local Service", "S-1-5-20": "Network Service", "S-1-5-7": "Anonymous Logon",
};
const MANDATORY: Record<string, string> = { "S-1-16-4096": "Low integrity", "S-1-16-8192": "Medium integrity", "S-1-16-12288": "High integrity", "S-1-16-16384": "System integrity" };
const KEYWORDS: Record<string, string> = { "0x8020000000000000": "Audit Success", "0x8010000000000000": "Audit Failure", "0x8080000000000000": "Classic" };

/** The meaning of one value, or undefined when the value says itself. */
export function windowsValueMeaning(field: string, value: string, record?: Record<string, unknown>): string | undefined {
  const v = value.trim();
  const lc = v.toLowerCase();
  if (field === "LogonType") return LOGON_TYPE[v];
  if (field === "Keywords") return KEYWORDS[lc];
  if (/^%%\d+$/.test(v)) return MSG[v];
  if (/Sid$/.test(field)) return WELL_KNOWN_SID[v];
  if (field === "MandatoryLabel") return MANDATORY[v];
  if (/LogonId$/.test(field) && lc === "0x3e7") return "SYSTEM's session";
  const id = String(record?.EventID ?? "");
  if (field === "TicketEncryptionType") return ENC_TYPE[lc];
  if (field === "PreAuthType") return PREAUTH[v];
  if (field === "Status" || field === "SubStatus") return ["4768", "4769", "4770", "4771"].includes(id) ? KERB_STATUS[lc] : NT_STATUS[lc];
  return undefined;
}

const SYSTEM = new Set(["EventID", "Computer", "TimeCreated", "Channel", "Provider", "EventRecordID", "Keywords"]);

/** Which Event Viewer group a field sits in, for one event id. */
function groupOf(id: string, field: string): string {
  if (SYSTEM.has(field)) return "Event";
  if (field.startsWith("Subject")) return "Subject";
  if (["Status", "SubStatus", "FailureReason"].includes(field)) return id === "4625" ? "Failure Information" : "Result";
  if (["LogonType", "RestrictedAdminMode", "VirtualAccount", "ElevatedToken", "ImpersonationLevel"].includes(field)) return "Logon Information";
  if (field.startsWith("Target") || field.startsWith("Member") || ["LogonGuid", "SamAccountName", "DisplayName", "UserPrincipalName"].includes(field))
    return id === "4624" ? "New Logon" : id === "4625" ? "Account For Which Logon Failed" : id === "4648" ? "Account Whose Credentials Were Used" : "Account / Target";
  if (["ProcessId", "ProcessName", "NewProcessId", "NewProcessName", "ParentProcessName", "CommandLine", "TokenElevationType", "MandatoryLabel"].includes(field)) return "Process Information";
  if (["WorkstationName", "Workstation", "IpAddress", "IpPort", "TargetServerName", "TargetInfo"].includes(field)) return "Network Information";
  if (["LogonProcessName", "AuthenticationPackageName", "TransmittedServices", "LmPackageName", "KeyLength", "PackageName"].includes(field)) return "Detailed Authentication Information";
  if (field.startsWith("Service") || field.startsWith("Ticket") || field.startsWith("PreAuth") || field.startsWith("Cert")) return "Service / Ticket Information";
  return "Details";
}
const ORDER = ["Event", "Subject", "Logon Information", "New Logon", "Account For Which Logon Failed", "Account Whose Credentials Were Used", "Account / Target",
  "Failure Information", "Result", "Service / Ticket Information", "Process Information", "Network Information", "Detailed Authentication Information", "Details"];

/** The record's fields in Event Viewer groups (record order kept inside a group). */
export function windowsEventSections(record: Record<string, unknown>): WinSection[] {
  const id = String(record.EventID ?? "");
  const groups = new Map<string, [string, string][]>();
  for (const [k, v] of Object.entries(record)) {
    if (v === undefined || v === null) continue;
    const g = groupOf(id, k);
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g)!.push([k, String(v)]);
  }
  return ORDER.filter(t => groups.has(t)).map(title => ({ title, rows: groups.get(title)! }));
}
