/**
 * Per-scenario "Recommended first" prerequisites — the learning rooms that teach
 * what a scenario assumes the analyst already knows.
 *
 * External realism audit F-10: only 13/67 scenarios declared prerequisites, and
 * they lived inline in a client component so nothing could enforce them. This map
 * covers ALL scenarios in the SCENARIOS catalogue, keyed by slug, valued by real
 * room IDs (validated against ROOMS_META by the scenario-integrity gate). It lives
 * in a shared module so both the /scenarios list page and the integrity gate import
 * the one source of truth.
 *
 * Every value must be a real room id (see src/data/roomsMeta.ts). The gate fails if
 * a scenario is missing here or points at a room that doesn't exist.
 */
export const SCENARIO_PREP: Record<string, string[]> = {
  // Phishing / email-borne / BEC
  "phishing-malware-basic":        ["phishing-analysis", "email-security", "malware-types"],
  "phishing-to-cloud-exfil":       ["phishing-analysis", "cloud-security-monitoring"],
  "bec-mailbox-rule":              ["email-security", "bec-investigation", "entra-id"],
  "bec-wire-fraud":                ["email-security", "bec-investigation", "phishing-analysis"],
  "gws-phishing-attachment":       ["google-workspace-security", "email-security"],
  "gws-oauth-marketplace":         ["google-workspace-security", "identity-basics"],
  "oauth-consent-grant-phishing":  ["identity-basics", "cloud-security-monitoring", "phishing-analysis"],
  "aitm-token-theft":              ["identity-basics", "auth-identity-monitoring", "phishing-analysis"],
  "vishing-rmm":                   ["phishing-analysis", "endpoint-security-fundamentals"],
  "email-bomb-helpdesk":           ["email-security", "phishing-analysis", "endpoint-security-fundamentals"],

  // Endpoint malware / commodity initial access
  "usb-malware-basic":             ["malware-types", "endpoint-security-fundamentals"],
  "bundled-cryptominer":           ["malware-types", "endpoint-security-fundamentals"],
  "seo-poisoned-installer":        ["commodity-initial-access", "malware-types"],
  "clickfix-fake-captcha":         ["commodity-initial-access", "phishing-analysis"],
  "trojanized-installer-keylogger":["malware-types", "commodity-initial-access"],
  "fake-browser-update":           ["commodity-initial-access", "malware-types"],
  "drive-by-browser-miner":        ["commodity-initial-access", "malware-types"],
  "iso-container-smuggling":       ["commodity-initial-access", "malware-types"],
  "infostealer-session-theft":     ["malware-types", "identity-basics"],
  "clipboard-clipper":             ["commodity-initial-access", "malware-types"],
  "macos-stealer-dmg":             ["macos-security-fundamentals"],
  "macos-tcc-pkg":                 ["macos-security-fundamentals"],

  // Ransomware / extortion / destruction
  "ransomware-lockbit":            ["ransomware-full-lifecycle", "endpoint-security-fundamentals"],
  "esxi-ransomware":               ["esxi-virtualization-security", "ransomware-full-lifecycle"],
  "exfil-first-extortion":         ["dlp-fundamentals", "ransomware-full-lifecycle"],
  "destructive-wiper":             ["endpoint-security-fundamentals", "malware-analysis-fundamentals", "ransomware-full-lifecycle"],

  // Identity & account takeover / mobile
  "mfa-fatigue-ato":               ["okta-identity-fundamentals", "identity-basics"],
  "impossible-travel-basic":       ["identity-basics", "auth-identity-monitoring"],
  "helpdesk-mfa-reset":            ["identity-basics", "auth-identity-monitoring"],
  "rogue-admin-account":           ["active-directory", "auth-identity-monitoring"],
  "oauth-app-persistence":         ["identity-basics", "cloud-security-monitoring"],
  "ueba-compromised-account":      ["siem-fundamentals", "identity-basics", "auth-identity-monitoring"],
  "golden-saml":                   ["entra-id", "active-directory"],
  "mobile-mdm-compromise":         ["entra-id", "identity-basics"],
  "brute-force-single-account":    ["auth-identity-monitoring", "identity-basics"],
  "okta-password-burst":           ["okta-identity-fundamentals", "auth-identity-monitoring"],

  // Active Directory / credential theft
  "kerberoasting":                 ["active-directory", "kerberos-authentication"],
  "asrep-roasting":                ["active-directory", "kerberos-authentication"],
  "dcsync-golden-ticket":          ["active-directory", "kerberos-authentication"],
  "ntlm-relay-responder":          ["active-directory", "windows-protocols-lateral"],

  // Privilege escalation & lateral movement
  "windows-privesc-token":         ["windows-privilege-escalation", "windows-event-logs"],
  "linux-privesc-suid":            ["linux-fundamentals", "linux-log-analysis"],
  "lateral-movement-pth":          ["active-directory", "windows-protocols-lateral", "lateral-movement-practice"],
  "pam-vault-abuse":               ["privileged-access-monitoring", "active-directory"],

  // Cloud & container
  "cloud-cryptomining":            ["aws-security", "cloud-security-monitoring"],
  "k8s-pod-escape-imds":           ["kubernetes-container-security", "aws-security"],
  "azure-managed-identity-abuse":  ["azure-security", "cloud-security-monitoring"],
  "cicd-supply-chain":             ["aws-security", "cloud-security-monitoring"],
  "s3-exfil-exposure":             ["aws-security", "cloud-security-monitoring"],
  "gcp-sa-key-theft":              ["gcp-security", "cloud-security-monitoring"],
  "container-escape-cryptomining": ["kubernetes-container-security", "cloud-security-monitoring"],

  // Web / perimeter / DB
  "web-shell-sqli":                ["web-application-security", "web-attacks-practice"],
  "sqli-db-exfil":                 ["web-application-security", "web-attacks-practice"],
  "edge-vpn-cve-exploit":          ["vpn-monitoring", "firewall-log-analysis", "vulnerability-management"],

  // C2, exfiltration & threat hunting
  "dns-tunneling":                 ["dns-investigation", "tunneling-c2-channels"],
  "lolbins":                       ["windows-event-logs", "mitre-attack", "powershell-for-soc-analyst"],
  "threat-intel-hunt":             ["threat-intelligence", "threat-hunting-fundamentals", "ioc-analysis"],
  "linux-ssh-cryptominer":         ["linux-fundamentals", "linux-log-analysis"],

  // Insider, supply-chain, physical, OT
  "insider-threat-finance":        ["dlp-fundamentals", "analyst-mindset"],
  "insider-dlp-usb-cloud":         ["dlp-fundamentals"],
  "supply-chain-vendor-update":    ["malware-analysis-fundamentals", "threat-intelligence"],
  "nac-rogue-device":              ["nac-masterclass", "networking-fundamentals"],
  "ot-network-anomaly":            ["networking-fundamentals", "firewall-log-analysis"],

  // Persistence / triage / multi-stage
  "scheduled-task-persistence":    ["persistence-mechanisms", "windows-event-logs"],
  "backup-agent-false-positive":   ["alert-triage", "endpoint-security-fundamentals"],
  "software-install-false-positive":["alert-triage", "endpoint-security-fundamentals"],
  "multi-host-intrusion":          ["cyber-kill-chain", "lateral-movement-practice", "active-directory"],
};
