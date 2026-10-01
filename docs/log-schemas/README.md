# Log schema cards — one per data source

**Rule (Tal, 2026-10-01): no schema mixing.** Every log the platform shows is rendered in its
SOURCE's NATIVE format — exactly the structure and field names the product itself emits or its
official API/export returns. No SIEM normalisation layer (no ECS / Elastic `vendor.*` flattening,
no Wazuh `data.*` envelope) is applied on top.

- JSON-native sources (CloudTrail, Okta System Log, Entra sign-ins via Graph, M365 Management
  Activity API, Google Workspace Reports API, CrowdStrike FDR / Alerts API, SentinelOne, Sophos
  Central, GuardDuty, GCP Audit Logs, Cloudflare Logpush, Zscaler NSS JSON feeds…) are shown as the
  JSON object the source delivers, nested exactly as documented.
- Text-native sources (FortiGate key=value, Check Point Log Exporter, PAN-OS syslog, Cisco ASA/FTD
  syslog, Windows Event Log XML, Sysmon, auditd) are shown as a FLAT JSON object whose keys are the
  vendor's own field names, unchanged (plus the original raw line where useful).
- One vendor per category in a session; a log never carries a field from another vendor.

Each card: official sources (URLs), native format + delivery path, core field reference (type,
meaning, allowed values), realistic JSON samples for the SOC-relevant event types, investigation
notes (what an analyst pivots on), and common mistakes / fields that do NOT exist.

## Index (33 cards, 239 JSON samples — all parse; researched 2026-10-01)

| Category | Cards |
|---|---|
| EDR | [edr-crowdstrike](edr-crowdstrike.md) · [edr-defender-endpoint](edr-defender-endpoint.md) · [edr-sentinelone](edr-sentinelone.md) · [edr-sophos](edr-sophos.md) |
| Firewall | [fw-paloalto](fw-paloalto.md) · [fw-fortigate](fw-fortigate.md) · [fw-checkpoint](fw-checkpoint.md) · [fw-cisco](fw-cisco.md) |
| Identity | [idp-entra-id](idp-entra-id.md) · [idp-okta](idp-okta.md) · [windows-security](windows-security.md) · [pam-cyberark](pam-cyberark.md) |
| Email & collaboration | [collab-m365](collab-m365.md) · [collab-google-workspace](collab-google-workspace.md) · [email-defender-o365](email-defender-o365.md) · [email-proofpoint](email-proofpoint.md) |
| Cloud | [cloud-aws-cloudtrail](cloud-aws-cloudtrail.md) · [cloud-aws-guardduty](cloud-aws-guardduty.md) · [cloud-aws-vpc-flow](cloud-aws-vpc-flow.md) · [cloud-azure-activity](cloud-azure-activity.md) · [cloud-gcp-audit](cloud-gcp-audit.md) · [k8s-audit](k8s-audit.md) |
| Remote access | [vpn-globalprotect](vpn-globalprotect.md) · [vpn-cisco-anyconnect](vpn-cisco-anyconnect.md) · [vpn-fortigate-sslvpn](vpn-fortigate-sslvpn.md) · [ztna-zscaler-zpa](ztna-zscaler-zpa.md) · [ztna-cloudflare-access](ztna-cloudflare-access.md) |
| Proxy / DNS | [proxy-zscaler-zia](proxy-zscaler-zia.md) · [dns-windows](dns-windows.md) · [dns-infoblox](dns-infoblox.md) |
| Host / ITSM | [host-sysmon](host-sysmon.md) · [host-linux-auditd](host-linux-auditd.md) · [itsm-servicenow](itsm-servicenow.md) |

Items a source did not confirm are marked **UNVERIFIED** inside each card; they must be resolved or
avoided before an emitter relies on them.

## Findings that change the platform's current logs

1. **CrowdStrike** — raw FDR process/network events carry no `ComputerName` / `UserName` (those come
   from the host table and logon events). Alerts use the Alerts API v2 (the Detects API was retired
   2025-09-30).
2. **Defender for Endpoint** — native export = Event Hub streaming record wrapping the Advanced Hunting
   row (`category: "AdvancedHunting-<Table>"`, `properties: {…}`); `mde.AlertTitle` does not exist
   (use the AlertInfo table).
3. **SentinelOne** — Data Lake / Cloud Funnel keys are flat with literal dots (`src.process.cmdline`),
   `event.type` uses spaced names (`Process Creation`, `IP Connect`).
4. **Sophos** — no native per-event telemetry stream (DNS / network / file): only SIEM events + alerts,
   Detections, and Data Lake query rows. Stories that need an EDR network/DNS trail cannot run on Sophos.
5. **Check Point** — the default Log Exporter format differs from the `ProductName/ProductFamily`
   style used so far; never mix the two.
6. **M365 ↔ Google Workspace** — no Google equivalent for a user Gmail filter (New-InboxRule) or
   mailbox delegation (Add-MailboxPermission); such stories are M365-only.
7. **Proofpoint TAP** — the wire format differs from the doc page (`cluster`, array `fromAddress`,
   lowercase `classification`, `campaignID` vs `campaignId`); cards follow the wire.
8. **Zscaler ZPA** — authentication is SAML, so brute force appears in the IdP logs, not ZPA.
9. **Okta Identity Engine** — a rejected push is `user.authentication.auth_via_mfa` FAILURE /
   `INVALID_CREDENTIALS`; `user.mfa.okta_verify.deny_push` is classic-engine only.
10. **Kubernetes** — `kubectl exec` is verb `create` on `pods/exec` (there is no `exec` verb).
