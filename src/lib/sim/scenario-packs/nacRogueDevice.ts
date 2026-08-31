/**
 * Scenario pack: "Rogue Device on the Corporate LAN — Printer That Isn't a Printer"
 *
 * BEGINNER tier. An unmanaged laptop is plugged into a wall port in a NexaCorp
 * meeting room. It has no 802.1X supplicant and no corporate certificate, so it
 * cannot log in the way a managed laptop does. Instead it copies the MAC address
 * of a nearby HP printer and lets the switch authenticate it by MAC alone (MAB —
 * MAC Authentication Bypass). Cisco ISE recognises the MAC as a known printer,
 * accepts it, and drops it onto the printer VLAN.
 *
 * The device gives itself away almost immediately. A printer does not ask for a
 * DHCP address the way a Windows PC does, and ISE's profiler reads that DHCP
 * fingerprint: the "printer" is advertising a Microsoft Windows stack and a
 * workstation hostname. The OUI (the vendor half of the MAC) still says
 * Hewlett-Packard, but everything else says laptop. That contradiction is the
 * whole scenario. When the device then tries to reach the corporate VLAN, ISE
 * runs a posture check, finds no machine certificate, no running AV and no EDR,
 * fails it, and issues a Change of Authorization that quarantines the port.
 *
 * A legitimately-onboarded managed laptop is included first, so the analyst has
 * a clean baseline to compare the rogue against: same building, same NAC, but
 * EAP-TLS with a valid corp certificate and a Compliant posture result.
 *
 * Everything the debrief asserts is observable in the events: the spoofed MAC,
 * the HP OUI, the Windows DHCP fingerprint, the switch port, the VLAN it landed
 * on, the failed posture, and the quarantine. Nothing in the telemetry states
 * the verdict.
 *
 * VENDOR NOTE: All NAC events use Cisco ISE, which IS registered in
 * scripts/log-field-registry.json (label "Cisco ISE", prefixes cise./ise.).
 * Raw blocks mix the registry's ECS-style exact fields (radius.*, switch.*,
 * posture.*, device.*, quarantine.*, network.vlan.id ...) with ise.-prefixed
 * native ISE attributes (ise.MessageCode, ise.EndpointPolicy, ise.CoAReason ...),
 * both of which pass the vendor log-field gate.
 *
 * NOTE: `difficulty: "beginner"` is declared on the SCENARIOS registry entry in
 * scenarios.ts (ScenarioBundle itself carries no difficulty field). This pack is
 * intentionally NOT registered in scenarios.ts yet.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";

export function buildNacRogueDeviceScenario(
  scenarioId = "nac-rogue-device-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T06:40:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;

  // ── Access-layer infrastructure ──────────────────────────────────────────
  const ise = { host: "ISE-PSN-01", ip: "10.10.5.11" };
  const accessSwitch = { name: "SW-ACC-07", ip: "10.10.7.7", port: "GigabitEthernet1/0/14", interface: "GigabitEthernet1/0/14" };

  // ── The real printer whose identity gets stolen ──────────────────────────
  // Its MAC's first three octets (00:1B:78) are Hewlett-Packard's registered OUI.
  const printerMac = "00:1B:78:AA:41:9C";
  const printerOuiVendor = "Hewlett-Packard";

  // ── The rogue: an unmanaged Windows laptop spoofing that MAC ──────────────
  const rogueIp = "10.50.14.83";                 // address it pulls on the printer VLAN
  const rogueHostname = "DESKTOP-3F9KQ2";        // Windows-style name the DHCP request leaks

  // ── The benign baseline: a managed corporate laptop ──────────────────────
  const goodLaptop = {
    mac: "AC:1F:6B:22:0D:E4",
    name: "NEXA-LT-4471",
    user: "d.reyes",
    ip: "10.20.4.61",
  };

  const INCIDENT = "inc:rd:1";

  const events: TelemetryEvent[] = [
    // ---------------------------------------------------------------------
    // 1. BENIGN BASELINE — a managed laptop onboards the correct way.
    //    EAP-TLS with a valid corporate cert, posture Compliant, CORP VLAN.
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_01_benign_onboard",
      ts: T(0),
      source: "nac",
      vendor: "Cisco ISE",
      event_type: "nac_allow",
      hostname: goodLaptop.name,
      severity: "informational",
      description:
        "A managed corporate laptop authenticated with 802.1X EAP-TLS on SW-ACC-07, passed posture, and was placed on the CORP VLAN. This is what a healthy onboarding looks like.",
      fp_explanation:
        "Benign baseline. EAP-TLS with a valid NexaCorp machine certificate, a Compliant posture result, and placement on the CORP VLAN — the correct, expected onboarding for a managed device. Included as the comparison for the rogue.",
      authentication: { method: "EAP-TLS", result: "success" },
      raw: {
        "ise.MessageCode": "5200",
        "ise.MessageText": "Authentication succeeded",
        "event.action": "authentication",
        "event.category": "authentication",
        "event.type": "nac_allow",
        "event.outcome": "success",
        "event.severity": "informational",
        "authentication.method": "EAP-TLS",
        "authentication.protocol": "802.1X",
        "authentication.status": "success",
        "authentication.server": ise.host,
        "certificate.subject": `CN=${goodLaptop.name}.nexacorp.com`,
        "certificate.issuer": "CN=NexaCorp Issuing CA 2, DC=nexacorp, DC=com",
        "certificate.valid_to": "2027-04-18T00:00:00Z",
        "user.name": goodLaptop.user,
        "host.name": goodLaptop.name,
        "host.mac": goodLaptop.mac,
        "host.ip": goodLaptop.ip,
        "source.mac": goodLaptop.mac,
        "radius.calling_station_id": goodLaptop.mac,
        "radius.called_station_id": `00-2A-10-3C-7E-14:NEXA-DOT1X`,
        "radius.nas.ip": accessSwitch.ip,
        "radius.session.id": "0A0A0707000000A15E1B33F0",
        "switch.name": accessSwitch.name,
        "switch.ip": accessSwitch.ip,
        "switch.port": "GigabitEthernet1/0/03",
        "switch.interface": "GigabitEthernet1/0/03",
        "network.access.type": "wired",
        "network.vlan.id": "20",
        "network.zone": "CORP",
        "device.type": "Workstation",
        "device.managed": "true",
        "device.compliant": "true",
        "device.posture.status": "Compliant",
        "ise.EndpointPolicy": "Microsoft-Workstation",
        "ise.IdentityGroup": "Corporate-Managed",
        "ise.SelectedAuthorizationProfile": "PERMIT_CORP_VLAN20",
      },
    },

    // ---------------------------------------------------------------------
    // 2. THE ROGUE LANDS — MAB accepts the spoofed printer MAC.
    //    No 802.1X, no cert; the switch authenticates by MAC alone and ISE
    //    recognises it as a known printer, so it goes to the PRINTER VLAN.
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_02_mab_accept",
      ts: T(52 * MIN),
      source: "nac",
      vendor: "Cisco ISE",
      event_type: "nac_allow",
      hostname: accessSwitch.name,
      src_ip: rogueIp,
      severity: "medium",
      mitre_technique: "T1200",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      description:
        "A new endpoint appeared on SW-ACC-07 port GigabitEthernet1/0/14 with no 802.1X supplicant. ISE authenticated it by MAC (MAB), matched the MAC to the Printers group, and assigned the printer VLAN.",
      authentication: { method: "MAB", result: "success" },
      raw: {
        "ise.MessageCode": "5200",
        "ise.MessageText": "Authentication succeeded",
        "event.action": "authentication",
        "event.category": "authentication",
        "event.type": "nac_allow",
        "event.outcome": "success",
        "event.severity": "medium",
        "authentication.method": "MAB",
        "authentication.protocol": "MAC-Bypass",
        "authentication.status": "success",
        "authentication.server": ise.host,
        "source.mac": printerMac,
        "host.mac": printerMac,
        "radius.calling_station_id": printerMac,
        "radius.called_station_id": `00-2A-10-3C-7E-14:NEXA-MAB`,
        "radius.nas.ip": accessSwitch.ip,
        "radius.session.id": "0A0A07070000010C5E1C77A2",
        "switch.name": accessSwitch.name,
        "switch.ip": accessSwitch.ip,
        "switch.port": accessSwitch.port,
        "switch.interface": accessSwitch.interface,
        "network.access.type": "wired",
        "network.vlan.id": "50",
        "network.zone": "PRINTERS",
        "device.type": "Printer",
        "device.vendor": printerOuiVendor,
        "device.model": "HP LaserJet M507",
        "device.managed": "false",
        "ise.EndpointPolicy": "HP-Device",
        "ise.IdentityGroup": "Printers",
        "ise.EndpointOUI": printerOuiVendor,
        "ise.SelectedAuthorizationProfile": "PERMIT_PRINTER_VLAN50",
      },
    },

    // ---------------------------------------------------------------------
    // 3. THE TELL — the "printer" asks for DHCP like a Windows PC.
    //    ISE's profiler reads the DHCP fingerprint and hostname.
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_03_dhcp_fingerprint",
      ts: T(52 * MIN + 40_000),
      source: "nac",
      vendor: "Cisco ISE",
      event_type: "dhcp_lease",
      hostname: rogueHostname,
      src_ip: rogueIp,
      severity: "medium",
      incident_id: INCIDENT,
      description:
        "The endpoint that just authenticated as a printer sent a DHCP request on VLAN 50. Its DHCP options carry a Microsoft Windows fingerprint and a workstation-style hostname — not what an HP printer emits.",
      raw: {
        "ise.MessageCode": "80002",
        "ise.ProfilerServer": ise.host,
        "event.action": "dhcp-profiling",
        "event.category": "network",
        "event.type": "dhcp_lease",
        "event.outcome": "success",
        "event.severity": "medium",
        "source.mac": printerMac,
        "host.mac": printerMac,
        "host.name": rogueHostname,
        "host.ip": rogueIp,
        "source.ip": rogueIp,
        "device.type": "Printer",
        "ise.dhcp-class-identifier": "MSFT 5.0",
        "ise.dhcp-parameter-request-list": "1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121, 249, 252",
        "ise.dhcp-requested-hostname": rogueHostname,
        "ise.dhcp-fingerprint": "Windows 10/11 Workstation",
        "ise.EndpointOUI": printerOuiVendor,
        "switch.name": accessSwitch.name,
        "switch.port": accessSwitch.port,
        "network.vlan.id": "50",
        "network.zone": "PRINTERS",
      },
    },

    // ---------------------------------------------------------------------
    // 4. THE CONTRADICTION ISE FLAGS — OUI says HP, fingerprint says Windows.
    //    Endpoint reprofiled; Anomalous Behaviour raised (MAC-spoof signature).
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_04_profiler_anomaly",
      ts: T(54 * MIN),
      source: "nac",
      vendor: "Cisco ISE",
      event_type: "ueba_anomaly",
      hostname: rogueHostname,
      src_ip: rogueIp,
      severity: "high",
      mitre_technique: "T1036",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description:
        "ISE's profiler reclassified the endpoint from HP-Device to Microsoft-Workstation while its MAC OUI still resolves to Hewlett-Packard, and raised Anomalous Behaviour — the signature of a device presenting a MAC that does not belong to it.",
      raw: {
        "ise.MessageCode": "80111",
        "ise.MessageText": "Profiler detected anomalous behaviour for endpoint",
        "event.action": "profiling-anomaly",
        "event.category": "threat",
        "event.type": "ueba_anomaly",
        "event.outcome": "detected",
        "event.severity": "high",
        "event.risk_score": "78",
        "event.reason": "OUI/fingerprint mismatch — vendor OUI Hewlett-Packard, DHCP fingerprint Windows Workstation",
        "source.mac": printerMac,
        "host.mac": printerMac,
        "host.name": rogueHostname,
        "host.ip": rogueIp,
        "source.ip": rogueIp,
        "device.vendor": printerOuiVendor,
        "ise.EndpointOUI": printerOuiVendor,
        "ise.OldEndpointPolicy": "HP-Device",
        "ise.EndpointPolicy": "Microsoft-Workstation",
        "ise.AnomalousBehaviour": "true",
        "ise.AnomalousBehaviourDetail": "MACSpoofing",
        "threat.name": "Endpoint MAC Spoofing",
        "threat.category": "rogue-device",
        "threat.severity": "high",
        "switch.name": accessSwitch.name,
        "switch.port": accessSwitch.port,
        "network.vlan.id": "50",
        "network.zone": "PRINTERS",
      },
    },

    // ---------------------------------------------------------------------
    // 5. POSTURE FAILS — the device tries to reach CORP and cannot prove it
    //    is managed. No machine cert, no running AV, no EDR.
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_05_posture_fail",
      ts: T(56 * MIN),
      source: "nac",
      vendor: "Cisco ISE",
      event_type: "auth_failure",
      hostname: rogueHostname,
      src_ip: rogueIp,
      severity: "high",
      mitre_technique: "T1078",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description:
        "The endpoint attempted 802.1X to move off the printer VLAN toward CORP. EAP-TLS failed with an unknown CA (no NexaCorp machine certificate), and the posture check found no compliant AV, no EDR, and the host firewall off.",
      authentication: {
        method: "EAP-TLS",
        result: "failure",
      },
      raw: {
        "ise.MessageCode": "5411",
        "ise.MessageText": "Supplicant stopped responding to ISE / posture failed",
        "event.action": "posture-assessment",
        "event.category": "authentication",
        "event.type": "auth_failure",
        "event.outcome": "failure",
        "event.severity": "high",
        "authentication.method": "EAP-TLS",
        "authentication.protocol": "802.1X",
        "authentication.status": "failure",
        "authentication.server": ise.host,
        "authentication.failure_reason": "12514 EAP-TLS failed — certificate chain not trusted (unknown CA)",
        "certificate.issuer": "CN=DESKTOP-3F9KQ2 self-signed, O=WORKGROUP",
        "certificate.subject": "CN=DESKTOP-3F9KQ2",
        "policy.name": "Corp_Posture_Required",
        "policy.result": "NonCompliant",
        "policy.violation": "No machine certificate; AV not running; EDR agent absent; host firewall disabled",
        "device.managed": "false",
        "device.compliant": "false",
        "device.posture.status": "NonCompliant",
        "posture.antivirus.status": "not-running",
        "posture.edr.status": "absent",
        "posture.firewall.status": "disabled",
        "posture.patch_level": "unknown",
        "posture.disk_encryption.status": "not-detected",
        "source.mac": printerMac,
        "host.mac": printerMac,
        "host.name": rogueHostname,
        "host.ip": rogueIp,
        "source.ip": rogueIp,
        "switch.name": accessSwitch.name,
        "switch.port": accessSwitch.port,
        "network.vlan.id": "50",
      },
    },

    // ---------------------------------------------------------------------
    // 6. IT TRIED TO GO WHERE IT SHOULDN'T — authorization denied for the
    //    Finance segment; ISE's dACL confined it to the printer VLAN.
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_06_segment_denied",
      ts: T(58 * MIN),
      source: "nac",
      vendor: "Cisco ISE",
      event_type: "net_blocked",
      hostname: rogueHostname,
      src_ip: rogueIp,
      dst_ip: "10.30.9.55",
      severity: "high",
      mitre_technique: "T1078",
      mitre_tactic: "Defense Evasion",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description:
        "ISE authorization denied the endpoint's request to reach the Finance server segment. Because posture failed, the applied result was a restrictive dACL, keeping the rogue confined to the printer VLAN instead of the segment it aimed for.",
      raw: {
        "ise.MessageCode": "5434",
        "ise.MessageText": "Endpoint conducted authorization request — access denied by policy",
        "event.action": "authorization",
        "event.category": "network",
        "event.type": "net_blocked",
        "event.outcome": "failure",
        "event.severity": "high",
        "event.reason": "Posture NonCompliant — corporate segment access denied",
        "policy.name": "Deny_NonCompliant_To_Finance",
        "policy.result": "DenyAccess",
        "policy.id": "AUTHZ-DENY-0042",
        "source.mac": printerMac,
        "host.mac": printerMac,
        "host.name": rogueHostname,
        "host.ip": rogueIp,
        "source.ip": rogueIp,
        "destination.ip": "10.30.9.55",
        "destination.hostname": "FS-FIN-01.nexacorp.com",
        "network.vlan.id": "50",
        "network.zone": "PRINTERS",
        "ise.SelectedAuthorizationProfile": "DENY_ACCESS_LIMITED_DACL",
        "switch.name": accessSwitch.name,
        "switch.port": accessSwitch.port,
      },
    },

    // ---------------------------------------------------------------------
    // 7. NAC QUARANTINE — ISE issues a Change of Authorization; the port is
    //    bounced onto the quarantine VLAN.
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_07_quarantine_coa",
      ts: T(59 * MIN),
      source: "nac",
      vendor: "Cisco ISE",
      event_type: "nac_quarantine",
      hostname: accessSwitch.name,
      src_ip: rogueIp,
      severity: "high",
      mitre_technique: "T1200",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description:
        "ISE issued a Change of Authorization for the endpoint on SW-ACC-07 GigabitEthernet1/0/14 and moved it to the quarantine VLAN, citing MAC spoofing and a failed posture assessment.",
      raw: {
        "ise.MessageCode": "5442",
        "ise.MessageText": "Dynamic Authorization succeeded — CoA issued",
        "event.action": "change-of-authorization",
        "event.category": "network",
        "event.type": "nac_quarantine",
        "event.outcome": "success",
        "event.severity": "high",
        "quarantine.status": "quarantined",
        "quarantine.reason": "MAC spoofing (OUI/fingerprint mismatch) and failed posture assessment",
        "ise.CoAType": "Port Bounce",
        "ise.CoAReason": "ANC-Quarantine",
        "ise.ANCPolicy": "QUARANTINE_ROGUE",
        "source.mac": printerMac,
        "host.mac": printerMac,
        "host.ip": rogueIp,
        "radius.nas.ip": accessSwitch.ip,
        "radius.session.id": "0A0A07070000010C5E1C77A2",
        "switch.name": accessSwitch.name,
        "switch.ip": accessSwitch.ip,
        "switch.port": accessSwitch.port,
        "switch.interface": accessSwitch.interface,
        "network.vlan.id": "999",
        "network.zone": "QUARANTINE",
      },
    },

    // ---------------------------------------------------------------------
    // 8. THE ALERT THAT OPENED THE TICKET — ISE rogue-endpoint correlation.
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_08_ise_alert",
      ts: T(61 * MIN),
      source: "nac",
      vendor: "Cisco ISE",
      event_type: "ueba_anomaly",
      hostname: rogueHostname,
      src_ip: rogueIp,
      severity: "high",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description:
        "ISE raised a rogue-endpoint alert tying the sequence together: a MAB session on a printer MAC, a Windows DHCP fingerprint, an anomalous reprofile, a failed posture, and the quarantine that followed.",
      raw: {
        "alert.id": "ISE-ROGUE-2026-0831-014",
        "alert.name": "Rogue Endpoint — MAC Spoofing on Access Port",
        "alert.description":
          "Endpoint on SW-ACC-07 Gi1/0/14 authenticated via MAB using printer MAC 00:1B:78:AA:41:9C but exhibits a Windows workstation profile; posture NonCompliant; endpoint quarantined.",
        "alert.status": "open",
        "event.action": "correlation-alert",
        "event.category": "threat",
        "event.type": "ueba_anomaly",
        "event.outcome": "alerted",
        "event.severity": "high",
        "event.risk_score": "84",
        "threat.name": "Rogue Device via MAB Abuse",
        "threat.category": "unauthorized-access",
        "threat.severity": "high",
        "source.mac": printerMac,
        "host.mac": printerMac,
        "host.name": rogueHostname,
        "host.ip": rogueIp,
        "source.ip": rogueIp,
        "ise.EndpointOUI": printerOuiVendor,
        "ise.EndpointPolicy": "Microsoft-Workstation",
        "ise.IdentityGroup": "Printers",
        "switch.name": accessSwitch.name,
        "switch.port": accessSwitch.port,
        "network.vlan.id": "999",
        "network.zone": "QUARANTINE",
      },
    },
  ];

  // Baseline event also belongs to the investigation (as the comparison).
  events[0].incident_id = INCIDENT;

  const iocs: IOC[] = [
    {
      // Rogue MAC — the printer's address, spoofed onto an unmanaged laptop.
      type: "host",
      value: printerMac,
      first_seen: T(52 * MIN),
      last_seen: T(61 * MIN),
      reputation: "malicious",
      tags: ["mac", "spoofed", "mab-abuse", "printer-mac"],
    },
    {
      // OUI / vendor half of the spoofed MAC — resolves to Hewlett-Packard,
      // which is exactly why MAB trusted it and why the Windows fingerprint is
      // a contradiction.
      type: "host",
      value: printerOuiVendor,
      first_seen: T(52 * MIN),
      last_seen: T(61 * MIN),
      reputation: "suspicious",
      tags: ["oui", "vendor", "hp", "spoofed-identity"],
    },
    {
      // The IP the rogue pulled on the printer VLAN.
      type: "ip",
      value: rogueIp,
      first_seen: T(52 * MIN + 40_000),
      last_seen: T(61 * MIN),
      reputation: "malicious",
      tags: ["internal", "printer-vlan", "rogue-endpoint"],
    },
    {
      // The Windows hostname the DHCP request leaked — a printer would not have it.
      type: "host",
      value: rogueHostname,
      first_seen: T(52 * MIN + 40_000),
      last_seen: T(61 * MIN),
      reputation: "malicious",
      tags: ["hostname", "windows", "unmanaged"],
    },
    {
      // The physical switch port the device was plugged into — the containment
      // point. The switch itself is NexaCorp infrastructure (the victim estate),
      // so the indicator here is the port, not the switch's trustworthiness.
      type: "host",
      value: accessSwitch.port,
      first_seen: T(52 * MIN),
      last_seen: T(59 * MIN),
      reputation: "unknown",
      tags: ["switch-port", "SW-ACC-07", "containment-point"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "The rogue device had no corporate certificate and no 802.1X supplicant. Which event explains how it still got an IP and a place on the network?",
      hint: "Look at how evt_rd_02 authenticated — the method, not a password or a cert.",
      kind: "single",
      options: [
        { value: "mab", label: "evt_rd_02_mab_accept — MAB authenticated it by MAC address alone, and the MAC matched a known printer" },
        { value: "eaptls", label: "evt_rd_01_benign_onboard — it reused the managed laptop's EAP-TLS certificate" },
        { value: "dhcp", label: "evt_rd_03_dhcp_fingerprint — DHCP handed it an address with no authentication at all" },
        { value: "posture", label: "evt_rd_05_posture_fail — the failed posture check let it on with reduced access" },
      ],
      answer: "mab",
      xp: 40,
      explanation:
        "MAB — MAC Authentication Bypass — exists for devices that cannot run 802.1X, like printers and IoT sensors: the switch simply checks whether the MAC address is known and authorised. It verifies the address, not the device. By copying an HP printer's MAC (00:1B:78:AA:41:9C), the rogue inherited the printer's authorisation and was dropped onto the printer VLAN without ever proving what it was. This is the core weakness of MAB and the reason profiling exists to back it up. EAP-TLS (evt_rd_01) is the managed path the rogue could not use; DHCP only leases an address after the port is already authorised; the posture failure comes later and grants nothing.",
    },
    {
      id: "q2",
      prompt:
        "evt_rd_04_profiler_anomaly is the event that gives the rogue away. What is the contradiction ISE detected?",
      hint: "Compare the OUI (the vendor half of the MAC) with the DHCP fingerprint from evt_rd_03.",
      kind: "single",
      options: [
        { value: "oui_vs_fingerprint", label: "The MAC's OUI resolves to Hewlett-Packard (a printer), but the DHCP fingerprint and hostname are a Windows workstation" },
        { value: "two_ips", label: "The same device requested two different IP addresses within one minute" },
        { value: "wrong_switch", label: "The printer MAC appeared on a switch it had never been seen on before" },
        { value: "expired_cert", label: "The device presented a corporate certificate that had already expired" },
      ],
      answer: "oui_vs_fingerprint",
      xp: 60,
      explanation:
        "A MAC address has two halves: the first three octets are the OUI, which is assigned to a hardware vendor — 00:1B:78 belongs to Hewlett-Packard. So the address claims to be an HP device. But a real HP printer does not send a DHCP request advertising 'MSFT 5.0', a Windows parameter-request list, and a hostname like DESKTOP-3F9KQ2 (evt_rd_03). ISE's profiler reads that fingerprint, sees a Windows workstation wearing a printer's MAC, reprofiles the endpoint from HP-Device to Microsoft-Workstation, and raises Anomalous Behaviour flagged as MAC spoofing. The identity and the behaviour disagree, and that disagreement is the detection. The other options describe things that did not happen in the telemetry.",
    },
    {
      id: "q3",
      prompt:
        "The rogue tried to move beyond the printer VLAN. Which event shows why it was stopped, and what stopped it?",
      kind: "single",
      options: [
        { value: "posture_fail", label: "evt_rd_05_posture_fail — EAP-TLS failed on an unknown CA and posture found no cert, no AV and no EDR, so ISE would not grant corporate access" },
        { value: "fw_block", label: "evt_rd_06_segment_denied — a perimeter firewall dropped the packets before ISE was involved" },
        { value: "benign", label: "evt_rd_01_benign_onboard — the managed laptop's session took priority over the rogue's" },
        { value: "dhcp", label: "evt_rd_03_dhcp_fingerprint — DHCP refused to renew the lease" },
      ],
      answer: "posture_fail",
      xp: 70,
      explanation:
        "When the device tried to authenticate onto a corporate VLAN, ISE ran a posture assessment (evt_rd_05). EAP-TLS failed because the only certificate it could present was self-signed by DESKTOP-3F9KQ2 — an unknown CA, not the NexaCorp issuing CA — and the posture check returned NonCompliant: antivirus not running, EDR agent absent, host firewall disabled. That is the profile of an unmanaged machine, and ISE will not place an unmanaged, uncompliant device on a trusted segment. evt_rd_06 is the authorization *result* of that failure (a deny handled by ISE's dACL, not a perimeter firewall), which is why evt_rd_05 is the event that explains it. The device never had the certificate or the agents that a managed endpoint carries, so it could not pass.",
    },
    {
      id: "q4",
      prompt:
        "You are writing the report. Which statement is actually supported by the events?",
      kind: "single",
      options: [
        { value: "rogue_quarantined", label: "An unmanaged Windows laptop spoofed a printer's MAC to bypass MAB, landed on the printer VLAN, failed posture when it reached for corporate access, and ISE quarantined it" },
        { value: "just_a_printer", label: "A legitimate HP printer was mistakenly quarantined after a routine firmware update changed its behaviour" },
        { value: "managed_laptop", label: "The managed laptop NEXA-LT-4471 was the rogue device and should be investigated" },
        { value: "blocked_at_edge", label: "The device was blocked at the network edge and never authenticated or received an address" },
      ],
      answer: "rogue_quarantined",
      xp: 60,
      explanation:
        "The chain is fully evidenced: MAB accepted the printer MAC onto VLAN 50 (evt_rd_02), the DHCP fingerprint exposed a Windows workstation (evt_rd_03), the profiler flagged the OUI/fingerprint contradiction as MAC spoofing (evt_rd_04), posture failed on an unknown CA with no AV or EDR (evt_rd_05), the reach for the Finance segment was denied (evt_rd_06), and ISE issued a CoA to the quarantine VLAN (evt_rd_07). Option (b) is contradicted by the Windows DHCP fingerprint and self-signed certificate — no printer emits those. Option (c) names the benign baseline: NEXA-LT-4471 authenticated with a valid corp certificate and passed posture (evt_rd_01). Option (d) is wrong because the device did authenticate (via MAB) and did receive 10.50.14.83 — the failure and quarantine happened after it was already on the network, not before.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Rogue Device on the Corporate LAN — Printer That Isn't a Printer",
    threat_actor: "Unauthorized insider / unmanaged device (physical network access)",
    attack_kind: "rogue_device",
    briefing:
      "Cisco ISE raised a High alert at 07:41: a rogue endpoint on access switch SW-ACC-07, port GigabitEthernet1/0/14, authenticated by MAC as a printer but behaves like a Windows workstation, failed posture, and was quarantined. Establish what the device was, how it got on the network, and whether anything followed.",
    narrative: `At 07:32 a device was plugged into a meeting-room wall port on NexaCorp's access switch SW-ACC-07, interface GigabitEthernet1/0/14. It had no 802.1X supplicant and no corporate certificate, so it could not onboard the way a managed laptop does. Instead it presented the MAC address 00:1B:78:AA:41:9C — an HP printer's address — and let the switch authenticate it by MAC alone. That mechanism, MAB, checks only whether an address is known and authorised; the address matched the Printers group, so Cisco ISE accepted it and placed it on the printer VLAN (VLAN 50).

Forty seconds later it gave itself away. The "printer" sent a DHCP request advertising a Microsoft Windows stack — dhcp-class-identifier MSFT 5.0, a Windows parameter-request list — and a hostname, DESKTOP-3F9KQ2, that no HP printer would use. ISE's profiler read that fingerprint, saw a Windows workstation wearing a printer's MAC, reprofiled the endpoint from HP-Device to Microsoft-Workstation and raised Anomalous Behaviour flagged as MAC spoofing: the OUI in the MAC still resolved to Hewlett-Packard, but everything else said laptop.

When the device then attempted 802.1X to move off the printer VLAN toward the corporate network, ISE ran a posture assessment. EAP-TLS failed on an unknown CA — the only certificate on offer was self-signed by DESKTOP-3F9KQ2, not the NexaCorp issuing CA — and the posture check returned NonCompliant: no antivirus running, no EDR agent, host firewall disabled. ISE denied the request to reach the Finance server segment and, at 07:39, issued a Change of Authorization that bounced the port onto the quarantine VLAN.

The managed laptop NEXA-LT-4471, shown first, is the contrast: 802.1X EAP-TLS with a valid NexaCorp certificate, a Compliant posture, and clean placement on the CORP VLAN. Same building, same NAC — the difference is that one device could prove what it was and the other could only borrow a printer's name.`,
    learning_objectives: [
      "Explain MAB (MAC Authentication Bypass) and why authenticating a device by its MAC address alone is spoofable",
      "Read a MAC address as OUI (vendor) + device, and use the OUI to spot a device impersonating another vendor's hardware",
      "Use an endpoint's DHCP fingerprint and hostname to tell a real printer/IoT device from a workstation wearing its MAC",
      "Interpret a NAC posture result (certificate, AV, EDR, firewall) to judge whether a device is managed and compliant",
      "Follow a NAC response from detection to enforcement — profiling anomaly, posture failure, authorization deny, and CoA quarantine",
      "Compare a suspicious onboarding against a known-good managed onboarding to establish what 'normal' looks like",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Baseline", action: `Managed laptop ${goodLaptop.name} onboards cleanly — EAP-TLS, Compliant posture, CORP VLAN (the comparison)` },
      { ts: T(52 * MIN), phase: "Initial Access", action: `Rogue device plugged into ${accessSwitch.name} ${accessSwitch.port}; MAB accepts spoofed printer MAC ${printerMac} onto VLAN 50` },
      { ts: T(52 * MIN + 40_000), phase: "Defense Evasion", action: `DHCP request leaks a Windows fingerprint (MSFT 5.0) and hostname ${rogueHostname} — not a printer` },
      { ts: T(54 * MIN), phase: "Discovery", action: `ISE profiler reprofiles HP-Device → Microsoft-Workstation and raises Anomalous Behaviour (MAC spoofing)` },
      { ts: T(56 * MIN), phase: "Credential Access", action: "Posture assessment fails — unknown CA, no AV, no EDR, firewall off; device is unmanaged" },
      { ts: T(58 * MIN), phase: "Lateral Movement", action: "Attempt to reach the Finance segment denied by ISE authorization (restrictive dACL)" },
      { ts: T(59 * MIN), phase: "Containment", action: `ISE issues CoA — port bounced to quarantine VLAN 999` },
      { ts: T(61 * MIN), phase: "Detection", action: "ISE raises the rogue-endpoint correlation alert that opened the ticket" },
    ],
    questions,
  };
}
