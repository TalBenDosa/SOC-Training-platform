/**
 * Scenario pack: "NAC alert for an unknown endpoint on SW-ACC-07"
 *
 * BEGINNER tier. An unmanaged laptop is plugged into a wall port in a NexaCorp
 * meeting room. It has no 802.1X supplicant and no corporate certificate, so it
 * cannot log in the way a managed laptop does. Instead it copies the MAC address
 * of a nearby HP printer and lets the switch authenticate it by MAC alone (MAB -
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
    // 1. BENIGN BASELINE, a managed laptop onboards the correct way.
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
        "Managed corporate laptop NEXA-LT-4471 authenticated with 802.1X EAP-TLS on SW-ACC-07 GigabitEthernet1/0/03; posture Compliant; placed on CORP VLAN 20.",
      fp_explanation:
        "Benign baseline. EAP-TLS with a valid NexaCorp machine certificate, a Compliant posture result, and placement on the CORP VLAN, the correct, expected onboarding for a managed device. Included as the comparison for the rogue.",
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
        "radius.calling_station_id": goodLaptop.mac.replace(/:/g, "-"),
        "radius.called_station_id": "00-2A-10-3C-7E-14",
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
    // 2. THE ROGUE LANDS, MAB accepts the spoofed printer MAC.
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
        "MAB session on SW-ACC-07 GigabitEthernet1/0/14: MAC 00:1B:78:AA:41:9C matched the Printers identity group; authorization profile PERMIT_PRINTER_VLAN50.",
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
        "radius.calling_station_id": printerMac.replace(/:/g, "-"),
        "radius.called_station_id": "00-2A-10-3C-7E-14",
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
        "device.managed": "false",
        "ise.EndpointPolicy": "HP-Device",
        "ise.IdentityGroup": "Printers",
        "ise.EndpointOUI": printerOuiVendor,
        "ise.SelectedAuthorizationProfile": "PERMIT_PRINTER_VLAN50",
      },
    },

    // ---------------------------------------------------------------------
    // 3. THE TELL, the "printer" asks for DHCP like a Windows PC.
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
      mitre_technique: "T1036",
      mitre_tactic: "Stealth",
      incident_id: INCIDENT,
      description:
        "ISE profiler record of a DHCP request from the endpoint on VLAN 50: class identifier MSFT 5.0, requested hostname DESKTOP-3F9KQ2, parameter-request list 1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121, 249, 252.",
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
    // 3b. THE DHCP SERVER'S OWN VIEW, event 10 (new lease), same MAC and name.
    //     The profiler saw the request; the server granted the address.
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_03b_dhcp_server_lease",
      ts: T(52 * MIN + 41_000),
      source: "dhcp",
      vendor: "Windows DHCP Server",
      event_type: "dhcp_lease",
      hostname: rogueHostname,
      src_ip: rogueIp,
      severity: "informational",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description:
        "Windows DHCP Server event 10: new lease 10.50.14.83 to MAC 001B78AA419C, client hostname DESKTOP-3F9KQ2, scope Printers-VLAN50.",
      raw: {
        "event.code": "10",
        "dhcp.event_type": "new_lease",
        "dhcp.client_ip": rogueIp,
        "dhcp.client_hostname": rogueHostname,
        "dhcp.mac": "001B78AA419C",
        "dhcp.lease_duration_hours": "8",
      },
    },

    // ---------------------------------------------------------------------
    // 3c. FIRST TRAFFIC OFF THE SEGMENT, an ordinary DNS lookup through the
    //     core firewall, allowed by the printer-VLAN policy.
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_03c_fw_dns_allow",
      ts: T(52 * MIN + 55_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_connection",
      hostname: "FW-CORE-01",
      src_ip: rogueIp,
      dst_ip: "10.10.1.10",
      src_port: 53712,
      dst_port: 53,
      protocol: "udp",
      severity: "informational",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description: "Core firewall allowed udp/53 from 10.50.14.83 to the internal DNS server 10.10.1.10.",
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "end",
        "pan.action": "allow",
        "pan.rule": "Printers-To-DNS",
        "pan.from_zone": "printers",
        "pan.to_zone": "servers",
        "pan.src": rogueIp,
        "pan.dst": "10.10.1.10",
        "pan.sport": "53712",
        "pan.dport": "53",
        "pan.app": "dns",
        "pan.bytes_sent": "78",
        "pan.bytes_received": "142",
        "pan.session_end_reason": "aged-out",
        "action_result": "allow",
      },
    },

    // ---------------------------------------------------------------------
    // 4. THE CONTRADICTION ISE FLAGS, OUI says HP, fingerprint says Windows.
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
      mitre_tactic: "Stealth",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description:
        "ISE profiler changed the endpoint policy from HP-Device to Microsoft-Workstation; the MAC OUI still resolves to Hewlett-Packard; Anomalous Behaviour raised for the endpoint.",
      raw: {
        "ise.MessageCode": "80111",
        "ise.MessageText": "Profiler detected anomalous behaviour for endpoint",
        "event.action": "profiling-anomaly",
        "event.category": "threat",
        "event.type": "ueba_anomaly",
        "event.outcome": "detected",
        "event.severity": "high",
        "event.risk_score": "78",
        "event.reason": "Endpoint profile changed",
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
    // 5. POSTURE FAILS, the device tries to reach CORP and cannot prove it
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
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description:
        "802.1X EAP-TLS attempt from the endpoint on SW-ACC-07 GigabitEthernet1/0/14 failed: unknown CA in the client certificate chain; no posture agent responded; no machine certificate.",
      authentication: {
        method: "EAP-TLS",
        result: "failure",
      },
      raw: {
        "ise.MessageCode": "5400",
        "ise.MessageText": "Authentication failed",
        "event.action": "posture-assessment",
        "event.category": "authentication",
        "event.type": "auth_failure",
        "event.outcome": "failure",
        "event.severity": "high",
        "authentication.method": "EAP-TLS",
        "authentication.protocol": "802.1X",
        "authentication.status": "failure",
        "authentication.server": ise.host,
        "authentication.failure_reason": "12514 EAP-TLS failed SSL/TLS handshake because of an unknown CA in the client certificates chain",
        "certificate.issuer": "CN=DESKTOP-3F9KQ2 self-signed, O=WORKGROUP",
        "certificate.subject": "CN=DESKTOP-3F9KQ2",
        "policy.name": "Corp_Posture_Required",
        "policy.result": "NonCompliant",
        "policy.violation": "No posture agent response; no machine certificate",
        "device.managed": "false",
        "device.compliant": "false",
        "device.posture.status": "NonCompliant",
        "posture.antivirus.status": "not-reported",
        "posture.edr.status": "not-reported",
        "posture.firewall.status": "not-reported",
        "posture.patch_level": "not-reported",
        "posture.disk_encryption.status": "not-reported",
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
    // 6. ISE AUTHORIZATION RESULT: after the failed posture ISE hands the
    //    session a restrictive downloadable ACL; it stays on the printer VLAN.
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_06_posture_authz_result",
      ts: T(56 * MIN + 6_000),
      source: "nac",
      vendor: "Cisco ISE",
      event_type: "nac_allow",
      hostname: rogueHostname,
      src_ip: rogueIp,
      severity: "medium",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description:
        "ISE authorization for session 0A0A07070000010C5E1C77A2: policy Deny_NonCompliant_To_Finance matched; profile LIMITED_ACCESS_DACL applied; VLAN 50 unchanged.",
      raw: {
        "ise.MessageCode": "11002",
        "ise.MessageText": "Returned RADIUS Access-Accept",
        "event.action": "authorization",
        "event.category": "network",
        "event.type": "nac_allow",
        "event.outcome": "limited",
        "event.severity": "medium",
        "event.reason": "Posture NonCompliant",
        "policy.name": "Deny_NonCompliant_To_Finance",
        "policy.result": "LimitedAccess",
        "policy.id": "AUTHZ-DENY-0042",
        "source.mac": printerMac,
        "host.mac": printerMac,
        "host.name": rogueHostname,
        "host.ip": rogueIp,
        "source.ip": rogueIp,
        "radius.session.id": "0A0A07070000010C5E1C77A2",
        "network.vlan.id": "50",
        "network.zone": "PRINTERS",
        "ise.SelectedAuthorizationProfile": "LIMITED_ACCESS_DACL",
        "switch.name": accessSwitch.name,
        "switch.port": accessSwitch.port,
      },
    },

    // ---------------------------------------------------------------------
    // 6b/6c. THE REACH FOR FINANCE: the core firewall drops SMB then RDP from
    //        the printer VLAN to the Finance file server (first-packet drops).
    // ---------------------------------------------------------------------
    {
      id: "evt_rd_06b_fw_drop_smb",
      ts: T(57 * MIN + 30_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_blocked",
      hostname: "FW-CORE-01",
      src_ip: rogueIp,
      dst_ip: "10.30.9.55",
      src_port: 49822,
      dst_port: 445,
      protocol: "tcp",
      severity: "medium",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description: "Core firewall dropped tcp/445 from 10.50.14.83 to Finance file server 10.30.9.55 (rule Printers-Deny-Finance).",
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "drop",
        "pan.action": "deny",
        "pan.rule": "Printers-Deny-Finance",
        "pan.from_zone": "printers",
        "pan.to_zone": "finance",
        "pan.src": rogueIp,
        "pan.dst": "10.30.9.55",
        "pan.sport": "49822",
        "pan.dport": "445",
        "pan.app": "not-applicable",
        "pan.session_end_reason": "policy-deny",
        "action_result": "deny",
      },
    },
    {
      id: "evt_rd_06c_fw_drop_rdp",
      ts: T(58 * MIN + 10_000),
      source: "firewall",
      vendor: "Palo Alto Networks PAN-OS",
      event_type: "net_blocked",
      hostname: "FW-CORE-01",
      src_ip: rogueIp,
      dst_ip: "10.30.9.55",
      src_port: 49871,
      dst_port: 3389,
      protocol: "tcp",
      severity: "medium",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description: "Core firewall dropped tcp/3389 from 10.50.14.83 to Finance file server 10.30.9.55 (rule Printers-Deny-Finance).",
      raw: {
        "pan.type": "TRAFFIC",
        "pan.subtype": "drop",
        "pan.action": "deny",
        "pan.rule": "Printers-Deny-Finance",
        "pan.from_zone": "printers",
        "pan.to_zone": "finance",
        "pan.src": rogueIp,
        "pan.dst": "10.30.9.55",
        "pan.sport": "49871",
        "pan.dport": "3389",
        "pan.app": "not-applicable",
        "pan.session_end_reason": "policy-deny",
        "action_result": "deny",
      },
    },

    // ---------------------------------------------------------------------
    // 7. NAC QUARANTINE, ISE issues a Change of Authorization; the port is
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
        "ISE Change of Authorization (Reauthenticate, ANC policy QUARANTINE_ROGUE) for the endpoint on SW-ACC-07 GigabitEthernet1/0/14; VLAN 999.",
      raw: {
        "ise.MessageCode": "5442",
        "ise.MessageText": "Dynamic Authorization succeeded, CoA issued",
        "event.action": "change-of-authorization",
        "event.category": "network",
        "event.type": "nac_quarantine",
        "event.outcome": "success",
        "event.severity": "high",
        "quarantine.status": "quarantined",
        "quarantine.reason": "ANC policy QUARANTINE_ROGUE applied",
        "ise.CoAType": "Reauthenticate",
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
    // 8. THE ALERT THAT OPENED THE TICKET, ISE rogue-endpoint correlation.
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
      mitre_technique: "T1200",
      mitre_tactic: "Initial Access",
      incident_id: INCIDENT,
      edr_scope: "non_edr",
      description:
        "ISE alert ISE-ROGUE-2026-0831-014 (High) for the endpoint on SW-ACC-07 GigabitEthernet1/0/14; port now in quarantine VLAN 999.",
      raw: {
        "alert.id": "ISE-ROGUE-2026-0831-014",
        "alert.name": "Rogue Endpoint, MAC Spoofing on Access Port",
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
      // Rogue MAC, the printer's address, spoofed onto an unmanaged laptop.
      type: "host",
      value: printerMac,
      first_seen: T(52 * MIN),
      last_seen: T(61 * MIN),
      reputation: "malicious",
      tags: ["mac", "radius-calling-station-id"],
    },
    {
      // The IP the rogue pulled on the printer VLAN.
      type: "ip",
      value: rogueIp,
      first_seen: T(52 * MIN + 40_000),
      last_seen: T(61 * MIN),
      reputation: "malicious",
      tags: ["internal", "dhcp-lease"],
    },
    {
      // The Windows hostname the DHCP request leaked, a printer would not have it.
      type: "host",
      value: rogueHostname,
      first_seen: T(52 * MIN + 40_000),
      last_seen: T(61 * MIN),
      reputation: "malicious",
      tags: ["hostname", "dhcp-client-name"],
    },
    {
      // The physical switch port the device was plugged into, the containment
      // point. The switch itself is NexaCorp infrastructure (the victim estate),
      // so the indicator here is the port, not the switch's trustworthiness.
      type: "host",
      value: accessSwitch.port,
      first_seen: T(52 * MIN),
      last_seen: T(59 * MIN),
      reputation: "unknown",
      tags: ["switch-port", "SW-ACC-07"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "q1",
      prompt:
        "The rogue device had no corporate certificate and no 802.1X supplicant. Which event explains how it still got an IP and a place on the network?",
      hint: "Look at how evt_rd_02 authenticated, the method, not a password or a cert.",
      kind: "single",
      options: [
        { value: "mab", label: "The MAB accept, the switch authenticated it by MAC address alone, and that MAC matched a known printer" },
        { value: "eaptls", label: "The EAP-TLS onboarding, it reused NEXA-LT-4471's corporate certificate to complete 802.1X as that laptop" },
        { value: "dhcp", label: "The DHCP exchange, the server leased it an address on request, and a lease is all a wall port needs to join" },
        { value: "posture", label: "The posture failure, ISE put the non-compliant device on a limited remediation VLAN, which gave it its address" },
      ],
      answer: "mab",
      xp: 40,
      explanation:
        "MAB, MAC Authentication Bypass, exists for devices that cannot run 802.1X, like printers and IoT sensors: the switch simply checks whether the MAC address is known and authorised. It verifies the address, not the device. By copying an HP printer's MAC (00:1B:78:AA:41:9C), the rogue inherited the printer's authorisation and was dropped onto the printer VLAN without ever proving what it was. This is the core weakness of MAB and the reason profiling exists to back it up. EAP-TLS (evt_rd_01) is the managed path the rogue could not use; DHCP only leases an address after the port is already authorised; the posture failure comes later and grants nothing.",
    },
    {
      id: "q2",
      prompt:
        "evt_rd_04_profiler_anomaly is the event that gives the rogue away. What is the contradiction ISE detected?",
      hint: "Compare the OUI (the vendor half of the MAC) with the DHCP fingerprint from evt_rd_03.",
      kind: "single",
      options: [
        { value: "oui_vs_fingerprint", label: "The MAC's OUI resolves to Hewlett-Packard, but the DHCP fingerprint and hostname are those of a Windows workstation" },
        { value: "two_ips", label: "The endpoint requested two different IP addresses within one minute, the pattern of a device cycling through spoofed MACs" },
        { value: "wrong_switch", label: "ISE saw the printer MAC authenticate on two switch ports at once, a duplicate-MAC conflict it reports as spoofing" },
        { value: "expired_cert", label: "The device presented a corporate certificate that had expired, so its identity no longer matched the printer group" },
      ],
      answer: "oui_vs_fingerprint",
      xp: 60,
      explanation:
        "A MAC address has two halves: the first three octets are the OUI, which is assigned to a hardware vendor, 00:1B:78 belongs to Hewlett-Packard. So the address claims to be an HP device. But a real HP printer does not send a DHCP request advertising 'MSFT 5.0', a Windows parameter-request list, and a hostname like DESKTOP-3F9KQ2 (evt_rd_03). ISE's profiler reads that fingerprint, sees a Windows workstation wearing a printer's MAC, reprofiles the endpoint from HP-Device to Microsoft-Workstation, and raises Anomalous Behaviour flagged as MAC spoofing. The identity and the behaviour disagree, and that disagreement is the detection. The other options describe things that did not happen in the telemetry.",
    },
    {
      id: "q3",
      prompt:
        "The device was later refused corporate access. Which event shows the condition ISE used to refuse it?",
      kind: "single",
      options: [
        { value: "posture_fail", label: "The EAP-TLS failure, an unknown CA in its certificate chain and no posture agent response, so ISE judged it unmanaged" },
        { value: "fw_block", label: "The firewall drops, the core firewall blocked its Finance-bound traffic, and ISE simply followed the firewall's verdict" },
        { value: "benign", label: "The laptop onboarding, the managed laptop's 802.1X session took priority on the shared port and pushed the rogue off" },
        { value: "dhcp", label: "The DHCP fingerprint, the server refused to renew its printer-scope lease once the Windows stack was profiled" },
      ],
      answer: "posture_fail",
      xp: 70,
      explanation:
        "When the device tried 802.1X toward a corporate VLAN, ISE failed it (evt_rd_05): EAP-TLS ended with 'unknown CA in the client certificates chain' because the only certificate on offer was self-signed by DESKTOP-3F9KQ2, and no posture agent answered, so the result was NonCompliant. That is the profile of an unmanaged machine. evt_rd_06 is ISE's authorization result of that failure (a restrictive downloadable ACL on the session), which is why evt_rd_05 is the event that explains the refusal. The core firewall drops of the SMB and RDP attempts toward 10.30.9.55 are a separate control acting on the traffic itself, not on the posture decision: ISE reached its verdict from its own certificate and posture inputs, before and independent of any firewall log.",
    },
    {
      id: "q4",
      prompt:
        "You are writing the report. Which statement is actually supported by the events?",
      kind: "single",
      options: [
        { value: "rogue_quarantined", label: "An unmanaged Windows laptop spoofed a printer MAC past MAB, landed on the printer VLAN, failed posture reaching for corporate access, and was quarantined" },
        { value: "just_a_printer", label: "A genuine HP printer was quarantined by mistake after a firmware update changed its DHCP fingerprint and hostname format, so ISE misprofiled it" },
        { value: "managed_laptop", label: "The managed laptop NEXA-LT-4471 was the rogue: it onboarded minutes earlier with its certificate, then came back behind the printer's MAC" },
        { value: "blocked_at_edge", label: "MAB rejected the device at the switch port, so it was denied before authenticating, receiving a DHCP address or joining any VLAN at all" },
      ],
      answer: "rogue_quarantined",
      xp: 60,
      explanation:
        "The chain is fully evidenced: MAB accepted the printer MAC onto VLAN 50 (evt_rd_02), the DHCP fingerprint exposed a Windows workstation (evt_rd_03, and the DHCP server's own lease record evt_rd_03b), the profiler flagged the OUI/fingerprint contradiction as MAC spoofing (evt_rd_04), EAP-TLS failed on an unknown CA with no posture agent response (evt_rd_05), ISE limited the session (evt_rd_06), the core firewall dropped its SMB and RDP attempts toward the Finance file server (evt_rd_06b, evt_rd_06c), and ISE issued a CoA to the quarantine VLAN (evt_rd_07). Option (b) is contradicted by the Windows DHCP fingerprint and self-signed certificate, no printer emits those. Option (c) names the benign baseline: NEXA-LT-4471 authenticated with a valid corp certificate and passed posture (evt_rd_01). Option (d) is wrong because the device did authenticate (via MAB) and did receive 10.50.14.83 from the DHCP server, the failure and quarantine happened after it was already on the network, not before.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "NAC alert for an unknown endpoint on SW-ACC-07",
    threat_actor: "Unauthorized insider / unmanaged device (physical network access)",
    attack_kind: "rogue_device",
    briefing:
      "Cisco ISE raised alert ISE-ROGUE-2026-0831-014 (High) at 07:41 for an endpoint on access switch SW-ACC-07, port GigabitEthernet1/0/14. The port is now in quarantine VLAN 999. Establish what the device is, how it got on the network, and whether anything followed.",
    narrative: `At 07:32 a device was plugged into a meeting-room wall port on NexaCorp's access switch SW-ACC-07, interface GigabitEthernet1/0/14. It had no 802.1X supplicant and no corporate certificate, so it could not onboard the way a managed laptop does. Instead it presented the MAC address 00:1B:78:AA:41:9C, an HP printer's address, and let the switch authenticate it by MAC alone. That mechanism, MAB, checks only whether an address is known and authorised; the address matched the Printers group, so Cisco ISE accepted it and placed it on the printer VLAN (VLAN 50).

Forty seconds later it gave itself away. The "printer" sent a DHCP request advertising a Microsoft Windows stack, dhcp-class-identifier MSFT 5.0, a Windows parameter-request list, and a hostname, DESKTOP-3F9KQ2, that no HP printer would use. ISE's profiler read that fingerprint, saw a Windows workstation wearing a printer's MAC, reprofiled the endpoint from HP-Device to Microsoft-Workstation and raised Anomalous Behaviour flagged as MAC spoofing: the OUI in the MAC still resolved to Hewlett-Packard, but everything else said laptop.

When the device then attempted 802.1X to move off the printer VLAN toward the corporate network, ISE ran a posture assessment. EAP-TLS failed on an unknown CA, the only certificate on offer was self-signed by DESKTOP-3F9KQ2, not the NexaCorp issuing CA, and no posture agent answered, so the result was NonCompliant. ISE limited the session with a restrictive downloadable ACL. At 07:37 and 07:38 the core firewall dropped the device's SMB (tcp/445) and RDP (tcp/3389) attempts toward the Finance file server 10.30.9.55, and at 07:39 ISE issued a Change of Authorization that moved the port onto the quarantine VLAN. Nothing else from 10.50.14.83 crossed the firewall apart from its DNS lookups; the Windows DHCP Server log shows the same MAC and hostname taking the lease at 07:32:41.

The managed laptop NEXA-LT-4471, shown first, is the contrast: 802.1X EAP-TLS with a valid NexaCorp certificate, a Compliant posture, and clean placement on the CORP VLAN. Same building, same NAC, the difference is that one device could prove what it was and the other could only borrow a printer's name.`,
    learning_objectives: [
      "Explain MAB (MAC Authentication Bypass) and why authenticating a device by its MAC address alone is spoofable",
      "Read a MAC address as OUI (vendor) + device, and use the OUI together with the DHCP fingerprint and hostname to tell a real printer/IoT device from a workstation wearing its MAC",
      "Interpret a NAC authentication and posture result (certificate chain, posture-agent response) against a known-good managed onboarding to judge whether a device is managed and compliant",
      "Follow a NAC response from detection to enforcement, correlating NAC, DHCP and firewall logs: profiling anomaly, posture failure, firewall drops, and CoA quarantine",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: T(0), phase: "Baseline", action: `Managed laptop ${goodLaptop.name} onboards cleanly: EAP-TLS, Compliant posture, CORP VLAN (the comparison)` },
      { ts: T(52 * MIN), phase: "Initial Access", action: `Rogue device plugged into ${accessSwitch.name} ${accessSwitch.port}; MAB accepts spoofed printer MAC ${printerMac} onto VLAN 50` },
      { ts: T(52 * MIN + 40_000), phase: "Stealth", action: `DHCP request leaks a Windows fingerprint (MSFT 5.0) and hostname ${rogueHostname}; the DHCP server leases ${rogueIp}` },
      { ts: T(54 * MIN), phase: "Detection", action: `ISE profiler changes the endpoint policy HP-Device to Microsoft-Workstation and raises Anomalous Behaviour` },
      { ts: T(56 * MIN), phase: "Enforcement", action: "EAP-TLS fails on an unknown CA with no posture agent response; ISE limits the session with a restrictive dACL" },
      { ts: T(57 * MIN + 30_000), phase: "Discovery", action: "SMB and RDP attempts toward the Finance file server 10.30.9.55 dropped by the core firewall" },
      { ts: T(59 * MIN), phase: "Containment", action: `ISE issues CoA (ANC quarantine): port moved to quarantine VLAN 999` },
      { ts: T(61 * MIN), phase: "Detection", action: "ISE raises the rogue-endpoint correlation alert that opened the ticket" },
    ],
    questions,
  };
}
