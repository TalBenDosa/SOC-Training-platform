import type { TelemetryEvent } from "@/lib/sim/types";

// ── NAC posture quarantine event ─────────────────────────────────────────────
const nacPostureEvent: TelemetryEvent = {
  id: "evt-nac-posture-001",
  ts: "2024-10-03T08:47:22.000Z",
  source: "nac",
  vendor: "Cisco ISE",
  event_type: "nac_quarantine",
  severity: "medium",
  hostname: "ISE-PSN-01",
  src_ip: "10.10.5.67",
  description:
    "Endpoint quarantined: posture assessment failed - AV signatures 45 days out of date, Windows patches missing",
  raw: {
    "cisco.ise.step": "11507",
    "cisco.ise.message_code": "5411",
    "cisco.ise.authentication_identity_store": "AD1",
    "cisco.ise.identity_group": "Domain Users",
    "cisco.ise.authorization_rule": "Posture-NonCompliant",
    "cisco.ise.selected_authorization_profile": "QUARANTINE",
    "cisco.ise.network_device_name": "SW-ACCESS-FL2-01",
    "cisco.ise.network_device_ip": "10.10.0.1",
    "cisco.ise.nas_port": "GigabitEthernet1/0/14",
    "cisco.ise.calling_station_id": "3C:22:FB:A1:D7:09",
    "cisco.ise.endpoint_mac_address": "3C:22:FB:A1:D7:09",
    "cisco.ise.endpoint_profile": "Windows10-Workstation",
    "cisco.ise.posture_assessment_status": "NonCompliant",
    "cisco.ise.posture_failure_reasons":
      "AntivirusDefinitionOutOfDate, MissingWindowsPatches",
    "cisco.ise.selected_vlan": "VLAN-50-QUARANTINE",
    "cisco.ise.acl": "ACL-QUARANTINE-REMEDIATION",
    "cisco.ise.cisco_av_pair":
      "url-redirect=https://ise-psn-01.corp.local/guestportal/gateway",
    "user.name": "CORP\\t.goldberg",
    "source.ip": "10.10.5.67",
  },
};

// ── Room: NAC Masterclass ─────────────────────────────────────────────────────
const nacMasterclass = {
  id: "nac-masterclass",
  title: "Network Access Control: Zero Trust at the Port",
  description:
    "Master Network Access Control from the ground up: 802.1X authentication, RADIUS, device posture assessment, VLAN segmentation, Cisco ISE, Aruba ClearPass, Zero Trust integration, and NAC bypass detection. Learn how NAC enforces identity-based access before a single packet reaches the corporate network.",
  difficulty: "intermediate" as const,
  category: "Network Security",
  estimatedMinutes: 65,
  xp: 170,
  icon: "🔐",
  prerequisites: ["networking-protocols", "active-directory"],
  tasks: [
    // ── Reading 1 ──────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "nac-r1",
      heading: "What Is NAC and the Problem It Solves",
      content:
        "Picture a large office building in 2012. The lobby has dozens of Ethernet wall ports. A contractor arrives for a one-day visit, opens their laptop, plugs it into an unused port near the conference room, and immediately has full access to the corporate network — file servers, HR databases, the ERP system — everything. Nobody checked who they were, nobody verified the device was safe, and nobody assigned them only the access they needed. This is the rogue device problem, and it was happening in companies worldwide.\n\n" +
        "The BYOD (Bring Your Own Device) explosion of the early 2010s made things dramatically worse. Employees wanted to work on personal smartphones and tablets. Each personal device brought unknown software, potentially outdated operating systems, and zero corporate security controls. At the same time, IoT devices proliferated: smart TVs in meeting rooms, IP cameras in hallways, Wi-Fi-enabled printers — all connecting to the same network switches as the finance team's computers.\n\n" +
        "The core problem is a flawed assumption baked into traditional network design: being physically connected to the network is treated as proof of legitimacy. A device plugged into the office switch is assumed to be a trusted corporate device. This assumption breaks the moment anyone can physically reach a network port.\n\n" +
        "Network Access Control (NAC) was developed to solve exactly this problem. NAC enforces three principles before granting network access:\n\n" +
        "First, authenticate: prove who you are (user identity via Active Directory credentials, or device identity via certificate). Second, assess: verify that the device is healthy (antivirus running, OS patches current, encryption enabled). Third, authorize: grant only the minimum necessary access based on who you are and how healthy your device is.\n\n" +
        "The philosophical foundation comes from Zero Trust: network location is not a measure of trust. Being physically connected to an Ethernet port does not make you trusted. Being on the Wi-Fi does not make you trusted. Every device must prove its identity and health before receiving access, every time.\n\n" +
        "A useful analogy is airport security. Before NAC, the office network was like an airport with doors but no security checkpoints — anyone who walked through could go anywhere. With NAC, every device passes through a scanner (posture assessment) and shows a boarding pass (identity credential) before entering the gate area. First-class passengers (senior executives with fully compliant devices) get access to the executive lounge. Economy passengers (contractors) get access only to their assigned areas. Passengers who fail security screening (non-compliant devices) are taken to a secondary inspection area (quarantine VLAN) until the problem is resolved.\n\n" +
        "A second analogy: a building's access badge system. Every door is controlled. Employees have badges that open specific doors based on their role. Visitors get a temporary badge that only opens the lobby and meeting rooms. Unauthorized people are stopped at the door. NAC is the digital equivalent for network access — but instead of doors, it controls switch ports and wireless access points.",
      codeExample:
        "WITHOUT NAC\n" +
        "============\n" +
        "Contractor laptop\n" +
        "      |\n" +
        "      | (plug in)\n" +
        "      v\n" +
        "Office Ethernet Port\n" +
        "      |\n" +
        "      v\n" +
        "Access Switch  -->  Core Switch  -->  [FULL CORPORATE NETWORK]\n" +
        "                                       - HR Database\n" +
        "                                       - Finance Server\n" +
        "                                       - ERP System\n" +
        "                                       - Active Directory\n" +
        "No authentication. No posture check. Full access granted by default.\n\n" +
        "WITH NAC (Cisco ISE)\n" +
        "=====================\n" +
        "Contractor laptop\n" +
        "      |\n" +
        "      | (plug in)\n" +
        "      v\n" +
        "Access Switch  -- UNAUTHORIZED STATE -->\n" +
        "      |                                  \\\n" +
        "      | (EAPOL auth frames only)          \\\n" +
        "      v                                    \\\n" +
        "   Cisco ISE  <-- RADIUS Access-Request     |\n" +
        "      |                                     |\n" +
        "      | Check: identity? device health?     |\n" +
        "      |                                     |\n" +
        "      v                                     |\n" +
        "   RESULT:                                  |\n" +
        "   Domain user, compliant device  --> VLAN 10 (Full Corporate)\n" +
        "   Domain user, non-compliant     --> VLAN 50 (Quarantine Only)\n" +
        "   Contractor, compliant          --> VLAN 20 (Limited Access)\n" +
        "   Unknown device                 --> VLAN 30 (Guest / Internet Only)\n" +
        "   Authentication failure         --> Port blocked entirely",
    },
    // ── Reading 2 ──────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "nac-r2",
      heading: "The Three Components of NAC: Supplicant, Authenticator, Server",
      content:
        "Every NAC deployment in the world — whether it is Cisco ISE, Aruba ClearPass, Fortinet FortiNAC, or Microsoft NPS — is built on exactly three components working together. Understanding these three roles is the foundation for understanding how NAC functions.\n\n" +
        "The first component is the Supplicant. This is the software running on the endpoint device that participates in the authentication dialogue. On Windows, there is a built-in 802.1X supplicant included since Windows Vista — it is the 'Wired AutoConfig' or 'WLAN AutoConfig' service, and it requires no additional software installation. macOS also includes a native 802.1X supplicant. For corporate NAC deployments, organizations often replace or supplement the native supplicant with a vendor-specific agent (such as the Cisco AnyConnect Network Access Manager or the Aruba VIA client) that adds posture assessment capability on top of pure authentication.\n\n" +
        "The second component is the Authenticator. This is the network device that enforces access — typically an access-layer switch or a wireless access point (WAP). The authenticator's role is purely enforcement: it does not make the authentication decision itself. When a device connects, the switch port is placed in an UNAUTHORIZED state. In this state, the port only passes EAPOL (EAP over LAN) frames — the special Layer 2 frames used for the authentication conversation. No IP traffic, no DHCP, no DNS, no HTTP can pass through an unauthorized port. The switch acts as a controlled gate, not a decision-maker.\n\n" +
        "The third component is the Authentication Server. This is where the actual trust decision is made. In enterprise NAC, this is almost always a RADIUS server: Cisco ISE (Identity Services Engine), Aruba ClearPass Policy Manager, Microsoft Network Policy Server (NPS), or Fortinet FortiAuthenticator. The authentication server validates the user's or device's identity against Active Directory or a certificate store, evaluates posture data from the agent, consults its authorization policies, and sends back to the switch either an Access-Accept (with VLAN and ACL instructions) or an Access-Reject.\n\n" +
        "The key architectural insight is the separation of concerns: the switch does not decide who gets in (it would have no idea how to check AD or evaluate certificate validity). The RADIUS server does not enforce access (it is not physically in the traffic path). Each component does what it is best at. The switch enforces, the RADIUS server decides, and the supplicant provides the credentials.\n\n" +
        "A practical implication for SOC analysts: when investigating a NAC bypass or authentication failure, you need to know which component's logs to check. Switch logs (Syslog or SNMP) tell you about port state changes and 802.1X events. RADIUS server logs (ISE or ClearPass) tell you about authentication attempts, identity decisions, and policy matches. Endpoint logs tell you about supplicant behavior and certificate issues.",
      codeExample:
        "THREE-COMPONENT NAC ARCHITECTURE\n" +
        "==================================\n\n" +
        "ENDPOINT                  SWITCH (Authenticator)        RADIUS SERVER (ISE)\n" +
        "(Supplicant)              \n" +
        "   |                          |                              |\n" +
        "   |--- EAPOL-Start --------->|                              |\n" +
        "   |                          |--- RADIUS Access-Request --->|\n" +
        "   |                          |    (Username, MAC, NAS-Port) |\n" +
        "   |<-- EAP-Request/Identity -|<-- EAP-Request/Identity -----|\n" +
        "   |--- EAP-Response -------->|--- RADIUS Access-Request --->|\n" +
        "   |    (username or cert)    |    (EAP payload forwarded)   |\n" +
        "   |                          |                              |\n" +
        "   |    [challenge exchange]  |    [ISE checks AD/cert]      |\n" +
        "   |<-- EAP-Request ---------|<-- RADIUS Access-Challenge ---|\n" +
        "   |--- EAP-Response -------->|--- RADIUS Access-Request --->|\n" +
        "   |                          |                              |\n" +
        "   |<-- EAP-Success ----------|<-- RADIUS Access-Accept -----|\n" +
        "   |                          |    Tunnel-PVID: 10           |\n" +
        "   |                          |    Filter-ID: ACL-CORP       |\n" +
        "   |                          |    url-redirect: (none)      |\n" +
        "   |                          |                              |\n" +
        "   |                          |  Port transitions to         |\n" +
        "   |                          |  AUTHORIZED state            |\n" +
        "   |                          |  VLAN 10 assigned            |\n" +
        "   |<========= IP traffic now flows ========================>|\n\n" +
        "KEY STATES:\n" +
        "  Port UNAUTHORIZED: only EAPOL frames pass. No IP, no DHCP.\n" +
        "  Port AUTHORIZED:   full traffic based on VLAN/ACL from ISE.\n\n" +
        "COMPONENT RESPONSIBILITIES:\n" +
        "  Supplicant     = presents credentials / certificate\n" +
        "  Switch         = enforces port state, forwards EAP to RADIUS\n" +
        "  RADIUS/ISE     = validates identity, evaluates policy, decides",
    },
    // ── Reading 3 ──────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "nac-r3",
      heading: "802.1X: The Authentication Protocol That Powers NAC",
      content:
        "802.1X is an IEEE standard for port-based network access control, first published in 2001 and widely deployed in enterprise networks since 2004. It defines the framework for how a device must authenticate before gaining access to a network port — whether wired Ethernet or wireless Wi-Fi. Understanding 802.1X is non-negotiable for anyone working in network security.\n\n" +
        "At its core, 802.1X uses EAP (Extensible Authentication Protocol) as the authentication framework. EAP is not a single authentication method — it is a container protocol that can carry different authentication mechanisms. This extensibility is why EAP is so widely used: you can swap authentication methods without changing the underlying 802.1X infrastructure.\n\n" +
        "The three most important EAP methods in enterprise NAC are:\n\n" +
        "EAP-TLS (EAP-Transport Layer Security) is the gold standard. The endpoint presents a client certificate to prove its identity, and the RADIUS server presents its own certificate to prove the network is legitimate (mutual authentication). No username or password is needed — the certificate is the credential. EAP-TLS requires a PKI (Public Key Infrastructure) to issue certificates to all managed devices, which is operationally complex but provides the strongest security. EAP-TLS is resistant to password spray, phishing, and credential theft because there is no password to steal.\n\n" +
        "PEAP (Protected EAP) is the most common method in organizations without a full PKI. PEAP creates a TLS tunnel between the client and the RADIUS server (using only the server's certificate, not the client's), then runs username and password authentication inside that encrypted tunnel. The inner method is usually MS-CHAPv2. PEAP is vulnerable to rogue RADIUS server attacks if clients do not validate the server certificate — a common misconfiguration.\n\n" +
        "EAP-FAST (EAP-Flexible Authentication via Secure Tunneling) is a Cisco proprietary method that uses a shared secret called a PAC (Protected Access Credential) instead of PKI certificates. It was designed to be easier to deploy than EAP-TLS while being more secure than unprotected PEAP.\n\n" +
        "An important distinction in enterprise environments is machine authentication versus user authentication. Machine authentication happens when the device boots, before any user logs in — the device itself authenticates to the network using a computer certificate or computer account credentials. This is critical for domain-joined Windows machines that need network access to receive Group Policy and complete the logon process. User authentication happens after the user logs in, using the user's credentials or certificate. Some ISE deployments enforce both: the machine must authenticate first, and then the user must authenticate before full access is granted.",
      codeExample:
        "EAP-TLS FULL HANDSHAKE (802.1X over wired Ethernet)\n" +
        "=====================================================\n\n" +
        "CLIENT (Supplicant)          SWITCH              ISE (RADIUS)\n" +
        "       |                        |                     |\n" +
        "[Link up detected]              |                     |\n" +
        "       |--- EAPOL-Start ------->|                     |\n" +
        "       |                        |--- Access-Request ->|\n" +
        "       |<-- EAP-Request/ID -----| (NAS-Port, MAC)     |\n" +
        "       |--- EAP-Response/ID --->|--- Access-Request ->|\n" +
        "       |    (identity: host/    |    (EAP-Identity)   |\n" +
        "       |     WS-FIN-2847.corp)  |                     |\n" +
        "       |                        |                     |\n" +
        "       | [TLS ClientHello] ---->|--Access-Challenge-->|\n" +
        "       | [Server cert sent] <---|<-Access-Challenge ---|\n" +
        "       | [Client validates      |                     |\n" +
        "       |  ISE server cert]      |                     |\n" +
        "       | [Client cert sent] --->|--- Access-Request ->|\n" +
        "       |                        |    (client cert     |\n" +
        "       |                        |     forwarded)      |\n" +
        "       |                        |                     |\n" +
        "       |                        | [ISE validates      |\n" +
        "       |                        |  client cert        |\n" +
        "       |                        |  against PKI CRL]   |\n" +
        "       |                        |                     |\n" +
        "       |<-- EAP-Success --------| <-- Access-Accept --|\n" +
        "       |                        |  Tunnel-PVID=10     |\n" +
        "       |                        |  Filter-ID=ACL-CORP |\n" +
        "       |                        |                     |\n" +
        "       |====== Port AUTHORIZED, VLAN 10 assigned =====|\n\n" +
        "EAP METHOD COMPARISON:\n" +
        "  Method      Client Cert   Server Cert   Password   Strength\n" +
        "  --------    -----------   -----------   --------   --------\n" +
        "  EAP-TLS     Required      Required      None       Strongest\n" +
        "  PEAP        Not needed    Required      Required   Strong*\n" +
        "  EAP-FAST    Not needed    Optional      PAC        Moderate\n\n" +
        "  * PEAP is vulnerable if clients do not validate the server certificate.",
    },
    // ── Reading 4 ──────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "nac-r4",
      heading: "RADIUS: The Authentication Server That Makes the Decision",
      content:
        "RADIUS stands for Remote Authentication Dial-In User Service, defined in RFC 2865 (published 1997). The 'Dial-In' in the name is a relic of its origin — RADIUS was created to authenticate modem dial-up connections at internet service providers. Despite its aged name, RADIUS is the universal standard authentication server for network access to this day, used by virtually every enterprise NAC, VPN, and Wi-Fi deployment on the planet.\n\n" +
        "Understanding how RADIUS works end-to-end is critical for SOC analysts investigating authentication failures, NAC policy misconfigurations, and bypass attempts.\n\n" +
        "The RADIUS conversation works as follows. When a device connects to a switch port, the switch sends a RADIUS Access-Request packet to the ISE server. This packet includes the username (or machine name), the device's MAC address, the NAS-Port (which physical switch port), and the encapsulated EAP authentication data. ISE receives this and begins its validation process: it queries Active Directory via LDAP to validate user credentials or checks the certificate store to validate a client certificate. It also evaluates which authorization policy matches this request.\n\n" +
        "If authentication succeeds and the authorization policy approves access, ISE sends back a RADIUS Access-Accept. Crucially, the Access-Accept carries RADIUS attributes that tell the switch exactly what to do:\n\n" +
        "Tunnel-Type (value 13) and Tunnel-Medium-Type (value 6) together indicate that a VLAN assignment is being provided. Tunnel-Private-Group-ID contains the actual VLAN number or name to assign. Filter-ID contains the name of an ACL to apply to the port. The Cisco-AVpair attribute (also called cisco_av_pair) can carry additional instructions including url-redirect (to force the user's browser to a captive portal) and url-redirect-acl (which ACL defines what traffic gets redirected). If authentication fails, ISE sends RADIUS Access-Reject, and the switch keeps the port in UNAUTHORIZED state.\n\n" +
        "RADIUS accounting is the often-overlooked third part of RADIUS. After successful authentication, the switch sends Accounting-Request Start to ISE, recording who connected, from where, and when. When the session ends, it sends Accounting-Request Stop with session duration and bytes transferred. These accounting records are invaluable for forensic investigations — they tell you which device was on which switch port at what time.\n\n" +
        "A common point of confusion: RADIUS vs LDAP. RADIUS is the protocol the switch uses to ask ISE for an access decision. LDAP is the protocol ISE uses internally to query Active Directory for user validation. LDAP is a directory protocol; RADIUS is an access-decision protocol. ISE sits between them, translating the network's RADIUS request into an AD query over LDAP.",
      codeExample:
        "RADIUS ACCESS-REQUEST (Switch to ISE)\n" +
        "========================================\n" +
        "Code:            Access-Request (1)\n" +
        "Identifier:      142\n" +
        "Attributes:\n" +
        "  User-Name:               CORP\\t.goldberg\n" +
        "  NAS-IP-Address:          10.10.0.1          (switch IP)\n" +
        "  NAS-Port:                50114              (GigabitEthernet1/0/14)\n" +
        "  NAS-Port-Type:           Ethernet (15)\n" +
        "  Called-Station-Id:       3C-22-FB-A1-D7-09  (endpoint MAC)\n" +
        "  Calling-Station-Id:      3C-22-FB-A1-D7-09\n" +
        "  Service-Type:            Framed-User\n" +
        "  EAP-Message:             [TLS handshake data]\n" +
        "  Message-Authenticator:   [HMAC-MD5]\n\n" +
        "RADIUS ACCESS-ACCEPT (ISE to Switch) -- COMPLIANT DEVICE\n" +
        "==========================================================\n" +
        "Code:            Access-Accept (2)\n" +
        "Identifier:      142\n" +
        "Attributes:\n" +
        "  Tunnel-Type:             VLAN (13)\n" +
        "  Tunnel-Medium-Type:      802 (6)\n" +
        "  Tunnel-Private-Group-ID: 10                 (assign VLAN 10)\n" +
        "  Filter-ID:               ACL-CORP-FULL\n" +
        "  Session-Timeout:         28800              (8 hours)\n" +
        "  Class:                   ISE:PostureStatus=Compliant\n\n" +
        "RADIUS ACCESS-ACCEPT (ISE to Switch) -- NON-COMPLIANT DEVICE\n" +
        "===============================================================\n" +
        "Code:            Access-Accept (2)\n" +
        "Identifier:      143\n" +
        "Attributes:\n" +
        "  Tunnel-Type:             VLAN (13)\n" +
        "  Tunnel-Medium-Type:      802 (6)\n" +
        "  Tunnel-Private-Group-ID: 50                 (assign VLAN 50 Quarantine)\n" +
        "  Filter-ID:               ACL-QUARANTINE-REMEDIATION\n" +
        "  Cisco-AVpair:            url-redirect=https://ise-psn-01.corp.local/guestportal/gateway\n" +
        "  Cisco-AVpair:            url-redirect-acl=REDIRECT-ACL\n" +
        "  Class:                   ISE:PostureStatus=NonCompliant\n\n" +
        "RADIUS ACCESS-REJECT (ISE to Switch) -- AUTH FAILURE\n" +
        "======================================================\n" +
        "Code:            Access-Reject (3)\n" +
        "Identifier:      144\n" +
        "Attributes:\n" +
        "  Reply-Message:           Authentication failed\n" +
        "  [Port remains UNAUTHORIZED]",
    },
    // ── Reading 5 ──────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "nac-r5",
      heading: "Device Posture Assessment: Checking Health Before Granting Full Access",
      content:
        "Authentication answers the question 'Who are you?' Posture assessment answers the question 'Is your device safe to let in?' A user can have valid corporate credentials and still be connecting from a personal laptop infected with malware. NAC posture assessment addresses this second gate.\n\n" +
        "Posture assessment is the process by which ISE (or another NAC server) verifies that the endpoint meets a defined security baseline before granting it full network access. The checks typically include: antivirus software installed and running with signature database updated within a defined period (commonly 7 days, sometimes 30); operating system patches applied with no critical security updates missing beyond a grace period (commonly 30 days); disk encryption enabled (BitLocker on Windows, FileVault on macOS); a valid corporate certificate present on the device; specific software absent (personal VPN clients, P2P file sharing tools, remote access tools not approved by IT); and corporate endpoint agent (EDR) installed and running.\n\n" +
        "Two mechanisms exist to perform the posture check. The persistent agent (also called a permanent agent) is a lightweight software package installed on all managed corporate devices by IT. It runs continuously in the background, reporting posture status to ISE via the RADIUS session. When the device connects to the network, ISE queries the agent for current posture data. The agent is the preferred method for managed endpoints because it provides real-time, continuous posture monitoring.\n\n" +
        "The temporal agent (also called a dissolvable agent or web agent) is used for unmanaged or guest devices. When such a device connects, ISE redirects the browser to a captive portal. The user is instructed to download and run a small executable. The executable runs the posture checks, sends results to ISE, and then deletes itself. Because the device is unmanaged, posture requirements are typically lighter (or the device is placed in a limited-access VLAN regardless of posture outcome).\n\n" +
        "The outcome of posture assessment flows directly into VLAN assignment. A device that passes all posture checks is 'Compliant' and receives full corporate network access. A device that fails one or more checks is 'NonCompliant' and is placed in the Quarantine VLAN with access only to remediation resources. A device where the posture agent is not installed or does not respond is marked 'Unknown' and typically receives limited network access pending posture validation.\n\n" +
        "From a SOC investigation standpoint, posture assessment failures are high-value signals. They indicate devices that are not being managed correctly by IT, which may represent shadow IT (unauthorized devices), devices that have been offline long enough to fall out of patch compliance (potential dormant compromised devices), or devices where the AV has been disabled (a ransomware indicator on some malware families).",
      codeExample:
        "POSTURE ASSESSMENT DECISION TREE\n" +
        "==================================\n\n" +
        "Device connects to switch port\n" +
        "          |\n" +
        "          v\n" +
        "   802.1X Authentication\n" +
        "          |\n" +
        "    [passes?]\n" +
        "     /       \\\n" +
        "   NO         YES\n" +
        "    |           |\n" +
        "  Port         ISE queries posture agent\n" +
        "  blocked           |\n" +
        "               [agent present?]\n" +
        "                /           \\\n" +
        "              NO             YES\n" +
        "               |               |\n" +
        "           Posture=Unknown    Run posture checks:\n" +
        "               |               - AV installed?   [Y/N]\n" +
        "           VLAN 30 (Limited)   - AV definitions current? [Y/N]\n" +
        "                               - OS patches current? [Y/N]\n" +
        "                               - BitLocker enabled? [Y/N]\n" +
        "                               - Corp certificate present? [Y/N]\n" +
        "                               |\n" +
        "                         [all pass?]\n" +
        "                          /       \\\n" +
        "                        YES        NO (any fail)\n" +
        "                         |              |\n" +
        "                  Posture=Compliant  Posture=NonCompliant\n" +
        "                         |              |\n" +
        "                    VLAN 10         VLAN 50 (Quarantine)\n" +
        "                  Full Access      + ACL-QUARANTINE-REMEDIATION\n" +
        "                                  + url-redirect to remediation portal\n\n" +
        "POSTURE POLICY REQUIREMENTS (example corporate policy):\n" +
        "  Check                        Requirement          Action on Fail\n" +
        "  --------                     -----------          --------------\n" +
        "  Antivirus installed          Yes                  NonCompliant\n" +
        "  AV definitions age           <= 7 days            NonCompliant\n" +
        "  Windows critical patches     <= 30 days old       NonCompliant\n" +
        "  BitLocker encryption         Enabled              NonCompliant\n" +
        "  Corp EDR agent               Running              NonCompliant\n" +
        "  Unauthorized VPN software    Absent               Warning only",
    },
    // ── Reading 6 ──────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "nac-r6",
      heading: "VLANs and How NAC Uses Them for Segmentation",
      content:
        "A VLAN (Virtual Local Area Network) is a logical network segment created within a physical switch. Without VLANs, every device plugged into a switch can communicate with every other device on that switch — they share one broadcast domain. With VLANs, the switch is partitioned: devices in VLAN 10 cannot communicate with devices in VLAN 20 unless a router or firewall explicitly permits that traffic. This logical isolation is enforced in hardware by the switch, regardless of IP addressing.\n\n" +
        "NAC uses dynamic VLAN assignment as its primary enforcement mechanism. When ISE sends a RADIUS Access-Accept to the switch, it includes the VLAN number to assign to that specific port. The switch immediately moves the port to the specified VLAN. The device on that port does not need to do anything — it does not know which VLAN it is in. From the device's perspective, it connects to the network and requests an IP address via DHCP. The DHCP server for the assigned VLAN responds with an IP in that VLAN's subnet.\n\n" +
        "A well-designed corporate NAC VLAN structure typically has five or more distinct segments. The Corporate Full Access VLAN (commonly VLAN 10 or a similar low number) is for authenticated domain users on compliant devices. These devices can reach all corporate resources: file servers, ERP systems, SharePoint, printers, and the internet. The Contractor Limited VLAN is for authenticated external users or contractors on compliant devices. These have internet access and specific application access, but cannot reach core corporate servers. The Guest VLAN is for internet-only access — no access to any corporate resource. The Quarantine VLAN is the remediation zone for non-compliant devices. Access is limited to Windows Update servers, AV update servers, and the ISE remediation portal. Nothing else. The IoT VLAN is for network devices (printers, IP cameras, smart TVs) that cannot participate in 802.1X. These devices are identified by MAC address or device profiling and placed in a restricted VLAN where they can only communicate with specific authorized destinations.\n\n" +
        "For SOC analysts, the VLAN assignment visible in NAC logs is a direct indicator of risk. Any device showing VLAN 50 (Quarantine) in ISE logs is a device that failed posture — it needs investigation. Any device in VLAN 10 (Corporate) that the ISE profiler identifies as an IoT device is potentially a MAC spoofing attack. Any device generating traffic from Guest VLAN toward corporate VLANs is a potential firewall policy violation that may indicate Guest VLAN abuse.",
      codeExample:
        "VLAN ASSIGNMENT DECISION MATRIX\n" +
        "=================================\n\n" +
        "Identity + Posture Result --> VLAN Assignment\n\n" +
        "User Role            Device Posture    VLAN    Access Level\n" +
        "-------------        --------------    ----    ------------\n" +
        "Domain User          Compliant         10      Full corporate + internet\n" +
        "Domain User          NonCompliant      50      Remediation only\n" +
        "Domain User          Unknown           30      Limited (internet only)\n" +
        "Contractor           Compliant         20      Internet + specific apps\n" +
        "Contractor           NonCompliant      50      Remediation only\n" +
        "Guest (no auth)      N/A               30      Internet only\n" +
        "IoT Device           N/A (no 802.1X)   40      Defined destinations only\n" +
        "Auth Failure         N/A               --      Port blocked (no VLAN)\n\n" +
        "VLAN ISOLATION (what can reach what):\n\n" +
        "VLAN 10 (Corporate):\n" +
        "  Can reach: file servers, ERP, SharePoint, printers, internet\n" +
        "  Cannot reach: VLAN 50 (quarantine)\n\n" +
        "VLAN 20 (Contractor):\n" +
        "  Can reach: internet, specific permitted app servers\n" +
        "  Cannot reach: VLAN 10 resources, VLAN 40 IoT, VLAN 50\n\n" +
        "VLAN 30 (Guest):\n" +
        "  Can reach: internet only (via firewall)\n" +
        "  Cannot reach: VLANs 10, 20, 40, 50\n\n" +
        "VLAN 40 (IoT):\n" +
        "  Can reach: specific servers (print server, camera NVR)\n" +
        "  Cannot reach: VLANs 10, 20, 30, 50\n\n" +
        "VLAN 50 (Quarantine):\n" +
        "  Can reach: ISE portal, Windows Update, AV update server\n" +
        "  Cannot reach: anything else\n\n" +
        "Inter-VLAN routing controlled by core firewall (not the access switch).",
    },
    // ── Reading 7 ──────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "nac-r7",
      heading: "Cisco ISE: The Enterprise NAC Standard",
      content:
        "Cisco Identity Services Engine (ISE) is the most widely deployed enterprise NAC solution globally. If you work in a large enterprise SOC, the probability of encountering Cisco ISE is high. Understanding its architecture and policy model is essential.\n\n" +
        "ISE is deployed as a cluster of appliances (physical or virtual machines), each playing one or more roles. The Policy Administration Node (PAN) hosts the configuration web interface — this is where administrators write authentication and authorization policies, configure identity stores, and manage the system. The Policy Service Node (PSN) is the workhorse: it handles all live RADIUS authentication requests, runs posture assessment queries, and enforces policy. In large deployments there are multiple PSNs for redundancy and load distribution. The Monitoring and Troubleshooting Node (MnT) collects all authentication logs, generates reports, and supports the Troubleshooting Wizard that helps diagnose authentication failures.\n\n" +
        "The ISE policy flow has multiple stages. First, the Policy Set determines which rule set handles this request — is this a wired 802.1X request? A wireless request? A VPN request? Each service type can have its own complete policy set. Within a policy set, the Authentication Policy determines how to validate identity: check Active Directory first, then the local ISE certificate store, then the guest store. The Authorization Policy contains the rules that determine what access to grant. Each authorization rule has conditions (is this a domain user? Is the device profile matching Windows? Is posture compliant?) and a result (which authorization profile to apply, containing the VLAN and ACL attributes).\n\n" +
        "ISE Profiling is one of the most powerful features for SOC analysts. ISE passively fingerprints every device on the network by collecting and analyzing DHCP options (certain options reveal device OS), HTTP User-Agent headers, Cisco Discovery Protocol (CDP) and Link Layer Discovery Protocol (LLDP) data from switches, NMAP scan results, and RADIUS attributes. From this data, ISE builds a device profile: this is a Windows 10 workstation, this is an Apple iPhone, this is a Cisco IP phone model 8861. Profiling feeds into authorization policy and is critical for detecting MAC address spoofing.\n\n" +
        "Cisco TrustSec is an advanced ISE feature that assigns Security Group Tags (SGTs) to traffic flows. Instead of enforcing policy based on IP addresses (which change), TrustSec enforces policy based on identity groups. A device belonging to the Finance department gets SGT 10. A medical device gets SGT 40. Switches and firewalls enforce policy by SGT rather than IP, enabling microsegmentation that follows the identity, not the address.",
      codeExample:
        "CISCO ISE POLICY SET STRUCTURE\n" +
        "================================\n\n" +
        "Policy Set: Wired-802.1X\n" +
        "  Condition: Radius:NAS-Port-Type EQUALS Ethernet\n" +
        "  |\n" +
        "  +-- Authentication Policy\n" +
        "  |     Rule 1: Certificate-Based Auth\n" +
        "  |       If:     EAP-TLS\n" +
        "  |       Then:   Validate against Corp-PKI certificate store\n" +
        "  |     Rule 2: Password-Based Auth\n" +
        "  |       If:     PEAP\n" +
        "  |       Then:   Validate against AD1 (Active Directory)\n" +
        "  |     Default: DenyAccess\n" +
        "  |\n" +
        "  +-- Authorization Policy (evaluated after auth success)\n" +
        "  |     Rule 1: Compliant-Domain-Device\n" +
        "  |       If:   AD:MemberOf = Domain Computers\n" +
        "  |             AND PostureStatus = Compliant\n" +
        "  |       Then: AuthProfile = FULL-CORPORATE-ACCESS\n" +
        "  |               (VLAN 10, ACL-CORP-FULL, no redirect)\n" +
        "  |\n" +
        "  |     Rule 2: NonCompliant-Domain-Device\n" +
        "  |       If:   AD:MemberOf = Domain Computers\n" +
        "  |             AND PostureStatus = NonCompliant\n" +
        "  |       Then: AuthProfile = QUARANTINE\n" +
        "  |               (VLAN 50, ACL-QUARANTINE-REMEDIATION,\n" +
        "  |                url-redirect to remediation portal)\n" +
        "  |\n" +
        "  |     Rule 3: Unknown-Posture-Domain-Device\n" +
        "  |       If:   AD:MemberOf = Domain Computers\n" +
        "  |             AND PostureStatus = Unknown\n" +
        "  |       Then: AuthProfile = LIMITED-PENDING-POSTURE\n" +
        "  |               (VLAN 30, ACL-LIMITED)\n" +
        "  |\n" +
        "  |     Rule 4: Contractor\n" +
        "  |       If:   AD:MemberOf = External-Contractors\n" +
        "  |             AND PostureStatus = Compliant\n" +
        "  |       Then: AuthProfile = CONTRACTOR-LIMITED\n" +
        "  |               (VLAN 20, ACL-CONTRACTOR)\n" +
        "  |\n" +
        "  |     Default: DenyAccess\n\n" +
        "ISE PROFILING FLOW:\n" +
        "  DHCP options collected  -->  Device type fingerprinted\n" +
        "  HTTP User-Agent captured -->  OS version identified\n" +
        "  CDP/LLDP data from switch -> Device model identified\n" +
        "  Profile matched          --> AuthZ policy conditions updated",
    },
    // ── Reading 8 ──────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "nac-r8",
      heading: "Aruba ClearPass: The Multi-Vendor Alternative",
      content:
        "Aruba ClearPass Policy Manager (CPPM) is the primary alternative to Cisco ISE in the enterprise NAC market. While ISE is tightly integrated with the Cisco networking ecosystem and works best in Cisco-heavy environments, ClearPass is designed to be network-agnostic — it integrates natively with Cisco switches, HP/Aruba switches, Juniper, FortiGate, and virtually any 802.1X-capable network device. This makes ClearPass the preferred choice in multi-vendor environments and organizations that run Aruba or HPE wireless infrastructure.\n\n" +
        "The ClearPass architecture is considerably simpler than ISE. A ClearPass deployment can start with a single virtual appliance (ClearPass Policy Manager) handling both administration and policy service functions. Scaling is achieved by adding additional ClearPass servers in a cluster. This lower operational complexity is frequently cited as a key advantage over ISE, particularly for organizations without a dedicated Cisco infrastructure team.\n\n" +
        "The ClearPass policy model is built around four sequential stages. A Service is the entry point — it matches the incoming request type (wired 802.1X, wireless 802.1X, VPN, guest portal, MAC authentication bypass). Once a Service matches, the Authentication stage validates the user or device identity against an identity source: Active Directory, LDAP, SQL database, certificate store, or the ClearPass local database. The Role Mapping stage translates the authenticated identity into a role: is this a Finance department user? A contractor? An IT administrator? The role is determined by AD group memberships, certificate attributes, or other attributes retrieved during authentication. Finally, the Enforcement stage maps roles to Enforcement Profiles: network access policies containing VLAN, ACL, and session attributes returned to the switch via RADIUS.\n\n" +
        "ClearPass Exchange is one of the most powerful differentiators. It provides a REST API framework for integrating with over 150 third-party security products. When an endpoint is flagged by Splunk as suspicious, ClearPass Exchange can receive that signal via API and immediately quarantine the endpoint at the network layer — without human intervention. Integrations include Splunk, ServiceNow (for automated ticketing), vulnerability scanners (Rapid7, Tenable), and MDM platforms (Intune, Jamf).\n\n" +
        "ClearPass OnBoard manages the device certificate lifecycle for EAP-TLS deployments. When a new device needs a certificate, the user visits the ClearPass OnBoard portal, authenticates with their AD credentials, and ClearPass automatically provisions a device certificate from the corporate PKI. This removes the operational burden of manually managing device certificates at scale.\n\n" +
        "The Guest module in ClearPass is widely considered best-in-class. It provides a fully customizable self-service guest portal with sponsor workflows (a guest's corporate sponsor receives an email to approve access), SMS verification, time-limited access, acceptable use policy acknowledgment, and detailed guest usage reporting.",
      codeExample:
        "CLEARPASS POLICY FLOW vs CISCO ISE POLICY FLOW\n" +
        "================================================\n\n" +
        "CLEARPASS                         CISCO ISE\n" +
        "-------------------               ------------------\n" +
        "Service                           Policy Set\n" +
        "  (match request type)              (match request type)\n" +
        "       |\n" +
        "       v\n" +
        "Authentication                    Authentication Policy\n" +
        "  (validate identity)               (validate identity)\n" +
        "       |                                    |\n" +
        "       v                                    v\n" +
        "Role Mapping                      Posture Assessment (optional)\n" +
        "  (AD groups -> role)               (agent check)\n" +
        "       |                                    |\n" +
        "       v                                    v\n" +
        "Enforcement                       Authorization Policy\n" +
        "  (role -> VLAN/ACL/policy)          (conditions -> AuthZ profile)\n" +
        "       |                                    |\n" +
        "       v                                    v\n" +
        "RADIUS Access-Accept              RADIUS Access-Accept\n" +
        "  (VLAN + ACL to switch)            (VLAN + ACL to switch)\n\n" +
        "CLEARPASS EXCHANGE INTEGRATIONS:\n" +
        "  Splunk -------> [alert: host compromise] ---> ClearPass API\n" +
        "                                                       |\n" +
        "                                              Quarantine endpoint\n" +
        "                                              (change VLAN to 50)\n" +
        "                                                       |\n" +
        "  ServiceNow <-- [auto-ticket created] <----- ClearPass\n\n" +
        "VENDOR COMPARISON:\n" +
        "  Feature                  Cisco ISE       Aruba ClearPass\n" +
        "  -------                  ---------       ---------------\n" +
        "  Best with                Cisco switches  Any vendor\n" +
        "  Deployment complexity    High            Moderate\n" +
        "  TrustSec / SGT           Yes             No\n" +
        "  Guest portal             Good            Excellent\n" +
        "  API integrations         Good            Excellent (150+ native)\n" +
        "  Profiling                Yes (robust)    Yes (good)\n" +
        "  OnBoard (device certs)   Separate PKI    Built-in",
    },
    // ── Reading 9 ──────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "nac-r9",
      heading: "NAC in Zero Trust Architecture and Cloud Environments",
      content:
        "Traditional network security operated on a castle-and-moat model: build strong perimeter defenses (firewall, IDS, NAC at the door) and treat everything inside the perimeter as trusted. Zero Trust fundamentally rejects this model. The core Zero Trust principle — never trust, always verify — states that network location grants no inherent trust. A device on the internal network is not trusted. A device connected to the corporate VPN is not trusted. Every request must prove identity, assert device health, and receive only the minimum necessary access for the specific task requested.\n\n" +
        "Traditional on-premises NAC (Cisco ISE, Aruba ClearPass) fits naturally into Zero Trust as the enforcement point at the physical network layer. When a device connects to an office switch or corporate wireless, ISE enforces identity and posture before granting any network access. This is a strong Zero Trust control for on-premises environments.\n\n" +
        "However, the shift to remote work, cloud applications, and BYOD has created scenarios that on-premises NAC was not designed for. An employee working from home is not connecting to a switch managed by ISE. They are connecting to the internet and then to cloud applications. On-premises NAC has zero visibility into this traffic. This gap is filled by cloud-native Zero Trust tools.\n\n" +
        "Microsoft Entra ID (formerly Azure Active Directory) combined with Microsoft Intune provides the cloud-native equivalent of NAC. Entra ID Conditional Access policies enforce authentication and authorization rules for every access to cloud applications. Conditional Access evaluates: user identity and MFA compliance, device compliance status (reported by Intune — is the device enrolled, encrypted, and patch-current?), sign-in risk score (from Microsoft's threat intelligence), and the application being accessed. Based on these signals, Conditional Access grants full access, requires additional authentication (step-up MFA), blocks access, or grants limited access to a restricted version of the application. This is functionally identical to the posture-based VLAN assignment in ISE — the mechanism is different but the Zero Trust policy logic is the same.\n\n" +
        "SASE (Secure Access Service Edge) is the emerging architecture that converges NAC, CASB (Cloud Access Security Broker), SWG (Secure Web Gateway), and SD-WAN into a unified cloud-delivered security service. In a SASE architecture, identity and device posture are evaluated in the cloud for every session, regardless of where the user is connecting from. Vendors like Zscaler, Netskope, Palo Alto Prisma Access, and Cisco Umbrella are building SASE platforms. For SOC analysts, SASE logs combine what previously required ISE, firewall, proxy, and DLP log sources into a unified stream.",
      codeExample:
        "ON-PREMISES NAC vs CLOUD-NATIVE ZERO TRUST\n" +
        "=============================================\n\n" +
        "SCENARIO: Employee connects to corporate resources\n\n" +
        "ON-PREMISES (Office, ISE):\n" +
        "  Employee device\n" +
        "       |\n" +
        "  Plugs into office switch\n" +
        "       |\n" +
        "  ISE evaluates: 802.1X identity + posture\n" +
        "       |\n" +
        "  Result: VLAN 10 (compliant) or VLAN 50 (quarantine)\n" +
        "       |\n" +
        "  On-premises apps accessible via VLAN 10\n\n" +
        "CLOUD-NATIVE (Remote, Entra Conditional Access + Intune):\n" +
        "  Employee device (home office)\n" +
        "       |\n" +
        "  Accesses Microsoft 365 / Azure app\n" +
        "       |\n" +
        "  Entra ID Conditional Access evaluates:\n" +
        "    - User signed in? MFA completed?\n" +
        "    - Device: Intune enrolled? Compliant?\n" +
        "      (patches current, BitLocker on, EDR running)\n" +
        "    - Sign-in risk: low / medium / high?\n" +
        "    - Location: trusted / untrusted?\n" +
        "       |\n" +
        "  Result: GRANT / REQUIRE MFA / BLOCK / LIMIT\n\n" +
        "SASE (Converged Cloud NAC):\n" +
        "  Any device, any location\n" +
        "       |\n" +
        "  All traffic routed through SASE cloud\n" +
        "  (Zscaler / Netskope / Prisma Access)\n" +
        "       |\n" +
        "  Identity + posture + risk evaluated per session\n" +
        "       |\n" +
        "  Result enforced inline for ALL traffic\n" +
        "  (replaces ISE + firewall + proxy + DLP + CASB)\n\n" +
        "WHEN TO USE EACH:\n" +
        "  On-premises NAC (ISE/ClearPass): Wired networks, campus, IoT\n" +
        "  Cloud NAC (Entra CA + Intune):   SaaS apps, remote workers\n" +
        "  SASE:                             All-location, all-app unified",
    },
    // ── Reading 10 ─────────────────────────────────────────────────────────────
    {
      type: "reading" as const,
      id: "nac-r10",
      heading: "NAC Bypass Techniques and Detection Strategies",
      content:
        "No security control is perfect, and NAC is no exception. Understanding how attackers bypass NAC is essential for SOC analysts because these bypasses leave detectable artifacts that should trigger alerts.\n\n" +
        "The first and most common bypass is MAC address spoofing. Every network device has a hardware MAC address burned into its network card. NAC can be configured to use MAC Authentication Bypass (MAB) for devices that cannot participate in 802.1X (IoT devices, printers, legacy equipment). In MAB, the switch sends the device's MAC address to ISE, and ISE checks whether that MAC is in an approved list. An attacker on the same network segment can observe authorized MAC addresses (by sniffing ARP traffic, reading LLDP frames, or simply checking the label on a printer) and then change their own MAC address to match an authorized one. The switch will then see what appears to be the authorized printer, and ISE may grant network access. Detection relies on ISE profiling: ISE has fingerprinted the real printer and knows its device profile. When the attacker's Windows laptop sends DHCP options and HTTP traffic inconsistent with a printer, the profiler flags a profile mismatch. The SIEM should alert when ISE reports 'Unexpected profiler event: device profile mismatch' for a MAB-authenticated endpoint.\n\n" +
        "The second bypass technique is 802.1X pass-through via multi-host mode. Some switch configurations allow a port to be in 'multi-host' mode: once one device on the port authenticates, the port is opened for all traffic from all MAC addresses on that port. An attacker plugs a small unmanaged hub or switch between an authorized device and the wall port. The authorized device authenticates normally (or was already authenticated). The hub allows the attacker's device to also send traffic through the now-authorized port, bypassing NAC entirely. Detection: ISE and the switch can track the number of MAC addresses seen on a single port. Multiple MACs on a single 802.1X port that was configured for single-host mode is an alert condition. Switch syslog events referencing 'security-violation' on a dot1x port indicate this condition.\n\n" +
        "The third bypass is guest VLAN abuse. If the guest VLAN is misconfigured with routes to corporate subnets, or if firewall rules permit guest-to-corporate traffic for 'convenience,' an attacker who obtains guest network access can reach corporate resources directly. Detection: firewall logs showing traffic from guest VLAN (VLAN 30 subnet) destined for corporate VLAN (VLAN 10 subnet) are an immediate alert condition. This traffic should never occur in a properly configured environment.\n\n" +
        "A fourth technique is rogue 802.1X server (evil RADIUS). An attacker sets up a rogue RADIUS server on the network and configures a rogue wireless access point advertising the corporate SSID. When a user attempts to authenticate to what they believe is the corporate wireless, their supplicant sends credentials to the rogue RADIUS server. If the supplicant is not configured to validate the RADIUS server's certificate, credentials are captured. Detection: clients connecting to access points not in the authorized AP inventory, or RADIUS authentication requests from unknown NAS-IP-Address values in ISE logs.",
      codeExample:
        "BYPASS TECHNIQUE 1: MAC ADDRESS SPOOFING\n" +
        "==========================================\n\n" +
        "BEFORE BYPASS:\n" +
        "  Authorized Printer (MAC: AA:BB:CC:DD:EE:FF)\n" +
        "       |  <-- MAB: ISE approves this MAC\n" +
        "  Switch Port --> VLAN 40 (IoT)\n\n" +
        "ATTACKER SPOOFS MAC:\n" +
        "  Attacker Laptop\n" +
        "    [ifconfig eth0 hw ether AA:BB:CC:DD:EE:FF]\n" +
        "       |\n" +
        "  Switch sends MAC AA:BB:CC:DD:EE:FF to ISE\n" +
        "  ISE: 'Recognized MAC, approve'  --> VLAN 40\n" +
        "  Attacker is now on the IoT VLAN\n\n" +
        "DETECTION:\n" +
        "  ISE Profiler: 'Expected: Printer profile\n" +
        "                 Observed: Windows DHCP options, HTTP User-Agent\n" +
        "                 Result:   Profile mismatch - alert!'\n" +
        "  SIEM rule: cisco.ise.posture_assessment_status = unexpected_profile\n\n" +
        "BYPASS TECHNIQUE 2: 802.1X PASS-THROUGH (HUB INSERTION)\n" +
        "==========================================================\n\n" +
        "  Wall port (single-host 802.1X configured)\n" +
        "       |\n" +
        "  [Attacker inserts unmanaged hub here]\n" +
        "       |\n" +
        "   ----+----\n" +
        "   |       |\n" +
        "  Auth'd   Attacker's\n" +
        "  Laptop   Laptop\n" +
        "   (authenticates normally)\n\n" +
        "  After auth: port opens for authorized MAC.\n" +
        "  Hub allows attacker's traffic through too.\n\n" +
        "DETECTION:\n" +
        "  Switch syslog: %DOT1X-5-SECURITY_VIOLATION: Security violation on\n" +
        "    interface GigabitEthernet1/0/14, New MAC address 1A:2B:3C:4D:5E:6F\n" +
        "    detected.\n" +
        "  ISE: multiple MAC addresses on single 802.1X port\n" +
        "  Alert: more than 1 unique MAC on an 802.1X wired port\n\n" +
        "BYPASS TECHNIQUE 3: GUEST VLAN MISCONFIGURATION\n" +
        "=================================================\n\n" +
        "  Guest device (no authentication)\n" +
        "  --> VLAN 30 (192.168.30.x)\n" +
        "  --> Firewall\n" +
        "  --> VLAN 10 Corporate (10.10.0.x)   <-- SHOULD BE BLOCKED\n\n" +
        "DETECTION:\n" +
        "  Firewall log: src=192.168.30.50 dst=10.10.0.25 PERMIT\n" +
        "  Alert: any traffic from VLAN 30 subnet to VLAN 10 subnet\n" +
        "  SIEM rule: src_ip in 192.168.30.0/24 AND dst_ip in 10.10.0.0/16",
    },
    // ── Question 1 ─────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "nac-q1",
      question:
        "What happens to a network switch port configured for 802.1X BEFORE the endpoint has successfully authenticated?",
      options: [
        "The port allows all traffic normally — authentication happens in the background while the user works",
        "The port is in UNAUTHORIZED state and only allows EAPOL (authentication) frames to pass — no regular network traffic",
        "The port blocks all traffic including authentication, requiring manual IT intervention to open",
        "The port allows traffic on the management VLAN only while awaiting authentication",
      ],
      answer: 1,
      explanation:
        "In 802.1X, a switch port is configured in UNAUTHORIZED state by default. In this state, the port ONLY passes EAPOL (EAP over LAN) frames — the authentication messages between the supplicant and the switch. No regular network traffic (IP, DHCP, HTTP) can pass until authentication succeeds. Once the RADIUS server sends an Access-Accept, the switch transitions the port to AUTHORIZED state and traffic flows normally.",
      xp: 20,
    },
    // ── Question 2 ─────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "nac-q2",
      question:
        "A corporate laptop connecting to the office network fails Cisco ISE posture assessment because it has not received Windows security patches for 45 days. What is the MOST LIKELY outcome based on standard NAC policy?",
      options: [
        "The laptop is fully blocked — it receives no network access until IT manually approves it",
        "The laptop is placed in a quarantine VLAN with access only to a remediation server that can push Windows Update and AV updates. The user is redirected to a self-service portal.",
        "The laptop receives full corporate network access with a warning notification to the user to update their system",
        "The laptop is assigned to the Guest VLAN with internet-only access until patches are applied",
      ],
      answer: 1,
      explanation:
        "Standard NAC posture policy places non-compliant devices in a Quarantine VLAN (not full block, not guest). The quarantine VLAN restricts access to ONLY the remediation infrastructure: Windows Update servers, AV update servers, and the ISE self-service remediation portal. The user is redirected to a web page explaining what is wrong and how to fix it. Full block would prevent remediation; guest VLAN is for unknown devices; quarantine with remediation path is the industry-standard approach.",
      xp: 25,
    },
    // ── Question 3 ─────────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "nac-q3",
      question:
        "What is the key difference between RADIUS and LDAP in the context of network authentication?",
      options: [
        "RADIUS and LDAP are the same protocol with different names used by different vendors",
        "RADIUS is the protocol the switch uses to ask the authentication server for an access decision; LDAP is the protocol the authentication server uses to query the user directory (like Active Directory)",
        "LDAP is used for wired 802.1X authentication; RADIUS is used for wireless authentication only",
        "RADIUS stores user accounts and passwords; LDAP manages network access policies",
      ],
      answer: 1,
      explanation:
        "RADIUS and LDAP serve different roles in the authentication chain. The switch (authenticator) speaks RADIUS to Cisco ISE: 'Should this user be allowed in?' ISE then speaks LDAP (or Kerberos) to Active Directory to validate the user's credentials and group memberships. LDAP is a directory protocol for reading user data; RADIUS is an authentication and authorization protocol for network access decisions. ISE sits between them: RADIUS inbound from switches, LDAP outbound to AD.",
      xp: 25,
    },
    // ── Log Analysis ───────────────────────────────────────────────────────────
    {
      type: "log_analysis" as const,
      id: "nac-la1",
      heading: "Cisco ISE: Investigating a Posture Failure Quarantine Event",
      context:
        "You are a SOC analyst monitoring Cisco ISE events in the SIEM. An alert fires: endpoint quarantined due to posture failure. The event shows a Windows 10 workstation belonging to t.goldberg@corp.com was placed in quarantine VLAN when connecting to access switch SW-ACCESS-FL2-01, port GigabitEthernet1/0/14. Review the ISE log fields carefully — each field tells you something specific about what NAC checked and what action was taken.",
      event: nacPostureEvent,
      questions: [
        {
          question:
            "The cisco.ise.selected_vlan field shows VLAN-50-QUARANTINE and cisco.ise.acl shows ACL-QUARANTINE-REMEDIATION. Together, what do these two fields tell you about the access this device has received?",
          options: [
            "The device has been completely blocked — VLAN-50 has no network access and the ACL blocks all traffic",
            "The device is in quarantine VLAN 50 with access restricted by an ACL — likely allowing only remediation server traffic (Windows Update, AV updates, ISE portal) and blocking all corporate resources",
            "The device has full corporate network access but with enhanced logging enabled",
            "The device has been placed in the guest WiFi network with internet-only access",
          ],
          answer: 1,
          explanation:
            "VLAN-50-QUARANTINE isolates the device into a restricted network segment. The ACL-QUARANTINE-REMEDIATION Access Control List then further limits what traffic is permitted within that VLAN — typically allowing only: the ISE remediation portal, Windows Update servers (port 443 to microsoft.com), and the corporate AV update server. This gives the device enough access to fix its compliance issues without allowing it to touch corporate servers or other endpoints.",
          xp: 25,
        },
        {
          question:
            "The cisco.ise.posture_failure_reasons field shows 'AntivirusDefinitionOutOfDate, MissingWindowsPatches'. From a SOC analyst perspective, why is an out-of-date AV definition a significant security concern that justifies quarantine?",
          options: [
            "It is not a significant concern — AV definitions only affect commodity malware, and modern attacks do not use malware that would be caught by AV",
            "Out-of-date AV definitions mean the endpoint cannot detect malware variants released in the past 45 days. Combined with missing patches, this device is highly vulnerable and could be a vector for introducing malware into the corporate network",
            "Out-of-date AV is primarily a compliance issue for audit purposes, not an operational security risk",
            "AV definitions are automatically updated by Windows Update, so this is likely a temporary condition that resolves itself",
          ],
          answer: 1,
          explanation:
            "AV signatures are released multiple times per day to address newly discovered malware. A device with 45-day-old signatures cannot detect any malware family introduced in the past 45 days. Combined with missing Windows patches (which fix exploitable vulnerabilities), this device presents a high risk: if it connects to the corporate network, it could be exploited by recently patched vulnerabilities and could spread malware that its AV cannot detect. Quarantine until remediation is the correct security posture.",
          xp: 20,
        },
        {
          question:
            "The cisco.ise.cisco_av_pair field contains 'url-redirect=https://ise-psn-01.corp.local/guestportal/gateway'. What is the purpose of this attribute, and what will the user experience?",
          options: [
            "This is an error message — the url-redirect indicates the authentication failed and the user should go to the helpdesk URL",
            "When the user opens a web browser, their HTTP requests will be intercepted by the switch and redirected to the ISE remediation portal. The portal will explain what failed and provide instructions or automated tools to fix the compliance issues",
            "This attribute sends an automated email to the user explaining the quarantine reason",
            "The URL is the address of the corporate Windows Update server that the device should connect to for remediation",
          ],
          answer: 1,
          explanation:
            "The url-redirect Cisco AV-pair is a RADIUS attribute sent by ISE to the switch. The switch is instructed to intercept all HTTP (port 80) requests from this endpoint and redirect the browser to the ISE captive portal URL. The user opens a browser, tries to visit any website, and instead sees the ISE remediation page: 'Your device was quarantined for the following reasons: AV out of date, missing patches. Click here to update.' Some organizations configure the portal to automatically push updates; others provide instructions for IT to remediate manually.",
          xp: 25,
        },
      ],
    },
    // ── Flag ───────────────────────────────────────────────────────────────────
    {
      type: "flag" as const,
      id: "nac-f1",
      prompt:
        "Look at the NAC log event. What is the MAC address of the quarantined endpoint? (Find it in the cisco.ise.endpoint_mac_address field. Enter it exactly as shown.)",
      answer: "3C:22:FB:A1:D7:09",
      hint: "Look for cisco.ise.endpoint_mac_address in the raw field of the event.",
      xp: 30,
    },
  ],
};

export default [nacMasterclass];
