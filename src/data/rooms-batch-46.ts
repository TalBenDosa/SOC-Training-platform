/**
 * Learning Rooms — Batch 46
 *
 * Closes a P1 coverage gap (topic 6 of 9): the platform's existing cloud rooms
 * — "AWS Security for SOC Analysts" (aws-security), "Cloud Security
 * Monitoring" (cloud-security-monitoring), and "Azure IaaS Security for SOC
 * Analysts" (azure-security) — all teach cloud security from the DEFENDER's
 * monitoring seat: what CloudTrail/Activity Log/Audit Logs are, how GuardDuty
 * and Defender for Cloud raise findings, how to triage an IAM backdoor or an
 * exposed S3 bucket. None of them walk what an attacker DOES, action by
 * action, once they are already sitting inside a compromised tenant with a
 * working identity. This room is that missing piece: the attacker's own
 * defense-evasion and infrastructure-manipulation playbook, told through the
 * exact API calls that playbook produces.
 *
 * The story deliberately continues the SAME fictional intrusion the
 * aws-security room already teaches (NexaCorp, account 482915007733, the
 * IAM role ec2-webapp-role compromised via stolen EC2 Instance Metadata
 * Service (IMDS) credentials, attacker source IP 185.220.101.47). Readers who
 * completed that room will recognise the identity; readers who have not still
 * get a self-contained lesson, because reading r0 restates the needed
 * context.
 *
 * TECHNIQUES COVERED, verified directly against attack.mitre.org at write
 * time (2026-09-09), including a live restructuring this room teaches
 * explicitly because it changes real detection content: MITRE ATT&CK v19
 * (released 28 April 2026) split the old "Defense Evasion" tactic into two
 * new tactics, Stealth (TA0005, re-using the old tactic ID) and Defense
 * Impairment (TA0112) — techniques about actively breaking defenses moved to
 * Defense Impairment. As part of that release, two sub-techniques this room
 * covers were REVOKED and replaced:
 *   - old T1562.007 "Impair Defenses: Disable or Modify Cloud Firewall"
 *     -> now T1686.001 "Disable or Modify System Firewall: Cloud Firewall"
 *   - old T1562.008 "Impair Defenses: Disable or Modify Cloud Logs"
 *     -> now T1685.002 "Disable or Modify Tools: Disable or Modify Cloud Log"
 * Both live under the new Defense Impairment tactic (TA0112). This room
 * teaches the CURRENT ids and tactic, while naming the legacy ids explicitly,
 * because plenty of detection rules, SIEM content packs, and older training
 * material were authored before the split and still cite the old numbering
 * (this platform's own rooms, including cloud-security-monitoring and
 * aws-security, were moved to the v19 ids in the platform-wide ATT&CK v19
 * update), and an analyst needs to recognise both.
 *
 *   - T1686.001 — Disable or Modify System Firewall: Cloud Firewall
 *     (formerly T1562.007), Defense Impairment. Covered 4 times across this
 *     room: a dedicated reading, a log_analysis event, a scenario question,
 *     and a matching pair.
 *   - T1578.002 — Modify Cloud Compute Infrastructure: Create Cloud Instance,
 *     Defense Impairment.
 *   - T1068 — Exploitation for Privilege Escalation, Privilege Escalation —
 *     covered as the cloud/container mechanism that hands an attacker a MORE
 *     privileged identity than the one they started with, which is usually
 *     what makes the rest of this room's chain possible in the first place.
 *   - T1578.001 — Modify Cloud Compute Infrastructure: Create Snapshot,
 *     Defense Impairment (the snapshot-and-share exfiltration technique).
 *   - T1578.003 — Modify Cloud Compute Infrastructure: Delete Cloud Instance,
 *     Defense Impairment (anti-forensic destruction).
 *   - T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log
 *     (formerly T1562.008), Defense Impairment — named here specifically for
 *     the GuardDuty-detector-deletion angle that the existing aws-security
 *     room's own cloud-logging reading (which only covers CloudTrail StopLogging)
 *     does not cover, so as not to re-teach what that room already teaches
 *     in depth.
 *   - T1531 — Account Access Removal, Impact — the destructive endgame once
 *     an attacker has finished with a tenant.
 *
 * Rooms in this batch:
 *  1. cloud-attacker-defense-evasion
 *
 * SOURCES consulted directly for this content:
 *  - MITRE ATT&CK T1686.001, Disable or Modify System Firewall: Cloud Firewall
 *    (attack.mitre.org/techniques/T1686/001/)
 *  - MITRE ATT&CK T1578, Modify Cloud Compute Infrastructure, and its
 *    sub-techniques T1578.001, T1578.002, T1578.003
 *    (attack.mitre.org/techniques/T1578/, /T1578/001/, /T1578/002/, /T1578/003/)
 *  - MITRE ATT&CK T1685.002, Disable or Modify Tools: Disable or Modify Cloud Log
 *    (attack.mitre.org/techniques/T1685/002/)
 *  - MITRE ATT&CK T1531, Account Access Removal (attack.mitre.org/techniques/T1531/)
 *  - MITRE ATT&CK T1068, Exploitation for Privilege Escalation
 *    (attack.mitre.org/techniques/T1068/)
 *  - MITRE ATT&CK, "Updates - April 2026" release notes documenting the
 *    Defense Evasion -> Stealth/Defense Impairment tactic split and the
 *    T1562.007/T1562.008 revocations (attack.mitre.org/resources/updates/updates-april-2026/)
 *  - AWS EC2 API Reference, AuthorizeSecurityGroupIngress
 *    (docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html)
 *  - AWS EC2 API Reference, ModifySnapshotAttribute
 *    (docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySnapshotAttribute.html)
 *  - AWS GuardDuty API Reference, DeleteDetector
 *    (docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html)
 *  - AWS Security Hub, EC2 controls EC2.13 / EC2.14
 *    (docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html)
 *  - AWS Config managed rule "restricted-ssh"
 *    (docs.aws.amazon.com/config/latest/developerguide/restricted-ssh.html)
 */

import type { TelemetryEvent } from "@/lib/sim/types";

// ===========================================================================
// ROOM — Cloud Attacker Actions: Defense Impairment & Manipulation
// ===========================================================================

// Log-analysis event: the attacker opens the production database subnet's
// security group to the entire internet on RDP, minutes after the same
// identity was seen exercising a stolen-then-escalated IAM policy in the
// aws-security room. Non-EDR, so no hashDatabase dependency.
const sgOpenEvent: TelemetryEvent = {
  "id": "cad-ct-sg-open-001",
  "ts": "2026-08-04T02:47:33.000Z",
  "source": "cloudtrail",
  "vendor": "AWS CloudTrail",
  "event_type": "cloud_api_call",
  "severity": "critical",
  "user_email": "svc-deploy@nexacorp.com",
  "src_ip": "185.220.101.47",
  "geo": { "country": "Netherlands", "city": "Amsterdam" },
  "description": "The security group attached to NexaCorp's production database subnet received a new inbound rule sixteen minutes after the ec2-webapp-role identity was last seen making an IAM policy change, opening TCP port 3389 to the full 0.0.0.0/0 address range.",
  "mitre_technique": "T1686.001",
  "mitre_tactic": "Defense Impairment",
  "raw": {
    "aws.cloudtrail.eventName": "AuthorizeSecurityGroupIngress",
    "aws.cloudtrail.eventSource": "ec2.amazonaws.com",
    "aws.cloudtrail.awsRegion": "us-east-1",
    "aws.cloudtrail.userIdentity.type": "AssumedRole",
    "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::482915007733:assumed-role/ec2-webapp-role/i-0a1b2c3d4e5f67890",
    "aws.cloudtrail.userIdentity.accountId": "482915007733",
    "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.type": "Role",
    "aws.cloudtrail.userIdentity.sessionContext.sessionIssuer.arn": "arn:aws:iam::482915007733:role/ec2-webapp-role",
    "aws.cloudtrail.sourceIPAddress": "185.220.101.47",
    "aws.cloudtrail.userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0",
    "aws.cloudtrail.requestParameters.groupId": "sg-0f3a8b2c1d9e7f45",
    "aws.cloudtrail.requestParameters.ipPermissions.items.0.ipProtocol": "tcp",
    "aws.cloudtrail.requestParameters.ipPermissions.items.0.fromPort": 3389,
    "aws.cloudtrail.requestParameters.ipPermissions.items.0.toPort": 3389,
    "aws.cloudtrail.requestParameters.ipPermissions.items.0.ipRanges.items.0.cidrIp": "0.0.0.0/0",
    "aws.cloudtrail.responseElements.securityGroupRuleSet.items.0.securityGroupRuleId": "sgr-0d4e5f6a7b8c9012d",
    "aws.cloudtrail.errorCode": "",
    "aws.cloudtrail.errorMessage": "",
    "aws.cloudtrail.requestID": "9A8B7C6D5E4F3021",
    "aws.cloudtrail.eventType": "AwsApiCall",
    "aws.cloudtrail.managementEvent": true,
    "aws.cloudtrail.readOnly": false,
    "cloud.account.id": "482915007733",
    "cloud.region": "us-east-1",
    "action_result": "allowed"
  }
};

// Analyst-choice control case: Auto Scaling launching a routine replacement
// instance via its own AWS-managed service-linked role. Same eventName
// (RunInstances) as the T1578.002 attack pattern this room teaches, resolved
// via it_verify_result/it_verify_message rather than any invented raw field.
const autoScalingRunInstancesEvent: TelemetryEvent = {
  "id": "cad-ct-asg-runinstances-001",
  "ts": "2026-08-04T14:02:11.000Z",
  "source": "cloudtrail",
  "vendor": "AWS CloudTrail",
  "event_type": "cloud_api_call",
  "severity": "informational",
  "user_title": "AWS Service-Linked Role",
  "description": "A RunInstances call landed in CloudTrail for NexaCorp's account, launching a new EC2 instance in the organisation's standard production region.",
  "it_verify_result": "confirmed",
  "it_verify_message": "Confirmed against NexaCorp's Auto Scaling Group 'asg-nexacorp-webtier-prod': this RunInstances call was issued by the AWS-managed service-linked role AWSServiceRoleForAutoScaling in direct response to a CloudWatch alarm ('WebTierCPUHigh') that breached 80% average CPU utilisation across the fleet at 14:02 UTC. The launched instance type (c5.xlarge), AMI (ami-0c7217cdde317cfec, the fleet's current golden image), subnet, and security group are identical to every other instance already running in this Auto Scaling Group, and the group has scaled out 3-4 times per week for the past six months with no exceptions.",
  "raw": {
    "aws.cloudtrail.eventName": "RunInstances",
    "aws.cloudtrail.eventSource": "ec2.amazonaws.com",
    "aws.cloudtrail.awsRegion": "us-east-1",
    "aws.cloudtrail.userIdentity.type": "AssumedRole",
    "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::482915007733:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling",
    "aws.cloudtrail.userIdentity.accountId": "482915007733",
    "aws.cloudtrail.userIdentity.invokedBy": "autoscaling.amazonaws.com",
    "aws.cloudtrail.sourceIPAddress": "autoscaling.amazonaws.com",
    "aws.cloudtrail.userAgent": "autoscaling.amazonaws.com",
    "aws.cloudtrail.requestParameters.instanceType": "c5.xlarge",
    "aws.cloudtrail.requestParameters.instancesSet.items.0.imageId": "ami-0c7217cdde317cfec",
    "aws.cloudtrail.requestParameters.subnetId": "subnet-0a1b2c3d4e5f60789",
    "aws.cloudtrail.requestParameters.groupSet.items.0.groupId": "sg-0d1e2f3a4b5c6d789",
    "aws.cloudtrail.responseElements.instancesSet.items.0.instanceId": "i-0f1e2d3c4b5a69870",
    "aws.cloudtrail.errorCode": "",
    "aws.cloudtrail.errorMessage": "",
    "aws.cloudtrail.requestID": "4F3E2D1C0B9A8776",
    "aws.cloudtrail.eventType": "AwsApiCall",
    "aws.cloudtrail.managementEvent": true,
    "aws.cloudtrail.readOnly": false,
    "cloud.account.id": "482915007733",
    "cloud.region": "us-east-1",
    "action_result": "allowed"
  }
};

const cloudAttackerDefenseEvasionRoom = {
  "id": "cloud-attacker-defense-evasion",
  "title": "Cloud Attacker Actions: Defense Impairment & Manipulation Inside a Compromised Tenant",
  "description": "The platform's existing cloud rooms teach you to monitor a tenant: what CloudTrail, Azure Activity Log, and GCP Audit Logs record, and how GuardDuty or Defender for Cloud raise findings. This room teaches the other side of that same coin, the exact actions a real attacker takes once they are already sitting inside a compromised cloud account with a working identity: opening a security group to the entire internet, spinning up a new instance to sidestep the restrictions on the ones already running, sharing a snapshot of a sensitive volume with an external account, escalating privilege through a vulnerable workload, and finally destroying evidence and locking administrators out. Every technique is verified against MITRE ATT&CK's current (2026) classification, including a real, dated restructuring (ATT&CK v19's split of Defense Evasion into Stealth and Defense Impairment) that changed the technique IDs this exact subject matter uses.",
  "difficulty": "advanced",
  "category": "Cloud Security",
  "estimatedMinutes": 60,
  "xp": 260,
  "icon": "🔓",
  "prerequisites": [
    "aws-security",
    "cloud-security-monitoring",
    "azure-security"
  ],
  "tasks": [
    {
      "type": "reading" as const,
      "id": "cad-r0",
      "heading": "The Other Side of the Coin: What an Attacker Does Inside a Tenant",
      "content": "Picture a bank robbery, but the vault door was never forced: the robber simply walked in holding an employee's badge. Once inside, they do not run straight for the cash. They disable the cameras first, prop a fire door open in case they need a second exit, quietly copy the manager's spare keys, and only then move to the vault. Every one of those steps is a distinct, deliberate ACTION with its own evidence trail, and a security team that only ever asks 'how did the robber get in' misses everything that happens after the badge swipe. This room is about everything that happens after the badge swipe, inside a cloud account.\n\nThis platform already has three rooms that teach you to watch a cloud tenant: 'AWS Security for SOC Analysts' covers CloudTrail, GuardDuty, IAM backdoors, and the exposed-access-key chain; 'Cloud Security Monitoring' covers the audit-log landscape across AWS, Azure, and GCP; and 'Azure IaaS Security for SOC Analysts' covers Azure's resource model and its own control-plane audit trail. All three are written from the DEFENDER'S monitoring seat: what the logs record, and how to read them. None of them walk, action by action, what the ATTACKER actually DOES with a working cloud identity once they already have one. That is this room's entire subject: not how the door got opened, but what happens on the other side of it.\n\nThe story below continues a specific, concrete intrusion you may already recognise: NexaCorp (AWS account 482915007733), whose ec2-webapp-role identity was compromised via stolen EC2 Instance Metadata Service (IMDS, the link-local endpoint at 169.254.169.254 that hands live temporary credentials to any process running on an instance) credentials, exactly as taught in the 'AWS Security for SOC Analysts' room. If you completed that room, the attacker's next moves below are the literal continuation of that same case. If you have not, nothing here depends on having read it. This room is self-contained.\n\n### A Real, Dated Complication Worth Knowing About\n\nMITRE ATT&CK: the industry-standard, freely published catalogue of real adversary TECHNIQUES (specific methods) organised under TACTICS (the attacker's goal at that step, such as Privilege Escalation or Impact). Underwent a significant restructuring in its version 19 release on 28 April 2026. The single most bloated tactic in the whole framework, Defense Evasion, was split into two narrower, more precise tactics: STEALTH (which kept the old tactic ID, TA0005, and covers techniques about avoiding notice. Obfuscation, injection, indicator removal) and DEFENSE IMPAIRMENT (a brand-new tactic, TA0112, covering techniques that actively BREAK an organisation's defensive tooling and infrastructure rather than merely hiding from it). As part of that same release, two sub-techniques this room teaches were formally revoked and replaced with new IDs under the new tactic:\n\n| Old ID (pre-April 2026) | New ID (current) | What it covers |\n| --- | --- | --- |\n| T1562.007 | T1686.001 | Disable or Modify System Firewall: Cloud Firewall |\n| T1562.008 | T1685.002 | Disable or Modify Tools: Disable or Modify Cloud Log |\n\nThis matters to you as a working analyst for a very practical reason: plenty of detection-rule packs, SIEM content, vendor documentation, and older training material were authored before this split and still cite the old T1562.007/T1562.008 numbering. Recognising BOTH the legacy id and the current one is not academic trivia. It is exactly the kind of currency gap that makes the difference between correctly mapping an alert to the right ATT&CK reference and citing a number that no longer resolves on attack.mitre.org.\n\n### The Seven Techniques This Room Walks\n\n| Technique | Tactic | What it does |\n| --- | --- | --- |\n| T1686.001 (was T1562.007) | Defense Impairment | Open or widen a cloud firewall (security group / NSG / VPC firewall rule) |\n| T1578.002 | Defense Impairment | Launch a new compute instance to sidestep restrictions on existing ones |\n| T1068 | Privilege Escalation | Exploit a vulnerability to gain a more privileged identity: the mechanism that often unlocks everything else |\n| T1578.001 | Defense Impairment | Create (and often share) a snapshot of an existing volume |\n| T1578.003 | Defense Impairment | Delete a compute instance to destroy forensic evidence |\n| T1685.002 (was T1562.008) | Defense Impairment | Disable or modify cloud logging/detection tooling |\n| T1531 | Impact | Remove account access. Lock legitimate users out entirely |\n\nBy the end of this room you will be able to name the current technique id and tactic for each of these, read the real CloudTrail telemetry each one produces, and, just as important, tell a genuine attack from the DevOps and Auto Scaling activity that can look identical on the surface.",
      "checkpoint": {
        "question": "Per MITRE ATT&CK v19 (released 28 April 2026), which statement correctly describes what happened to the old Defense Evasion tactic and the old T1562.007/T1562.008 sub-technique IDs?",
        "options": [
          "It was renamed Stealth (TA0005); T1562.007 and T1562.008 kept their IDs and simply moved under the renamed tactic",
          "It split into Stealth (TA0005) and Defense Impairment (TA0112); T1562.007 became T1686.001 and T1562.008 became T1685.002",
          "It split into Stealth (TA0005) and Defense Impairment (TA0112); T1562.007 became T1685.002 and T1562.008 became T1686.001",
          "It split into Stealth (TA0112) and Defense Impairment (TA0005); T1562.007 became T1686.001 and T1562.008 became T1685.002"
        ],
        "answer": 1,
        "explanation": "ATT&CK v19 split Defense Evasion into Stealth (which kept the old ID, TA0005) and the new Defense Impairment (TA0112) for techniques that actively break defensive tooling; in the same release T1562.007 (cloud firewall) was revoked and replaced by T1686.001, and T1562.008 (cloud logs) by T1685.002. “It was renamed Stealth … kept their IDs” misses both the new tactic and the revocations: the old sub-technique IDs no longer resolve as current. “T1562.007 became T1685.002 and T1562.008 became T1686.001” swaps the mapping: T1686 is the firewall parent and T1685 the tools/logging parent. “Stealth (TA0112) and Defense Impairment (TA0005)” swaps the tactic IDs: Stealth is the tactic that inherited TA0005, while Defense Impairment is the new TA0112."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "cad-r1",
      "heading": "T1686.001: Disable or Modify Cloud Firewall",
      "content": "### What It Is\n\nA cloud FIREWALL is the virtual equivalent of the perimeter fence around a data centre. Except it is not a physical device at all, it is a set of rules enforced by the cloud provider's own network fabric. AWS calls its version a SECURITY GROUP (a stateful set of allow-rules attached to one or more instances); Azure calls its version a NETWORK SECURITY GROUP or NSG; GCP calls its version simply a VPC FIREWALL RULE. All three do the same job: they decide which source IP addresses, on which ports, using which protocol, are allowed to reach a given resource. T1686.001, Disable or Modify System Firewall: Cloud Firewall (the current id for what was T1562.007 before ATT&CK v19), is MITRE's name for an attacker with sufficient permissions changing those rules to let themselves in, or to let a service they already control reach further than it should.\n\n### How an Attacker Does It\n\nThe attacker rarely needs to compromise the network fabric itself. They only need one identity with permission to call the right API. On AWS, the relevant call is AuthorizeSecurityGroupIngress, adding a new inbound rule to an existing security group. A worked example, exactly as it would appear on an attacker's command line:\n\naws ec2 authorize-security-group-ingress --group-id sg-0f3a8b2c1d9e7f45 --protocol tcp --port 3389 --cidr 0.0.0.0/0\n\nRead this the way an analyst has to: --group-id names the specific security group being modified; --protocol tcp --port 3389 targets Windows Remote Desktop Protocol (RDP), a favourite target because it gives interactive, GUI access to whatever the group protects; and --cidr 0.0.0.0/0 is the entire IPv4 address space, every device on the internet, not a specific trusted range. On Azure, the parallel action creates or widens a Network Security Group rule (the operation recorded in Azure's Activity Log as Microsoft.Network/networkSecurityGroups/securityRules/write), typically also with a source-address-prefix of '*' (all addresses). On GCP, the equivalent API method is compute.firewalls.insert, dynamically creating a new ingress rule. MITRE ATT&CK's own documentation for this technique specifically calls out attackers using a script or utility that calls this exact method to open unrestricted TCP/UDP access.\n\nATT&CK also documents a real, publicly available tool built for exactly this kind of AWS post-exploitation: Pacu, an open-source AWS exploitation framework used by both penetration testers and real attackers, which, beyond opening security groups, can allowlist an attacker's own IP address directly inside AWS GuardDuty's trusted-IP list, so that GuardDuty simply stops flagging traffic from that address as suspicious in the first place.\n\n### What This Looks Like in Telemetry\n\nEvery one of these changes lands as a single CloudTrail management event with eventName AuthorizeSecurityGroupIngress, eventSource ec2.amazonaws.com, and a requestParameters block naming the exact group, protocol, port range, and CIDR that was added. The single field that separates a routine, narrowly-scoped change from this technique is the CIDR itself: a rule scoped to a specific corporate IP range or a peered security group is ordinary infrastructure work; a rule scoped to 0.0.0.0/0 (or its IPv6 equivalent, ::/0) on a sensitive port is exactly the pattern AWS's own Security Hub ships two dedicated, high-severity controls to catch: EC2.13 (security groups should not allow ingress from 0.0.0.0/0 to port 22) and EC2.14 (the same check for port 3389). EC2.13 is backed by the AWS Config managed rule 'restricted-ssh' (rule identifier INCOMING_SSH_DISABLED); EC2.14 is backed by 'restricted-common-ports', deployed as a rule named 'restricted-rdp'.\n\n### The Analyst's Questions\n\nA security-group change is not inherently suspicious. DevOps teams open and close ports constantly as part of ordinary infrastructure work. The questions that separate routine change from this technique are: does the new rule's CIDR span the entire internet rather than a specific, known range? Does the identity making the change have a documented, ticketed reason to touch THIS security group, on THIS port, right now? And critically, does this change follow closely behind some other suspicious event on the same identity, such as an unexpected privilege-escalation call? A security-group change in isolation is a data point. A security-group change sixteen minutes after the same identity was seen doing something else unusual is a pattern.",
      "checkpoint": {
        "question": "AWS Security Hub ships two dedicated controls specifically for the pattern this reading describes. What do controls EC2.13 and EC2.14 check for?",
        "options": [
          "Whether a security group allows 0.0.0.0/0 ingress on any port (EC2.13) or on well-known ports only (EC2.14)",
          "Whether a security group allows 0.0.0.0/0 or ::/0 ingress to port 22 (EC2.13) or to port 3389 (EC2.14)",
          "Whether a security group allows 0.0.0.0/0 ingress to port 3389 (EC2.13) or to port 22 (EC2.14)",
          "Whether a network ACL, not a security group, allows 0.0.0.0/0 ingress to ports 22 and 3389"
        ],
        "answer": 1,
        "explanation": "The reading names both controls: EC2.13 checks for ingress from 0.0.0.0/0 or ::/0 to port 22 (SSH), backed by the restricted-ssh Config rule, and EC2.14 does the same for port 3389 (RDP), backed by restricted-common-ports, the exact pattern T1686.001 produces. “On any port (EC2.13) or on well-known ports only (EC2.14)” broadens the checks beyond the two specific admin ports they target. “Port 3389 (EC2.13) or … port 22 (EC2.14)” swaps the ports. “A network ACL, not a security group” moves the check to the wrong layer. This reading and both controls are about security groups, the stateful rules attached to instances."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "cad-r2",
      "heading": "T1578.002, Create Cloud Instance: A New Machine to Escape the Old Rules",
      "content": "### What It Is\n\nEvery running compute instance in a cloud account sits inside whatever security groups, IAM roles, and network placement it was launched with. Those restrictions were often chosen deliberately by the organisation's own engineers, and an attacker who cannot easily change them on an EXISTING instance has a simpler option: launch a brand-new one, with none of those restrictions attached at all. T1578.002, Modify Cloud Compute Infrastructure: Create Cloud Instance, is MITRE ATT&CK's name for exactly this move. ATT&CK's own documentation is direct about the motive: attackers 'may leverage snapshots of existing volumes, provision a new instance, attach those snapshots, and implement weaker security policies' specifically to bypass restrictions enforced on the instances that are already running, and a fresh instance also lets an attacker operate independently, without disrupting or drawing attention to systems already in production.\n\nThis technique now belongs to the DEFENSE IMPAIRMENT tactic (TA0112) per ATT&CK v19 (it was Defense Evasion before the split) for the same logical reason as the previous reading: nothing here is about hiding from a defender, it is about actively defeating the security controls the defender already relies on.\n\n### How an Attacker Does It\n\nA worked AWS example, using the exact stolen role identity this room's story has already established:\n\naws ec2 run-instances --image-id ami-0abcdef1234567890 --instance-type g4dn.xlarge --region ap-southeast-1 --security-group-ids sg-0a1b2c3d4e5f6789a\n\nRead the choices deliberately: --region ap-southeast-1 places the instance in a region the organisation's own engineers rarely, if ever, use. Fewer eyes are watching that region's activity, and some organisations do not even ingest CloudTrail logs from regions they consider 'unused.' --instance-type g4dn.xlarge is a GPU-accelerated instance type, disproportionately favoured for compute-intensive abuse such as cryptocurrency mining. And --security-group-ids sg-0a1b2c3d4e5f6789a references a security group the attacker created themselves (using the T1686.001 technique from the previous reading), rather than any group the organisation's own engineers configured, meaning none of the restrictions that protect the rest of the fleet apply to this one machine at all.\n\nATT&CK's documented real-world procedure examples for this exact technique include two well-known threat actors: Scattered Spider, which has created both Azure virtual machines and Amazon EC2 instances inside victim environments after obtaining cloud credentials, and LAPSUS$, which has provisioned new virtual machines inside target cloud environments following credential compromise, in both cases, the new instance became the attacker's own private foothold, walled off from whatever hardening the organisation had applied to its production fleet.\n\n### What This Looks Like in Telemetry\n\nOn AWS, the event is a CloudTrail management event with eventName RunInstances and eventSource ec2.amazonaws.com, carrying the requested instance type, AMI, subnet, security group, and region in its requestParameters, and the newly assigned instance id in its responseElements. On its own this event is entirely unremarkable. Legitimate infrastructure launches new instances constantly, whether by hand, by a deployment pipeline, or by an Auto Scaling Group reacting to load. The context that turns it into a lead is the SAME context this room keeps returning to: an unfamiliar region, a security group the organisation's engineers do not recognise, an identity with no history of ever launching instances before, or, most damning of all, an identity that was already flagged for something else minutes earlier.\n\n### The Analyst's Questions\n\nNever evaluate a RunInstances event on volume or instance type alone, a legitimate GPU-heavy machine-learning workload looks identical in isolation to a crypto-mining instance. Ask instead: does the LAUNCHING IDENTITY have any history of provisioning compute (a human engineer, a CI/CD pipeline role, or an AWS service-linked role like Auto Scaling), or is this the first time this identity has ever called RunInstances? Does the REGION match where this organisation actually operates? And does the SECURITY GROUP attached to the new instance match the organisation's own hardened baseline, or is it a group that appeared minutes before the instance itself did?",
      "checkpoint": {
        "question": "Two RunInstances events land in CloudTrail on the same day, both launching g4dn.xlarge GPU instances. Per this reading, which detail most directly separates an attacker's T1578.002 launch from a legitimate one?",
        "options": [
          "The instance type: a GPU type such as g4dn.xlarge points to cryptomining, so that launch is the attacker's",
          "The launching identity's history: one that has never called RunInstances before versus a known launcher",
          "The eventName: attacker launches log as RunInstances, while Auto Scaling launches log under a separate name",
          "The time of day: a launch outside business hours has no legitimate driver, unlike a planned deployment"
        ],
        "answer": 1,
        "explanation": "The reading's first analyst question is about the LAUNCHING IDENTITY: an engineer, a CI/CD pipeline role or an AWS service-linked role such as Auto Scaling has a history of provisioning compute, while an identity calling RunInstances for the first time has no baseline at all, together with region and security group, that is what separates the two. “The instance type” is what the reading warns against: a GPU machine-learning workload looks identical to a mining instance in isolation, and here both launches use the same type anyway. “Auto Scaling launches log under a separate name” is false. Auto Scaling produces the same RunInstances eventName, which is why the room's analyst-choice task exists. “The time of day” ignores that Auto Scaling launches whenever load demands, at any hour."
      },
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "cad-q1",
      "question": "An identity that has never before called any EC2 API suddenly calls RunInstances in ap-southeast-1 (a region this organisation has never operated in) attaching a security group that was created by the SAME identity four minutes earlier via AuthorizeSecurityGroupIngress with a 0.0.0.0/0 rule. Which two techniques does this sequence describe, in the order they occurred, and what do both currently have in common per MITRE ATT&CK v19?",
      "options": [
        "T1686.001 (Disable or Modify Cloud Firewall) then T1578.002 (Create Cloud Instance). Both currently classified under the Defense Impairment tactic (TA0112)",
        "T1578.002 (Create Cloud Instance) then T1686.001 (Disable or Modify Cloud Firewall). Both currently classified under the Stealth tactic (TA0005)",
        "T1531 (Account Access Removal) then T1578.003 (Delete Cloud Instance). Both currently classified under the Impact tactic",
        "T1068 (Exploitation for Privilege Escalation) then T1578.001 (Create Snapshot). Both currently classified under the Privilege Escalation tactic"
      ],
      "answer": 0,
      "explanation": "The security-group rule came first (T1686.001, opening the group the new instance would use) and the instance launch followed (T1578.002, attaching that freshly-opened group). That is the correct order this room's own readings walked. MITRE ATT&CK v19 places BOTH of these current-generation ids under the new Defense Impairment tactic (TA0112), not the older, broader Defense Evasion or the new Stealth tactic that took over the 'avoid notice' half of the old Defense Evasion. The “Account Access Removal then Delete Cloud Instance” option substitutes two techniques (T1531, T1578.003) that describe the ENDGAME of an intrusion (locking users out and destroying instances) not this opening sequence. The “Exploitation for Privilege Escalation then Create Snapshot” option substitutes T1068 and T1578.001, which describe privilege escalation and snapshot creation, neither of which this scenario mentions at all.",
      "xp": 20
    },
    {
      "type": "reading" as const,
      "id": "cad-r3",
      "heading": "T1578.001, Create Snapshot: The Quiet Exfiltration Channel",
      "content": "### What It Is\n\nA SNAPSHOT is a point-in-time copy of an existing cloud storage volume, on AWS, an Elastic Block Store (EBS) volume attached to an EC2 instance, or an entire Relational Database Service (RDS) instance. Snapshots exist for an entirely legitimate reason: backups, disaster recovery, and moving data between regions. T1578.001, Modify Cloud Compute Infrastructure: Create Snapshot, is MITRE ATT&CK's name for an attacker abusing that same legitimate mechanism, not to revert to an existing snapshot, but to create a FRESH one specifically so it can be shared or moved somewhere the organisation does not control. ATT&CK's documentation describes the chained version of this technique directly: mounting a snapshot to a brand-new instance (the T1578.002 technique from the previous reading) with a permissive security group attached, giving the attacker unsupervised access to the data the snapshot contains.\n\nLike its sibling sub-techniques, T1578.001 sits under the Defense Impairment tactic (TA0112), creating a snapshot does not by itself move any data outside the account, but it is the step that makes everything after it possible, exactly the same logical role staging and archiving played in this platform's data-exfiltration curriculum for on-premises file shares.\n\n### How an Attacker Does It\n\nTwo AWS API calls, run back to back, accomplish the entire technique. First, create the snapshot:\n\naws ec2 create-snapshot --volume-id vol-0123456789abcdef0 --description prod-db-backup\n\nThen (and this is the step that actually matters to a defender) share it with an account the attacker controls, using ModifySnapshotAttribute:\n\naws ec2 modify-snapshot-attribute --snapshot-id snap-1234567890abcdef0 --attribute createVolumePermission --operation-type add --user-ids 999988887777\n\nRead the second call precisely, because its exact parameter names matter: --attribute createVolumePermission names the specific permission being modified (per AWS's own API documentation, this is the ONLY attribute ModifySnapshotAttribute can change on a snapshot); --operation-type add specifies that a permission is being GRANTED rather than revoked; and --user-ids 999988887777 is the AWS account ID being granted that permission. Critically, an account NUMBER, not a name, and one that belongs to the attacker, not to any NexaCorp subsidiary or partner. Once this call succeeds, the account 999988887777 can create its own EBS volume directly from NexaCorp's snapshot, in the attacker's own AWS account, entirely outside NexaCorp's network boundary: no further network transfer, upload, or download ever has to touch a monitored perimeter at all. AWS's own documentation on modifying snapshot permissions notes one relevant limit: an encrypted snapshot using the account's DEFAULT KMS (Key Management Service) key cannot be shared this way, which is exactly why attackers targeting this technique prefer unencrypted volumes or ones using a customer-managed key with permissive cross-account grants.\n\nMITRE's own documented tooling for this technique names Pacu again (the same open-source AWS exploitation framework from the previous readings) which is capable of creating snapshots of both EBS volumes and RDS instances as a built-in feature.\n\n### What This Looks Like in Telemetry\n\nTwo CloudTrail events, close together in time: CreateSnapshot naming the source volume, followed by ModifySnapshotAttribute naming the snapshot id, the createVolumePermission attribute, and (this is the field to watch) a UserId value in the request that does not match any AWS account this organisation owns or has a documented business relationship with.\n\n### The Analyst's Questions\n\nSnapshot creation on its own is completely routine. Every backup job does this constantly. The question that separates a backup from this technique is entirely about the SECOND call: was a createVolumePermission grant added at all, and if so, to which AWS account number? A snapshot that is created and never shared anywhere is just a backup. A snapshot shared to an account number with no documented relationship to this organisation, especially one created minutes or hours earlier by an identity already behaving unusually, is this technique in progress.",
      "checkpoint": {
        "question": "In the ModifySnapshotAttribute API call this reading walks through, what does the parameter createVolumePermission actually control?",
        "options": [
          "Which IAM users in the same account are allowed to delete or overwrite the snapshot",
          "Which AWS account IDs may create a volume from the snapshot: the sharing step",
          "Whether the snapshot may be copied into another Region within the same account",
          "Whether a volume built from the snapshot is encrypted with the default KMS key"
        ],
        "answer": 1,
        "explanation": "createVolumePermission is, per AWS's API documentation quoted in this reading, the one attribute ModifySnapshotAttribute changes: which AWS account IDs may create a volume from the snapshot. Adding an external account ID is how an attacker shares the snapshot outside the organisation without any network transfer crossing a monitored perimeter. “Which IAM users … are allowed to delete” describes IAM policy on the snapshot, not this attribute. “Copied into another Region within the same account” is a separate operation (CopySnapshot) that keeps the data inside the account. “Encrypted with the default KMS key” is set when the snapshot or its source volume is created, and the reading notes a default-key snapshot cannot be shared this way at all."
      },
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "cad-q2",
      "question": "A backup automation script calls CreateSnapshot against every production EBS volume nightly and never calls ModifySnapshotAttribute on any of them. A separate, previously-unseen identity calls CreateSnapshot once against a single database volume, then calls ModifySnapshotAttribute on that new snapshot thirty seconds later, granting createVolumePermission to AWS account 999988887777: an account number with no record anywhere in NexaCorp's vendor or subsidiary documentation. Which of these two activities is the T1578.001 exfiltration pattern, and why?",
      "options": [
        "The nightly backup script, snapshotting every production volume each night is the bulk volume-staging behaviour this technique depends on",
        "The previously-unseen identity: CreateSnapshot alone is routine, but the immediate grant to an undocumented external account is the sharing step",
        "Neither: ModifySnapshotAttribute only edits tags and description metadata on a snapshot, so no data can reach another account through it",
        "The previously-unseen identity, but only because it is new: the same grant from an established identity would be routine regardless of the target account"
      ],
      "answer": 1,
      "explanation": "This reading is explicit that CreateSnapshot alone is routine. Every backup job does exactly that, which is why the nightly script is not the concerning activity, however many volumes it covers. What makes the second identity's activity the T1578.001 pattern is the ModifySnapshotAttribute call immediately afterward, granting createVolumePermission to an AWS account number with no documented relationship to the organisation. That grant is the actual sharing mechanism, and it is precisely what the routine backup job never does. The “Neither, it only edits tags” option is factually wrong: ModifySnapshotAttribute with an add operation is exactly how a snapshot becomes accessible to an external account, which does move data outside the organisation's boundary once that account creates its own volume from it. The “only because it is new” option misplaces the signal: a new identity is a useful aggravating factor, but the deciding detail is the undocumented destination account number, not the identity's age alone.",
      "xp": 20
    },
    {
      "type": "reading" as const,
      "id": "cad-r4",
      "heading": "T1578.003 and T1531: The Destructive Endgame",
      "content": "### T1578.003 (Delete Cloud Instance\n\nOnce an attacker has finished using a resource) a staging instance, a compromised production server, or anything else they no longer need active, deleting it accomplishes two goals at once. MITRE ATT&CK's own description of T1578.003, Modify Cloud Compute Infrastructure: Delete Cloud Instance, states it directly: 'deleting an instance or virtual machine can remove valuable forensic artifacts and other evidence of suspicious behavior if the instance is not recoverable.' The technique sits, like its siblings, under the Defense Impairment tactic (TA0112). This is not about hiding from a defender who is currently watching, it is about making sure there is nothing left to examine once they start looking.\n\nOn AWS, the relevant call is straightforward:\n\naws ec2 terminate-instances --instance-ids i-0f1e2d3c4b5a69870\n\nTermination (as distinct from merely stopping an instance) can permanently destroy the instance's attached storage if its volumes are configured to delete on termination (the default setting for the root volume of most AWS instance types) which means any locally-staged data, log files, or malware artefacts that were never uploaded elsewhere can vanish along with the instance itself.\n\nATT&CK documents two real, named threat actors using exactly this technique, for two different destructive purposes: LAPSUS$ has deleted a target's systems and resources in the cloud specifically 'to trigger the organization's incident and crisis response process' (using the destruction itself as a form of disruption and distraction) and Storm-0501, a threat actor Microsoft has tracked conducting hybrid-cloud ransomware operations, has 'conducted mass deletion of cloud data stores and resources from Azure subscriptions,' turning cloud-native deletion into the ransomware payload itself: rather than encrypting files in place, simply delete the cloud resources that hold them, with backups often deleted alongside the production copies.\n\n### T1531. Account Access Removal\n\nThe final, most disruptive move in many real intrusions is not technical at all: it is administrative. T1531, Account Access Removal, sits under the IMPACT tactic (a tactic ATT&CK v19 left untouched by the Defense Evasion split, since removing access is not about evading detection, it is about denying legitimate users their own systems). MITRE's description covers deletion, locking, or manipulation of accounts, changing credentials, revoking permissions, or logging users out and blocking them from logging back in.\n\nCloud and SaaS environments make this technique unusually fast and unusually total. In an on-premises Active Directory environment, disabling every administrator account still leaves physical console access to the domain controllers as a recovery path. In a cloud tenant, an attacker who has gained sufficiently privileged access can, in minutes, remove or disable every global administrator account that would otherwise be used to recover from the incident, with no physical fallback at all. ATT&CK documents exactly this: LAPSUS$ has 'removed a targeted organization's global admin accounts, effectively locking the organization out of all access to their systems', a single documented group, doing to cloud identity administration what T1578.003 does to cloud compute infrastructure.\n\n### Why These Two Come Last\n\nBoth of these techniques are almost always the FINAL stage of an intrusion the attacker intends to end destructively, rather than an opening move, an attacker still gathering data or maintaining quiet access has every reason to keep the environment running and administrators unaware. Seeing either of these techniques fire is rarely a subtle finding requiring careful correlation the way a single security-group change is; it is very often the moment an incident becomes impossible to ignore, and the priority shifts immediately from investigation to containment and recovery.",
      "checkpoint": {
        "question": "Per this reading, why does T1531 (Account Access Removal) tend to be unusually TOTAL and fast specifically in a cloud/SaaS environment, compared to an on-premises Active Directory environment?",
        "options": [
          "Cloud tenants keep no audit trail of admin-account removal, so the lockout cannot be traced or rolled back",
          "On-premises, DC console access is still a way back in; a tenant with every global admin removed has no such fallback",
          "Cloud changes skip AD replication, so the lockout lands faster, but it is no more complete than on-premises",
          "A tenant can hold only one global administrator, so removing that single account locks out everyone at once"
        ],
        "answer": 1,
        "explanation": "The reading's point is the recovery path: on-premises, physical console access to a domain controller remains a way back in even with every admin account disabled, while a cloud tenant whose global admins have all been removed has no physical fallback at all. “No audit trail of admin-account removal” is false. Those removals are logged identity events; the problem is having no one left with rights to reverse them. “Faster, but it is no more complete” gets the speed half and denies the half that matters: the missing physical fallback is what makes it total. “Only one global administrator” is wrong. Tenants can and should have several, and the reading's LAPSUS$ example removed all of them."
      },
      "xp": 5
    },
    {
      "type": "reading" as const,
      "id": "cad-r5",
      "heading": "T1068: Exploitation for Privilege Escalation, as a Cloud Mechanism",
      "content": "### What It Is\n\nEverything this room has covered so far assumes the attacker already holds an identity with meaningful permissions inside the tenant. T1068, Exploitation for Privilege Escalation, is MITRE ATT&CK's name for the general mechanism that often GETS an attacker that identity in the first place: exploiting a genuine software vulnerability (a bug in an operating system, a service, or a kernel) to run attacker-controlled code with more privilege than the account or process should legitimately have. This technique belongs to the PRIVILEGE ESCALATION tactic (TA0004), a tactic ATT&CK v19 left entirely untouched by the Defense Evasion split, because gaining higher privilege is a different goal from breaking or hiding from defenses.\n\nOn a traditional Windows endpoint, this technique is most associated with BYOVD (Bring Your Own Vulnerable Driver): an attacker installs a legitimately-signed but known-vulnerable kernel driver specifically because its signature satisfies Windows' driver-signing requirements while its vulnerability grants kernel-level code execution once loaded. That endpoint-focused version of the technique is covered in depth elsewhere in this platform's Windows privilege-escalation material and is not repeated here.\n\n### Why This Matters Specifically in a Cloud/Container Tenant\n\nWhat earns T1068 a place in THIS room is a different, cloud-native application of the exact same idea: exploiting a vulnerability to break out of a CONTAINER or a virtualised workload and gain code execution directly on the underlying host, which, in a cloud environment, usually means the host's own cloud identity (its IAM role or service-account credentials, reachable through the Instance Metadata Service this room's story has already used once). ATT&CK's own documentation names Siloscape, malware that 'leveraged a vulnerability in Windows containers to perform an Escape to Host,' as a direct procedure example, and separately documents container-breakout behaviour achieved via exploitation of specific kernel vulnerabilities such as DirtyPipe (CVE-2022-0847), a real, publicly disclosed Linux kernel flaw that allowed a low-privileged process to overwrite data in files it should only have been able to read, including files that grant root access when tampered with.\n\nThis platform's own 'Kubernetes and Container Security' room walks the full chain from a compromised container, through a MISCONFIGURATION-based escape (a container run with dangerous settings like privileged mode or a host filesystem mount), to node-level code execution, to IMDS credential theft, to full cloud account access. That material is not repeated here. What that room's chain does not name explicitly is the ATT&CK id for the case where the escape itself is achieved not through a misconfiguration an attacker merely takes advantage of, but through actively EXPLOITING a genuine software vulnerability in the container runtime or kernel to force the same breakout. That exploitation-driven variant is T1068, and it is the reason this technique earns its place in a room about attacker actions inside a tenant: it is very often the exact mechanism that upgrades 'attacker controls one application container' into 'attacker holds the cloud identity of the entire node,' which is precisely the more-privileged identity every technique earlier in this room assumes the attacker already has.\n\n### The Analyst's Question\n\nT1068 rarely announces itself with an obvious log line the way a CloudTrail API call does, a kernel exploit or a container-escape vulnerability is, by nature, an attempt to do something the platform's own logging was never designed to observe directly. Be precise about what it can and cannot explain. T1068 explains how an ATTACKER reaches a more powerful identity's credentials, for example, escaping from an application container to the node and then using the node's instance role. It never explains how a ROLE gains permissions. A cloud identity can only succeed at the API calls its policies already allow, and any change to those policies (AttachRolePolicy, PutRolePolicy, CreatePolicyVersion) is itself a logged IAM API call. So the practical question for an analyst is retrospective: when a cloud identity's credentials are suddenly being used by something that should never hold them, the node's instance role making calls from inside an application pod that is supposed to run under its own narrower identity, or a role calling APIs it has never called before with no change to its policies. Ask 'how did the attacker get hold of this identity?' The answer is very often a T1068 escape moments earlier that left no cloud-audit-log trace, after which CloudTrail simply shows the role using permissions it always had. If instead a role's permissions appear to have CHANGED with no matching CloudTrail event, do not reach for T1068: suspect a logging gap, a trail that does not cover that Region or global-service events, a filtered event selector, or broken ingestion into the SIEM.",
      "checkpoint": {
        "question": "Per this reading, what real, publicly disclosed Linux kernel vulnerability does MITRE ATT&CK document as an example of exploitation-driven container-breakout behaviour under T1068?",
        "options": [
          "Log4Shell (CVE-2021-44228), remote code execution in the Log4j Java logging library",
          "DirtyPipe (CVE-2022-0847), letting a low-privileged process overwrite files it could only read",
          "PwnKit (CVE-2021-4034), a local privilege escalation in polkit's pkexec helper on Linux",
          "Siloscape, the exploit ATT&CK records for breaking out of Windows containers to the host"
        ],
        "answer": 1,
        "explanation": "DirtyPipe (CVE-2022-0847) is the Linux kernel flaw this reading names: it let a low-privileged process overwrite data in files it should only have been able to read, including files that grant root, the exploitation-driven container breakout ATT&CK documents under T1068. “Log4Shell” is a real remote-code-execution bug, but in a Java library, giving an attacker a foothold inside an application rather than breaking the kernel's isolation. “PwnKit” is a real Linux privilege escalation, but it is a bug in a userland setuid helper, and it is not the example this reading cites. “Siloscape” is the reading's other example, but it is MALWARE that used a Windows-container vulnerability to escape, not a Linux kernel vulnerability, and not a CVE."
      },
      "xp": 5
    },
    {
      "type": "question" as const,
      "id": "cad-q3",
      "question": "An EKS worker node's instance role, which in six months has only ever pulled container images, suddenly calls s3:ListBuckets and ec2:DescribeSecurityGroups. CloudTrail shows the calls coming from the node's own private IP, and shows no change to any IAM role or policy. The node's EDR ties the calls to a process inside an application pod (a pod configured to use its own narrow IAM role, never the node's) that began running as root on the host minutes earlier, right after a crash in the node's container runtime. What does this room's reading suggest is the most likely explanation, and which ATT&CK technique and tactic does it point to?",
      "options": [
        "The node role's credentials were stolen through the instance metadata service and replayed from outside AWS (T1552.005, Credential Access), which is why the calls look unfamiliar",
        "A container escape via a runtime exploit (T1068, Privilege Escalation): the pod's process reached the host and the node role's EXISTING credentials",
        "The exploit silently granted the node role new IAM permissions without calling any IAM API, which is why no policy change appears in CloudTrail (T1068, Privilege Escalation)",
        "T1578.002 (Create Cloud Instance): a new instance launched recently under the role would explain its new API activity"
      ],
      "answer": 1,
      "explanation": "This is the case this room's T1068 reading describes: an exploitation-driven escape from a container to the host leaves no CloudTrail event of its own, and afterwards CloudTrail simply shows the node's instance role using permissions it always had, from the node's own IP, by a process that should never have held those credentials. Replay from outside AWS does not fit, because the calls come from the node's own private IP, not an external address. The idea that an exploit can grant a role new IAM permissions without an IAM API call is the trap: a kernel or runtime exploit gives code execution on a host, never new IAM policy. Any permission change would be a logged IAM call such as AttachRolePolicy or CreatePolicyVersion, and nothing here changed. T1578.002 concerns launching a NEW instance, not an existing node's role being used by an escaped workload.",
      "xp": 25
    },
    {
      "type": "reading" as const,
      "id": "cad-r6",
      "heading": "Putting It Together: The Attacker's Real Order of Operations",
      "content": "Every technique in this room has been presented on its own, but a real intrusion walks them in a fairly predictable sequence, because each stage depends on the capability the previous stage unlocked. Understanding this order is what turns seven isolated facts into a single coherent investigation.\n\n### The Chain\n\n1. PRIVILEGE ESCALATION FIRST (T1068). An attacker with only ordinary application-level access to a single workload cannot yet touch security groups, launch instances, or create snapshots: those are account-level, IAM-gated actions. Exploiting a vulnerability to escape a container or workload and take over the underlying host's EXISTING cloud identity (the role gains nothing: the attacker gains access to it) is very often the step that hands the attacker enough permission to do anything else in this room at all.\n\n2. OPEN THE FIREWALL (T1686.001). With a working, sufficiently privileged identity in hand, the attacker's next practical obstacle is network reachability: the existing security groups were not built with the attacker's own infrastructure in mind. Opening ingress on a security group, or creating a new permissive one, removes that obstacle.\n\n3. STAND UP INDEPENDENT INFRASTRUCTURE (T1578.002). Rather than risk disrupting, or being noticed on, a production instance the organisation is actively watching, the attacker launches a fresh instance, attached to the security group just opened, that answers only to them.\n\n4. STAGE AND MOVE THE DATA (T1578.001). If the objective includes data theft rather than pure disruption, the attacker creates a snapshot of a valuable volume and shares it directly to an account they control, moving the data out without a single byte crossing a monitored network perimeter.\n\n5. DESTROY THE EVIDENCE (T1578.003, and often T1685.002 alongside it). Once the attacker has what they came for, deleting the instances and snapshots they created, and, if they have not already done so earlier in the intrusion, disabling the logging and detection tooling that would otherwise reconstruct these very steps. Removes as much of the forensic trail as possible.\n\n6. LOCK THE DOOR BEHIND THEM (T1531). If the intrusion is meant to end destructively (a ransomware-style operation, or simple maximum disruption) removing every legitimate administrator's access is the final act, and it is the one an organisation is guaranteed to notice immediately, because it is the one that stops their own team from doing anything about any of the steps before it.\n\n### Why the Order Matters to an Analyst\n\nThis sequence is not a rigid law: a real intrusion can skip steps, reorder them, or repeat them across multiple sessions over days or weeks. But knowing the TYPICAL order gives an analyst something extremely practical: if you catch step 2 (a security-group change) in progress, you now know exactly what to hunt for both BEFORE it (a workload suddenly using a more powerful identity's credentials with no IAM change, per T1068) and AFTER it (a RunInstances call using the newly-opened group, per T1578.002). A single alert stops being an isolated data point and becomes a known position on a known map, which is precisely what turns a Tier-1 'suspicious event' ticket into a Tier-2 confirmed, scoped incident.",
      "xp": 5
    },
    {
      "type": "ordering" as const,
      "id": "cad-o1",
      "heading": "Order the Chain: Inside a Compromised Tenant",
      "instructions": "Place these five stages of this room's attacker chain in the order a real intrusion typically performs them, from gaining a more privileged identity to locking legitimate administrators out.",
      "items": [
        {
          "id": "step-privesc",
          "text": "Exploit a vulnerability in a workload or container runtime to gain a more privileged cloud identity than the one the attacker started with (T1068, Privilege Escalation)"
        },
        {
          "id": "step-firewall",
          "text": "Open or widen a security group so attacker-controlled infrastructure can reach the tenant (T1686.001, Defense Impairment)"
        },
        {
          "id": "step-instance",
          "text": "Launch a new compute instance, attached to the newly-opened security group, that answers only to the attacker (T1578.002, Defense Impairment)"
        },
        {
          "id": "step-snapshot",
          "text": "Create a snapshot of a valuable volume and share it directly to an attacker-controlled AWS account (T1578.001, Defense Impairment)"
        },
        {
          "id": "step-lockout",
          "text": "Remove every legitimate administrator's account access, ending the intrusion destructively (T1531, Impact)"
        }
      ],
      "correct_order": [
        "step-privesc",
        "step-firewall",
        "step-instance",
        "step-snapshot",
        "step-lockout"
      ],
      "explanation": "This is the exact order this room's reading on putting the chain together walked: privilege escalation (T1068) is what typically hands the attacker enough permission to touch security groups and IAM at all; opening the firewall (T1686.001) removes the network obstacle standing between the attacker's own infrastructure and the tenant; launching an independent instance (T1578.002) gives the attacker infrastructure that answers only to them, attached to the group just opened; sharing a snapshot (T1578.001) moves valuable data out without crossing a monitored perimeter; and removing administrator access (T1531) is the final, most visible act, reserved for the end of an intrusion because it is the step guaranteed to be noticed immediately and to end the organisation's own ability to respond to everything that came before it.",
      "xp": 25
    },
    {
      "type": "reading" as const,
      "id": "cad-r7",
      "heading": "Detection Craft: Baselines, GuardDuty, and the DevOps False-Positive Problem",
      "content": "Every single technique this room has covered produces an API call that, in complete isolation, is also something a legitimate engineer does constantly. Security groups get opened for real reasons. Instances get launched by real Auto Scaling Groups reacting to real load. Snapshots get created and shared with real partner accounts for real backup and disaster-recovery reasons. A detection strategy built on 'alert every time any of these seven API calls happens' would drown a SOC in false positives within hours, and the fix is not a cleverer single rule, it is baselining and correlation.\n\n### Baselining Admin Actions\n\nThe single most useful question for every technique in this room is the same one: does THIS identity, doing THIS action, on THIS resource, match a pattern this identity has established before? An Auto Scaling Group's service-linked role calling RunInstances every few days for six months, always with the same instance type, AMI, and security group, has a baseline. An identity that has NEVER called RunInstances before, suddenly doing so in a region the organisation does not use, has no baseline at all, and the absence of history is itself a signal, not merely the presence of an unusual value.\n\n### What GuardDuty and Defender for Cloud Actually Add\n\nAWS GuardDuty and Microsoft Defender for Cloud (covered in depth in this platform's existing AWS and Azure rooms) both continuously analyse the exact audit-log streams this room's readings have walked through, and both raise pre-scored findings for a subset of the patterns covered here: an unusually permissive security-group change or an instance launched with characteristics matching known cryptomining patterns can each trigger a finding without a human analyst having hand-written the underlying correlation rule. But (and this is the point worth internalising rather than skimming past) those managed detection engines do not cover every technique in this room equally well. A snapshot shared to an external account number with zero other suspicious signals nearby, or a GuardDuty detector itself being deleted (a variant of T1685.002 this room's story has not needed to walk in detail, since the aws-security room already covers its CloudTrail-disabling sibling in depth; it lands in CloudTrail as eventName DeleteDetector from eventSource guardduty.amazonaws.com), can each slip past automated detection specifically because the finding engine that would have caught it is the very thing being tampered with, or because the signal is genuinely ambiguous without the surrounding context a human analyst has to supply.\n\n### The DevOps and Terraform Problem, Directly\n\nModern cloud infrastructure is overwhelmingly managed by INFRASTRUCTURE AS CODE. Tools like Terraform that apply configuration changes automatically, often on a schedule or in response to a pull request being merged, with no human directly typing an AWS CLI command at all. This produces exactly the same API calls this room has covered: Terraform opening a security group for a legitimate reason still calls AuthorizeSecurityGroupIngress; an Auto Scaling Group still calls RunInstances. The four checks that separate this legitimate automation from an attack are consistent across every technique in this room:\n\n1. THE IDENTITY. Is the calling identity a documented service role (an AWS-managed service-linked role, a CI/CD pipeline's own role, a Terraform execution role) with a naming convention and history the organisation recognises, or an identity with no such pattern?\n2. THE DOCUMENTATION. Is there a change ticket, a pull request, or a standing, approved configuration an analyst can point to?\n3. THE CONSISTENCY. Has this exact identity performed this exact kind of action, at a similar frequency, for a meaningful stretch of time already?\n4. THE DESTINATION OR SCOPE. Does the change stay within the organisation's own documented boundaries (a specific CIDR range, a specific account, a specific region), or does it reach the entire internet, an undocumented account, or an unfamiliar region?\n\nAll four pointing to 'legitimate' closes the case as expected automation. Any one of them missing is exactly the gap this room's practice tasks ask you to find.",
      "checkpoint": {
        "question": "Per this reading, why can GuardDuty or Defender for Cloud sometimes fail to catch a technique from this room even though both continuously analyse the relevant audit logs?",
        "options": [
          "They read only VPC flow and DNS logs, so control-plane API calls like these never reach the engine",
          "The engine itself can be tampered with (a deleted detector), and some signals are ambiguous without context",
          "They score only known-bad IPs, so an attacker working from a clean IP address produces no finding",
          "They cover every technique here equally well; misses come only from analysts ignoring the findings"
        ],
        "answer": 1,
        "explanation": "The reading gives both reasons: the finding engine can itself be the target (deleting the GuardDuty detector that would have raised the finding), and some signals (a snapshot shared to an external account with nothing else nearby) are genuinely ambiguous without context a human supplies. “They read only VPC flow and DNS logs” is wrong: the reading says both services continuously analyse the same audit-log streams this room walks through. “They score only known-bad IPs” undersells them: the reading's examples are behaviour-based findings, such as an unusually permissive security-group change or a cryptomining-shaped launch. “They cover every technique here equally well” contradicts the reading, which says plainly that coverage is uneven across this room's techniques."
      },
      "xp": 5
    },
    {
      "type": "log_analysis" as const,
      "id": "cad-la1",
      "heading": "Investigate: A Security Group Opened to the Entire Internet",
      "context": "You are triaging NexaCorp's CloudTrail stream. Earlier this shift, the ec2-webapp-role identity: the same role compromised via stolen EC2 Instance Metadata Service credentials and used to attach a new, highly permissive IAM policy version to itself, made another API call, this time against EC2 rather than IAM. The event below is that call.",
      "event": sgOpenEvent,
      "questions": [
        {
          "question": "Which single field in this event is the clearest evidence that the new rule is not narrowly scoped to a specific trusted network?",
          "options": [
            "…ipPermissions.items.0.fromPort / toPort: 3389 shows the new rule exposes RDP",
            "…ipPermissions.items.0.ipRanges.items.0.cidrIp: 0.0.0.0/0 is every IPv4 address",
            "…requestParameters.groupId: sg-0f3a8b2c1d9e7f45 is the production database's group",
            "…sourceIPAddress: 185.220.101.47 shows the call came from outside the corporate network"
          ],
          "answer": 1,
          "explanation": "Scope means WHO the new rule lets in, and only the cidrIp field answers that: 0.0.0.0/0 is AWS's notation for every IPv4 address, the opposite of a trusted range, and exactly what Security Hub's EC2.13/EC2.14 controls catch. “fromPort / toPort, 3389” tells you WHAT is exposed (RDP), which matters for severity, but a port-3389 rule limited to the corporate range would be ordinary admin work. “groupId” tells you WHICH resource changed: important context, but it says nothing about who can now reach it. “sourceIPAddress” describes who MADE the call, not the scope of the rule the call created: an engineer working from home produces an outside address too.",
          "xp": 20
        },
        {
          "question": "Given this room's investigation workflow, what is the strongest reason to treat this specific event as connected to a larger incident rather than an isolated security-group change?",
          "options": [
            "The call came from aws-cli rather than Terraform, the tool this organisation uses for infrastructure changes",
            "The same ec2-webapp-role session was already tied to an unexplained IAM policy change minutes earlier",
            "Port 3389 on a database subnet's group has no business reason, which marks the change as part of an attack",
            "It landed at 02:47 UTC, outside business hours, when no engineer would normally be changing groups"
          ],
          "answer": 1,
          "explanation": "The room's chain reading is built on this correlation: a security-group change (T1686.001) means most when you know what the same identity did just before it, and the context says this ec2-webapp-role session had already attached a new, highly permissive policy version to itself. That link (same identity, minutes apart) is concrete evidence of one intrusion, not a property of this event alone. “aws-cli rather than Terraform” treats the client tool as evidence, but engineers still use the CLI alongside infrastructure-as-code; the room's detection-craft reading treats the identity, documentation, consistency and scope as the deciding checks, not the client tool. “Port 3389 … has no business reason” overclaims: RDP is common in legitimate administration, which is exactly why attackers target it. “Outside business hours” is weak on its own: global teams, on-call engineers and automation all work at 02:47 UTC.",
          "xp": 20
        }
      ]
    },
    {
      "type": "analyst_choice" as const,
      "id": "cad-ac1",
      "heading": "Triage: A RunInstances Call the Same Afternoon",
      "scenario": "A separate alert fires for a RunInstances event in NexaCorp's account, roughly the same eventName this room's readings just covered under T1578.002. The underlying detection rule matches every RunInstances call in the account with no allowance for the calling identity, the region, or the organisation's own launch history.",
      "event": autoScalingRunInstancesEvent,
      "correct_verdict": "false_positive",
      "explanation": "Every discriminator this room's detection-craft reading names checks out as legitimate: the calling identity is the AWS-managed service-linked role AWSServiceRoleForAutoScaling, invoked directly by autoscaling.amazonaws.com rather than a human or an assumed application role; the instance type, AMI, subnet, and security group all match the rest of the existing fleet exactly; the region (us-east-1) is the organisation's own standard production region, not an unfamiliar one; and the it_verify_message confirms a documented, six-month-consistent scaling pattern tied to a specific CloudWatch alarm. This is the legitimate Auto Scaling shape this room's reading warned about: it produces the identical eventName as the T1578.002 attack pattern, and only the surrounding context, not the event name itself, tells them apart.",
      "fp_trap": "A student who has just learned T1578.002 and now sees ANY RunInstances event is primed to escalate reflexively. That is exactly the overcorrection this task exists to catch. The event name alone carries no verdict; this room's own reading on Create Cloud Instance was explicit that a RunInstances call is unremarkable in isolation, and the four checks (identity, documentation, consistency, scope) are what actually decide the case, not the mere fact that the technique's own API call appeared in the log.",
      "xp": 25
    },
    {
      "type": "matching" as const,
      "id": "cad-m1",
      "heading": "Match Each Attacker Action to Its Real CloudTrail eventName",
      "instructions": "Match each action an attacker takes inside a compromised tenant to the exact AWS CloudTrail eventName that action produces.",
      "pairs": [
        {
          "id": "p1",
          "left": "Open a security group's inbound rules to the entire internet (T1686.001, Disable or Modify Cloud Firewall)",
          "right": "AuthorizeSecurityGroupIngress"
        },
        {
          "id": "p2",
          "left": "Launch a new EC2 instance to sidestep the restrictions on existing ones (T1578.002, Create Cloud Instance)",
          "right": "RunInstances"
        },
        {
          "id": "p3",
          "left": "Create a point-in-time copy of an EBS volume before sharing it externally (T1578.001, Create Snapshot)",
          "right": "CreateSnapshot"
        },
        {
          "id": "p4",
          "left": "Grant an external AWS account permission to build a volume from a shared snapshot (T1578.001, the sharing step)",
          "right": "ModifySnapshotAttribute"
        },
        {
          "id": "p5",
          "left": "Permanently remove a compromised instance to destroy forensic evidence (T1578.003, Delete Cloud Instance)",
          "right": "TerminateInstances"
        },
        {
          "id": "p6",
          "left": "Delete the account's GuardDuty threat-detection engine so future findings never fire (T1685.002, formerly T1562.008)",
          "right": "DeleteDetector"
        }
      ],
      "explanation": "Each of these six eventName values is the exact API action this room's readings walked through: AuthorizeSecurityGroupIngress adds an inbound firewall rule; RunInstances launches a new compute instance; CreateSnapshot makes a point-in-time volume copy; ModifySnapshotAttribute is the specific call that grants an external account id the createVolumePermission needed to build a volume from a shared snapshot; TerminateInstances permanently removes an instance (and, by default configuration, its attached storage); and DeleteDetector is the AWS GuardDuty API action that removes the account's own threat-detection engine entirely, a cloud-log-tampering technique (T1685.002, the current id for what was T1562.008) distinct from, and less commonly taught than, the CloudTrail StopLogging pattern this platform's AWS Security room already covers in depth.",
      "xp": 25
    },
    {
      "type": "question" as const,
      "id": "cad-q4",
      "question": "An incident response team reconstructs a NexaCorp intrusion with this timeline: 09:14 a process inside an application pod on EKS node ip-10-20-4-17 begins making AWS API calls with that node's instance-role credentials, minutes after a crash in the node's container runtime, no IAM change to any role precedes it; 09:30 the same role opens a security group to 0.0.0.0/0 on port 3389; 09:41 the same role launches a new EC2 instance in ap-southeast-1 attached to that group; 10:15 the same role creates a snapshot of a production RDS volume and shares it with an undocumented external AWS account; 14:20 the same role deletes the instance created at 09:41; 14:25 the organisation's global administrator accounts are all disabled. Which technique most plausibly explains the 09:14 event specifically, and why is that technique harder to catch than every other event in this timeline?",
      "options": [
        "T1531 (Account Access Removal), disabling administrators is the opening step that lets the attacker change policies without being reversed",
        "T1068 (Exploitation for Privilege Escalation): the container escape itself writes no CloudTrail event",
        "T1098.003 (Additional Cloud Roles): harder to catch because role attachments blend into routine IAM administration",
        "T1685.002 (Disable or Modify Cloud Log): harder to catch because logging was already switched off, which is why no event explains the jump"
      ],
      "answer": 1,
      "explanation": "The 09:14 event, a workload process suddenly using the node's instance-role credentials right after a container-runtime crash, with no IAM change. Is exactly the signature this room's T1068 reading describes: an exploitation-driven container escape hands the attacker the host's EXISTING cloud identity. The escape itself never calls a cloud API, so it leaves no audit-log entry the way every other event in this timeline (all of which ARE named CloudTrail eventNames) does; CloudTrail only shows the node role doing things it was always allowed to do. This room explicitly places T1531 at the END of a typical chain, not the beginning: the 14:25 lockout in this very timeline confirms that ordering. Granting a role an additional policy through IAM (T1098.003) is a real technique, but nothing in this timeline attaches a role or policy, and it would itself be a CloudTrail-logged API call. Disabled logging fails on the timeline itself: CloudTrail events keep appearing from 09:30 onward.",
      "xp": 25
    },
    {
      "type": "flag" as const,
      "id": "cad-f1",
      "prompt": "Containing the security-group change from the log analysis task means removing exactly the inbound rule the attacker's call created, not the whole group. In that CloudTrail event, what identifier did AWS assign to the new rule? Enter it exactly as recorded.",
      "answer": "sgr-0d4e5f6a7b8c9012d",
      "hint": "Look at what AWS sent back in its response, not at what the caller put in the request.",
      "xp": 15
    }
  ]
};

export const roomsBatch46 = [cloudAttackerDefenseEvasionRoom];
