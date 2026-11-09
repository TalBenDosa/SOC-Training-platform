import type { RoomExperience } from "./types";

// "Operation Last Cloud" for the "cloud-attacker-defense-evasion" room, the campaign's last room.
// Script: docs/campaign/110-cloud-attacker-defense-evasion.md.
// Station task ids follow the room's own task order, unchanged.
//
// Aurelia Space Systems (fictional), not the graded tasks' NexaCorp records.
// Signature: What's Missing Is the Alert. Attackers stop logs, delete detectors and rotate into
// unwatched Regions, so the trace reads a silence through GuardDuty, the trails and the audit copy
// to StopLogging, and the duel meets each evasion move with the off-account copy that still shows it.
// Game mix: deduce + duel + hunt + tune (trace, worksheet, anatomy, inspect, sort, simulate and
// queue carry the reading content and are not arcade kinds).
// Lab data differs from the graded tasks: account 604217738150 and role gs-platform-role, never
// 482915007733 or ec2-webapp-role; the unwatched Region is sa-east-1, never ap-southeast-1; the
// firewall anatomy is a routine Terraform rule on port 5432 from 10.40.16.0/24, never 3389 from
// 0.0.0.0/0, and its rule ID is not the flag (la1, f1); the launch rule uses g5 and t3 types, never
// g4dn.xlarge or c5.xlarge (r2 checkpoint, ac1); the snapshot share goes to Aurelia's own DR account
// and the ledger's outside grant comes from a known role, never a new identity 30 seconds later to
// 999988887777 (q2); the identity-jump case is a root-only key file on an EC2 web host taken with a
// kernel exploit, never a pod, a node role or a container runtime crash (q3, q4); the chain card
// deck is Azure and unordered, never the five AWS stages (o1); the queue's benign cases are Terraform
// and AWS Backup, never Auto Scaling or RunInstances (ac1). Event names appear as data, and the
// labs never ask for an action-to-name pairing (m1): the trace's answer is StopLogging, and
// DeleteDetector, TerminateInstances and the rest are only shown.

export const CLOUD_ATTACKER_DEFENSE_EVASION: RoomExperience = {
  roomId: "cloud-attacker-defense-evasion",
  codename: "Operation Last Cloud",
  theme: "lastcloud",
  handler: { name: "Nils Ferreira-Okoye", role: "Cloud Threat Lead, Aurelia Space Systems" },
  briefing: [
    "Aurelia Space Systems builds small Earth-observation satellites, and every image they send down lands in one AWS organization.",
    "Sunday night the account that runs the ground segment went quiet: no findings, no alerts, a green dashboard, and twelve days to a launch review.",
    "Nils Ferreira-Okoye, Cloud Threat Lead, does not trust a quiet account. Anyone who can stop a log will not leave a note saying so.",
    "This one is a final exam of method: read what is there, ask what is missing, and find the copy the attacker could not reach.",
  ],
  mission: "Follow a silent account to the call that caused it, re-map the ATT&CK v19 numbers, read a firewall change, tune a launch rule, follow a snapshot, see what survives the endgame, explain an identity jump no log recorded, hunt the Region nobody watches, work the queue, and play the copies an attacker can't reach.",
  estimate: "~80 min",
  look: { primary: "#b8c0ff", secondary: "#ffd166", warn: "#ff5c7a" },
  scene: "facilitylastcloud",
  layout: "facility",
  stations: [
    {
      id: "trail",
      label: "The Trail",
      topic: "What an attacker does inside a tenant · ATT&CK v19 · T1686.001 Cloud Firewall · T1578.002 Create Cloud Instance",
      tagline: "The quietest account on the board",
      building: "control",
      taskIds: ["cad-r0", "cad-r1", "cad-r2", "cad-q1"],
    },
    {
      id: "copies",
      label: "The Copies",
      topic: "T1578.001 Create Snapshot · T1578.003 Delete Cloud Instance · T1531 Account Access Removal",
      tagline: "What leaves, and what stays",
      building: "vault",
      taskIds: ["cad-r3", "cad-q2", "cad-r4"],
    },
    {
      id: "below",
      label: "Below the Log",
      topic: "T1068 as a cloud mechanism · the attacker's order of operations",
      tagline: "A jump with no line above it",
      building: "lab",
      taskIds: ["cad-r5", "cad-q3", "cad-r6", "cad-o1"],
    },
    {
      id: "baseline",
      label: "The Baseline",
      topic: "Baselining admin actions · what GuardDuty adds · the four checks · event names",
      tagline: "Same call, different story",
      building: "office",
      taskIds: ["cad-r7", "cad-la1", "cad-ac1", "cad-m1"],
    },
    {
      id: "lastcloud",
      label: "Last Cloud",
      topic: "Reading a whole timeline · removing one firewall rule",
      tagline: "Read every line, then the gap",
      building: "ticket",
      taskIds: ["cad-q4", "cad-f1"],
      boss: true,
    },
  ],
  personas: {
    "cad-q1": { name: "Nils Ferreira-Okoye", role: "Cloud Threat Lead", line: "Two calls from one identity. Name them for the ticket." },
    "cad-q2": { name: "Nils Ferreira-Okoye", role: "Cloud Threat Lead", line: "Two snapshot patterns in one morning. Which one gets the page?" },
    "cad-q3": { name: "Nils Ferreira-Okoye", role: "Cloud Threat Lead", line: "An old role, new calls. Give me the likeliest story." },
    "cad-o1": { name: "Nils Ferreira-Okoye", role: "Cloud Threat Lead", line: "Put the stages in the order they usually run." },
    "cad-la1": { name: "Nils Ferreira-Okoye", role: "Cloud Threat Lead", line: "Read the event, then tell me what it proves." },
    "cad-ac1": { name: "Nils Ferreira-Okoye", role: "Cloud Threat Lead", line: "Same afternoon, another launch. What's your call?" },
    "cad-m1": { name: "Nils Ferreira-Okoye", role: "Cloud Threat Lead", line: "The ticket needs the exact event names." },
    "cad-q4": { name: "Nils Ferreira-Okoye", role: "Cloud Threat Lead", line: "One timeline, six lines. Start at the top." },
    "cad-f1": { name: "Nils Ferreira-Okoye", role: "Cloud Threat Lead", line: "Character for character, please." },
  },
  briefings: {
    // ── Reading 0: the other side of the coin ──
    "cad-r0": [
      {
        kind: "trace",
        title: "Follow a Silence to Its Cause",
        prompt: "Monday 07:40. aurelia-ground-prod averages six GuardDuty findings a night, and it has had none since Sunday evening. Nothing alerted, so nothing is assigned to anyone. Follow the silence through the findings, the trails and the audit copy to the call that caused it.",
        lead: "aurelia-ground-prod (604217738150): no findings after Sunday evening, normal rate six a night",
        primer: {
          title: "Silence is a reading",
          points: [
            "**CloudTrail** records AWS API calls as events: who called what, from where, in which Region. A **trail** delivers those events to a storage bucket.",
            "An **organization trail** is set up above the accounts. A member account can see it but cannot stop it, and its files land in a separate log archive account.",
            "**GuardDuty** is a detection service that reads those logs and raises **findings**. It runs as a **detector**, one per Region, and Aurelia forwards each finding to its **SIEM** (security information and event management), the central log and alert platform.",
            "Once a watcher is switched off, nothing is left to report that it was. A green dashboard can mean all is well, or that nobody is looking.",
            "So when a noisy source goes quiet: find the last thing it said, then read a copy the attacker could not reach for the call that ended it.",
          ],
          example: {
            label: "A different silence: a firewall's syslog feed",
            lines: [
              "`fw-edge-2` sends about 40 lines a minute to the SIEM. The last line is at 03:12:08. No health alert.",
              "The command-accounting server, outside the firewall, holds a copy of every admin command.",
              "It shows at 03:12:05: `no logging host 10.9.0.4`, typed by `adm-rkoh`.",
              "The silence was a command, and only the outside copy shows who typed it.",
            ],
          },
          fold: true,
        },
        steps: [
          {
            id: "last",
            ask: "These are the findings already forwarded to the SIEM. Which row is the last thing the detector said before the silence?",
            source: "GuardDuty · findings copy in the SIEM · aurelia-ground-prod",
            columns: ["updatedAt (UTC)", "region", "type", "severity", "resource"],
            rows: [
              ["10-24T03:12:55Z", "eu-west-1", "Recon:EC2/PortProbeUnprotectedPort", "2.0", "i-0c44e1a7b2f90d316"],
              ["10-24T22:58:40Z", "eu-west-1", "Policy:IAMUser/RootCredentialUsage", "2.0", "root"],
              ["10-25T19:05:12Z", "eu-west-1", "Recon:EC2/PortProbeUnprotectedPort", "2.0", "i-0c44e1a7b2f90d316"],
              ["10-25T21:17:33Z", "eu-west-1", "UnauthorizedAccess:EC2/SSHBruteForce", "2.0", "i-0c44e1a7b2f90d316"],
              ["10-25T22:41:07Z", "eu-west-1", "Discovery:IAMUser/AnomalousBehavior", "2.0", "gs-platform-role"],
            ],
            answer: 4,
            why: "22:41:07 is the latest timestamp, and it is the only finding that names gs-platform-role, a role the platform team's automation uses. After it, nothing. A finding that is merely the last one proves little, but it gives you an hour and an identity to pivot on.",
            learned: "Last finding 22:41 UTC, names gs-platform-role",
          },
          {
            id: "state",
            ask: "A stopped trail throws no error, so ask each trail its state. Which trail covering this account stopped recording?",
            source: "CloudTrail · describe-trails and get-trail-status · every trail covering this account",
            columns: ["Trail", "Delivers to", "IsOrganizationTrail", "IsLogging", "StopLoggingTime", "LatestDeliveryTime"],
            rows: [
              ["aurelia-org-trail", "log-archive account", "true", "true", "-", "10-26T07:35:18Z"],
              ["gs-prod-trail", "aurelia-ground-prod bucket", "false", "false", "10-25T22:54:13Z", "10-25T23:01:44Z"],
              ["gs-data-events", "aurelia-ground-prod bucket", "false", "true", "-", "10-26T07:31:02Z"],
              ["dev-sandbox-trail", "aurelia-dev bucket", "false", "true", "-", "10-26T07:28:49Z"],
            ],
            answer: 1,
            why: "IsLogging false, thirteen minutes after the last finding. The organization trail above it is still logging and delivering to another account, so the record of what happened next was never in this account's hands.",
            learned: "gs-prod-trail stopped 22:54:13. aurelia-org-trail kept recording",
          },
          {
            id: "cause",
            ask: "gs-prod-trail stopped at 22:54:13. Find the call that stopped it, in the copy the role could not touch.",
            source: "CloudTrail · aurelia-org-trail · copy in the log-archive account",
            columns: ["eventTime", "eventSource", "eventName", "awsRegion", "sessionIssuer", "sourceIPAddress", "errorCode"],
            rows: [
              ["22:33:02", "ec2.amazonaws.com", "DescribeInstances", "eu-west-1", "tf-exec-role", "203.0.113.44", "-"],
              ["22:38:16", "iam.amazonaws.com", "ListAttachedRolePolicies", "us-east-1", "gs-platform-role", "198.51.100.73", "-"],
              ["22:47:31", "cloudtrail.amazonaws.com", "DescribeTrails", "eu-west-1", "gs-platform-role", "198.51.100.73", "-"],
              ["22:49:05", "guardduty.amazonaws.com", "ListDetectors", "eu-west-1", "gs-platform-role", "198.51.100.73", "-"],
              ["22:52:40", "guardduty.amazonaws.com", "DeleteDetector", "eu-west-1", "gs-platform-role", "198.51.100.73", "-"],
              ["22:53:28", "cloudtrail.amazonaws.com", "UpdateTrail", "eu-west-1", "gs-platform-role", "198.51.100.73", "AccessDenied"],
              ["22:54:13", "cloudtrail.amazonaws.com", "StopLogging", "eu-west-1", "gs-platform-role", "198.51.100.73", "-"],
              ["22:54:41", "cloudtrail.amazonaws.com", "GetTrailStatus", "eu-west-1", "gs-platform-role", "198.51.100.73", "-"],
            ],
            answer: 6,
            why: "StopLogging, to the second, by gs-platform-role. This is T1685.002, Disable or Modify Cloud Log, under Defense Impairment (TA0112): a defence was switched off, not hidden from. GuardDuty has a finding for a stopped trail, Stealth:IAMUser/CloudTrailLoggingDisabled, and it never fired, because of the DeleteDetector line two rows up. The attacker took out the watcher first.",
            learned: "22:54:13 StopLogging by gs-platform-role, T1685.002",
          },
          {
            id: "next",
            ask: "gs-prod-trail saw nothing more, but the copy did. Which call shows this role looking for somewhere else to go?",
            source: "CloudTrail · aurelia-org-trail · the same copy, after the stop",
            columns: ["eventTime", "eventSource", "eventName", "awsRegion", "sessionIssuer", "sourceIPAddress"],
            rows: [
              ["22:54:41", "cloudtrail.amazonaws.com", "GetTrailStatus", "eu-west-1", "gs-platform-role", "198.51.100.73"],
              ["22:56:10", "ec2.amazonaws.com", "DescribeInstances", "eu-west-1", "tf-exec-role", "203.0.113.44"],
              ["22:57:22", "sts.amazonaws.com", "AssumeRole", "eu-west-1", "dr-replica-role", "203.0.113.44"],
              ["22:58:02", "ec2.amazonaws.com", "DescribeRegions", "eu-west-1", "gs-platform-role", "198.51.100.73"],
            ],
            answer: 3,
            why: "DescribeRegions lists the Regions an account can use. GetTrailStatus is the role checking its own work, and the other two rows belong to other identities. A role that has just blinded one Region and then asks where else it can run is about to move.",
            learned: "22:58 DescribeRegions: the role is choosing where to work next",
          },
        ],
      },
      {
        kind: "worksheet",
        title: "Re-Map the Rule Pack",
        prompt: "Aurelia's detection rules were written before ATT&CK v19. Nils wants Sunday's ticket to cite numbers that still resolve. Read the audit of the rule pack and work out how much editing it needs.",
        caption: "Detection rule pack · ATT&CK audit against v19",
        primer: {
          title: "ATT&CK moved some numbers",
          points: [
            "**ATT&CK** is the public catalogue of attacker techniques, each filed under a **tactic**: the attacker's goal at that step.",
            "Version 19, released 28 April 2026, split the old Defense Evasion tactic in two.",
            "One question sorts the two halves: is every defence still running? If it is, and the attacker is just not being noticed, that is hiding. If a control was switched off or changed, that is impairment.",
            "A **revoked** ID no longer resolves as current, so a rule citing one points at nothing, even though the event it fires on is real.",
          ],
          example: {
            label: "Reading one audit line from another pack",
            lines: [
              "Rule: `Password spray on VPN`. On the site: current.",
              "The ID still resolves, so that line needs no edit.",
              "Only lines marked revoked need a new number.",
            ],
          },
          fold: true,
        },
        columns: ["Rule", "Cited in the rule", "On attack.mitre.org", "Current ID", "Current tactic"],
        rows: [
          ["Trail stopped", "T1562.008", "Revoked", "T1685.002", "Defense Impairment (TA0112)"],
          ["Detector deleted", "T1562.008", "Revoked", "T1685.002", "Defense Impairment (TA0112)"],
          ["Group opened to the internet", "T1562.007", "Revoked", "T1686.001", "Defense Impairment (TA0112)"],
          ["First launch by an identity", "T1578.002", "Current", "T1578.002", "Defense Impairment (TA0112)"],
          ["Snapshot taken outside the backup job", "T1578.001", "Current", "T1578.001", "Defense Impairment (TA0112)"],
          ["Instance deleted after a finding", "T1578.003", "Current", "T1578.003", "Defense Impairment (TA0112)"],
          ["Admin removed from a role", "T1531", "Current", "T1531", "Impact (TA0040)"],
          ["Kernel exploit on a host", "T1068", "Current", "T1068", "Privilege Escalation (TA0004)"],
          ["Code injected into a host process", "TA0005 (tactic only)", "Current, renamed", "TA0005", "Stealth (TA0005)"],
        ],
        questions: [
          { id: "edit", q: "How many rules cite an ID that no longer resolves?", hint: "Count one column, not the IDs.", answer: ["3"], why: "Three rules, on two old IDs: one old number can sit on several rules. Search the pack for the number, not for one rule name." },
          { id: "new", q: "How many rules now sit under the tactic that did not exist before April 2026?", hint: "The tactic with the new TA number.", answer: ["6"], why: "Six. v19 kept TA0005 for hiding and gave breaking a defence its own tactic, and every cloud infrastructure rule here moved with it." },
          { id: "wrong", q: "A vendor pack from 2025 labels Sunday's stopped trail T1562.008. Is the alert wrong about what happened? (yes/no)", hint: "Which part is out of date: the event or the label?", answer: ["no"], why: "The event is real and the label is old. Older packs keep using the old numbers, so know both and write the current one in your ticket." },
        ],
      },
    ],
    // ── Reading 1: T1686.001 ──
    "cad-r1": [
      {
        kind: "anatomy",
        title: "Read a Firewall Change Field by Field",
        prompt: "Last Wednesday, the platform pipeline added a database rule in aurelia-ground-prod, under a merged pull request. Read this ordinary change field by field, so you know what each part of the event holds.",
        source: "CloudTrail · AuthorizeSecurityGroupIngress · aurelia-ground-prod",
        primer: {
          title: "A cloud firewall is a set of rules",
          points: [
            "A **security group** is AWS's stateful set of allow rules attached to instances. Azure calls its version a Network Security Group, GCP a VPC firewall rule.",
            "There is no appliance to break into. Any identity allowed to call the right API can change the rules.",
            "ATT&CK files that abuse as **T1686.001**, Disable or Modify System Firewall: Cloud Firewall.",
            "**CIDR** notation writes a range of addresses. A smaller number after the slash means a wider range: `/24` is 256 addresses, `/16` is 65,536.",
          ],
          example: {
            label: "The same reading on a GCP rule",
            lines: [
              "`compute.firewalls.insert` by `ci-deployer@example-project.iam.gserviceaccount.com`",
              "`allowed: tcp:6379` is the service, Redis.",
              "`sourceRanges: 10.8.0.0/16` is who may connect.",
              "Each field answers its own question, so read them one at a time.",
            ],
          },
          fold: true,
        },
        fields: [
          { key: "eventTime", value: "2026-10-21T10:14:02Z", label: "When" },
          { key: "eventName", value: "AuthorizeSecurityGroupIngress", label: "The call", note: "Adds an inbound rule to a security group. On Azure the same act is Microsoft.Network/networkSecurityGroups/securityRules/write, and on GCP compute.firewalls.insert." },
          { key: "eventSource", value: "ec2.amazonaws.com", note: "Security groups belong to the EC2 service." },
          { key: "userIdentity.arn", value: "arn:aws:sts::604217738150:assumed-role/tf-exec-role/pipeline-88213", label: "Who called", note: "The role, then the session name. This is the identity to compare with its own history." },
          { key: "sourceIPAddress", value: "203.0.113.44", label: "Called from", note: "Where the API request came from. Here, the pipeline's outbound address." },
          { key: "requestParameters.groupId", value: "sg-07c41e9ad2b36f018", label: "Which group", note: "The group being edited, and so the resources behind it." },
          { key: "requestParameters.ipPermissions.items.0.ipProtocol", value: "tcp" },
          { key: "requestParameters.ipPermissions.items.0.fromPort", value: "5432", label: "Which service", note: "From and to are equal, so one port: PostgreSQL." },
          { key: "requestParameters.ipPermissions.items.0.toPort", value: "5432" },
          { key: "requestParameters.ipPermissions.items.0.ipRanges.items.0.cidrIp", value: "10.40.16.0/24", label: "Who the rule admits", note: "The source range of the new rule. 0.0.0.0/0 means every IPv4 address and ::/0 every IPv6 address. Security Hub controls EC2.13 (port 22) and EC2.14 (port 3389) look for those two values." },
          { key: "responseElements.securityGroupRuleSet.items.0.securityGroupRuleId", value: "sgr-0b77e1a24c90d3e16", label: "The new rule's own ID", note: "AWS assigns this when it creates the rule, so it appears in the response and not in the request. revoke-security-group-ingress takes it with --security-group-rule-ids and removes that rule alone." },
          { key: "errorCode", value: "(empty)", note: "Empty means the call succeeded." },
        ],
        summary: "One event, several questions: who called, from where, on which group, for which service, and who the new rule admits. Each has its own field, and the request half says what was asked while the response half says what AWS created. One event cannot tell its own story, so the next step is always to widen the view to the session around it.",
      },
    ],
    // ── Reading 2: T1578.002 ──
    "cad-r2": [
      {
        kind: "tune",
        title: "Tune a New-Launch Rule",
        prompt: "Eleven RunInstances events from last quarter, four of them the red team's. Every row is the same call. Nils has two dials for a rule that fires if either one trips. Catch all four with at most one false alarm, and you have three deploys.",
        eventColumn: "Launched by, type, Region",
        primer: {
          title: "One call, many owners",
          points: [
            "`RunInstances` starts an EC2 instance, a virtual machine in AWS. **T1578.002**, Create Cloud Instance, is the attacker's version: a new machine with none of the restrictions on the fleet.",
            "Pipelines, AWS services and people all produce that same event, so an alert on the call alone drowns you.",
            "A **baseline** is what an identity normally does. An identity with no baseline for an action is a signal in its own right.",
            "**Region share** is how much of an account's launching happens in a Region. Fewer eyes rest on a Region that sees little.",
          ],
          example: {
            label: "The same idea on a different call: CreateAccessKey",
            lines: [
              "`hr-sync-role`: 212 calls in a year, monthly, same user group.",
              "`report-fn-role`: 0 calls in a year, then one this morning.",
              "One event name, two very different histories. The second goes to the top of the pile.",
            ],
          },
          fold: true,
        },
        dials: [
          { id: "hist", label: "Launch history of this identity", short: "History", unit: "days", min: 0, max: 180, step: 5, start: 90, dir: "below" },
          { id: "share", label: "Region's share of account launches", short: "Region %", unit: "%", min: 0, max: 40, step: 1, start: 20, dir: "below" },
        ],
        mode: "any",
        events: [
          { id: "a1", label: "ops-metrics-role, t3.large, ca-central-1", bad: true, values: { hist: 0, share: 0 } },
          { id: "a2", label: "gs-ci-key, t3.medium, eu-west-1", bad: true, values: { hist: 0, share: 62 } },
          { id: "a3", label: "j.ibarra SSO session, g5.xlarge, me-central-1", bad: true, values: { hist: 140, share: 1 } },
          { id: "a4", label: "web-canary-role, g5.2xlarge, ap-south-1", bad: true, values: { hist: 10, share: 3 } },
          { id: "b1", label: "AWSServiceRoleForEC2Spot, m6i.large, eu-west-1", bad: false, values: { hist: 180, share: 62 } },
          { id: "b2", label: "ml-train-role, g5.2xlarge, eu-central-1", bad: false, values: { hist: 170, share: 15 } },
          { id: "b3", label: "r.adeyemi SSO session, t3.micro, eu-west-1, ticket CHG-5011", bad: false, values: { hist: 0, share: 62 } },
          { id: "b4", label: "dr-drill-role, m6i.xlarge, eu-north-1", bad: false, values: { hist: 175, share: 4 } },
          { id: "b5", label: "tf-exec-role, m6i.large, eu-west-1", bad: false, values: { hist: 165, share: 62 } },
          { id: "b6", label: "render-batch-role, c6i.2xlarge, eu-central-1", bad: false, values: { hist: 120, share: 15 } },
          { id: "b7", label: "qa-loadtest-role, m6i.large, eu-west-1", bad: false, values: { hist: 20, share: 62 } },
        ],
        goal: { catch: 4, maxFalse: 1 },
        lesson: "The red team's launches split two ways. Two came from identities with no launch history at all, and one of those stayed in the busiest Region. One came from a session with months of history that went somewhere the account never goes. Neither dial catches all four alone inside the false-alarm limit. Setting a dial just past the attacks, and no further, keeps the quarterly drill and the new test role quiet, and the one false alarm left is a first launch that a ticket explains in a minute. That is the price of treating no history as a signal.",
      },
    ],
    // ── Reading 3: T1578.001 ──
    "cad-r3": [
      {
        kind: "inspect",
        title: "Read a Snapshot Share Line by Line",
        prompt: "Every night the disaster recovery (DR) job shares one snapshot with Aurelia's DR account. Open last night's event and tap each line to see what it records.",
        artifact: "CloudTrail · ModifySnapshotAttribute · aurelia-ground-prod",
        primer: {
          title: "A copy that can change hands",
          points: [
            "A **snapshot** is a point-in-time copy of a storage volume, on AWS an EBS (Elastic Block Store) volume. Backups create them constantly.",
            "**T1578.001**, Create Snapshot, is the attacker's use of the same mechanism, filed under Defense Impairment. Handing the copy to a cloud account the attacker holds is a separate entry, **T1537**, Transfer Data to Cloud Account, under Exfiltration.",
            "It takes two calls: `CreateSnapshot` makes the copy, and `ModifySnapshotAttribute` decides who else may use it.",
            "Sharing moves no bytes at the time. The other account builds its own volume, so nothing crosses a network you monitor.",
          ],
          example: {
            label: "The same pair on a managed RDS database",
            lines: [
              "`CreateDBSnapshot`: `dBSnapshotIdentifier: ledger-weekly`",
              "`ModifyDBSnapshotAttribute`: `attributeName: restore`",
              "`valuesToAdd: [\"444455556666\"]` lets that account restore the copy.",
              "Different service, same shape: one call copies, the next one opens.",
            ],
          },
          fold: true,
        },
        items: [
          { id: "name", text: "\"eventName\": \"ModifySnapshotAttribute\"", tag: "The call", tone: "info", note: "The second call of the pair. CreateSnapshot came first and made the copy." },
          { id: "who", text: "\"arn\": \"arn:aws:sts::604217738150:assumed-role/dr-replica-role/nightly\"", tag: "Who asked", tone: "info", note: "The role and session that made the change." },
          { id: "snap", text: "\"snapshotId\": \"snap-0e4b71c9a25d6f803\"", tag: "Which copy", tone: "info", note: "The ID ties this call back to the CreateSnapshot event that named the source volume." },
          { id: "attr", text: "\"attributeType\": \"CREATE_VOLUME_PERMISSION\"", tag: "What changed", tone: "info", note: "createVolumePermission is the list of accounts that can build their own disk from this copy." },
          { id: "add", text: "\"createVolumePermission\": { \"add\": { \"items\": [ { \"userId\": \"604217738411\" } ] } }", tag: "The grant", tone: "info", note: "add grants and remove revokes. The value is an account number, not a name, so it means nothing until you look it up. This one is aurelia-dr in the account inventory." },
          { id: "result", text: "\"responseElements\": { \"_return\": true }", tag: "Result", tone: "info", note: "The call succeeded: from this moment, that account can build its own volume from the snapshot." },
        ],
      },
      {
        kind: "worksheet",
        title: "Work Through the Snapshot Ledger",
        prompt: "Nils picked six snapshots from the week and joined their events from the organization trail to the account inventory. Now read the ledger the way the event taught you, and find the one to open first.",
        caption: "Snapshot ledger · six snapshots picked from the last 7 days · CloudTrail joined to the account inventory · IDs shortened",
        columns: ["Snapshot", "Source", "CreateSnapshot by", "Grant added by", "Granted to", "In account inventory"],
        rows: [
          ["snap-02b7c1", "gs-telemetry-db", "backup-nightly-role", "-", "-", "-"],
          ["snap-07de44", "img-archive-01", "backup-nightly-role", "-", "-", "-"],
          ["snap-0e4b71", "ops-wiki", "dr-replica-role", "dr-replica-role", "604217738411", "aurelia-dr"],
          ["snap-0c19a8", "payload-models", "tf-exec-role", "tf-exec-role", "731184620957", "Not listed"],
          ["snap-05e2f6", "imaging-models", "ml-train-role", "ml-train-role", "604217738377", "aurelia-security"],
          ["snap-0a66d3", "gs-telemetry-db", "backup-nightly-role", "-", "-", "-"],
        ],
        questions: [
          { id: "first", q: "Which snapshot do you open first?", hint: "Follow each grant to where it points.", answer: ["snap-0c19a8", "0c19a8"], why: "snap-0c19a8 is the only grant to a number the inventory cannot name. Finding out who owns 731184620957 comes before anything else." },
          { id: "plain", q: "How many of these snapshots were created and never shared?", hint: "Count the rows with no grant.", answer: ["3"], why: "Three. With no grant, no other account can build a volume from them, and that is simply what a backup looks like." },
          { id: "out", q: "How many of these can an account outside Aurelia build a volume from?", hint: "Which grants point at Aurelia's own accounts?", answer: ["1"], why: "One. The other two grants stay inside the organization, which is what the inventory join shows you at a glance." },
        ],
      },
    ],
    // ── Reading 4: the destructive endgame ──
    "cad-r4": [
      {
        kind: "sort",
        title: "What Survives a Termination?",
        prompt: "A foothold instance in eu-west-1 was deleted with TerminateInstances before anyone looked at it. Nils wants to know what is still there to examine. Sort each item.",
        primer: {
          title: "Stopped is not terminated",
          points: [
            "A **stopped** instance can start again with its disks intact. A **terminated** one is gone for good.",
            "Each EBS volume has a `DeleteOnTermination` setting. For most root volumes the default is true.",
            "**T1578.003**, Delete Cloud Instance, uses that on purpose: no instance means nothing left to examine. It sits under Defense Impairment.",
            "Whatever already left the machine is out of reach of the deletion, such as telemetry from an **EDR** (endpoint detection and response) agent.",
            "Storm-0501 and LAPSUS$ are both documented deleting cloud resources at scale.",
          ],
          example: {
            label: "The same question on an Azure VM",
            lines: [
              "A VM whose OS disk has `deleteOption: Delete` is deleted.",
              "The disk goes with it, and `Microsoft.Compute/virtualMachines/delete` stays in the Activity Log.",
              "A data disk set to `Detach` survives as a separate resource.",
            ],
          },
          fold: true,
        },
        buckets: [
          { id: "gone", label: "Gone with the instance" },
          { id: "stays", label: "Still there afterwards" },
        ],
        items: [
          { id: "root", text: "The root EBS volume, DeleteOnTermination true", bucket: "gone", why: "That setting is the default on most root volumes, so the disk goes with the instance." },
          { id: "logs", text: "/var/log on the root volume, never shipped anywhere", bucket: "gone", why: "It lived only on the disk that was just deleted." },
          { id: "store", text: "Scratch files on an instance store volume", bucket: "gone", why: "Instance store disks belong to the physical host, and their data ends with the instance." },
          { id: "mem", text: "A payload running only in memory", bucket: "gone", why: "Memory dies with the instance, unless someone captured it first." },
          { id: "data", text: "A second EBS volume, DeleteOnTermination false", bucket: "stays", why: "It detaches and stays in the account. Check this flag before assuming the disks are gone." },
          { id: "event", text: "The TerminateInstances event", bucket: "stays", why: "The API call is a control-plane event, recorded outside the instance." },
          { id: "snap", text: "A snapshot of the root volume taken last night", bucket: "stays", why: "A snapshot is its own object. Terminating the source does not touch it." },
          { id: "edr", text: "Process telemetry the EDR agent already sent", bucket: "stays", why: "It left the box as it happened. Evidence that has left cannot be deleted with the box." },
        ],
      },
      {
        kind: "simulate",
        title: "Run a Lockout Against Three Setups",
        prompt: "The last move of a destructive intrusion is administrative: remove every administrator. Nils wants to know how far that would reach. Run the same lockout against each of three setups and read what each one leaves you.",
        primer: {
          title: "Locking the door behind them",
          points: [
            "**T1531**, Account Access Removal, covers deleting, locking or changing accounts so the owners cannot get in. It sits under Impact (TA0040), and v19 left it there.",
            "A **global administrator** holds the top role in a cloud identity tenant.",
            "It usually comes last, because an attacker who wants quiet has no reason to alert anyone. It is also the step nobody can miss.",
            "Recovery depends on one thing: a way in that does not need the accounts that were just removed.",
          ],
          example: {
            label: "The same question on a SaaS payroll app",
            lines: [
              "The only owner account has its email changed by an intruder.",
              "No second owner exists, so no one inside can reverse it.",
              "The vendor wants a signed letter: two working days with no payroll access.",
            ],
          },
          fold: true,
        },
        checks: [
          { name: "Admin accounts", question: "Is any admin account left after the sweep?" },
          { name: "A way back in", question: "Is there a path that needs none of those accounts?" },
          { name: "Your own recovery", question: "Can your own people restore access tonight?" },
        ],
        scenarios: [
          {
            id: "hypervisor",
            label: "Hypervisor cluster",
            detail: "Every administrator removed from the management console. Four hypervisor hosts in a locked room in the ops building.",
            results: ["fail", "pass", "pass"],
            why: ["All of them removed.", "Someone can walk to a host's console and sign in as its local root account, which the management layer does not own.", "Slow and unpleasant, but Aurelia's staff can do it themselves."],
            verdict: "Bad night, but survivable. A physical console is a way back that does not depend on any management account.",
          },
          {
            id: "tenant",
            label: "Cloud tenant, no emergency account",
            detail: "Every global administrator removed. There is no server anywhere to walk up to.",
            results: ["fail", "fail", "fail"],
            why: ["All of them removed, in minutes.", "No console and no room to walk into: the tenant has no physical side.", "Only the provider's support process can help, and nobody can undo a single attacker change while you wait."],
            verdict: "Total, and fast. LAPSUS$ is documented removing a target's global admins in exactly this way. The cloud gives you no physical fallback by default.",
          },
          {
            id: "breakglass",
            label: "Cloud tenant, emergency account",
            detail: "Every day-to-day global admin removed. One emergency account, never used, kept in a safe, with an alert on any sign-in.",
            results: ["pass", "pass", "pass"],
            why: ["It survives only if the sweep misses it: a full role listing would show it.", "It does not depend on the accounts that were removed.", "Your own staff can sign in and start reversing."],
            verdict: "The fallback exists because someone built it before the bad day. It is worth checking that yours is still there.",
          },
        ],
      },
    ],
    // ── Reading 5: T1068 ──
    "cad-r5": [
      {
        kind: "deduce",
        title: "Which Identity Was Reached Through Its Host?",
        prompt: "How did the attacker get anywhere near gs-platform-role? This month, six Aurelia identities made calls they had never made. One was reached by someone who exploited a bug on the host holding its key. The rest can be set aside. Strike them out as Nils reads the clues.",
        primer: {
          title: "Two ways to end up able to do more",
          points: [
            "An identity can be **given more**: a policy change, which is a logged IAM (Identity and Access Management) call you can find in CloudTrail.",
            "Or an attacker can **reach an identity that already had more**, by getting to wherever its credentials live.",
            "**T1068**, Exploitation for Privilege Escalation (TA0004), exploits a software bug to run code with higher privilege. It is often how that second kind of reach happens. **T1611**, Escape to Host, names the step when code breaks out of a container or VM onto its host.",
            "A bug below the cloud API calls no cloud API, so CloudTrail has no line for it. The trail just shows ordinary-looking calls by a valid identity, with nothing above them that explains the jump.",
            "So the question becomes: who is holding these credentials now, and how did they get there? Host telemetry has to answer that.",
          ],
          example: {
            label: "A different cloud, a different credential",
            lines: [
              "`batchjob` is a plain user on an Azure Linux VM. A token for a Key Vault identity sits in a root-only file.",
              "A kernel bug makes `batchjob` root, and it reads the token.",
              "Activity Log: the identity lists secrets for the first time. No role assignment write, no line about the bug.",
              "The VM's EDR is the only record of how it happened.",
            ],
          },
          fold: true,
        },
        nameColumn: "Identity",
        columns: ["New call", "IAM change this month", "Result", "Key lives on", "Host sensor, just before"],
        suspects: [
          { id: "imaging", name: "imaging-batch-role", cells: ["ssm:GetParameter", "PutRolePolicy, by tf-exec-role", "Success", "img-batch-02", "Quiet"] },
          { id: "archive", name: "archive-sync-role", cells: ["kms:ListKeys", "None", "AccessDenied", "arc-sync-01", "Quiet"] },
          { id: "tle", name: "tle-update-role", cells: ["sns:ListTopics", "None", "Success", "tle-worker-03", "Release v4.2 deployed, CHG-5120"] },
          { id: "metrics", name: "gs-metrics-role", cells: ["cloudwatch:GetDashboard", "None", "Success", "gs-metrics-02", "On-call sudo, INC-8821"] },
          { id: "labeler", name: "labeler-role", cells: ["sagemaker:ListModels", "None", "Success", "lab-gpu-01", "No sensor installed"] },
          { id: "report", name: "gs-report-key", cells: ["secretsmanager:ListSecrets", "None", "Success", "gs-portal-01", "svc-report spawned a root shell, no sudo event"] },
        ],
        clues: [
          "A cloud identity can only succeed at what its policies allow, and this one's policies did not change.",
          "No release, ticket or on-call shift explains the calls.",
          "The jump happened on the host, below anything CloudTrail records, and a sensor saw it.",
        ],
        culprit: "report",
        why: "gs-report-key's policy never moved and its calls succeeded, so the identity gained nothing: someone else reached it. Its key sits in a root-only file on gs-portal-01, and the plain service account svc-report got to root with DirtyPipe (CVE-2022-0847), a Linux kernel flaw that lets a low-privileged process overwrite files it should only be able to read. That is T1068. CloudTrail shows the key listing secrets and nothing about how anyone came to hold it. Its AssumeRole into gs-platform-role is in the log, and that is the link to Sunday. labeler-role is the near miss: with no sensor on the host there is nothing to tie it to a host event, which is a gap to close, not a finding.",
      },
    ],
    // ── Reading 6: the order of operations ──
    "cad-r6": [
      {
        kind: "hunt",
        title: "Find the Region Nobody Watches",
        prompt: "Sunday's role asked which Regions it could use. GuardDuty is regional, but the organization trail records them all, so the calls are in the log and no finding will ever point to them. Build the hunt one line at a time. Every result is what that line really returns.",
        language: "KQL",
        console: "SIEM · Logs",
        start: "AWSCloudTrail",
        goal: "the calls, in order, from an unexplained identity working where no detector runs",
        primer: {
          title: "Reading a KQL line, and a coverage gap",
          points: [
            "`| where` keeps matching rows. `==` is exact, and `!in~` means not in this list, ignoring case.",
            "`| join kind=inner Other on $left.A == $right.B` adds columns from another table wherever A equals B. Name both sides when the columns have different names.",
            "`| project` keeps only the columns you name.",
            "A **detector covers one Region**. A multi-Region trail records every Region, so an event can sit in the log with no finding ever raised on it. To see that gap you compare the log with an inventory of coverage.",
          ],
          example: {
            label: "The same pattern on Azure",
            lines: [
              "`AzureActivity`",
              "`| where ActivityStatusValue == \"Success\"`",
              "`| join kind=inner SubscriptionPlans_CL on $left.SubscriptionId == $right.Sub_s`",
              "`| where DefenderPlan_s == \"Off\"`",
              "Result: successful activity in subscriptions with no Defender plan.",
            ],
          },
          fold: true,
        },
        tables: [
          {
            name: "AWSCloudTrail",
            note: "API calls from the organization trail copy.",
            columns: ["TimeGenerated", "EventName", "AWSRegion", "SessionIssuerUserName", "SourceIpAddress", "ReadOnly"],
            rows: [
              ["10-25 21:40", "CreateTags", "eu-west-1", "tf-exec-role", "203.0.113.44", "false"],
              ["10-25 21:41", "DescribeInstances", "eu-west-1", "tf-exec-role", "203.0.113.44", "true"],
              ["10-25 22:30", "ModifyInstanceAttribute", "eu-west-1", "gs-platform-role", "198.51.100.73", "false"],
              ["10-25 22:58", "DescribeRegions", "eu-west-1", "gs-platform-role", "198.51.100.73", "true"],
              ["10-25 23:06", "DescribeImages", "sa-east-1", "gs-platform-role", "198.51.100.73", "true"],
              ["10-25 23:18", "ImportKeyPair", "sa-east-1", "gs-platform-role", "198.51.100.73", "false"],
              ["10-25 23:19", "RunInstances", "sa-east-1", "gs-platform-role", "198.51.100.73", "false"],
              ["10-25 23:21", "CreateTags", "sa-east-1", "gs-platform-role", "198.51.100.73", "false"],
              ["10-26 01:10", "CopySnapshot", "eu-north-1", "dr-replica-role", "203.0.113.44", "false"],
              ["10-26 01:12", "RunInstances", "eu-north-1", "dr-drill-role", "203.0.113.44", "false"],
            ],
          },
          {
            name: "RegionCoverage_CL",
            note: "Inventory of detectors. Last run Sunday 06:00, before the silence.",
            columns: ["Region_s", "GuardDutyDetector_s", "Owner_s"],
            rows: [
              ["eu-west-1", "Enabled", "Ground ops"],
              ["eu-central-1", "Enabled", "Imaging"],
              ["us-east-1", "Enabled", "Platform"],
              ["eu-north-1", "None", "DR site"],
              ["sa-east-1", "None", "Nobody"],
            ],
          },
        ],
        rungs: [
          {
            id: "write",
            ask: "Line 2: a read changes nothing. Keep only the calls that change something.",
            choices: [
              { id: "a", text: "| where ReadOnly == true", why: "That keeps the reads and drops every change.", apply: { op: "where", col: "ReadOnly", test: "eq", value: "true" } },
              { id: "b", text: '| where EventName == "RunInstances"', why: "Too narrow: a key pair and a tag are changes too. One call name cannot describe everything a session did.", apply: { op: "where", col: "EventName", test: "eq", value: "RunInstances" } },
              { id: "c", text: "| where ReadOnly == false", right: true, why: "CloudTrail flags every event as read-only or not. Seven rows are left.", apply: { op: "where", col: "ReadOnly", test: "eq", value: "false" } },
            ],
          },
          {
            id: "cover",
            ask: "Line 3: CloudTrail cannot say which Regions have a detector. Bring in the table that can.",
            choices: [
              { id: "a", text: "| join kind=inner RegionCoverage_CL on AWSRegion", why: "The right-hand table calls that column Region_s, so the console cannot resolve it. When the names differ, name both sides.", apply: { op: "join", table: "RegionCoverage_CL", left: "AWSRegion", right: "AWSRegion" } },
              { id: "b", text: "| join kind=inner RegionCoverage_CL on $left.AWSRegion == $right.Region_s", right: true, why: "Every call now carries the coverage of the Region it ran in.", apply: { op: "join", table: "RegionCoverage_CL", left: "AWSRegion", right: "Region_s" } },
              { id: "c", text: "| join kind=inner RegionCoverage_CL on $left.SessionIssuerUserName == $right.Owner_s", why: "No rows: a role name and a team name never match. Join on what the two tables really share.", apply: { op: "join", table: "RegionCoverage_CL", left: "SessionIssuerUserName", right: "Owner_s" } },
            ],
          },
          {
            id: "gap",
            ask: "Line 4: keep only what ran where no detector was running.",
            choices: [
              { id: "a", text: '| where AWSRegion == "sa-east-1"', why: "You typed the Region you already suspected, and eu-north-1 fell out without being looked at. Filter on coverage and let the data name the Regions.", apply: { op: "where", col: "AWSRegion", test: "eq", value: "sa-east-1" } },
              { id: "b", text: '| where GuardDutyDetector_s == "None"', right: true, why: "Two Regions, five rows. None of them could ever have raised a finding.", apply: { op: "where", col: "GuardDutyDetector_s", test: "eq", value: "None" } },
              { id: "c", text: '| where GuardDutyDetector_s == "Enabled"', why: "That is everything a detector could have seen. You want the other half.", apply: { op: "where", col: "GuardDutyDetector_s", test: "eq", value: "Enabled" } },
            ],
          },
          {
            id: "known",
            ask: "Line 5: dr-drill-role and dr-replica-role are the quarterly DR drill, change ticket CHG-5102. Remove what is documented and keep what you can't explain.",
            choices: [
              { id: "a", text: '| where SessionIssuerUserName in~ ("dr-drill-role", "dr-replica-role")', why: "That keeps the drill and throws away the rest. in~ keeps a list, !in~ removes it.", apply: { op: "where", col: "SessionIssuerUserName", test: "in", value: ["dr-drill-role", "dr-replica-role"] } },
              { id: "b", text: '| where EventName contains "Run"', why: "That keeps the drill's launch and drops the key pair import. Exclude by who is documented, not by the name of the call.", apply: { op: "where", col: "EventName", test: "has", value: "Run" } },
              { id: "c", text: '| where SessionIssuerUserName !in~ ("dr-drill-role", "dr-replica-role")', right: true, why: "A ticket explains those two. What is left has no explanation, and that is the point of the hunt.", apply: { op: "where", col: "SessionIssuerUserName", test: "notin", value: ["dr-drill-role", "dr-replica-role"] } },
            ],
          },
          {
            id: "show",
            ask: "Line 6: show only what the ticket needs.",
            choices: [
              { id: "a", text: "| summarize count() by AWSRegion", why: "A count says how much. The ticket needs what, when and who.", apply: { op: "summarize", by: ["AWSRegion"] } },
              { id: "b", text: "| project EventName, Owner_s", why: "That loses the identity and the time, which are what you pivot on next.", apply: { op: "project", cols: ["EventName", "Owner_s"] } },
              { id: "c", text: "| project TimeGenerated, EventName, AWSRegion, SessionIssuerUserName, SourceIpAddress", right: true, why: "Three rows: a key pair, a launch and a tag, from one role, in a Region with no owner.", apply: { op: "project", cols: ["TimeGenerated", "EventName", "AWSRegion", "SessionIssuerUserName", "SourceIpAddress"] } },
            ],
          },
        ],
        expect: 3,
        lesson: "A silent Region is not a clean Region. Every defence in that Region's path was untouched: this move broke nothing, and that makes it Stealth (TA0005), where the deleted detector was Defense Impairment (TA0112). Compare the log with a coverage inventory, because no finding will do it for you. Filter on coverage, never on the Region you already suspect.",
      },
      {
        kind: "worksheet",
        title: "One Alert, Two Directions",
        prompt: "A single alert is a position on a map. Nils keeps these cards from a red team exercise in a small Azure partner tenant, in no particular order. Each one says what a stage needs and what it hands over, so you can work out where to hunt next.",
        caption: "Red team exercise · Azure partner tenant · dependency cards",
        primer: {
          title: "Each stage pays for the next",
          points: [
            "An intrusion tends to run in order because each stage needs what the one before handed over.",
            "That turns one alert into two hunts: backward for what made it possible, forward for what it allowed.",
            "The order is typical, not a law. Steps get skipped and repeated, so hunt both ways anyway.",
          ],
          example: {
            label: "The same reasoning on a Windows domain",
            lines: [
              "Alert: a new Group Policy Object linked to every workstation.",
              "It needs domain-level rights, so hunt backward: who gained them, and how?",
              "It allows code on every machine, so hunt forward: what did the policy push?",
            ],
          },
          fold: true,
        },
        columns: ["Card", "Seen in the logs as", "Needs first", "Hands the attacker"],
        rows: [
          ["A", "Microsoft.Compute/snapshots/write, then beginGetAccess/action", "A valuable disk and somewhere to carry it", "A downloadable copy of the disk"],
          ["B", "Microsoft.Network/networkSecurityGroups/securityRules/write", "An identity allowed to edit the group", "A network path from outside"],
          ["C", "Entra audit log: Remove member from role, for every Global Administrator", "Nothing left to gain from staying quiet", "The defenders' own access, gone"],
          ["D", "A managed identity's first calls ever, with no role assignment write", "Code running where that identity's token can be read", "A stronger identity than the attacker began with"],
          ["E", "Microsoft.Compute/virtualMachines/write", "A network path to reach it", "A machine that answers only to the attacker"],
        ],
        questions: [
          { id: "after", q: "The alert fired on card B. Which card do you hunt straight after it, on the same caller?", hint: "What is a new path for?", answer: ["e", "card e"], why: "Card E needs what card B hands over: a path. Search the same caller for a machine that uses the rule just opened." },
          { id: "before", q: "Same alert. Which card do you hunt straight before it?", hint: "What did card B need first?", answer: ["d", "card d"], why: "Card B needs an identity allowed to edit the group, and card D is how a weaker foothold came to hold one. Expect little in the audit log for that step." },
          { id: "first", q: "Card C is what the whole company notices first. Is it the first thing the attacker did? (yes/no)", hint: "What does card C need?", answer: ["no"], why: "The loudest event is usually the last one. Noticing starts at the end of the chain, so the investigation has to walk it backward." },
        ],
      },
    ],
    // ── Reading 7: detection craft ──
    "cad-r7": [
      {
        kind: "queue",
        title: "Four Checks Before You Close",
        prompt: "Monday's cloud queue, on top of Sunday's incident. Every alert here is a real API call, so the event name decides nothing. Run the checks on each and choose a verdict.",
        console: "SIEM · Cloud queue",
        primer: {
          title: "Four checks, three verdicts",
          points: [
            "Check the **identity** (a documented role with a known pattern?), the **documentation** (a ticket, a pull request?), the **consistency** (has it done this, this often, for a while?) and the **scope** (inside your own ranges, accounts and Regions?).",
            "All four pointing to legitimate closes the case. Any one missing is the gap to chase.",
            "A **true positive** is a real attack. A **benign true positive** is a real, authorised event that the rule rightly saw. A **false positive** is a rule firing on something it was never meant to match.",
            "A **service-linked role** is created by AWS for one service. Its name starts `AWSServiceRoleFor`, and `userIdentity.invokedBy` names that service.",
            "Managed detection does not cover everything evenly. A signal with nothing else around it may need context only you have.",
          ],
          example: {
            label: "The checks on a different call: PutKeyPolicy",
            lines: [
              "Identity: `kms-admin-role`, the documented owner of key policies.",
              "Documentation: ticket SEC-3310 is linked.",
              "Consistency: the same change every quarter for two years.",
              "Scope: the added principal is one of the company's own audit accounts.",
            ],
          },
          fold: true,
        },
        actions: [
          { id: "btp", label: "Close: benign true positive", tone: "close" },
          { id: "fp", label: "Close: false positive", tone: "close" },
          { id: "esc", label: "Escalate: true positive", tone: "escalate" },
        ],
        alerts: [
          {
            id: "tf",
            time: "08:12",
            severity: "Medium",
            rule: "Security group ingress added",
            entity: "tf-exec-role",
            fields: [
              { k: "eventName", v: "AuthorizeSecurityGroupIngress" },
              { k: "userIdentity.arn", v: "assumed-role/tf-exec-role/pipeline-88402" },
              { k: "fromPort", v: "443" },
              { k: "cidrIp", v: "198.51.100.128/26" },
            ],
            context: "Pull request 1184, merged six minutes earlier, adds the ground-station partner's published range. tf-exec-role makes this kind of change every fortnight and has done for 14 months.",
            answer: "btp",
            why: "All four checks pass, and the rule did see a real change, so calling it a misfire would be wrong. If this gets noisy, the fix is a narrow, owned exclusion, not a weaker rule.",
          },
          {
            id: "backup",
            time: "08:31",
            severity: "Low",
            rule: "Snapshot created outside the backup window",
            entity: "AWSServiceRoleForBackup",
            fields: [
              { k: "eventName", v: "CreateSnapshot" },
              { k: "userIdentity.invokedBy", v: "backup.amazonaws.com" },
              { k: "sourceIPAddress", v: "backup.amazonaws.com" },
              { k: "volumeId", v: "vol-05ac1e77d20b4c691" },
            ],
            context: "AWS Backup plan gs-weekly ran two hours late after a quota retry. It covers the same volumes as every week, and no grant follows.",
            answer: "btp",
            why: "A service-linked role invoked by the service itself, a documented plan and the same scope as every week. The rule saw exactly what it says, so the time window is what needs adjusting.",
          },
          {
            id: "read",
            time: "08:47",
            severity: "High",
            rule: "Security group opened to the internet",
            entity: "gs-audit-role",
            fields: [
              { k: "eventName", v: "DescribeSecurityGroups" },
              { k: "readOnly", v: "true" },
              { k: "rule match", v: "text \"0.0.0.0/0\" in requestParameters.filterSet" },
            ],
            context: "The rule searches for that text anywhere in the event. The compliance scanner searched for groups with that range, and nothing was changed.",
            answer: "fp",
            why: "The rule claims a group was opened, and no group was opened: a read call only named the range. That is a true misfire, and the rule should filter on the eventName.",
          },
          {
            id: "share",
            time: "09:02",
            severity: "Medium",
            rule: "Snapshot shared to another account",
            entity: "dr-replica-role",
            fields: [
              { k: "eventName", v: "ModifySnapshotAttribute" },
              { k: "attributeType", v: "CREATE_VOLUME_PERMISSION" },
              { k: "add.items.0.userId", v: "590274416603" },
            ],
            context: "dr-replica-role shares every night, always to aurelia-dr. This account number has no entry in the inventory, there is no ticket, and GuardDuty has no finding about it.",
            answer: "esc",
            why: "The identity looks fine and the habit is real, but the scope fails. The absence of a finding clears nothing: a lone share gives an engine little to go on, and the context is yours to supply.",
          },
          {
            id: "chain",
            time: "09:20",
            severity: "Medium",
            rule: "Security group ingress added",
            entity: "gs-portal-role",
            fields: [
              { k: "eventName", v: "AuthorizeSecurityGroupIngress" },
              { k: "userIdentity.arn", v: "assumed-role/gs-portal-role/i-0d2fa7714c8e5b903" },
              { k: "fromPort", v: "443" },
              { k: "cidrIp", v: "10.40.0.0/16" },
            ],
            context: "Nine minutes earlier the same session called DeleteFlowLogs on the portal's VPC. No ticket for either call.",
            answer: "esc",
            why: "Taken alone, this rule is internal and tame. What matters is the session: one identity, minutes apart, removing a log and then changing a firewall. A change in isolation is a data point. Two in a row are a pattern.",
          },
        ],
      },
      {
        kind: "duel",
        title: "The Copy That Still Shows It",
        prompt: "Every move here tries to erase what happened or stay out of sight. Answer each one with the copy that still shows it. Anything inside aurelia-ground-prod is within the attacker's reach, so play a card it can't touch. Played cards are gone.",
        attacker: "gs-platform-role",
        primer: {
          title: "A copy only counts if it is out of reach",
          points: [
            "Anything stored in the compromised account can be changed by an identity with enough permissions there. A copy counts when a different account, with a different owner, holds it.",
            "Move evidence out as it is created: **after** the attacker arrives is too late.",
            "**Defense Impairment** (TA0112) is switching a control off. **Stealth** (TA0005) is working around controls that are still running. Ask which one a move is, because that tells you what to look for.",
            "**VPC Flow Logs** record who talked to whom, per network interface, without the content. A **Cost and Usage Report** lists what ran, where and for how long, for billing, in the account that pays.",
          ],
          example: {
            label: "The same idea on a Windows server",
            lines: [
              "`wevtutil cl Security` empties the Security log on `FILE-02`.",
              "Windows Event Forwarding had already sent each event to a collector.",
              "The collector's copy still holds the logons, and Event ID 1102 records the clearing itself.",
            ],
          },
          fold: true,
        },
        moves: [
          { id: "m1", move: "StopLogging on gs-prod-trail", detail: "The account's own trail is dark from 22:54. You still need to know what the role did next.", counter: "org", hint: "Which trail does this account not own?", why: "An organization trail is managed above the account. A member can read it, not stop it, and it records the StopLogging call itself. That call is T1685.002, formerly T1562.008." },
          { id: "m2", move: "DeleteDetector in eu-west-1", detail: "The Findings page is empty. Deleting a detector takes the findings it held with it.", counter: "siem", hint: "Where did findings go when they were raised?", why: "Findings forwarded as they arrived are out of the detector's hands. The engine itself was the target here, so an empty page says nothing about what happened." },
          { id: "m3", move: "PutBucketLifecycle on the account's log bucket", detail: "A new rule expires every log object after one day. Nothing looks broken, and the files just age out.", counter: "replica", hint: "What is locked against deletion, and where?", why: "Deletions made by a lifecycle rule are not replicated, and Object Lock in another account protects the replica. The PutBucketLifecycle call is a management event, so it is a lead in its own right." },
          { id: "m4", move: "TerminateInstances on the foothold in eu-west-1", detail: "The root volume is gone, and the local logs with it. Who did that machine talk to?", counter: "flow", hint: "Which record is kept per network interface?", why: "Flow records left the machine as the traffic happened, so they show its peers, ports and volumes after the instance is gone. They do not show content." },
          { id: "m5", move: "Keeps working in sa-east-1", detail: "No detector and nobody's dashboard, and this move broke nothing. What ran there, and for how long?", counter: "cost", hint: "Who always finds out what you ran?", why: "This is Stealth: nothing was switched off. Billing data lives in the paying account and lists usage by Region and type, and a member account cannot edit it." },
        ],
        cards: [
          { id: "cw", name: "CloudWatch log group in this account", effect: "Application logs, held in the compromised account." },
          { id: "org", name: "Organization trail, log archive", effect: "Managed above the accounts. Members can read it." },
          { id: "flow", name: "VPC Flow Logs, central bucket", effect: "Delivered to the log archive account as they are written." },
          { id: "config", name: "Config recorder in this account", effect: "Resource history, held in the compromised account." },
          { id: "cost", name: "Cost and Usage Report", effect: "Usage by Region and type, in the payer account." },
          { id: "siem", name: "Findings copy in the SIEM", effect: "Forwarded on arrival, held in the security account." },
          { id: "replica", name: "Locked replica of the log bucket", effect: "Replicated to log archive under S3 Object Lock." },
        ],
        lesson: "Two questions, in order. Is this move breaking a control or working around one? And which copy did the attacker's identity never have the rights to touch? The account's own stores look like evidence, but they are within reach of whoever holds the account. Build the off-account copies before you need them.",
      },
    ],
    // ── Boss warm-up: the step with no line ──
    "cad-q4": [
      {
        kind: "sort",
        title: "Does It Reach the Cloud API?",
        prompt: "Last stop before the final call. Not everything an attacker does reaches a cloud API. Sort each action on Aurelia's fleet: does it write a CloudTrail event, or does it happen below the API?",
        primer: {
          title: "CloudTrail records API calls, and nothing else",
          points: [
            "The **control plane** is the cloud provider's API: create, change, delete. Every management call to it is an event in CloudTrail.",
            "Inside a running machine, the operating system is yours. The provider's audit log sees none of what happens there.",
            "Asking the **instance metadata service**, at 169.254.169.254, for a role's credentials is a local request and not an API call.",
            "So a timeline can have a step with no cloud log at all. Only telemetry from inside the machine can fill it.",
          ],
          example: {
            label: "One morning on a Windows VM in Azure",
            lines: [
              "`net user` in a shell on the VM: nothing in the Activity Log.",
              "`Microsoft.Compute/virtualMachines/runCommand/action`: logged, but not what the script did.",
              "What ran inside is only in the guest's own Event Log or the EDR.",
            ],
          },
          fold: true,
        },
        buckets: [
          { id: "api", label: "Writes a CloudTrail event" },
          { id: "below", label: "Happens below the API" },
        ],
        items: [
          { id: "i1", text: "AttachRolePolicy on a role", bucket: "api", why: "An IAM change is an API call, so it has a line with a caller and a time." },
          { id: "i2", text: "A kernel exploit makes a plain user root on an EC2 instance", bucket: "below", why: "It happens inside the operating system. No cloud API is involved, so only host telemetry can show it." },
          { id: "i3", text: "RevokeSecurityGroupIngress on a group", bucket: "api", why: "Removing a rule is as much a control-plane call as adding one." },
          { id: "i4", text: "A process reads role credentials from 169.254.169.254", bucket: "below", why: "That is a local request to the metadata service. The first CloudTrail line comes when those credentials are used." },
          { id: "i5", text: "A cron job added on an instance", bucket: "below", why: "A file edit inside the guest. Only host monitoring sees it." },
          { id: "i6", text: "PutBucketPolicy on a storage bucket", bucket: "api", why: "A management event on S3, recorded by default." },
          { id: "i7", text: "Shell history wiped on an instance", bucket: "below", why: "Nothing in the cloud audit log moves. If the history was shipped off the box, a copy survives elsewhere." },
          { id: "i8", text: "StopInstances from the console", bucket: "api", why: "The console calls the same API, and the event carries the signed-in identity." },
          { id: "i9", text: "A reverse shell from an instance out to the internet", bucket: "below", why: "No API call. VPC Flow Logs may show the connection, and CloudTrail never will." },
          { id: "i10", text: "CreateSnapshot on a volume", bucket: "api", why: "A control-plane call on the EC2 service." },
        ],
      },
    ],
  },
};
