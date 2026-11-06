import type { RoomExperience } from "./types";

// "Operation Project ID" for the "gcp-security" room.
// Script: docs/campaign/102-gcp-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Fernhollow Games Studio (fictional), not the graded tasks' NexaCorp records.
// Signature: Inherited, Not Granted. GCP IAM is a tree: a pathway walks down organization,
// folders, project and resource to find where a role really came from, and a trace follows a
// service account key through Cloud Audit Logs on real protoPayload fields (methodName,
// authenticationInfo.principalEmail, serviceAccountKeyName, serviceAccountDelegationInfo).
// Room 83 covers the common cloud idea; this room is GCP's own shape.
// Game mix: outbreak + pathway + rush.
//
// Task order changed. Original: r1, r2, r3, r4, q1, q2, q3, la1, la2, ac1, m1, r5, la-sakey, f1,
// r6, r7. New: r1, r2, r3, q1, r4, q2, q3, m1, la1, la2, ac1, r5, la-sakey, f1, r6, r7.
// q1 tests r3 and now follows it. m1 recaps the four readings before the logs. The tail keeps its
// order because the text depends on it: ac1 says the incident is contained (after la1, la2), r5
// cites ac1, f1 reads the event "above" (la-sakey, right before it), r6 opens on that flag, and r7
// cites r6. f1 has no "Log Analysis N" wording, and the flag stays right after its log.
//
// Lab data differs from the graded tasks: the story is a leaked key that impersonates a second
// account and starts GPU VMs, never a self-grant of Owner or a public customer export (la1, la2).
// The role in the pathway is roles/storage.objectAdmin on a folder, reached by build-runner. The
// policy anatomy is a Cloud Run service. The audit anatomy is a Pub/Sub topic grant by a developer.
// The log-stream sort uses Secret Manager and Firestore reads, never Cloud Storage reads (q1).
// The perimeter refusal is a developer laptop listing a build, never a dataset copy by an attacker
// (r3 checkpoint). The metadata lab is a token fetch through an avatar field, and it stops at the
// token, never at its use from an outside address (q2). The review sheet is folderIamAdmin on a
// folder (q3, la1). The public-read sheet is a game patch and a press kit, with players and
// journalists, never customer data (la2). No lab maps project to account as a question: the
// mapping appears once, in passing, in a route note (r1 checkpoint). The first match lab names only
// services outside m1. The triage queue fires on a watch list, and its scheduled case is a
// state-changing disk snapshot, never a read-only list by a pipeline (ac1). The key sheet is matchmaker-svc and payments-bot, never
// web-frontend or svc-data (la-sakey, f1). The trace's key on release-bot is made through
// impersonation, on the account it ran as, with no caller and owner to tell apart. The status codes appear as labelled rows, never asked
// (r5 checkpoint). The containment blitz asks only what can be undone, never what comes first
// (r7 checkpoint).

export const GCP_SECURITY: RoomExperience = {
  roomId: "gcp-security",
  codename: "Operation Project ID",
  theme: "projectid",
  handler: { name: "Rashid Lundqvist", role: "GCP Security Engineer, Fernhollow Games Studio" },
  briefing: [
    "Fernhollow Games Studio. 140 people, one Google Cloud organization, and four days until Thornmere goes live.",
    "This morning a modder found a service account key inside the public Thornmere Mod Kit, and the account behind it can reach things nobody remembers granting.",
    "Rashid Lundqvist has one rule for this cloud: a role you can't find on a project may be inherited, not granted.",
    "Walk the org tree, read the audit trail, follow the key, then take the desk for a partner who needs a second analyst tonight.",
  ],
  mission: "Find where a role really came from, read an IAM policy and an audit entry field by field, sort the four log streams, follow a stolen key through its audit trail, cut a spreading identity off, work out what a public read leaves behind, then take the graded case on NexaCorp's desk and clear up afterwards.",
  estimate: "~50 min",
  look: { primary: "#9ae66e", secondary: "#ffcf70", warn: "#ff5d73" },
  scene: "facilityprojectid",
  layout: "facility",
  stations: [
    {
      id: "orgtree",
      label: "The Org Tree",
      topic: "The resource hierarchy · core services · members, roles and bindings · service accounts",
      tagline: "Whose role is this, really?",
      building: "control",
      taskIds: ["gcp-r1", "gcp-r2"],
    },
    {
      id: "audit",
      label: "The Audit Trail",
      topic: "The four Cloud Audit Log types · reading an entry · Security Command Center · VPC Flow Logs",
      tagline: "What gets written down, and what doesn't",
      building: "archive",
      taskIds: ["gcp-r3", "gcp-q1"],
    },
    {
      id: "key",
      label: "The Mod Kit Key",
      topic: "The six GCP attack patterns · key theft · the metadata server · impersonation · crypto-mining",
      tagline: "One file, one long night",
      building: "lab",
      taskIds: ["gcp-r4", "gcp-q2", "gcp-q3", "gcp-m1"],
    },
    {
      id: "partner",
      label: "The Partner Desk",
      topic: "Reading a policy change · what public reads leave behind · containing and scoping · weighing a verdict",
      tagline: "Same cloud, another company's tree",
      building: "office",
      taskIds: ["gcp-la1", "gcp-la2", "gcp-ac1"],
    },
    {
      id: "sixminutes",
      label: "The Six Minutes",
      topic: "The triage workflow · who asked for a key · lateral chains · containing a compromised identity",
      tagline: "Go back before the record you started from",
      building: "ticket",
      taskIds: ["gcp-r5", "gcp-la-sakey", "gcp-f1", "gcp-r6", "gcp-r7"],
      boss: true,
    },
  ],
  personas: {
    "gcp-q1": { name: "Rashid Lundqvist", role: "GCP Security Engineer", line: "Legal wants to know what we would find. What do you tell them?" },
    "gcp-q2": { name: "Rashid Lundqvist", role: "GCP Security Engineer", line: "Talk me through what this one means." },
    "gcp-q3": { name: "Rashid Lundqvist", role: "GCP Security Engineer", line: "Say it's your detection. Which line goes on it?" },
    "gcp-la1": { name: "Rashid Lundqvist", role: "GCP Security Engineer", line: "NexaCorp publishes our games and their desk is one analyst short tonight. Sit in. Read the record, not the finding title." },
    "gcp-m1": { name: "Rashid Lundqvist", role: "GCP Security Engineer", line: "Before you leave the building: put every name where it belongs." },
    "gcp-la2": { name: "Rashid Lundqvist", role: "GCP Security Engineer", line: "Same night, same desk. Keep going." },
    "gcp-ac1": { name: "Rashid Lundqvist", role: "GCP Security Engineer", line: "Next morning, same desk. Another alert. Your call." },
    "gcp-la-sakey": { name: "Rashid Lundqvist", role: "GCP Security Engineer", line: "NexaCorp found one more entry from that night. Read it." },
    "gcp-f1": { name: "Rashid Lundqvist", role: "GCP Security Engineer", line: "One name, exactly as logged." },
  },
  briefings: {
    // ── Reading 1: the tree, and the service names ──
    "gcp-r1": [
      {
        kind: "pathway",
        title: "Where Did the Role Come From?",
        prompt: "Policy Troubleshooter says build-runner can write to the bucket fh-thornmere-saves in project fernhollow-thornmere-prod, yet the bucket's own policy doesn't name it. This map is the slice of Fernhollow's tree that matters. Start at the organization and walk down to the bucket, reading the allow policy at each level.",
        goal: "Reach the bucket, reading each level on the way",
        nodes: [
          { id: "org", label: "fernhollow.example", sub: "Organization", x: 50, y: 10 },
          { id: "fprod", label: "Production", sub: "Folder", x: 28, y: 28 },
          { id: "fproto", label: "Prototypes", sub: "Folder", x: 74, y: 28 },
          { id: "flive", label: "Live Games", sub: "Folder", x: 14, y: 48 },
          { id: "fplat", label: "Platform", sub: "Folder", x: 44, y: 48 },
          { id: "oldproj", label: "Thornmere Prod", sub: "thornmere-prod-2291", x: 74, y: 50 },
          { id: "tprod", label: "Thornmere Prod", sub: "fernhollow-thornmere-prod", x: 12, y: 68 },
          { id: "tqa", label: "Thornmere QA", sub: "fernhollow-thornmere-qa", x: 34, y: 68 },
          { id: "ci", label: "Shared CI", sub: "fernhollow-shared-ci", x: 58, y: 68 },
          { id: "saves", label: "fh-thornmere-saves", sub: "Bucket", x: 12, y: 88 },
        ],
        edges: [["org", "fprod"], ["org", "fproto"], ["fprod", "flive"], ["fprod", "fplat"], ["fproto", "oldproj"], ["flive", "tprod"], ["flive", "tqa"], ["fplat", "ci"], ["tprod", "saves"]],
        route: ["org", "fprod", "flive", "tprod", "saves"],
        notes: {
          org: "Organization fernhollow.example, the root. Its allow policy names two org admins and no build-runner. Anything bound here would reach every folder and project below.",
          fprod: "Folder Production. No binding for build-runner. Folders group projects, they can nest, and a binding on one flows to everything inside it.",
          flive: "Folder Live Games. Here it is: roles/storage.objectAdmin bound to serviceAccount:build-runner, added for a launch script in 2024. Keep walking to see how it arrives.",
          tprod: "Project fernhollow-thornmere-prod. No binding for build-runner here either. A project holds resources, billing and permissions, and it's the boundary an analyst usually investigates within, about where an AWS account sits.",
          saves: "Bucket fh-thornmere-saves. Its own policy has no build-runner line, and the role still applies, because what counts is this policy plus every ancestor's.",
        },
        traps: {
          fproto: "Prototypes doesn't hold the project in the ticket. Two projects here are displayed as Thornmere Prod: go by the project ID, fernhollow-thornmere-prod, because display names can repeat.",
          fplat: "Platform holds build-runner's home project, Shared CI. Where a service account lives says nothing about where it holds roles: those sit on whatever it was granted access to.",
          tqa: "Thornmere QA sits in the same folder, so it inherits the same role. That belongs in the blast radius, but the bucket is in the project named in the ticket.",
        },
        lesson: "GCP IAM is a tree. Effective access on a resource is its own policy plus every ancestor's, and allow policies only add, so a role missing from a project's policy can still be in force. To remove it, go to the level that granted it. The blast radius is everything under that level: the Live Games binding reaches Thornmere QA too.",
        primer: {
          title: "Reading the GCP tree",
          points: [
            "Every resource sits in a **project**, projects can sit in **folders**, and folders roll up to one **organization**.",
            "An **allow policy** can sit at any of those levels. Each entry is a **binding**: a member and a role, on that resource.",
            "Policies are **inherited** downwards. What a member can do on a resource is that resource's policy plus every ancestor's.",
            "Allow policies only add. A lower level can't cancel a higher grant; only a separate deny policy can refuse it.",
            "A project's display name can repeat. Its **project ID** is unique across Google Cloud and permanent, and that's what logs carry.",
          ],
          example: {
            label: "Another company: why can dana publish to the topic ledger-events?",
            lines: [
              "organization `quarrybank.example`: no binding for dana",
              "folder `Finance`: `roles/pubsub.publisher` to `group:fin-ops@quarrybank.example`, and dana is in that group",
              "project `fin-batch`: no binding",
              "topic `ledger-events`: no binding",
              "Reading: granted at the folder, through a group. The project's policy never mentions dana.",
            ],
          },
        },
      },
      {
        kind: "match",
        title: "The Names on the Map",
        prompt: "These services turn up in Fernhollow's tickets all week. Match each one to the job it does.",
        pairs: [
          { id: "run", left: "Cloud Run", right: "Runs containers without a server to manage: the studio's landing page", why: "You'll read an allow policy from one of these next." },
          { id: "pubsub", left: "Pub/Sub", right: "Passes messages between services through topics and subscriptions", why: "It shows up in audit entries as pubsub.googleapis.com." },
          { id: "secret", left: "Secret Manager", right: "Stores API keys and passwords, with a version per value", why: "Reading a secret's value and changing who may read it land in different logs, as you'll see." },
          { id: "bq", left: "BigQuery", right: "The data warehouse: large tables, queried with SQL", why: "The one service whose data reads are logged by default." },
          { id: "vpc", left: "VPC", right: "The private network, with subnets and firewall rules", why: "GCP uses the same name as AWS. Its firewall rules do the job of Security Groups." },
          { id: "flow", left: "VPC Flow Logs", right: "Connection metadata: IPs, ports, bytes, allowed or denied, no payload", why: "Your network-layer view when the audit log alone doesn't tell the whole story." },
          { id: "log", left: "Cloud Logging", right: "The central store entries land in, routed onward by log sinks", why: "A sink sends entries to BigQuery, Cloud Storage or an external SIEM in near real time." },
        ],
        primer: {
          title: "Same jobs, new names",
          points: [
            "Almost everything you'll investigate sits on two services: **Compute Engine** runs the VMs, and **Cloud Storage** keeps objects in buckets.",
            "Many teams work AWS, Azure and GCP tickets in one shift. The jobs repeat, the names don't.",
            "An audit entry names the service in `serviceName`, for example `iam.googleapis.com` for IAM.",
          ],
          example: {
            label: "A service, read the way a log shows it",
            lines: [
              "`spanner.googleapis.com` is Cloud Spanner, a distributed database",
              "`resourceName` then says which instance or database inside it was touched",
            ],
          },
        },
      },
    ],
    // ── Reading 2: bindings and service accounts ──
    "gcp-r2": [
      {
        kind: "anatomy",
        title: "Anatomy of an Allow Policy",
        prompt: "Before the launch, Rashid pulled the policy on the landing page for Thornmere, a Cloud Run service. Read it field by field. This is the shape of every allow policy you'll meet in GCP.",
        source: "gcloud run services get-iam-policy thornmere-landing · project fernhollow-thornmere-prod",
        fields: [
          { key: "bindings[0].role", value: "roles/run.invoker", label: "Role", note: "A named set of permissions. This one lets a caller invoke the service, and nothing else." },
          { key: "bindings[0].members[0]", value: "allUsers", label: "Member", note: "Every person on the internet, authenticated or not." },
          { key: "bindings[1].role", value: "roles/run.developer", label: "Role", note: "A predefined role: narrower than a basic role, specific to one service, curated by Google." },
          { key: "bindings[1].members[0]", value: "group:web-team@fernhollow.example", label: "Member", note: "Everyone in the group, as it stands right now. Membership changes outside this policy." },
          { key: "bindings[1].members[1]", value: "serviceAccount:release-bot@fernhollow-thornmere-prod.iam.gserviceaccount.com", label: "Member", note: "A non-human identity. The address usually ends in .iam.gserviceaccount.com." },
          { key: "bindings[2].role", value: "roles/run.viewer", label: "Role" },
          { key: "bindings[2].members[0]", value: "user:m.adeyemi@fernhollow.example", label: "Member", note: "One human account." },
          { key: "etag", value: "BwYt4kQ9xPc=", note: "A version stamp for the policy. A write sends it back, so two edits can't silently overwrite each other." },
          { key: "version", value: "1", note: "Policy schema version. Version 3 appears when a binding carries a condition." },
        ],
        summary: "An allow policy is a list of bindings, and each one reads as member, role, resource. The resource isn't in the file because it's the thing the policy is attached to. This policy is only one level of the tree, so what a member can really do here also depends on the project, folders and organization above it.",
      },
      {
        kind: "worksheet",
        title: "Who Can Give Itself More?",
        prompt: "Launch-week access review. Rashid hands you the bindings that reach Thornmere QA and two questions. Work them out from the sheet.",
        caption: "IAM review · bindings that reach fernhollow-thornmere-qa",
        columns: ["Member", "Role", "Bound on", "Used for"],
        rows: [
          ["group:qa-leads@fernhollow.example", "roles/viewer", "project fernhollow-thornmere-qa", "Reading dashboards"],
          ["serviceAccount:test-rig", "roles/editor", "project fernhollow-thornmere-qa", "Nightly smoke tests that touch one bucket"],
          ["serviceAccount:crash-reporter", "roles/logging.logWriter", "project fernhollow-thornmere-qa", "Writing crash logs"],
          ["serviceAccount:sso-sync", "roles/resourcemanager.folderIamAdmin", "folder Live Games", "Adding contractors to projects each sprint"],
          ["serviceAccount:anim-export", "roles/pubsub.publisher", "topic render-done", "Announcing finished renders"],
        ],
        questions: [
          { id: "basic", q: "How many service accounts on this sheet hold a basic role?", hint: "Basic roles are the three short ones. Count members that start with serviceAccount:.", answer: ["1", "one"], why: "test-rig, as Editor on the whole project, for a job that touches one bucket. This is the most common GCP finding: a broad role granted because it was quick, never narrowed, and quietly multiplying whatever a stolen credential can do." },
          { id: "self", q: "Which member could write itself any role across Live Games, with nobody's help? Give the short name.", hint: "Look for the role that edits policies rather than using resources.", answer: ["sso-sync", "serviceAccount:sso-sync"], why: "folderIamAdmin edits the folder's allow policy, so sso-sync can call SetIamPolicy on Live Games and add any binding it likes, and inheritance carries that to every project inside. It holds no basic role at all, and it's the strongest line on the sheet." },
        ],
        primer: {
          title: "What a role reaches",
          points: [
            "Three tiers of role: **basic** (Viewer, Editor, Owner), **predefined** (narrow, per service) and **custom** (a set of permissions an organization picks).",
            "Basic roles stack. Viewer reads. Editor also creates, changes and deletes resources. Owner also manages IAM policy and billing.",
            "Watch for permissions that edit a policy, such as `resourcemanager.folders.setIamPolicy`. Whoever holds one can rewrite the policy itself, including their own line.",
          ],
          example: {
            label: "Another company: a job and its binding",
            lines: [
              "`ticket-bot` only ever publishes to Pub/Sub, in project `ops-tools`",
              "its binding is `roles/editor` on `ops-tools`",
              "the same binding also covers the VMs and databases in `ops-tools`, which it has never called",
              "Reading: what an account normally calls and what its binding covers are two different lists.",
            ],
          },
        },
      },
      {
        kind: "rush",
        title: "Attached Token or Key File?",
        prompt: "build-runner has been authenticating with a key file, and most of the studio's accounts use an attached token instead. Rashid wants you to tell them apart at speed. Call each line.",
        trueLabel: "Attached token",
        falseLabel: "Key file",
        seconds: 60,
        target: 10,
        cards: [
          { id: "c1", text: "Fetched from the metadata server inside a VM", answer: true, why: "A VM asks 169.254.169.254 for a token for its attached service account." },
          { id: "c2", text: "A JSON file with a private_key field", answer: false, why: "That's a service account key, a long-lived credential." },
          { id: "c3", text: "Expires about an hour after it's issued", answer: true, why: "Attached identities get short-lived access tokens." },
          { id: "c4", text: "Listed with an expiry of 9999-12-31", answer: false, why: "A user-managed key has no real expiry. The year 9999 shows that." },
          { id: "c5", text: "The request needs Metadata-Flavor: Google", answer: true, why: "The metadata server refuses requests without that header." },
          { id: "c6", text: "Works from any machine on the internet, for months", answer: false, why: "A key file carries its identity with it, until someone disables or deletes it." },
          { id: "c7", text: "The workload just asks again when it runs out", answer: true, why: "Nobody stores anything long-lived: the VM fetches a fresh token." },
          { id: "c8", text: "Creating it writes CreateServiceAccountKey", answer: false, why: "That Admin Activity event is your record of a key being born." },
          { id: "c9", text: "Turns up in a public code repository", answer: false, why: "Files get committed, baked into images and emailed. That's how keys leak." },
          { id: "c10", text: "Goes stale on its own if nobody does anything", answer: true, why: "A short-lived token dies by itself. A key doesn't." },
          { id: "c11", text: "Keeps working until someone disables or deletes it", answer: false, why: "There's no timer on a key, which is why a leak is so serious." },
          { id: "c12", text: "Named in audit entries by serviceAccountKeyName", answer: false, why: "That field ends in the key ID, on the services that log it." },
          { id: "c13", text: "Served from a link-local address on the VM", answer: true, why: "169.254.169.254 isn't routable, so the request comes from the VM itself." },
          { id: "c14", text: "Needs an owner to rotate it by hand", answer: false, why: "Keys get rotated only if somebody does it, which is why old ones linger." },
        ],
        lesson: "A service account authenticates two ways. Attached to a resource, the workload fetches a short-lived token from the metadata server. With a key, a JSON file holds a private key that works from anywhere and never expires by itself, so a leaked key carries about the same risk as a leaked AWS access key.",
        primer: {
          title: "Two ways to be a service account",
          points: [
            "A **service account** is a non-human identity for applications and VMs. It's a lasting identity with its own permissions, not something borrowed for a moment.",
            "**Attached:** the account is attached to a resource such as a VM, which asks the **metadata server** for a short-lived token.",
            "**Key:** a JSON file holding a private key, usable from anywhere, with no expiry unless someone removes it.",
          ],
          example: {
            label: "Another company: reading a key list",
            lines: [
              "`KEY_ID 91ab04...  CREATED_AT 2023-04-11  EXPIRES_AT 9999-12-31`",
              "`keyType: USER_MANAGED`: a person or a tool made this key",
              "Reading: three years old and no expiry, so it works until somebody acts.",
            ],
          },
        },
      },
    ],
    // ── Reading 3: Cloud Audit Logs ──
    "gcp-r3": [
      {
        kind: "anatomy",
        title: "Anatomy of an Audit Entry",
        prompt: "A developer on Thornmere QA gave a bot access to a crash-report topic last Thursday, with a ticket. Read the entry it left, field by field. Every key below is native to Cloud Audit Logs.",
        source: "Cloud Logging · cloudaudit.googleapis.com/activity · fernhollow-thornmere-qa",
        fields: [
          { key: "timestamp", value: "2026-10-22T14:06:21.418Z", label: "When" },
          { key: "logName", value: "projects/fernhollow-thornmere-qa/logs/cloudaudit.googleapis.com%2Factivity", label: "Stream", note: "The last part names the stream: activity, data_access, system_event or policy. SIEM exports often copy it to a log type field." },
          { key: "protoPayload.serviceName", value: "pubsub.googleapis.com", label: "Service" },
          { key: "protoPayload.methodName", value: "google.iam.v1.IAMPolicy.SetIamPolicy", label: "What", note: "The API call. Project-level entries show the shorter SetIamPolicy." },
          { key: "protoPayload.authenticationInfo.principalEmail", value: "j.okoye@fernhollow.example", label: "Who", note: "The identity the call ran as." },
          { key: "protoPayload.requestMetadata.callerIp", value: "198.51.100.31", label: "From where" },
          { key: "protoPayload.resourceName", value: "projects/fernhollow-thornmere-qa/topics/crash-reports", label: "On what", note: "The full resource name, with its project ID inside." },
          { key: "protoPayload.request.policy.bindings[0]", value: "roles/pubsub.subscriber to serviceAccount:triage-bot", label: "Asked for", note: "What the caller sent." },
          { key: "protoPayload.response.bindings[0]", value: "roles/pubsub.subscriber to serviceAccount:triage-bot", label: "Result", note: "What the API returned: the resulting policy." },
          { key: "protoPayload.status", value: "{}", label: "Outcome", note: "Empty here, shown as code 0 in many SIEM exports. Code 0 is gRPC OK: the call completed." },
          { key: "severity", value: "NOTICE", note: "The usual level for this stream. It says what kind of entry this is, not how dangerous the call was." },
        ],
        summary: "Who is principalEmail, what is methodName, from where is callerIp, on what is resourceName, and did it work is status. The request is what was asked for and the response is the result. A SIEM may flatten these names into something like gcp.audit.method_name, and the meanings stay the same.",
        primer: {
          title: "One entry, five questions",
          points: [
            "Cloud Audit Logs writes one entry per API call, whether it came from the console, gcloud or an application.",
            "The call sits in `protoPayload`. Every entry answers who, what, on what, from where, and whether it worked.",
            "`status.code` is a gRPC code. **0** is OK. **7** is PERMISSION_DENIED: IAM refused and nothing changed. **16** is UNAUTHENTICATED.",
          ],
          example: {
            label: "Another company: a refused call",
            lines: [
              "`methodName`: `google.pubsub.v1.Publisher.DeleteTopic`",
              "`principalEmail`: `intern@quarrybank.example`",
              "`status.code`: `7`, `status.message`: `PERMISSION_DENIED`",
              "Reading: the intern asked, IAM refused, the topic still exists.",
            ],
          },
        },
      },
      {
        kind: "sort",
        title: "Which Log Stream?",
        prompt: "Rashid is writing the SOC's cheat sheet for launch week. Put each event into the stream that records it. Mind the two streams that behave differently from the rest.",
        buckets: [
          { id: "admin", label: "Admin Activity" },
          { id: "data", label: "Data Access" },
          { id: "system", label: "System Event" },
          { id: "denied", label: "Policy Denied" },
        ],
        items: [
          { id: "i1", text: "google.iam.admin.v1.CreateServiceAccount: a new account for the matchmaker", bucket: "admin", why: "A configuration change. This stream is always on and can't be turned off." },
          { id: "i2", text: "v1.compute.instances.setMetadata: a startup script changed on a lobby VM", bucket: "admin", why: "Changing a resource's configuration is Admin Activity, and it's recorded whatever else is switched off." },
          { id: "i3", text: "SetIamPolicy on a Secret Manager secret: a bot gains read access", bucket: "admin", why: "A policy change on a secret is configuration, so it's logged even when reads of that secret aren't." },
          { id: "i4", text: "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion: a job reads the matchmaker's API secret", bucket: "data", why: "Reading the secret's value is data access. With Data Access off for Secret Manager, this read leaves no entry at all." },
          { id: "i5", text: "google.firestore.v1.Firestore.RunQuery: a tool reads player profiles", bucket: "data", why: "Reading stored data is Data Access, which is off by default for most services because of its volume." },
          { id: "i6", text: "A query against a BigQuery table of match results", bucket: "data", why: "Still Data Access, and BigQuery is the exception: its Data Access logs are on by default." },
          { id: "i7", text: "compute.instances.migrateOnHostMaintenance on a lobby VM", bucket: "system", why: "Google Cloud did this by itself, for host maintenance. Always on, and rarely security-relevant." },
          { id: "i8", text: "compute.instances.automaticRestart after a hardware fault", bucket: "system", why: "No person or API caller asked for it, so it's a system event." },
          { id: "i9", text: "A developer laptop outside the service perimeter is refused a build listing: violationReason NO_MATCHING_ACCESS_LEVEL", bucket: "denied", why: "A VPC Service Controls perimeter, a security policy rather than IAM, turned the request away, which makes it Policy Denied. This stream is generated by default and shows failed attempts you'd otherwise never see." },
        ],
        primer: {
          title: "Four streams, two default settings",
          points: [
            "**Admin Activity:** configuration and metadata changes. Always on, can't be turned off.",
            "**Data Access:** who read or wrote the data itself. Off by default for most services, BigQuery being the exception, so a read can leave no trace unless someone enabled it beforehand.",
            "**System Event:** actions Google Cloud takes by itself. Always on.",
            "**Policy Denied:** requests refused by a security policy. Generated by default.",
            "A plain IAM refusal stays in the stream of the call it was, with `status.code` 7.",
          ],
          example: {
            label: "Another company: sorting two calls on one Pub/Sub topic",
            lines: [
              "`google.pubsub.v1.Publisher.DeleteTopic`: the topic itself changed, so Admin Activity",
              "`google.pubsub.v1.Subscriber.Pull`: messages were read, so Data Access",
              "Reading: ask whether the call changed the setup or touched the contents.",
            ],
          },
        },
      },
      {
        kind: "anatomy",
        title: "Anatomy of a Finding",
        prompt: "An audit entry is what happened. A finding is what a detector made of it. Security Command Center raised this one on Thornmere QA last week. Read what it tells you.",
        source: "Security Command Center · Findings · fernhollow-thornmere-qa",
        fields: [
          { key: "category", value: "OPEN_FIREWALL", label: "What", note: "The detector's name for what it saw." },
          { key: "findingClass", value: "MISCONFIGURATION", label: "Class", note: "A setting that exposes something. THREAT is the class for activity." },
          { key: "severity", value: "HIGH", label: "Severity", note: "Assigned by the detector before anyone looks." },
          { key: "state", value: "ACTIVE" },
          { key: "resourceName", value: "//compute.googleapis.com/projects/fernhollow-thornmere-qa/global/firewalls/allow-playtest-7777", label: "On what", note: "The full resource name, ready to search for in the logs." },
          { key: "eventTime", value: "2026-10-20T11:42:08Z", label: "When" },
        ],
        summary: "Security Command Center analyses Cloud Audit Logs, VPC Flow Logs and other signals, and delivers findings already scored by severity and category. That makes a finding a good starting point for triage. Who changed the rule, from where, and whether it worked sit in the audit entries behind it, so search them for the resource name.",
      },
    ],
    // ── Reading 4: the attack patterns ──
    "gcp-r4": [
      {
        kind: "trace",
        title: "Follow the Key",
        prompt: "The file in the mod kit is real, and Rashid disabled the key within minutes. Now the trail: where the key came from, when it first left the building, who it became, what it left behind, and where the money went. Click the row that answers each step.",
        lead: "Monday 09:10. A modder reports a JSON file inside the public Thornmere Mod Kit. It names build-runner@fernhollow-shared-ci.iam.gserviceaccount.com, and its private_key_id begins 7c1e40ab.",
        steps: [
          {
            id: "born",
            ask: "Which entry created the leaked key?",
            source: "Cloud Logging · cloudaudit.googleapis.com/activity · fernhollow-shared-ci",
            columns: ["timestamp", "methodName", "principalEmail", "resourceName / response.name", "callerIp"],
            rows: [
              ["2026-08-19T10:22:31Z", "google.iam.admin.v1.CreateServiceAccountKey", "ci-admin@fernhollow.example", "build-runner / keys/e2b9d06f...41aa", "198.51.100.24"],
              ["2026-09-03T08:47:55Z", "google.iam.admin.v1.DeleteServiceAccountKey", "ci-admin@fernhollow.example", "build-runner / keys/a04c77e1...d9b2", "198.51.100.24"],
              ["2026-09-11T19:33:08Z", "google.iam.admin.v1.CreateServiceAccountKey", "m.adeyemi@fernhollow.example", "build-runner / keys/7c1e40ab...c057", "198.51.100.31"],
              ["2026-09-29T11:02:40Z", "google.iam.admin.v1.CreateServiceAccountKey", "ci-admin@fernhollow.example", "lint-bot / keys/7c1e90d2...3f16", "198.51.100.24"],
              ["2026-10-06T16:18:12Z", "SetIamPolicy", "r.lundqvist@fernhollow.example", "projects/fernhollow-shared-ci", "198.51.100.24"],
            ],
            answer: 2,
            why: "The key ID in the response matches private_key_id, and the account matches too: lint-bot's key starts almost the same way and belongs to someone else. A developer made this key for the mod kit's CI on 11 September, and it shipped with the kit. CreateServiceAccountKey is Admin Activity, so it's here whatever else was switched off.",
            learned: "Key 7c1e40ab...c057 for build-runner, created 2026-09-11 by m.adeyemi",
          },
          {
            id: "first",
            ask: "Now the key itself. Which entry is the first use from outside Fernhollow that we can see?",
            source: "Cloud Logging · cloudaudit.googleapis.com/activity · folder Production",
            columns: ["timestamp", "methodName", "serviceAccountKeyName", "callerIp", "status.code"],
            rows: [
              ["2026-10-24T19:02:14Z", "google.cloud.run.v2.Services.UpdateService", "keys/e2b9d06f...41aa", "10.20.8.12", "0"],
              ["2026-10-24T21:15:40Z", "google.cloud.run.v2.Services.UpdateService", "keys/7c1e40ab...c057", "10.20.8.15", "0"],
              ["2026-10-24T23:51:26Z", "google.cloud.run.v2.Services.UpdateService", "keys/e2b9d06f...41aa", "10.20.8.12", "0"],
              ["2026-10-25T01:10:03Z", "google.iam.admin.v1.CreateServiceAccount", "keys/7c1e40ab...c057", "203.0.113.58", "7"],
              ["2026-10-25T01:12:47Z", "google.iam.admin.v1.CreateServiceAccountKey", "keys/7c1e40ab...c057", "203.0.113.58", "7"],
              ["2026-10-25T01:19:22Z", "google.cloud.run.v2.Services.UpdateService", "keys/e2b9d06f...41aa", "10.20.8.12", "0"],
            ],
            answer: 3,
            why: "Same key, and the address moves from a VM inside Google Cloud to 203.0.113.58. The call was refused with code 7, and it still counts: a refused call is often the first sign that someone is testing what a key can do. It's only the first use we can see, though. This view holds the activity stream alone, a quiet read would leave no entry here, and the key has been public since the kit shipped. So the review window opens when the kit shipped, not at this row and not when the alert fired.",
            learned: "First outside use we can see: 2026-10-25T01:10:03Z from 203.0.113.58, refused. Review window opens when the kit shipped",
          },
          {
            id: "who",
            ask: "From 02:00 the same address appears under release-bot, a different account. Which entry shows who was really behind it?",
            source: "Cloud Logging · cloudaudit.googleapis.com/activity · fernhollow-thornmere-prod",
            columns: ["timestamp", "methodName", "principalEmail", "serviceAccountDelegationInfo[0] firstPartyPrincipal", "callerIp"],
            rows: [
              ["2026-10-24T23:40:10Z", "google.cloud.run.v2.Services.UpdateService", "release-bot@fernhollow-thornmere-prod.iam.gserviceaccount.com", "-", "10.20.8.12"],
              ["2026-10-25T02:03:44Z", "google.pubsub.v1.Subscriber.CreateSubscription", "release-bot@fernhollow-thornmere-prod.iam.gserviceaccount.com", "build-runner@fernhollow-shared-ci.iam.gserviceaccount.com", "203.0.113.58"],
              ["2026-10-25T02:40:02Z", "google.cloud.run.v2.Services.UpdateService", "release-bot@fernhollow-thornmere-prod.iam.gserviceaccount.com", "-", "10.20.8.12"],
              ["2026-10-26T08:55:37Z", "google.pubsub.v1.Publisher.CreateTopic", "release-bot@fernhollow-thornmere-prod.iam.gserviceaccount.com", "m.adeyemi@fernhollow.example", "198.51.100.31"],
            ],
            answer: 1,
            why: "principalEmail says the call ran as release-bot. The delegation field says who asked for that: build-runner, which holds roles/iam.serviceAccountTokenCreator on release-bot. The Monday row uses the same field for a developer's hotfix from the office, so read the name and the address together. Minting the token, GenerateAccessToken, is a Data Access event, and those were off here, which leaves this field as the record of the hop.",
            learned: "build-runner impersonated release-bot at 02:03 from the same address",
          },
          {
            id: "after",
            ask: "Impersonated tokens run out, and the leaked key is disabled now. Which entry gave the intruder a way to keep going?",
            source: "Cloud Logging · cloudaudit.googleapis.com/activity · folder Production",
            columns: ["timestamp", "methodName", "principalEmail", "serviceAccountDelegationInfo[0] firstPartyPrincipal", "resourceName / response.name", "callerIp"],
            rows: [
              ["2026-10-21T03:00:03Z", "google.iam.admin.v1.CreateServiceAccountKey", "key-rotator@fernhollow-shared-ci.iam.gserviceaccount.com", "-", "cdn-uploader / keys/5be1a7c4...08fd", "10.20.8.30"],
              ["2026-10-25T02:03:44Z", "google.pubsub.v1.Subscriber.CreateSubscription", "release-bot@fernhollow-thornmere-prod.iam.gserviceaccount.com", "build-runner@fernhollow-shared-ci.iam.gserviceaccount.com", "projects/fernhollow-thornmere-prod/subscriptions/tmp-sync", "203.0.113.58"],
              ["2026-10-25T02:07:18Z", "google.iam.admin.v1.CreateServiceAccountKey", "release-bot@fernhollow-thornmere-prod.iam.gserviceaccount.com", "build-runner@fernhollow-shared-ci.iam.gserviceaccount.com", "release-bot / keys/3d92f1c6...b7e0", "203.0.113.58"],
              ["2026-10-26T09:14:52Z", "google.iam.admin.v1.DisableServiceAccountKey", "r.lundqvist@fernhollow.example", "-", "build-runner / keys/7c1e40ab...c057", "198.51.100.24"],
            ],
            answer: 2,
            why: "Same outside address, four minutes after the hop, and this entry made a new key on release-bot itself. Rashid's disable on Monday stopped the mod kit key and touched nothing else. An impersonated token lasts an hour by default and twelve at most, so this key is what's left in the intruder's hands, and the row above Rashid's disable is the one the rest of the case turns on.",
            learned: "Key 3d92f1c6...b7e0 on release-bot, made 2026-10-25T02:07:18Z from 203.0.113.58",
          },
          {
            id: "money",
            ask: "A billing alert names Compute Engine in prod. Which insert is the intruder's?",
            source: "Cloud Logging · cloudaudit.googleapis.com/activity · fernhollow-thornmere-prod",
            columns: ["timestamp", "methodName", "principalEmail", "resourceName", "machineType", "callerIp"],
            rows: [
              ["2026-10-25T02:51:09Z", "v1.compute.instances.insert", "release-bot@fernhollow-thornmere-prod.iam.gserviceaccount.com", "projects/fernhollow-thornmere-prod/zones/asia-southeast1-b/instances/tmp-gpu-04", "a2-highgpu-8g", "203.0.113.58"],
              ["2026-10-25T04:30:18Z", "v1.compute.instances.insert", "release-bot@fernhollow-thornmere-prod.iam.gserviceaccount.com", "projects/fernhollow-thornmere-prod/zones/europe-west1-c/instances/lobby-canary-2", "n2-standard-8", "10.20.8.12"],
              ["2026-10-25T14:12:51Z", "v1.compute.instances.insert", "m.adeyemi@fernhollow.example", "projects/fernhollow-thornmere-prod/zones/us-central1-a/instances/bake-gpu-1", "g2-standard-24", "198.51.100.31"],
              ["2026-10-25T18:44:06Z", "v1.compute.instances.insert", "release-bot@fernhollow-thornmere-prod.iam.gserviceaccount.com", "projects/fernhollow-thornmere-prod/zones/europe-west1-b/instances/lobby-mig-x7f2", "n2-standard-8", "10.20.8.12"],
            ],
            answer: 0,
            why: "release-bot also starts honest lobby VMs, so the name settles nothing. Compute Engine doesn't log the key name either, which leaves callerIp: the same address as the last step. The zone is one Fernhollow never uses, and a2-highgpu-8g is an eight-GPU machine. GPU VMs in an unused region after a stolen credential is the shape of crypto-mining, and a billing spike is often what shows it first.",
            learned: "GPU VMs in asia-southeast1 from 203.0.113.58: crypto-mining, paid for by the studio",
          },
        ],
        primer: {
          title: "Following a service account through the logs",
          points: [
            "`authenticationInfo.principalEmail`: the identity the call ran as.",
            "`authenticationInfo.serviceAccountKeyName`: the key that authenticated. It ends in the key ID, the same value as `private_key_id` in the JSON file.",
            "`authenticationInfo.serviceAccountDelegationInfo[0].firstPartyPrincipal.principalEmail`: who stood behind the call when a service account was impersonated.",
            "`requestMetadata.callerIp`: where it came from. A VM with no external address, calling from inside the organization, shows its internal address. Fernhollow's build and deploy runners sit in `10.20.8.0/24`.",
            "Compute Engine doesn't log the key name. On those entries, pivot on `callerIp` and the time.",
          ],
          example: {
            label: "Another company: one call, read field by field",
            lines: [
              "`methodName`: `google.pubsub.v1.Publisher.CreateTopic`",
              "`principalEmail`: `reports-bot@ops-tools.iam.gserviceaccount.com`",
              "`firstPartyPrincipal.principalEmail`: `dana@quarrybank.example`",
              "Reading: it ran as reports-bot, and dana asked for it.",
            ],
          },
        },
      },
      {
        kind: "sequence",
        title: "Walk a Token Out of a VM",
        prompt: "The key wasn't Fernhollow's first scare. Last month a modder reported that the avatar field on the lobby server fetched any URL it was given, and Rashid replayed the report to see how far it went. Put the chain in the order it happens.",
        items: [
          { id: "s4", text: "The metadata server returns an access token for the VM's attached service account", note: "The default account's token sits at /computeMetadata/v1/instance/service-accounts/default/token." },
          { id: "s1", text: "A player pastes a URL into the avatar field, and the lobby app fetches it server-side", note: "A request made by the server on someone else's behalf is what SSRF, Server-Side Request Forgery, abuses." },
          { id: "s6", text: "Whoever reads the response now holds the token" },
          { id: "s3", text: "The fetch goes out with Metadata-Flavor: Google, because the app forwards whatever headers it's handed", note: "The header raises the bar, and an app that forwards whatever it's given can still be made to send it." },
          { id: "s5", text: "The app places the response in the avatar preview" },
          { id: "s2", text: "The URL points at 169.254.169.254, an address only the VM itself can reach" },
        ],
        order: ["s1", "s2", "s3", "s4", "s5", "s6"],
        doneNote: "A token is a bearer credential: it works for whoever holds it, wherever they are, until it expires. Taking it doesn't stop or change the VM, so nothing on the machine has to break. Fernhollow fixed the avatar fetch and blocked link-local targets the same day.",
        primer: {
          title: "The metadata server",
          points: [
            "Every Compute Engine VM can reach the **metadata server** at `169.254.169.254`, a non-routable address, for facts about itself.",
            "One of those facts is the live access token for its attached service account.",
            "Each request must carry the header `Metadata-Flavor: Google`.",
          ],
          example: {
            label: "Asking for something harmless, from inside a VM",
            lines: [
              "`curl -H \"Metadata-Flavor: Google\" http://169.254.169.254/computeMetadata/v1/instance/name`",
              "returns the VM's name",
              "the same request without the header returns `403 Forbidden`",
            ],
          },
        },
      },
    ],
    // ── Drills before the graded logs ──
    "gcp-la1": [
      {
        kind: "outbreak",
        title: "Stop It Moving",
        prompt: "Monday night. The mod kit key is dead, but the intruder still holds the key it made for release-bot, and Fernhollow's thirty projects share service accounts. It's hopping through those bindings toward SIGNING, the project that signs Friday's launch patch. A host on this map is a project, and isolating it strips its shared bindings. The rest of the history can wait. First, stop it moving.",
        hostPrefix: "PRJ",
        cols: 6,
        rows: 5,
        crown: "SIGNING",
        via: "service account bindings shared between projects",
        lesson: "Cut ahead of the spread, where the map narrows. The project that raised the alert is often one it has already left, so that's a poor place to spend a turn. Stop the movement first and count afterwards: the logs will wait, and a live identity won't.",
        primer: {
          title: "Contain first, count second",
          points: [
            "While a stolen identity still works, it keeps moving. History sits safely in the logs, so counting can come second.",
            "Containing an identity covers its roles and its credentials. Either one left in place keeps the door open.",
            "Stopping access ends the exposure. It doesn't say what already left, so a case stays open until the whole window has been counted.",
          ],
          example: {
            label: "Another team: a package-registry robot",
            lines: [
              "09:02 a robot's registry token turns up in a paste site",
              "09:03 token revoked, publish role stripped",
              "09:10 everything it published since the token was exposed goes on a list",
              "09:40 each package is checked, and only then does the case close",
            ],
          },
        },
      },
    ],
    "gcp-la2": [
      {
        kind: "worksheet",
        title: "Who Downloaded the Patch?",
        prompt: "Before the second record, one more from home. Marketing wants launch-week download numbers, and the first report came back empty. Rashid has laid six reads out side by side, with what each one left behind. Work from the rows.",
        caption: "Launch week · six reads, with the project's Data Access setting and each bucket's usage logs",
        columns: ["Read", "Bucket", "Reader", "Access came from", "Data Access (project)", "Usage logs (bucket)", "Audit entries", "Usage row"],
        rows: [
          ["1", "fh-thornmere-patches", "Anonymous, 198.51.100.140", "allUsers binding", "On", "On", "0", "sc_status 200, sc_bytes 734003200"],
          ["2", "fh-press-kit", "Anonymous, 198.51.100.77", "allUsers binding", "On", "Off", "0", "None"],
          ["3", "fh-thornmere-saves", "serviceAccount:lobby-svc", "IAM role", "On", "Off", "1", "None"],
          ["4", "fh-qa-builds", "user:m.adeyemi@fernhollow.example", "IAM role", "Off", "Off", "0", "None"],
          ["5", "fh-thornmere-patches", "Anonymous, 198.51.100.212", "allUsers binding", "On", "On", "0", "sc_status 206, sc_bytes 104857600"],
          ["6", "fh-thornmere-patches", "Anonymous, 198.51.100.188", "allUsers binding", "On", "On", "0", "sc_status 200, sc_bytes 734003200"],
        ],
        questions: [
          { id: "public", q: "How many of the allUsers reads show an audit entry?", hint: "Four rows came through allUsers. Read their Audit entries column.", answer: ["0", "zero", "none"], why: "None of reads 1, 2, 5 and 6. Set read 2 against read 3: the same Data Access setting, and only the one through an IAM role has an entry." },
          { id: "none", q: "How many of the six reads left no record anywhere?", hint: "Look for 0 audit entries and no usage row on the same line.", answer: ["2", "two"], why: "Reads 2 and 4. Read 4 had both settings off. Read 2 is the one people miss, because its Data Access setting was on." },
          { id: "count", q: "The patch file is 734,003,200 bytes. How many complete downloads do the usage rows show?", hint: "Compare sc_bytes with the file size, on the patch bucket's rows.", answer: ["2", "two"], why: "Reads 1 and 6 moved the whole file. Read 5 is a 206, a partial read of about 100 MB. That count is what Marketing gets, with an address for each reader and no name." },
        ],
        primer: {
          title: "Two logs, two settings",
          points: [
            "**Data Access** logging is set per service, on a project, folder or organization.",
            "**Cloud Storage usage logs** are set per bucket, off by default, and delivered hourly as CSV files to another bucket.",
            "A usage record has no caller identity for an anonymous read, only `c_ip` and a user agent.",
            "`sc_status` is the HTTP result and `sc_bytes` is what left. Bytes equal to the object's size mean the whole object.",
          ],
          example: {
            label: "Another company: one usage-log row",
            lines: [
              "`c_ip 198.51.100.9  cs_method GET  cs_object brochure.pdf`",
              "`sc_status 200  sc_bytes 912004`, and the object is 912,004 bytes",
              "Reading: one caller, known only by address, took the whole file.",
            ],
          },
        },
      },
    ],
    // ── Drill before the verdict ──
    "gcp-ac1": [
      {
        kind: "queue",
        title: "Fired Right, Still Fine?",
        prompt: "Back at Fernhollow, the SOC turned on a rule that fires on any call from an account on its high-privilege watch list. Five alerts came in on the first day. Open each one, read the call itself, and give your verdict.",
        console: "High-privilege watch list",
        actions: [
          { id: "btp", label: "Benign true positive", tone: "close" },
          { id: "fp", label: "False positive", tone: "close" },
          { id: "tp", label: "True positive: escalate", tone: "escalate" },
        ],
        alerts: [
          { id: "a1", time: "02:00", severity: "Low", rule: "High-privilege watch list", entity: "render-farm",
            fields: [{ k: "methodName", v: "v1.compute.disks.createSnapshot" }, { k: "callerIp", v: "10.20.4.17" }, { k: "callerSuppliedUserAgent", v: "google-cloud-sdk gcloud/471.0.0" }, { k: "status.code", v: "0" }, { k: "logName", v: ".../cloudaudit.googleapis.com%2Factivity" }],
            context: "The render runbook says render-farm snapshots its cache disk at 02:00 every night from the render subnet, 10.20.4.0/24. It holds a broad role, which is what the rule looks for.", answer: "btp", why: "The rule did what it says: a broad account really made a call. It changes something, and the runbook, the time and the subnet all account for it." },
          { id: "a2", time: "03:26", severity: "Medium", rule: "High-privilege watch list", entity: "test-rig",
            fields: [{ k: "methodName", v: "google.iam.admin.v1.CreateServiceAccountKey" }, { k: "callerIp", v: "203.0.113.140" }, { k: "callerSuppliedUserAgent", v: "python-requests/2.32.3" }, { k: "status.code", v: "0" }, { k: "logName", v: ".../cloudaudit.googleapis.com%2Factivity" }],
            context: "test-rig runs smoke tests from a VM inside the QA project. It has no documented reason to make keys.", answer: "tp", why: "A state-changing IAM call that worked, from an outside address, with a tool this account doesn't use. Every check points the same way." },
          { id: "a3", time: "11:04", severity: "Low", rule: "High-privilege watch list", entity: "release-bot",
            fields: [{ k: "methodName", v: "google.cloud.run.v2.Services.UpdateService" }, { k: "callerIp", v: "10.20.8.12" }, { k: "callerSuppliedUserAgent", v: "google-cloud-sdk gcloud/471.0.0" }, { k: "status.code", v: "0" }, { k: "logName", v: ".../cloudaudit.googleapis.com%2Factivity" }],
            context: "Change ticket CHG-4471 covers a landing page deploy between 11:00 and 11:30, run by release-bot from 10.20.8.0/24. The key the intruder made on release-bot was disabled on Monday night.", answer: "btp", why: "A change again, and still fine: the right identity, the right place, inside an approved window. A write isn't guilty by itself, it just earns a closer look." },
          { id: "a4", time: "13:40", severity: "Low", rule: "High-privilege watch list", entity: "crash-reporter",
            fields: [{ k: "methodName", v: "google.logging.v2.LoggingServiceV2.WriteLogEntries" }, { k: "callerIp", v: "10.20.12.9" }, { k: "bindings today", v: "roles/logging.logWriter only" }, { k: "status.code", v: "0" }],
            context: "The rule reads its list of broad accounts from a weekly export. Last week's export still lists crash-reporter, which lost its broad role in Friday's review. It writes from the lobby subnet, 10.20.12.0/24.", answer: "fp", why: "The condition wasn't really met: this account no longer holds a broad role, so the rule fired on stale data. That's the difference from a benign true positive, where the rule was right and the activity was fine." },
          { id: "a5", time: "22:15", severity: "Low", rule: "High-privilege watch list", entity: "lint-bot",
            fields: [{ k: "methodName", v: "google.iam.admin.v1.ListServiceAccounts" }, { k: "callerIp", v: "203.0.113.91" }, { k: "callerSuppliedUserAgent", v: "python-requests/2.32.3" }, { k: "calls in the last minute", v: "6 list calls on 6 services" }, { k: "status.code", v: "0" }, { k: "logName", v: ".../cloudaudit.googleapis.com%2Fdata_access" }],
            context: "lint-bot normally makes one kind of call, from a VM, during builds.", answer: "tp", why: "Read-only, and still not fine. A burst of list calls across many services from an outside address is someone mapping the project. The method lowers the blast radius of one call, and the source and pattern decide this one." },
        ],
        primer: {
          title: "Three ways an alert can end",
          points: [
            "**True positive:** the rule was right and the activity is an attack.",
            "**Benign true positive:** the rule was right, the call really happened, and it's authorised.",
            "**False positive:** the rule's condition wasn't really met.",
            "Read the call itself: who, from where, what, and did it work.",
            "`list` and `get` calls read state. `create`, `delete` and `SetIamPolicy` change state.",
          ],
          example: {
            label: "Another company: a rule on after-hours sign-ins",
            lines: [
              "The on-call engineer signs in at 03:00 during a paged outage",
              "The rule was right: it was after hours, and it was that person",
              "The page and the rota explain it, so it's a benign true positive",
            ],
          },
        },
      },
    ],
    // ── Reading 5: the triage workflow ──
    "gcp-r5": [
      {
        kind: "worksheet",
        title: "Pivot on the Address",
        prompt: "After Monday, Rashid switched Data Access on for every service, Admin Read included. Tuesday night's alert on lint-bot came back with this. Read the pattern from the outside address, and answer.",
        caption: "Cloud Logging · pivot on lint-bot · Tuesday night",
        columns: ["time", "methodName", "callerIp", "callerSuppliedUserAgent", "status"],
        rows: [
          ["22:02:11", "google.iam.admin.v1.ListServiceAccountKeys", "10.20.8.21", "google-cloud-sdk gcloud/471.0.0", "0 OK"],
          ["22:14:51", "storage.buckets.list", "203.0.113.91", "python-requests/2.32.3", "7 PERMISSION_DENIED"],
          ["22:14:58", "google.pubsub.v1.Publisher.ListTopics", "203.0.113.91", "python-requests/2.32.3", "7 PERMISSION_DENIED"],
          ["22:15:03", "google.iam.admin.v1.ListServiceAccounts", "203.0.113.91", "python-requests/2.32.3", "0 OK"],
          ["22:15:09", "google.cloud.secretmanager.v1.SecretManagerService.ListSecrets", "203.0.113.91", "python-requests/2.32.3", "7 PERMISSION_DENIED"],
          ["22:15:14", "google.spanner.admin.instance.v1.InstanceAdmin.ListInstances", "203.0.113.91", "python-requests/2.32.3", "7 PERMISSION_DENIED"],
          ["22:15:20", "google.cloud.bigquery.v2.DatasetService.ListDatasets", "203.0.113.91", "python-requests/2.32.3", "5 NOT_FOUND"],
        ],
        questions: [
          { id: "refused", q: "How many calls from 203.0.113.91 were refused for permissions?", hint: "Count one status only.", answer: ["4", "four"], why: "Four in thirty seconds across four services. One refusal is a misconfigured job. A run of them from one identity is someone finding out what the credential can do." },
          { id: "worked", q: "Which one call from that address worked? Give the last word of its methodName.", hint: "Look for status 0.", answer: ["ListServiceAccounts"], why: "One success matters more than the refusals around it: the caller now has the project's list of service accounts, which is the shopping list for the next step." },
          { id: "stage", q: "Every method here is a list. Which stage is this: recon, escalation or objective?", hint: "Nothing has changed yet.", answer: ["recon", "reconnaissance"], why: "List and get calls map the project. Escalation would be a state-changing call on IAM or on keys, and the objective is data leaving or resources appearing. Pivoting on the address and the identity across hours shows you which stage you've caught." },
        ],
        primer: {
          title: "A checklist for one suspicious entry",
          points: [
            "**WHO:** `principalEmail`. A person, or a service account that should run from one place only?",
            "**WHERE:** `callerIp` and the user agent. Do they fit this identity's normal behaviour?",
            "**WHAT:** `methodName` and `serviceName` together. Read-only, or state-changing?",
            "**OUTCOME:** `status.code`, then **PATTERN:** pivot on the same IP and identity across hours or days.",
            "An incident usually runs initial access, reconnaissance, privilege escalation, objective. In a SIEM these fields often start `gcp.audit.`.",
          ],
          example: {
            label: "Another company: the checklist on one entry",
            lines: [
              "WHO `reports-bot@ops-tools.iam.gserviceaccount.com`",
              "WHERE `198.51.100.8`, `curl/8.5.0`, and this bot normally runs from a VM",
              "WHAT `google.pubsub.v1.Publisher.DeleteTopic`, state-changing",
              "OUTCOME `status.code 0`",
              "PATTERN three more deletes from the same address, so pull the identity's whole day",
            ],
          },
        },
      },
    ],
    // ── Drill before the boss record ──
    "gcp-la-sakey": [
      {
        kind: "worksheet",
        title: "Whose Key Is It?",
        prompt: "Rashid has one last sweep at Fernhollow: every key made from 1 to 24 October, the weeks before the intruder's night. A key entry names two accounts, and they aren't always what they first seem. Read both.",
        caption: "Cloud Logging · methodName: google.iam.admin.v1.CreateServiceAccountKey · status.code 0 · 2026-10-01 to 2026-10-24",
        columns: ["Row", "timestamp", "principalEmail", "response.name", "callerIp", "keyType"],
        rows: [
          ["1", "2026-10-07T03:00:04Z", "key-rotator@fernhollow-shared-ci.iam.gserviceaccount.com", "projects/fernhollow-shared-ci/serviceAccounts/cdn-uploader@fernhollow-shared-ci.iam.gserviceaccount.com/keys/c40e8d17...a3b6", "10.20.8.30", "USER_MANAGED"],
          ["2", "2026-10-12T15:21:37Z", "ci-admin@fernhollow.example", "projects/fernhollow-shared-ci/serviceAccounts/lint-bot@fernhollow-shared-ci.iam.gserviceaccount.com/keys/b81f33a0...92c4", "198.51.100.24", "USER_MANAGED"],
          ["3", "2026-10-14T03:00:06Z", "key-rotator@fernhollow-shared-ci.iam.gserviceaccount.com", "projects/fernhollow-shared-ci/serviceAccounts/cdn-uploader@fernhollow-shared-ci.iam.gserviceaccount.com/keys/19d6fe42...7c0d", "10.20.8.30", "USER_MANAGED"],
          ["4", "2026-10-18T02:14:49Z", "matchmaker-svc@fernhollow-thornmere-prod.iam.gserviceaccount.com", "projects/fernhollow-thornmere-prod/serviceAccounts/payments-bot@fernhollow-thornmere-prod.iam.gserviceaccount.com/keys/e07d52b9...61af", "203.0.113.77", "USER_MANAGED"],
          ["5", "2026-10-21T03:00:03Z", "key-rotator@fernhollow-shared-ci.iam.gserviceaccount.com", "projects/fernhollow-shared-ci/serviceAccounts/cdn-uploader@fernhollow-shared-ci.iam.gserviceaccount.com/keys/5be1a7c4...08fd", "10.20.8.30", "USER_MANAGED"],
        ],
        questions: [
          { id: "asker", q: "On row 4, which account made the call? Give the name before the @.", hint: "Which field is the identity the call ran as?", answer: ["matchmaker-svc"], why: "principalEmail is the caller, the credential somebody already held when the call was made. That's the account to trace back from." },
          { id: "owner", q: "On row 4, which account does the new key log in as? Give the name before the @.", hint: "Read the path in response.name.", answer: ["payments-bot"], why: "The key belongs to the account in that path, and it works as that account straight away. So the caller has just given itself a second identity." },
          { id: "count", q: "How many rows have a caller that differs from the key's owner?", hint: "Every row, one at a time.", answer: ["5", "five"], why: "All five, so a different caller isn't guilty by itself. key-rotator runs at 03:00 every week from inside, and ci-admin works from the office. Row 4 fits no job, no time and no place." },
        ],
        primer: {
          title: "Two accounts on one entry",
          points: [
            "`authenticationInfo.principalEmail` is **who asked** for the key.",
            "`response.name`, the path of the new key, says **whose key it is**. `resourceName` often holds only the account's numeric ID.",
            "`keyType: USER_MANAGED` is a key someone created and holds as a file, as opposed to the ones Google keeps and rotates itself.",
            "Permission to create keys, `iam.serviceAccountKeys.create`, can be held on another account.",
          ],
          example: {
            label: "Another company: a person making a key for a bot",
            lines: [
              "`principalEmail`: `dana@quarrybank.example`",
              "`response.name`: `projects/ops-tools/serviceAccounts/reports-bot@ops-tools.iam.gserviceaccount.com/keys/91ab04...`",
              "Reading: dana asked, and the key logs in as reports-bot.",
            ],
          },
        },
      },
    ],
    // ── Reading 6: chains, and closing the gaps ──
    "gcp-r6": [
      {
        kind: "pathway",
        title: "Cash Out a Foothold",
        prompt: "Tabletop at Fernhollow. Rashid replays the avatar bug and asks one question: had nobody reported it, how far could it have gone? Play the intruder. Start from a browser, and end with a credential that outlives the token.",
        goal: "Turn a one-hour token into a lasting credential",
        nodes: [
          { id: "net", label: "The internet", sub: "A player's browser", x: 10, y: 50 },
          { id: "app", label: "Lobby app", sub: "thornmere-lobby-03", x: 28, y: 28 },
          { id: "fw", label: "VPC firewall", sub: "Allows 443 in", x: 28, y: 74 },
          { id: "meta", label: "Metadata server", sub: "169.254.169.254", x: 48, y: 14 },
          { id: "fs", label: "Firestore", sub: "Player profiles", x: 48, y: 46 },
          { id: "tok", label: "lobby-svc token", sub: "Expires in an hour", x: 66, y: 28 },
          { id: "saves", label: "fh-thornmere-saves", sub: "Bucket", x: 62, y: 64 },
          { id: "policy", label: "Project IAM policy", sub: "fernhollow-thornmere-prod", x: 86, y: 62 },
          { id: "mint", label: "Create a key", sub: "On release-bot", x: 86, y: 14 },
          { id: "key", label: "release-bot key", sub: "JSON, no expiry", x: 86, y: 38 },
        ],
        edges: [["net", "app"], ["net", "fw"], ["app", "meta"], ["app", "fs"], ["meta", "tok"], ["tok", "saves"], ["tok", "policy"], ["tok", "mint"], ["mint", "key"]],
        route: ["net", "app", "meta", "tok", "mint", "key"],
        notes: {
          net: "All you have is a browser and a form field.",
          app: "The avatar field makes the lobby app fetch URLs for you. The app is internet-facing and low value, and that's why it's the way in.",
          meta: "The fetch reaches the metadata server, an address you could never reach from outside.",
          tok: "You hold the live token for lobby-svc. It lasts about an hour, and when it dies, so does your access, unless you use it to get something better.",
          mint: "lobby-svc holds iam.serviceAccountKeys.create on release-bot, a leftover from an old deploy script. It's a narrow permission, easy to overlook in a review.",
          key: "CreateServiceAccountKey returns a JSON key for a stronger account. You no longer need the bug, the VM or the token: it works from anywhere until somebody finds it.",
        },
        traps: {
          fw: "The firewall lets players reach the app on 443, and there's nothing to take from it.",
          fs: "Player profiles are worth stealing, but they give you no identity. The chain needs a credential first.",
          saves: "lobby-svc can read saves, and a smash-and-grab would end when the token does. The goal here is access that lasts.",
          policy: "lobby-svc has no permission to edit this policy. The route to a stronger identity runs through a narrower permission.",
        },
        lesson: "This is how a temporary foothold becomes a permanent one: a low-value identity, one overlooked permission, and a fresh key for a stronger account. Treat iam.serviceAccountKeys.create as highly sensitive, and look hard at any CreateServiceAccountKey where the caller isn't expected to make keys for that owner.",
        primer: {
          title: "From a token to a key",
          points: [
            "A **lateral chain** moves from a weak identity to a stronger one, using a permission the weak one happens to hold.",
            "`iam.serviceAccountKeys.create` is narrow, and it's enough: held on another account, it makes a key for that account.",
            "A stolen token dies in about an hour. A key made with it doesn't, so the attacker no longer needs the first foothold.",
            "Keys aren't the only prize, so check what each identity can do to other identities, not only to data.",
          ],
          example: {
            label: "Another company: reading one identity's reach",
            lines: [
              "`reports-bot` holds `roles/logging.viewer` on project `ops-tools`",
              "`reports-bot` also holds `roles/iam.serviceAccountKeyAdmin` on `backup-bot`",
              "Reading: the second line is the one to worry about, because it reaches another identity.",
            ],
          },
        },
      },
      {
        kind: "match",
        title: "Close Each Gap",
        prompt: "The post-incident review. Rashid lists what went wrong this week. Match each gap to the control that closes it.",
        primer: {
          title: "Controls a SOC should verify",
          points: [
            "An **Organization Policy** sets a rule across the whole tree, and a project can't quietly opt out.",
            "Detection only covers what's logged and watched, so a control is often a setting that has to be switched on in advance.",
          ],
          example: {
            label: "Another company: one gap, one control",
            lines: [
              "Gap: a contractor's VM got a public IP address",
              "Control: the Organization Policy constraint `compute.vmExternalIpAccess`",
            ],
          },
        },
        pairs: [
          { id: "g1", left: "A developer could make a key for the mod kit", right: "The Organization Policy constraint iam.disableServiceAccountKeyCreation", why: "With key creation off at the organization, workloads have to use attached, short-lived credentials." },
          { id: "g2", left: "build-runner kept a folder-wide role for years", right: "A regular review that replaces broad roles with narrow ones", why: "Nothing expires a binding. Someone has to go and look." },
          { id: "g3", left: "Nobody was paged when a key appeared", right: "An unconditional alert on CreateServiceAccountKey", why: "It's a rare, high-impact event, and it's in Admin Activity whatever else is off." },
          { id: "g4", left: "The token mint for the impersonation left no entry", right: "Data Access logging on IAM", why: "GenerateAccessToken is a Data Access event, so it's recorded only once that's switched on." },
          { id: "g5", left: "Marketing couldn't count downloads of a public file", right: "Cloud Storage usage logs on the bucket", why: "Public reads stay out of the audit logs, whatever their settings." },
          { id: "g6", left: "An open firewall rule sat unread on QA for a week", right: "A daily triage of Security Command Center findings", why: "A finding only helps if someone works it." },
        ],
      },
    ],
    // ── Reading 7: containment ──
    "gcp-r7": [
      {
        kind: "rush",
        title: "Undo or Gone?",
        prompt: "Thursday, one day out, and Rashid is writing the runbook for next time. In the first hour of an incident you want moves you can reverse. Call each command.",
        trueLabel: "Can be undone",
        falseLabel: "Can't be undone",
        seconds: 60,
        target: 9,
        cards: [
          { id: "c1", text: "gcloud iam service-accounts keys disable", answer: true, why: "keys enable brings it straight back, and the key stays listed." },
          { id: "c2", text: "gcloud iam service-accounts keys delete", answer: false, why: "Delete is final, and the key is gone from the list." },
          { id: "c3", text: "gcloud projects remove-iam-policy-binding", answer: true, why: "Add the binding again and the role is back." },
          { id: "c4", text: "gcloud compute instances add-tags --tags=quarantined", answer: true, why: "A tag is a label. Remove it and the VM is as it was." },
          { id: "c5", text: "gcloud compute instances delete", answer: false, why: "Memory is gone, and the boot disk goes with it by default." },
          { id: "c6", text: "gcloud compute firewall-rules create, deny, priority 0", answer: true, why: "Delete the rule and traffic returns. The VM itself isn't touched." },
          { id: "c7", text: "gcloud compute disks snapshot", answer: true, why: "It changes nothing on the disk, and it's your forensic record." },
          { id: "c8", text: "gcloud compute disks delete", answer: false, why: "That's the evidence itself." },
          { id: "c9", text: "gcloud iam service-accounts disable", answer: true, why: "service-accounts enable reverses it." },
          { id: "c10", text: "Rebuilding the VM from an older image", answer: false, why: "It overwrites what you'd need to reconstruct the attack." },
          { id: "c11", text: "gcloud storage rm with no versioning and soft delete set to 0", answer: false, why: "Neither feature kept a copy, so there's nothing to restore from." },
          { id: "c12", text: "gcloud compute firewall-rules delete quarantine-deny-egress", answer: true, why: "Recreate the rule if you need it. It holds no evidence." },
        ],
        lesson: "A quarantined VM keeps its disk and memory for the investigation. A disabled key still shows up in the list, with its dates, for the investigation. Deleting belongs to eradication, once root cause is understood. Reading the audit trail says what happened, and the order you act in decides whether you can still prove it.",
        primer: {
          title: "Reversible first",
          points: [
            "Early in an incident you may be wrong about what a credential is used for, so you want moves that can be reversed.",
            "A `disable` blocks use immediately and leaves the thing in place to examine.",
            "Removing a binding takes away the power itself, whichever credential turns up next.",
            "Past audit entries survive either way. What you lose with a delete is the object.",
          ],
          example: {
            label: "Another company: a contractor's account",
            lines: [
              "`suspend` blocks sign-in, and the mailbox and history stay",
              "`delete` frees the licence and, after the retention period, the data",
              "Reading: suspend today, and delete at the end, on purpose.",
            ],
          },
        },
      },
      {
        kind: "sequence",
        title: "Hold the VM for Forensics",
        prompt: "Rashid's runbook needs Monday's hold written down. tmp-gpu-04 was still running in asia-southeast1-b, and everyone wanted it gone. Put the steps in order.",
        items: [
          { id: "v3", text: "Create the deny rule for inbound traffic the same way", note: "Both directions are needed to cut the VM off." },
          { id: "v5", text: "Mount a copy of the snapshot read-only on a clean investigation VM", note: "Analysis never touches the original." },
          { id: "v1", text: "gcloud compute instances add-tags tmp-gpu-04 --tags=quarantined", note: "The tag is what the firewall rules will target." },
          { id: "v6", text: "Delete the VM as part of eradication, after root cause is understood" },
          { id: "v4", text: "gcloud compute disks snapshot tmp-gpu-04 --snapshot-names=tmp-gpu-04-ir", note: "An isolated VM's disk can still change, so take the point-in-time record before anything destructive." },
          { id: "v2", text: "gcloud compute firewall-rules create quarantine-deny-egress --direction=EGRESS --action=DENY --rules=all --destination-ranges=0.0.0.0/0 --target-tags=quarantined --priority=0", note: "Rules are evaluated by priority, so 0 overrides any looser rule on this VM." },
        ],
        order: ["v1", "v2", "v3", "v4", "v5", "v6"],
        doneNote: "The VM is cut off with its disk and memory intact, the snapshot is the forensic record, and deletion comes last. Isolate, preserve, understand, and only then eradicate.",
        primer: {
          title: "Isolating a VM in GCP",
          points: [
            "Shutting down or deleting a VM destroys memory, and possibly its disk, along with any chance of seeing how the attacker got in.",
            "GCP isolates at the network layer: a **network tag** on the VM, plus deny **firewall rules** that target that tag.",
            "A lower priority number wins, so `--priority=0` beats everything else.",
          ],
          example: {
            label: "Another company: blocking one port on one VM",
            lines: [
              "`gcloud compute instances add-tags web-7 --tags=no-ftp`",
              "`gcloud compute firewall-rules create block-ftp --action=DENY --rules=tcp:21 --target-tags=no-ftp --priority=100`",
              "Reading: the tag selects the VM, and the rule does the blocking.",
            ],
          },
        },
      },
    ],
  },
};
