import type { TelemetryEvent } from "@/lib/sim/types";

// ── Event 1 (log_analysis): IAM privilege escalation via SetIamPolicy ─────────
const setIamPolicyEvent: TelemetryEvent = {
  id: "evt-gcp-setiampolicy-001",
  ts: "2026-05-19T02:47:11.000Z",
  source: "cloud_gcp",
  vendor: "GCP Cloud Audit Logs",
  event_type: "cloud_role_change",
  severity: "critical",
  user_email: "svc-data@nexacorp.iam.gserviceaccount.com",
  src_ip: "185.220.101.47",
  geo: { country: "Netherlands", city: "Amsterdam" },
  description: "A low-privilege service account granted itself the Owner role on the entire production project via SetIamPolicy, moments after being used from an unfamiliar external IP",
  mitre_technique: "T1078.004",
  mitre_tactic: "Privilege Escalation",
  raw: {
    "gcp.audit.method_name": "SetIamPolicy",
    "gcp.audit.service_name": "cloudresourcemanager.googleapis.com",
    "gcp.audit.resource_name": "projects/nexacorp-prod",
    "gcp.audit.authentication_info.principal_email": "svc-data@nexacorp.iam.gserviceaccount.com",
    "gcp.audit.request_metadata.caller_ip": "185.220.101.47",
    "gcp.audit.request_metadata.caller_supplied_user_agent": "google-api-python-client/2.86.0",
    "gcp.audit.status.code": 0,
    "gcp.audit.status.message": "",
    "gcp.audit.request.policy.bindings": [
      {
        "role": "roles/owner",
        "members": ["serviceAccount:svc-data@nexacorp.iam.gserviceaccount.com"],
      },
    ],
    "gcp.audit.response.bindings": [
      {
        "role": "roles/owner",
        "members": ["serviceAccount:svc-data@nexacorp.iam.gserviceaccount.com"],
      },
      {
        "role": "roles/editor",
        "members": ["serviceAccount:svc-data@nexacorp.iam.gserviceaccount.com"],
      },
    ],
    "gcp.project.id": "nexacorp-prod",
    "gcp.resource.type": "project",
    "gcp.audit.log_type": "ADMIN_ACTIVITY",
    "gcp.audit.severity": "NOTICE",
    "action_result": "allowed",
  },
};

// ── Event 2 (log_analysis): public Cloud Storage bucket exfil ─────────────────
const publicBucketExfilEvent: TelemetryEvent = {
  id: "evt-gcp-storage-exfil-001",
  ts: "2026-05-19T03:05:44.000Z",
  source: "cloud_gcp",
  vendor: "GCP Cloud Audit Logs",
  event_type: "cloud_storage_access",
  severity: "critical",
  user_email: "allUsers",
  src_ip: "91.108.56.19",
  geo: { country: "Russia", city: "Moscow" },
  description: "An anonymous internet caller downloaded customer export files from a Cloud Storage bucket that had been made public, generating Data Access audit log entries rather than an Admin Activity change",
  mitre_technique: "T1530",
  mitre_tactic: "Collection",
  raw: {
    "gcp.audit.method_name": "storage.objects.get",
    "gcp.audit.service_name": "storage.googleapis.com",
    "gcp.audit.resource_name": "projects/_/buckets/nexacorp-customer-exports/objects/exports/customers_full_2026Q2.csv",
    "gcp.audit.authentication_info.principal_email": "allUsers",
    "gcp.audit.request_metadata.caller_ip": "91.108.56.19",
    "gcp.audit.request_metadata.caller_supplied_user_agent": "python-requests/2.31.0",
    "gcp.audit.status.code": 0,
    "gcp.audit.status.message": "",
    "gcp.audit.log_type": "DATA_ACCESS",
    "gcp.audit.severity": "INFO",
    "storage.bucket.name": "nexacorp-customer-exports",
    "storage.object.name": "exports/customers_full_2026Q2.csv",
    "storage.object.size": 48302911,
    "storage.bucket.iam_configuration.public_access_prevention": "inherited",
    "storage.bucket.iam_binding.role": "roles/storage.objectViewer",
    "storage.bucket.iam_binding.members": ["allUsers"],
    "gcp.project.id": "nexacorp-prod",
    "action_result": "allowed",
  },
};

// ── Event 3 (analyst_choice): benign vs malicious service-account activity ────
const benignServiceAccountEvent: TelemetryEvent = {
  id: "evt-gcp-sa-benign-001",
  ts: "2026-05-19T09:00:12.000Z",
  source: "cloud_gcp",
  vendor: "GCP Cloud Audit Logs",
  event_type: "cloud_api_call",
  severity: "low",
  user_email: "svc-cicd@nexacorp.iam.gserviceaccount.com",
  src_ip: "10.128.0.14",
  hostname: "gke-nexacorp-prod-pool-1-a3f9",
  description: "A CI/CD pipeline service account listed Compute Engine instances from an internal GKE node as part of a routine scheduled deployment job",
  raw: {
    "gcp.audit.method_name": "compute.instances.list",
    "gcp.audit.service_name": "compute.googleapis.com",
    "gcp.audit.resource_name": "projects/nexacorp-prod",
    "gcp.audit.authentication_info.principal_email": "svc-cicd@nexacorp.iam.gserviceaccount.com",
    "gcp.audit.request_metadata.caller_ip": "10.128.0.14",
    "gcp.audit.request_metadata.caller_supplied_user_agent": "google-cloud-sdk gcloud/462.0.1",
    "gcp.audit.status.code": 0,
    "gcp.audit.status.message": "",
    "gcp.audit.log_type": "ADMIN_ACTIVITY",
    "gcp.audit.severity": "INFO",
    "gcp.project.id": "nexacorp-prod",
    "action_result": "allowed",
  },
};

// ── Event 4 (flag task): service-account key theft + metadata server abuse ────
const metadataKeyTheftEvent: TelemetryEvent = {
  id: "evt-gcp-metadata-theft-001",
  ts: "2026-05-19T02:42:30.000Z",
  source: "cloud_gcp",
  vendor: "GCP Cloud Audit Logs",
  event_type: "cloud_api_call",
  severity: "critical",
  user_email: "svc-data@nexacorp.iam.gserviceaccount.com",
  src_ip: "185.220.101.47",
  geo: { country: "Netherlands", city: "Amsterdam" },
  description: "A new, unauthorized JSON key was created for the svc-data service account minutes before it was used from an external IP address to escalate privileges",
  mitre_technique: "T1552.005",
  mitre_tactic: "Credential Access",
  raw: {
    "gcp.audit.method_name": "google.iam.admin.v1.CreateServiceAccountKey",
    "gcp.audit.service_name": "iam.googleapis.com",
    "gcp.audit.resource_name": "projects/nexacorp-prod/serviceAccounts/svc-data@nexacorp.iam.gserviceaccount.com/keys/8f3a1c9d2e4b7f60",
    "gcp.audit.authentication_info.principal_email": "web-frontend@nexacorp-prod.iam.gserviceaccount.com",
    "gcp.audit.request_metadata.caller_ip": "185.220.101.47",
    "gcp.audit.request_metadata.caller_supplied_user_agent": "google-api-python-client/2.86.0",
    "gcp.audit.status.code": 0,
    "gcp.audit.status.message": "",
    "gcp.audit.response.key_id": "8f3a1c9d2e4b7f60",
    "gcp.audit.response.key_type": "USER_MANAGED",
    "gcp.audit.log_type": "ADMIN_ACTIVITY",
    "gcp.audit.severity": "NOTICE",
    "gcp.project.id": "nexacorp-prod",
    "action_result": "allowed",
  },
};

const gcpRoom = {
  id: "gcp-security",
  title: "Google Cloud Platform (GCP) Security Essentials",
  description:
    "Learn how to investigate Google Cloud Platform environments as a SOC analyst. Cover GCP's core building blocks (projects, resources, Cloud IAM, service accounts), the essential services (Compute Engine, Cloud Storage, VPC), how Cloud Audit Logs record every action across Admin Activity and Data Access logs, Security Command Center as GCP's built-in threat detector, and the most common real-world GCP attacks: over-privileged service accounts, stolen service-account keys, public Cloud Storage buckets, IAM privilege escalation via SetIamPolicy, metadata-server credential theft, and crypto-mining on Compute Engine. Throughout, GCP concepts are contrasted with their closest AWS equivalents to build on knowledge you may already have.",
  difficulty: "intermediate" as const,
  category: "Cloud Security",
  estimatedMinutes: 70,
  xp: 320,
  icon: "🌐",
  prerequisites: ["cloud-security-monitoring"],
  tasks: [
    // ── Reading 1: GCP basics + AWS contrast ────────────────────────────────
    {
      type: "reading" as const,
      id: "gcp-r1",
      heading: "What Is GCP, and How Does It Map to What You Already Know?",
      content:
        `**Google Cloud Platform (GCP)** is Google's cloud computing platform — the third major public cloud provider alongside AWS (Amazon Web Services) and Microsoft Azure. Like the others, GCP lets an organization rent computing power, storage, and networking from Google's data centers instead of owning physical servers. If you already understand AWS or Azure security, GCP will feel very familiar in concept, even though almost every name is different.\n\n` +
        `**The GCP Resource Hierarchy**\n\n` +
        `Everything in GCP lives inside a **project** — a container that holds resources (virtual machines, storage buckets, databases, networks) and is the basic unit of billing, permissions, and isolation. A **project** in GCP is the rough equivalent of an **AWS account**: it is the boundary a SOC analyst usually investigates within. Projects can be grouped under **folders**, and folders roll up under a single **organization** (typically tied to a company's domain, like nexacorp.com) — this is conceptually similar to AWS Organizations grouping multiple AWS accounts. A **resource** is any object you create inside a project: a virtual machine, a storage bucket, a database instance, a network. Every resource has a unique **resource name** (for example, projects/nexacorp-prod/zones/us-central1-a/instances/web-01) that pinpoints exactly what it is and which project it belongs to — this full resource name is what you will see again and again inside audit logs.\n\n` +
        `**Why the Terminology Difference Matters for a SOC Analyst**\n\n` +
        `Many organizations run workloads across more than one cloud provider, and analysts frequently move between AWS, Azure, and GCP tickets in the same shift. Confusing an AWS "IAM role" (a temporary, assumable identity) with a GCP "service account" (a persistent, non-human identity with its own permanent identity and optional keys) is a common and costly mistake early in a GCP investigation — the two behave differently, and that difference is exactly what several of the attacks later in this room depend on.\n\n` +
        `**GCP's Three Core Services Every Analyst Must Know**\n\n` +
        `- **Compute Engine** — GCP's virtual machine service, the equivalent of AWS EC2. Compute Engine instances ("VMs") run applications exactly like a physical server would.\n\n` +
        `- **Cloud Storage** — GCP's object storage service, the equivalent of AWS S3. Data is organized into **buckets**, which can be configured private or, dangerously, public to the entire internet.\n\n` +
        `- **VPC (Virtual Private Cloud)** — GCP also uses the name VPC for its private, isolated network layer, just like AWS. A GCP VPC has subnets and firewall rules that control which traffic is allowed in and out, similar to AWS Security Groups.\n\n` +
        `Just as with AWS, the SOC analyst's core job in GCP is to read the audit trail of **API calls** — every action taken against a GCP project, from creating a virtual machine to changing a permission to downloading a file — and to recognize what's normal versus what's an attack in progress.`,
      codeExample:
        "GCP <-> AWS TERMINOLOGY CHEAT SHEET\n" +
        "=======================================================\n" +
        "GCP Concept                AWS Equivalent\n" +
        "-------------------------------------------------------\n" +
        "Project                    AWS Account\n" +
        "Organization               AWS Organizations (root)\n" +
        "Compute Engine (VM)        EC2 instance\n" +
        "Cloud Storage bucket       S3 bucket\n" +
        "VPC                        VPC\n" +
        "Cloud IAM                  IAM\n" +
        "Service Account            IAM Role (closest analogy,\n" +
        "                           but persistent, not assumed)\n" +
        "Cloud Audit Logs           CloudTrail\n" +
        "Security Command Center    GuardDuty + Security Hub\n" +
        "VPC Flow Logs              VPC Flow Logs (same name!)\n" +
        "Metadata Server            IMDS (Instance Metadata\n" +
        "  (169.254.169.254)          Service, same IP!)\n" +
        "=======================================================\n\n" +
        "GCP RESOURCE HIERARCHY\n" +
        "=======================================================\n" +
        "  Organization (nexacorp.com)\n" +
        "     |\n" +
        "     +-- Folder (e.g. \"Production\")\n" +
        "            |\n" +
        "            +-- Project (nexacorp-prod)\n" +
        "                   |\n" +
        "                   +-- Resources (VMs, buckets, etc.)\n" +
        "=======================================================",
    },

    // ── Reading 2: Cloud IAM & service accounts ─────────────────────────────
    {
      type: "reading" as const,
      id: "gcp-r2",
      heading: "Cloud IAM and Service Accounts: GCP's Permission Model",
      content:
        `**Cloud IAM** is GCP's system for controlling who can do what, exactly like AWS IAM. But GCP's permission model is built around three layers that are worth understanding precisely, because attackers exploit the gaps between them.\n\n` +
        `**Members, Roles, and Bindings**\n\n` +
        `A **member** (also called a principal) is any identity that can be granted access — a human Google account (like j.smith@nexacorp.com), a **service account**, a Google group, or even the special values allUsers (literally everyone on the internet, authenticated or not) and allAuthenticatedUsers (anyone with any Google account). A **role** is a named collection of **permissions** — for example, roles/storage.objectViewer bundles the permission to read objects in a bucket. GCP has three tiers of roles: **basic roles** (Owner, Editor, Viewer — broad, legacy, and dangerous if overused), **predefined roles** (narrower, service-specific, Google-curated, like roles/storage.objectViewer), and **custom roles** (an organization defines its own exact permission set). A **binding** connects a member to a role on a specific resource — this pairing (member + role + resource) is the fundamental unit you will see inside an IAM policy and inside audit logs, most importantly in the method call SetIamPolicy.\n\n` +
        `**Service Accounts: GCP's Non-Human Identity**\n\n` +
        `A **service account** is a special kind of account intended for applications and virtual machines rather than people — it has its own email-like identity (always ending in .iam.gserviceaccount.com) and its own set of granted permissions. This is GCP's closest analog to an AWS IAM role, but with one critical difference: a service account is a **persistent identity**, not something temporarily "assumed." A service account can authenticate in two ways: (1) by being **attached to a resource** (like a Compute Engine VM), in which case the VM can request short-lived credentials from the metadata server, similar to how an EC2 instance profile works; or (2) via a **service account key** — a long-lived JSON credential file that can be downloaded and used from absolutely anywhere on the internet, with no expiration unless manually revoked. This second option is functionally identical in risk to a leaked AWS IAM user access key: if a service account key JSON file is exposed (committed to a public code repository, left in a container image, emailed insecurely), an attacker can use it indefinitely until someone notices and deletes it.\n\n` +
        `**Why Over-Privileged Service Accounts Are GCP's #1 Real-World Risk**\n\n` +
        `In practice, the single most common GCP misconfiguration security teams find is a service account granted the basic **Editor** or even **Owner** role at the project level — far more access than the application actually needs — simply because it was the fastest way to make something work during development, and nobody ever narrowed it down afterward. Because service accounts don't have the same "this is clearly a human, and humans get MFA-prompted" visibility that user accounts do, over-privileged service accounts often go unnoticed for a very long time, making them an extremely attractive target: compromise one, and you may inherit sweeping project-wide permissions with a single stolen credential.`,
      codeExample:
        "IAM POLICY BINDING ANATOMY (simplified JSON)\n" +
        "=======================================================\n" +
        "{\n" +
        "  \"bindings\": [\n" +
        "    {\n" +
        "      \"role\": \"roles/storage.objectViewer\",\n" +
        "      \"members\": [\n" +
        "        \"serviceAccount:svc-data@nexacorp.iam.gserviceaccount.com\"\n" +
        "      ]\n" +
        "    }\n" +
        "  ]\n" +
        "}\n" +
        "  role:    which permission bundle\n" +
        "  members: which identities receive it\n" +
        "=======================================================\n\n" +
        "GCP ROLE TIERS -- LEAST TO MOST DANGEROUS IF MISUSED\n" +
        "=======================================================\n" +
        "Predefined role   roles/storage.objectViewer  (narrow,\n" +
        "                  scoped to one service)\n" +
        "Custom role       org-defined exact permission set\n" +
        "Basic role        roles/editor  (broad, most resources)\n" +
        "Basic role        roles/owner   (full control, incl.\n" +
        "                  IAM itself -- equivalent to AWS\n" +
        "                  AdministratorAccess)\n" +
        "=======================================================\n\n" +
        "SERVICE ACCOUNT AUTHENTICATION -- TWO PATHS\n" +
        "=======================================================\n" +
        "1. Attached to a VM   -> short-lived creds via metadata\n" +
        "                         server (like an EC2 instance\n" +
        "                         profile -- safer)\n" +
        "2. Downloaded JSON key -> long-lived, works from ANYWHERE\n" +
        "                          until manually revoked (like a\n" +
        "                          leaked AWS access key -- risky)\n" +
        "=======================================================",
    },

    // ── Reading 3: Cloud Audit Logs & Security Command Center ───────────────
    {
      type: "reading" as const,
      id: "gcp-r3",
      heading: "Cloud Audit Logs and Security Command Center: GCP's Audit Trail and Threat Detector",
      content:
        `**Cloud Audit Logs** is GCP's audit-logging service — the direct equivalent of AWS CloudTrail. Nearly every action taken in a GCP project, whether through the web Console, the gcloud command-line tool, or an application calling a GCP API directly, generates an entry in Cloud Audit Logs. Just like CloudTrail, each entry answers who did it, what they did, where from, when, and whether it succeeded.\n\n` +
        `**The Four Types of Cloud Audit Logs**\n\n` +
        `GCP splits audit activity into four log types, and knowing which is which is essential for a SOC analyst: **Admin Activity logs** record configuration and metadata changes — creating a VM, changing an IAM policy, creating a service account key. These are ALWAYS enabled and cannot be turned off, similar to AWS management events. **Data Access logs** record who accessed data — reading an object from a Cloud Storage bucket, querying a BigQuery table. Critically, Data Access logs are NOT enabled by default for most services (except for a few, like BigQuery) because of their high volume — this is the exact same visibility gap as AWS S3 data events not being logged by default, and it means a SOC analyst investigating a suspected data download may find no logs at all unless Data Access logging was explicitly turned on in advance. **System Event logs** record actions GCP itself takes automatically (like automatically restarting a VM after a hardware failure) — these are always enabled and rarely security-relevant. **Policy Denied logs** record when a request was blocked by a security policy (like an Organization Policy or VPC Service Controls) — these are extremely valuable for spotting an attacker's failed attempts to escalate access or exfiltrate data.\n\n` +
        `**Where Cloud Audit Logs Go**\n\n` +
        `Cloud Audit Log entries are written into **Cloud Logging** (GCP's centralized logging service) and can be routed via a **log sink** to BigQuery, Cloud Storage, or exported to an external SIEM in near-real time — this is exactly analogous to CloudTrail delivering to an S3 bucket and then a SIEM. Every entry includes a gcp.audit.log_type field telling you which of the four categories it belongs to (ADMIN_ACTIVITY, DATA_ACCESS, SYSTEM_EVENT, or POLICY_DENIED).\n\n` +
        `**Security Command Center (SCC): GCP's Built-In Threat Detector**\n\n` +
        `**Security Command Center** is GCP's managed security and risk platform — think of it as GCP's combined answer to AWS GuardDuty (automated threat detection) and AWS Security Hub (centralized findings and posture management). SCC continuously analyzes Cloud Audit Logs, VPC Flow Logs, and other signals, and automatically raises findings for things like publicly-exposed Cloud Storage buckets, anomalous IAM grants, leaked service account credentials being used, and cryptocurrency-mining process behavior on a Compute Engine VM. Like GuardDuty, SCC findings arrive pre-scored with a severity and category, making them an excellent starting point for triage — but exactly as with GuardDuty, the underlying Cloud Audit Log entries are still where the deep investigation actually happens.\n\n` +
        `**VPC Flow Logs in GCP**\n\n` +
        `GCP's **VPC Flow Logs** use the identical name to their AWS counterpart and serve the same purpose: capturing connection metadata (source IP, destination IP, ports, protocol, bytes, and whether traffic was allowed or denied) flowing through a VPC, without capturing payload content. This is your network-layer view whenever the audit log alone doesn't tell the full story.`,
      codeExample:
        "THE FOUR TYPES OF CLOUD AUDIT LOGS\n" +
        "=======================================================\n" +
        "Log Type          Enabled By Default?   Example\n" +
        "-------------------------------------------------------\n" +
        "Admin Activity     ALWAYS (cannot        SetIamPolicy,\n" +
        "                   be disabled)          instances.insert\n" +
        "Data Access        NO (must enable,      storage.objects.get,\n" +
        "                   except BigQuery)      bigquery.jobs.query\n" +
        "System Event       ALWAYS                Automatic VM restart\n" +
        "Policy Denied      ALWAYS                Blocked by Org Policy\n" +
        "                                         or VPC Service Ctrl\n" +
        "=======================================================\n\n" +
        "SAMPLE CLOUD AUDIT LOG ENTRY (simplified)\n" +
        "=======================================================\n" +
        "{\n" +
        "  \"gcp.audit.method_name\": \"SetIamPolicy\",\n" +
        "  \"gcp.audit.service_name\":\n" +
        "     \"cloudresourcemanager.googleapis.com\",\n" +
        "  \"gcp.audit.resource_name\": \"projects/nexacorp-prod\",\n" +
        "  \"gcp.audit.authentication_info.principal_email\":\n" +
        "     \"svc-data@nexacorp.iam.gserviceaccount.com\",\n" +
        "  \"gcp.audit.request_metadata.caller_ip\":\n" +
        "     \"185.220.101.47\",\n" +
        "  \"gcp.audit.log_type\": \"ADMIN_ACTIVITY\"\n" +
        "}\n" +
        "=======================================================",
    },

    // ── Reading 4: Common GCP attacks ───────────────────────────────────────
    {
      type: "reading" as const,
      id: "gcp-r4",
      heading: "The Six Attacks Every GCP-Facing SOC Analyst Must Recognize",
      content:
        `Real-world GCP incidents tend to cluster around a small set of repeatable patterns. Knowing these six by name — and by their audit-log signature — lets you triage the majority of GCP alerts quickly.\n\n` +
        `**1. Over-Privileged Service Accounts** — as covered in the IAM reading, a service account holding roles/editor or roles/owner at the project level when it only needs narrow access to one bucket or one API. This isn't an "attack" on its own, but it is the single biggest force-multiplier for every other attack on this list: compromise an over-privileged service account's credentials, and the attacker inherits everything it can do.\n\n` +
        `**2. Service-Account Key Theft** — an attacker creates a new, unauthorized JSON key for an existing service account (google.iam.admin.v1.CreateServiceAccountKey) or steals an already-existing key file from a leaked code repository, a misconfigured container image, or a compromised developer laptop. Because a service account key never expires on its own, this grants indefinite external access — the GCP equivalent of a leaked AWS IAM user access key.\n\n` +
        `**3. Public Cloud Storage Buckets** — a bucket's IAM policy grants roles/storage.objectViewer (or broader) to the special member allUsers or allAuthenticatedUsers, making some or all objects readable by anyone on the internet, no credentials required. Exactly like AWS S3 misconfigurations, this is one of the most common and most damaging real-world cloud data breaches, and because it's a permission on the bucket itself, it can generate no meaningful alert unless the org specifically checks for public bindings (SCC has a dedicated finding, Public bucket ACL, for exactly this).\n\n` +
        `**4. IAM Privilege Escalation via SetIamPolicy** — an identity that has permission to modify a resource's IAM policy (even if it does not itself hold that role) can call SetIamPolicy to grant itself — or any other identity it controls — a far more powerful role, such as roles/owner. This is GCP's direct equivalent of AWS's iam:PutRolePolicy / CreatePolicyVersion privilege-escalation pattern: the attacker never needed "grant myself Owner" permission directly, only the narrower "modify this resource's IAM bindings" permission (resourcemanager.projects.setIamPolicy), which is often overlooked when scoping custom roles.\n\n` +
        `**5. Metadata-Server Credential Theft** — every Compute Engine VM can reach the same special, non-routable address used by AWS EC2 — 169.254.169.254 — called the **metadata server**. Applications use it to retrieve instance information, including the live, short-lived access token for the VM's attached service account. If an attacker can trigger an unintended outbound request to this address from a vulnerable application (again, most commonly via SSRF — Server-Side Request Forgery), they can steal the service account's active token and use it from anywhere, exactly as with AWS IMDS. GCP's metadata server requires a specific header (Metadata-Flavor: Google) on every request, which raises the bar slightly compared to older AWS IMDSv1, but a vulnerable app that blindly proxies attacker-controlled requests can still be tricked into adding it.\n\n` +
        `**6. Crypto-Mining on Compute Engine** — following any of the credential-theft patterns above, a very common next step is launching a large number of powerful (often GPU-accelerated) Compute Engine VMs, frequently in a region the victim organization doesn't normally use, to run cryptocurrency-mining software at the victim's expense. This maps to Security Command Center's Malware: Cryptomining Detected finding and, just like on AWS, is often first noticed via an unexpected billing spike rather than a security alert.\n\n` +
        `Notice the common thread: attacks 2, 4, 5, and 6 very often chain together in a single incident — a stolen key or stolen metadata-server token (2 or 5) is used to escalate privileges (4), and the newly-gained access is then used to spin up mining infrastructure (6) or exfiltrate data from a bucket (3). This exact chain is what you will investigate in the two log-analysis exercises later in this room.`,
      codeExample:
        "SIX COMMON GCP ATTACKS -- QUICK REFERENCE\n" +
        "=======================================================\n" +
        "1. Over-privileged service account\n" +
        "   -> roles/editor or roles/owner granted too broadly\n" +
        "\n" +
        "2. Service-account key theft\n" +
        "   -> CreateServiceAccountKey (unauthorized) or leaked\n" +
        "      JSON key file -- works forever until revoked\n" +
        "\n" +
        "3. Public Cloud Storage bucket\n" +
        "   -> roles/storage.objectViewer granted to allUsers\n" +
        "\n" +
        "4. IAM privilege escalation via SetIamPolicy\n" +
        "   -> attacker with setIamPolicy permission grants\n" +
        "      themselves roles/owner\n" +
        "\n" +
        "5. Metadata-server credential theft (SSRF)\n" +
        "   -> GET http://169.254.169.254/computeMetadata/v1/\n" +
        "      instance/service-accounts/default/token\n" +
        "      Header: Metadata-Flavor: Google\n" +
        "\n" +
        "6. Crypto-mining on Compute Engine\n" +
        "   -> burst of large/GPU VM instances.insert calls,\n" +
        "      often in an unused region\n" +
        "=======================================================\n\n" +
        "TYPICAL CHAINED ATTACK SEQUENCE\n" +
        "=======================================================\n" +
        "02:52  CreateServiceAccountKey  Unauthorized key minted\n" +
        "02:47  SetIamPolicy             Self-granted roles/owner\n" +
        "03:05  storage.objects.get      Public-bucket data exfil\n" +
        "03:20+ instances.insert (many)  Crypto-mining VM burst\n" +
        "=======================================================",
    },

    // ── Question 1 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "gcp-q1",
      question:
        "A file was downloaded from a Cloud Storage bucket last night, but Data Access audit logging was never explicitly enabled for Cloud Storage in this project. What is the most accurate statement about what the SOC will find?",
      options: [
        "Cloud Audit Logs will still show the storage.objects.get call because all Cloud Storage activity is logged by default",
        "The storage.objects.get Data Access event was very likely NOT logged, even though Admin Activity events (like changing the bucket's IAM policy) would still appear, since Data Access logs are not enabled by default for most services",
        "GCP does not support logging of any Cloud Storage activity under any configuration",
        "Security Command Center automatically captures the download regardless of Cloud Audit Logs settings",
      ],
      answer: 1,
      explanation:
        "Data Access logs (which cover read/write operations on the data itself, like storage.objects.get) are NOT enabled by default for most GCP services because of their volume — an administrator must explicitly turn them on. Admin Activity logs (configuration and permission changes, like SetIamPolicy) are ALWAYS enabled and cannot be turned off. This is the exact same visibility gap as AWS S3 data events being off by default, and a SOC analyst should always confirm whether Data Access logging is enabled before assuming the absence of a storage.objects.get event means nobody downloaded anything.",
      xp: 20,
    },

    // ── Question 2 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "gcp-q2",
      question:
        "A Compute Engine VM has a service account attached to it. A SOC analyst notices that service account's credentials being used to call GCP APIs from a source IP address in Russia, while the VM itself is confirmed still running normally inside GCP in us-central1. What does this most likely indicate?",
      options: [
        "This is normal — service account credentials automatically work from anywhere in the world by design",
        "The VM's short-lived metadata-server token was likely stolen (for example via an SSRF attack) and is now being used by an attacker from outside GCP",
        "GCP load-balances API traffic through international points of presence, so varying source IPs are expected",
        "The service account must be misconfigured to allow global access, which is a normal and harmless setting",
      ],
      answer: 1,
      explanation:
        "A short-lived access token retrieved from a VM's metadata server is meant to be used only by that VM, from inside GCP's own network. Seeing the same service account's token used from an unexpected external IP address is the classic signature of metadata-server credential theft (commonly via SSRF), directly analogous to the AWS IMDS credential-theft pattern, and should be treated as a likely active compromise.",
      xp: 25,
    },

    // ── Question 3 ────────────────────────────────────────────────────────
    {
      type: "question" as const,
      id: "gcp-q3",
      question:
        "Which Cloud Audit Logs method call, when it grants a broad role like roles/owner to an unexpected member, should ALWAYS be treated as a critical-severity event requiring immediate investigation?",
      options: [
        "compute.instances.list — listing Compute Engine VMs",
        "SetIamPolicy — replacing or modifying a resource's IAM policy bindings",
        "storage.buckets.get — reading a bucket's metadata",
        "cloudresourcemanager.projects.get — reading basic project information",
      ],
      answer: 1,
      explanation:
        "SetIamPolicy changes who can do what on a resource — it is the method call behind both legitimate administration AND IAM privilege escalation attacks. When it grants a broad role (roles/owner or roles/editor) to a service account or member that shouldn't hold it, this should always trigger critical-severity review, exactly like AWS's AttachUserPolicy or PutRolePolicy with an admin policy. The other three calls listed are read-only, extremely common, and normally benign background activity.",
      xp: 20,
    },

    // ── Log Analysis 1: SetIamPolicy privilege escalation ───────────────────
    {
      type: "log_analysis" as const,
      id: "gcp-la1",
      heading: "Investigating an IAM Privilege Escalation via SetIamPolicy",
      context:
        "You are a SOC analyst at NexaCorp. Security Command Center raised a finding overnight for an anomalous IAM change in the nexacorp-prod project. The service account in question, svc-data, is normally used only by an internal ETL (data pipeline) job and should hold nothing beyond roles/bigquery.dataViewer. Five minutes earlier, a suspicious CreateServiceAccountKey event had also fired for the same service account (you will examine that event later in this room). Review the Cloud Audit Log entry below, generated at 02:47 UTC.",
      event: setIamPolicyEvent,
      questions: [
        {
          question:
            "The event shows gcp.audit.method_name 'SetIamPolicy' targeting resource_name 'projects/nexacorp-prod', called by principal_email svc-data@nexacorp.iam.gserviceaccount.com from caller_ip 185.220.101.47 (an external Tor exit node). The response.bindings show the service account now holds BOTH roles/owner AND roles/editor. Why is this combination especially alarming?",
          options: [
            "SetIamPolicy calls are purely informational and never actually change permissions until manually approved",
            "The service account, which should only have narrow BigQuery read access, granted itself roles/owner — GCP's most powerful basic role, equivalent to AWS AdministratorAccess — meaning it can now read, modify, or delete anything in the project, including further changing IAM itself",
            "roles/owner only applies to billing settings and has no bearing on data or compute resources",
            "This is expected behavior because all service accounts automatically receive roles/owner when first created",
          ],
          answer: 1,
          explanation:
            "roles/owner is GCP's most powerful basic role — it includes every permission in the project, including the ability to modify IAM policy itself, delete resources, and manage billing. A service account that should only be reading BigQuery data suddenly holding roles/owner is a textbook privilege-escalation outcome: the attacker used SetIamPolicy to grant themselves (via this service account) unrestricted control of the entire nexacorp-prod project.",
          xp: 25,
        },
        {
          question:
            "The caller_ip is 185.220.101.47, a known Tor exit node, and gcp.audit.status.code is 0 with an empty status.message. What does this combination confirm about the outcome of the request?",
          options: [
            "status.code 0 means the request failed and was rejected by Cloud IAM",
            "status.code 0 (with no error message) confirms the SetIamPolicy call succeeded — the privilege escalation was NOT blocked, and the attacker now holds Owner-level access to the project from external, anonymized infrastructure",
            "The Tor exit node IP is irrelevant since GCP automatically blocks all Tor traffic",
            "status.code fields in GCP audit logs only apply to billing operations",
          ],
          answer: 1,
          explanation:
            "In Cloud Audit Logs, status.code 0 (matching gRPC's OK status) with no populated status.message means the API call succeeded. Combined with the external Tor exit node source IP, this confirms an external attacker successfully executed the privilege-escalation call — this is now a confirmed, active project-wide compromise, not merely an attempted one.",
          xp: 25,
        },
        {
          question:
            "Given this is a confirmed successful privilege escalation to roles/owner from an external Tor IP, what should the analyst's immediate response be?",
          options: [
            "Wait for the next scheduled access review to catch and correct the over-broad role",
            "Immediately revoke the malicious IAM binding (remove roles/owner and roles/editor from svc-data), disable or delete any unauthorized service-account keys, audit every action taken by this identity and this source IP since the escalation, and rotate/re-scope the service account to its original narrow role",
            "Simply delete the svc-data service account entirely with no further investigation, since deleting it will automatically undo every action it performed",
            "Block the Tor exit node IP at the VPC firewall level and consider the incident resolved",
          ],
          answer: 1,
          explanation:
            "A confirmed, successful privilege escalation to project-wide Owner access requires full containment: remove the malicious IAM bindings immediately (Cloud IAM policy changes take effect right away), find and disable/delete any unauthorized service-account keys created around the same time, and pull the complete Cloud Audit Log history for this identity and IP going forward from the escalation to determine everything the attacker did while holding Owner access (they could have created new IAM bindings, exfiltrated data, or launched resources). Deleting the service account alone does not undo prior actions, and blocking one Tor IP does nothing against an attacker who can trivially switch exit nodes.",
          xp: 30,
        },
      ],
    },

    // ── Log Analysis 2: public bucket storage.objects.get exfil ─────────────
    {
      type: "log_analysis" as const,
      id: "gcp-la2",
      heading: "Investigating Data Exfiltration from a Public Cloud Storage Bucket",
      context:
        "Continuing the same incident timeline: 18 minutes after the confirmed SetIamPolicy privilege escalation, Cloud Logging recorded a Data Access log entry for a Cloud Storage bucket. This bucket, nexacorp-customer-exports, was supposed to be reachable only by internal analytics service accounts, but its IAM policy had been altered to grant roles/storage.objectViewer to allUsers. Review the event below.",
      event: publicBucketExfilEvent,
      questions: [
        {
          question:
            "The event shows gcp.audit.authentication_info.principal_email as 'allUsers' and storage.bucket.iam_binding.members includes 'allUsers'. What does the identity value 'allUsers' specifically mean in GCP IAM?",
          options: [
            "'allUsers' refers to every employee inside NexaCorp's Google Workspace domain only",
            "'allUsers' is a special GCP member representing literally anyone on the internet, authenticated or not — meaning the bucket object was readable by any anonymous caller with the object's URL, with no GCP account or credentials required at all",
            "'allUsers' is a placeholder value that GCP uses when the true caller identity could not be determined",
            "'allUsers' only applies to Compute Engine VMs, never to Cloud Storage buckets",
          ],
          answer: 1,
          explanation:
            "'allUsers' is one of GCP's special IAM members representing every person on the internet — anonymous, unauthenticated, no Google account required. When a bucket's IAM policy binds a role like roles/storage.objectViewer to allUsers, any object in that bucket becomes readable by anyone who has (or can guess) the URL. This is the direct GCP equivalent of an AWS S3 bucket policy granting access to Principal: '*' or the AllUsers group.",
          xp: 25,
        },
        {
          question:
            "This event's gcp.audit.log_type is 'DATA_ACCESS' rather than 'ADMIN_ACTIVITY', and the request came from caller_ip 91.108.56.19 (Russia) using a python-requests user agent. Why is the log_type field itself an important investigative clue here?",
          options: [
            "DATA_ACCESS log entries are less trustworthy than ADMIN_ACTIVITY entries and should be ignored",
            "Because this is a DATA_ACCESS event, it means Data Access logging happened to be explicitly enabled for this bucket — without that configuration, this exact download might have left NO audit trail at all, even though the bucket's public IAM binding (an ADMIN_ACTIVITY change) would still have been logged",
            "The log_type field has no bearing on the investigation — only the source IP matters",
            "DATA_ACCESS entries are only generated for BigQuery, never for Cloud Storage",
          ],
          answer: 1,
          explanation:
            "This event landing in Data Access logs (rather than being invisible) tells the analyst that Data Access logging was fortunately turned on for this bucket — a configuration that is NOT the default. If it had not been enabled, the analyst would only see that the bucket's IAM policy was changed (an Admin Activity event, always logged) but would have zero visibility into who actually read which objects afterward — a significant blind spot to flag for remediation regardless of this specific incident's outcome.",
          xp: 25,
        },
        {
          question:
            "Given a 46 MB customer export file was successfully downloaded (status.code 0) by an anonymous internet caller from Russia, what is the correct immediate action?",
          options: [
            "No action needed since storage.objects.get is a read-only, low-impact operation by definition",
            "Immediately remove the allUsers binding from the bucket's IAM policy to stop further exposure, treat this as confirmed data exfiltration of customer data (triggering incident response and potential breach-notification obligations), and audit the bucket's full Data Access history to determine how many other callers accessed it while it was public",
            "Simply rename the bucket so the old public URL no longer resolves, and consider the incident closed",
            "Wait for Security Command Center to automatically revoke the public binding, since SCC has write access to fix findings by default",
          ],
          answer: 1,
          explanation:
            "A read-only API call can still represent serious data exfiltration when the object contains customer PII, as here. The bucket's public IAM binding must be removed immediately to stop ongoing exposure (renaming the bucket does not un-expose already-downloaded data and is not a substitute for fixing the IAM policy). Because a confirmed download of a customer data file by an anonymous external party occurred, this triggers full incident response and likely breach-notification requirements — and the analyst must review the complete Data Access history for the bucket to determine whether other anonymous or unauthorized callers accessed it during the exposure window. Note also that Security Command Center only raises findings by default; it does not auto-remediate unless a response automation is explicitly configured.",
          xp: 30,
        },
      ],
    },

    // ── Analyst Choice: benign CI/CD service account activity FP trap ───────
    {
      type: "analyst_choice" as const,
      id: "gcp-ac1",
      heading: "Verdict: Is This Service Account Activity Suspicious?",
      scenario:
        "A SIEM correlation rule flagged an API call made by svc-cicd, a service account used by NexaCorp's automated deployment pipeline. The rule fired simply because the call originated from a service account with broad compute permissions. Review the event below: it occurred at 09:00 UTC, well after the earlier incident was contained, IAM bindings rolled back, and unauthorized service-account keys revoked. The source IP (10.128.0.14) is an internal GKE (Google Kubernetes Engine) node IP inside the same project, and the method is compute.instances.list, called via gcloud as part of a routine, scheduled deployment health check. Is this event suspicious?",
      event: benignServiceAccountEvent,
      correct_verdict: "false_positive",
      explanation:
        "This is a textbook false positive. compute.instances.list is a read-only method that simply enumerates VM instances — it cannot create, modify, or delete anything, and it is one of the most common calls made by deployment tooling, monitoring agents, and CI/CD pipelines to check the current state of infrastructure before or after a deploy. The source IP (10.128.0.14, an internal GKE node private address) and user agent (google-cloud-sdk gcloud/462.0.1) both indicate routine, internal, automated activity, entirely different from the external Tor exit node seen during the actual compromise. gcp.audit.log_type is ADMIN_ACTIVITY (list/describe calls do appear here) but the method itself carries no write capability. A correlation rule that fires purely on 'this service account has broad permissions' — rather than on the specific action taken and its source — will generate significant noise.",
      fp_trap:
        "It's tempting to escalate this because svc-cicd, like svc-data in the earlier incident, is a service account with elevated compute permissions, and 'broad permissions + recent incident in the project' can feel like enough reason to treat any of its activity as risky. But permission scope alone is not evidence of compromise — the specific method (read-only list, not a write/IAM operation), the source (a trusted internal IP, not external infrastructure), and the context (routine scheduled automation, not an unusual one-off action) all point to benign activity. Escalating every action from every broadly-permissioned service account, regardless of what the action actually does, leads to alert fatigue and pulls attention away from genuinely dangerous write/IAM operations.",
      xp: 30,
    },

    // ── Matching: GCP service <-> purpose / AWS equivalent ──────────────────
    {
      type: "matching" as const,
      id: "gcp-m1",
      heading: "Match Each GCP Service or Concept to Its Purpose and AWS Equivalent",
      instructions:
        "Match each GCP service or log source on the left to its correct description on the right.",
      pairs: [
        {
          id: "cloudiam",
          left: "Cloud IAM",
          right: "Controls who (members) can do what (roles/permissions) on which resource (bindings); the equivalent of AWS IAM",
        },
        {
          id: "serviceaccount",
          left: "Service Account",
          right: "A persistent, non-human identity used by applications and VMs; can authenticate via an attached resource or a long-lived downloadable JSON key — the closest GCP equivalent to an AWS IAM role",
        },
        {
          id: "computeengine",
          left: "Compute Engine",
          right: "GCP's virtual machine service; each VM can reach the metadata server at 169.254.169.254 to retrieve its service account's live access token — the equivalent of AWS EC2 and IMDS",
        },
        {
          id: "cloudstorage",
          left: "Cloud Storage",
          right: "Object storage organized into buckets; a bucket bound to the allUsers member becomes readable by anyone on the internet — the equivalent of AWS S3",
        },
        {
          id: "cloudauditlogs",
          left: "Cloud Audit Logs",
          right: "Records every API call made in a project across four log types (Admin Activity, Data Access, System Event, Policy Denied) — the equivalent of AWS CloudTrail",
        },
        {
          id: "scc",
          left: "Security Command Center",
          right: "Managed threat-detection and posture-management platform that analyzes audit logs and flow logs to raise pre-scored findings — the equivalent of AWS GuardDuty plus Security Hub",
        },
      ],
      explanation:
        "These six building blocks form the backbone of nearly every GCP security investigation, and each has a direct AWS parallel: Cloud IAM defines the permission boundaries (like AWS IAM), service accounts are GCP's persistent non-human identities (closest to AWS IAM roles, though not temporarily assumed), Compute Engine and Cloud Storage are the most commonly attacked resource types (paralleling EC2 and S3), Cloud Audit Logs is the ground-truth audit trail (paralleling CloudTrail), and Security Command Center is the automated first-pass detector (paralleling GuardDuty and Security Hub combined). Recognizing both the GCP name and its closest AWS analog lets an analyst who already knows one cloud provider ramp up quickly on the other.",
      xp: 40,
    },

    // ── Reading 5: How to investigate GCP audit logs in a SIEM ──────────────
    {
      type: "reading" as const,
      id: "gcp-r5",
      heading: "How to Read and Investigate GCP Audit Log Events in a SIEM",
      content:
        `Once Cloud Audit Logs are forwarded into a SIEM, they typically appear as structured fields prefixed with something like gcp.audit.* — the same fields you have been reviewing throughout this room. A consistent, repeatable workflow turns a wall of JSON into a fast investigation.\n\n` +
        `**Step 1 — Establish the WHO**\n\n` +
        `Start with gcp.audit.authentication_info.principal_email. Is this a human Google account (a person — check whether their normal working pattern matches), a service account ending in .iam.gserviceaccount.com (check whether it's meant to run from a specific VM or pipeline only), or one of the special anonymous members allUsers / allAuthenticatedUsers (an immediate red flag if seen accessing anything other than intentionally public resources)? The identity tells you what kind of credential compromise, if any, you might be dealing with.\n\n` +
        `**Step 2 — Establish the WHERE**\n\n` +
        `Check gcp.audit.request_metadata.caller_ip. Is it an internal GCP range (typically the 10.x private ranges used by Compute Engine or GKE nodes within your VPC), a known corporate office IP, or an unfamiliar external address? Cross-reference against threat intelligence — Tor exit nodes, known malicious IP lists, and unusual countries for your organization are all red flags, exactly as with CloudTrail investigations. Also check gcp.audit.request_metadata.caller_supplied_user_agent: legitimate automation has consistent, expected user agents (google-cloud-sdk gcloud/x.x.x, google-api-python-client, Terraform); a mismatched or unusual user agent for a given identity's normal behavior is worth investigating.\n\n` +
        `**Step 3 — Establish the WHAT and the OUTCOME**\n\n` +
        `Read gcp.audit.method_name and gcp.audit.service_name together — this tells you the exact action and which API/service it targeted. Then always check gcp.audit.status.code: a value of 0 means the call succeeded; a non-zero value (commonly 7 for PERMISSION_DENIED, 5 for NOT_FOUND) means it was rejected. A flood of PERMISSION_DENIED (status.code 7) calls from one identity is a strong signal of an attacker probing for working permissions — the same pattern you'd flag as repeated AccessDenied in CloudTrail.\n\n` +
        `**Step 4 — Pivot and Correlate**\n\n` +
        `Once you have one suspicious event, pivot in your SIEM on the same gcp.audit.request_metadata.caller_ip and the same principal_email across a wider time window (hours to days). Attackers rarely perform just one action — look for the full sequence: initial access (how was the credential obtained — a leaked key, a stolen metadata-server token, a phished human account?), reconnaissance (list/get calls used to map out the project), privilege escalation (SetIamPolicy or CreateServiceAccountKey), and the actual objective (data access from a bucket, or resource creation for crypto-mining). Also check the gcp.project.id — attackers sometimes deliberately target a less-monitored project, or one they've newly gained access to via an over-broad organization-level binding.\n\n` +
        `**Step 5 — Weigh Severity by Log Type and Action, Not Just Identity**\n\n` +
        `As you saw in the CI/CD false-positive exercise, the same broadly-permissioned service account can generate both benign and critical events. Always weigh: is this an ADMIN_ACTIVITY or DATA_ACCESS log_type, and within that, is the method_name read-only (list, get) or state-changing (create, delete, SetIamPolicy)? Does it touch IAM, service-account keys, or bucket public bindings (high blast radius) versus routine describe/list calls (low blast radius)? A fast mental checklist — WHO, WHERE, WHAT, OUTCOME, PATTERN — is enough to triage the overwhelming majority of GCP audit-log-based alerts within the first few minutes, and it maps almost one-to-one onto the CloudTrail triage process if you already know AWS.`,
      codeExample:
        "GCP AUDIT LOG TRIAGE CHECKLIST\n" +
        "=======================================================\n" +
        "1. WHO    gcp.audit.authentication_info.principal_email\n" +
        "          -> human account, service account, or the\n" +
        "             red-flag values allUsers / allAuthenticatedUsers?\n" +
        "\n" +
        "2. WHERE  gcp.audit.request_metadata.caller_ip / UA\n" +
        "          -> internal GCP range, known office IP, or\n" +
        "             unfamiliar/malicious external IP?\n" +
        "\n" +
        "3. WHAT   gcp.audit.method_name + service_name\n" +
        "          -> exact action + which API/service\n" +
        "\n" +
        "4. OUTCOME gcp.audit.status.code\n" +
        "          -> 0 = succeeded, non-zero = denied/failed\n" +
        "          -> a FLOOD of status.code 7 (PERMISSION_DENIED)\n" +
        "             = attacker probing\n" +
        "\n" +
        "5. PATTERN pivot on same caller_ip / principal_email\n" +
        "          across time -> recon -> privesc -> objective?\n" +
        "=======================================================\n\n" +
        "EXAMPLE SIEM QUERY (pseudo-syntax)\n" +
        "=======================================================\n" +
        "SELECT ts, method_name, service_name, caller_ip,\n" +
        "       principal_email, status_code\n" +
        "FROM gcp_audit_logs\n" +
        "WHERE caller_ip = '185.220.101.47'\n" +
        "  AND ts BETWEEN '2026-05-19T00:00:00Z'\n" +
        "             AND '2026-05-19T12:00:00Z'\n" +
        "ORDER BY ts ASC;\n" +
        "=======================================================",
    },

    // ── Flag: extract value from raw Cloud Audit Log block ──────────────────
    {
      type: "flag" as const,
      id: "gcp-f1",
      prompt:
        "Review the event above where an unauthorized JSON key was created for the svc-data service account minutes before the privilege escalation. What is the exact key_id value shown in gcp.audit.response.key_id for the newly created service account key? Enter it exactly as shown.",
      answer: "8f3a1c9d2e4b7f60",
      hint: "Look inside the raw block of the CreateServiceAccountKey event for the response.key_id field — this identifies the specific unauthorized credential the attacker minted.",
      xp: 25,
    },

    // ── Reading 6 (context for the flag event): metadata theft + key creation chain ──
    {
      type: "reading" as const,
      id: "gcp-r6",
      heading: "Metadata-Server Theft, Unauthorized Key Creation, and Why the Order of Events Matters",
      content:
        `The event referenced in the flag question above is the missing link that ties the whole incident timeline together: how did the attacker first get a foothold that let them later call SetIamPolicy from an external Tor IP?\n\n` +
        `**Reconstructing the Attack Chain**\n\n` +
        `Look closely at the CreateServiceAccountKey event: it was called by web-frontend@nexacorp-prod.iam.gserviceaccount.com — NOT by svc-data itself — but its target resource_name is a key belonging to svc-data. This is the signature of a classic **lateral privilege chain**: the attacker first compromised a public-facing web application (likely via an SSRF vulnerability reaching the Compute Engine metadata server, exactly as described in the earlier reading on metadata-server credential theft, stealing the web-frontend service account's live token). That web-frontend service account, in turn, had been over-permissioned with iam.serviceAccountKeys.create rights on OTHER service accounts in the project — a common but dangerous misconfiguration. Using that stolen token, the attacker minted a brand-new, long-lived JSON key (key_id 8f3a1c9d2e4b7f60) for the far more powerful svc-data service account. From that point forward, the attacker no longer needed the original stolen web-frontend token at all — they now held a standalone, indefinitely-valid credential for svc-data, which is exactly what was used minutes later, from an external Tor IP, to call SetIamPolicy and self-grant roles/owner.\n\n` +
        `**Why This Pattern Is So Dangerous**\n\n` +
        `This chain — compromise a low-value, internet-facing identity via SSRF, then use a narrow-but-overlooked permission (iam.serviceAccountKeys.create) to mint a fresh credential for a higher-value identity — lets an attacker "cash out" a temporary metadata-server foothold into a permanent, portable credential that works from anywhere, indefinitely. This is precisely why iam.serviceAccountKeys.create should be treated as a highly sensitive permission and restricted to only the humans and automation that genuinely need to mint keys — and why any CreateServiceAccountKey event targeting a DIFFERENT service account than the one making the call deserves immediate scrutiny.\n\n` +
        `**Defensive Best Practices Every SOC Should Verify**\n\n` +
        `- Disable service-account key creation at the organization level wherever possible (an Organization Policy constraint, iam.disableServiceAccountKeyCreation), forcing workloads to use attached, short-lived credentials instead\n` +
        `- Alert immediately and unconditionally on CreateServiceAccountKey, SetIamPolicy grants of roles/owner or roles/editor, and any Data Access to a bucket bound to allUsers or allAuthenticatedUsers\n` +
        `- Enable Data Access audit logging on Cloud Storage and other sensitive services, not just the always-on Admin Activity logs\n` +
        `- Enable Security Command Center Premium, including its Public bucket ACL and Anomalous IAM Grant findings\n` +
        `- Regularly review which service accounts hold basic roles (Owner/Editor) and replace them with narrowly-scoped predefined or custom roles`,
      codeExample:
        "FULL ATTACK CHAIN: SSRF -> STOLEN TOKEN -> NEW KEY -> PRIVESC\n" +
        "=======================================================\n" +
        "02:3x  SSRF against public web app on Compute Engine VM\n" +
        "       reaches metadata server, steals web-frontend\n" +
        "       service account's live access token\n" +
        "\n" +
        "02:42  CreateServiceAccountKey  Using the stolen token,\n" +
        "       attacker mints a NEW long-lived JSON key for the\n" +
        "       more powerful svc-data service account\n" +
        "       (key_id: 8f3a1c9d2e4b7f60)\n" +
        "\n" +
        "02:47  SetIamPolicy  Using the freshly minted svc-data key\n" +
        "       from an external Tor IP, attacker grants svc-data\n" +
        "       roles/owner on the entire project\n" +
        "\n" +
        "03:05  storage.objects.get  Owner-level access used to\n" +
        "       read/expose customer export bucket\n" +
        "=======================================================\n\n" +
        "WHY THE PERMISSION iam.serviceAccountKeys.create MATTERS\n" +
        "=======================================================\n" +
        "A compromised LOW-value identity that can mint keys for a\n" +
        "HIGH-value identity effectively inherits that identity's\n" +
        "power, permanently, until the key is revoked. SOC rule of\n" +
        "thumb: any CreateServiceAccountKey call targeting a\n" +
        "DIFFERENT service account than the caller = automatic\n" +
        "HIGH/CRITICAL severity, investigate immediately.\n" +
        "=======================================================",
    },
  ],
};

export default [gcpRoom];
