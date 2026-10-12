import type { ScenarioBundle, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { gcpSaKeyTheftScenarioEvents } from "./gcpSaKeyTheft.events";
/**
 * Scenario pack: "Minted Key — Service-Account Key Theft on GCP" (ADVANCED)
 *
 * A GCP-native credential-theft case that never touches an endpoint and lives
 * entirely in Cloud Audit Logs (Admin Activity + Data Access) plus two Event Threat
 * Detection findings delivered through Security Command Center. It fills the platform's GCP gap: where the AWS/Azure
 * packs are dense, GCP identity abuse has been thin.
 *
 * TEACHING ARC — the quiet pivot vs. the blast radius:
 *   THE QUIET PIVOT (Admin Activity log): an attacker holding a compromised
 *   developer identity (t.levy@rocketstack.io, phished gcloud creds) enumerates the
 *   project, then calls google.iam.admin.v1.CreateServiceAccountKey on an
 *   over-permissioned service account. That single admin-activity line mints a
 *   long-lived, user-managed JSON key — a persistence foothold that keeps working
 *   after the developer's password is reset. It is the easiest event to scroll
 *   past and the one the whole case turns on.
 *
 *   THE BLAST RADIUS (Data Access log): once the key exists, every subsequent
 *   call carries principalEmail = the SERVICE ACCOUNT, not the developer — and
 *   they arrive from the SAME external caller IP. The SA lists and reads objects
 *   in a production bucket, pulls a Secret Manager secret, all from an address
 *   that has never hosted it. That is the reach.
 *
 * THE KEY TELL: the from-outside-GCP request_metadata.caller_ip on a service
 * account whose real work only ever runs inside the pipeline, correlated with a
 * user-managed key that was minted minutes earlier by a developer identity.
 *
 * BENIGN CONTROL (gcpkey_00): the day before, the Terraform CI service account
 * (terraform-ci-sa) creates a user-managed key AS PART OF a normal apply — the
 * SAME CreateServiceAccountKey method — but from a Google Cloud Build address,
 * with a Terraform user agent, inside a change-tracked pipeline run. Same
 * "new SA key" shape, opposite verdict. The lesson: minting a key is not the
 * incident; minting one from off-network on a developer identity, then driving
 * the target SA from the internet, is.
 *
 * SOURCES: "GCP Cloud Audit Logs" (Admin Activity / Data Access, rendered as the native
 * LogEntry) and "Google Security Command Center" (the Event Threat Detection Findings,
 * as SCC Pub/Sub notifications). The ETD categories are the real catalogue names; ETD
 * has no finding for Cloud Storage object reads, so the drain is evidenced only in the
 * Data Access log.
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */


export function buildGcpSaKeyTheftScenario(
  scenarioId = "gcp-sa-key-theft-2026",
): ScenarioBundle {
  const { title, events, T, MIN, SEC, bucket, secretName, targetSa, mintedKeyResource, devUser, attackerIp, ciSa } = gcpSaKeyTheftScenarioEvents();

  const iocs: IOC[] = [
    {
      type: "ip",
      value: attackerIp, // 185.129.62.66 — the external caller behind every enumeration, mint and read
      first_seen: T(0),
      last_seen: T(24 * MIN),
      reputation: "malicious",
      tags: ["external", "internet-source", "off-network"],
    },
    {
      type: "email",
      value: devUser, // t.levy@rocketstack.io — the compromised developer identity that minted the key
      first_seen: T(0),
      last_seen: T(15 * MIN),
      reputation: "suspicious",
      tags: ["developer", "compromised-identity", "foothold"],
    },
    {
      type: "email",
      value: targetSa, // data-pipeline-sa — the over-permissioned service account driven from outside
      first_seen: T(4 * MIN),
      last_seen: T(24 * MIN),
      reputation: "suspicious",
      tags: ["service-account", "over-permissioned", "driven-remotely"],
    },
    {
      type: "url",
      value: mintedKeyResource, // the user-managed key resource — the persistence artifact
      first_seen: T(4 * MIN),
      last_seen: T(24 * MIN),
      reputation: "malicious",
      tags: ["user-managed-key", "persistence-artifact"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "gcpq1",
      xp: 60,
      kind: "single",
      prompt:
        "The benign control (gcpkey_00) and the pivotal event (gcpkey_03) both call CreateServiceAccountKey and both mint a user-managed key. Reading the two records against each other, what separates the malicious one?",
      hint: "Compare the calling principal and the request_metadata.caller_ip on each — a pipeline identity from Google's network versus a login from somewhere else.",
      options: [
        { value: "principal_and_ip", label: "The suspect key was minted by t.levy@rocketstack.io from an internet caller_ip on an SA it does not own; the benign one by terraform-ci-sa from Cloud Build" },
        { value: "key_algorithm", label: "The suspect call requests a stronger key algorithm than the benign run, and user-managed RSA-2048 keys are something only attackers mint in this project" },
        { value: "method_differs", label: "The suspect call uses a different, undocumented IAM admin method to mint the key, whereas the benign Terraform run uses the supported API method" },
        { value: "response_count", label: "The suspect call returns more response items than the benign one, and a key-create that returns multiple keys is the signature of credential theft" },
      ],
      answer: "principal_and_ip",
      explanation:
        "Minting a key is a routine operation — the CI account rotates keys constantly, so the method name alone proves nothing. The split is the identity and its origin: gcpkey_00 is terraform-ci-sa calling from a Google Cloud Build egress address inside a change-tracked apply, while gcpkey_03 is a human developer login (t.levy@rocketstack.io) reaching in from 185.129.62.66 — an internet address — to key a service account the developer has no ownership of. (b) is false: both keys are ordinary RSA-2048 GOOGLE_CREDENTIALS_FILE keys. (c) is wrong — both call the same google.iam.admin.v1.CreateServiceAccountKey. (d) invents a count difference that does not decide anything; a key-create returns a single key either way.",
    },
    {
      id: "gcpq2",
      xp: 65,
      kind: "single",
      prompt:
        "After the developer identity was seen, the calls that read the datalake bucket and the secret carry principalEmail = data-pipeline-sa, not t.levy@rocketstack.io. Why does the acting identity change partway through the chain?",
      hint: "Think about what the minted key and the GenerateAccessToken call give the operator that the developer login on its own did not.",
      options: [
        { value: "acts_as_sa", label: "With the minted key and token the operator authenticates AS the SA, so the log names the SA as principal while the same external caller_ip drives it" },
        { value: "log_rotation", label: "Cloud Audit Logs rotate the principal field to the resource owner after a few minutes, so the change is an artifact of logging rather than a change of actor" },
        { value: "sa_woke_up", label: "The real data-pipeline-sa resumed its scheduled job at that moment, so the later reads are the legitimate pipeline and unrelated to the earlier activity" },
        { value: "impersonation_blocked", label: "The principal changed because GenerateAccessToken failed and GCP automatically fell back to the service account's own identity to complete the calls" },
      ],
      answer: "acts_as_sa",
      explanation:
        "The identity change is the whole point of the theft. By minting a user-managed key (gcpkey_03) and generating an access token for the account (gcpkey_04), the operator obtained the service account's own credentials — so every call afterward is authenticated as data-pipeline-sa and the audit log honestly records that principal. The tell that it is still the operator is the constant: the same 185.129.62.66 caller_ip carries both the developer-attributed and the SA-attributed calls. (b) is invented — the principal field reflects the real authenticated identity, it does not rotate. (c) is the trap: the SA's real work runs inside the pipeline, never from an internet address. (d) is wrong — the token call succeeded (authorization_info.granted true), it did not fall back.",
    },
    {
      id: "gcpq3",
      xp: 55,
      kind: "single",
      prompt:
        "The data-pipeline-sa is a real account that reads rocketstack-prod-datalake every day as part of the pipeline, so its storage reads are expected. Which single observation shows this run was not the pipeline doing its job?",
      hint: "Look at request_metadata.caller_ip on the SA's reads and compare it with where this account's work normally originates.",
      options: [
        { value: "caller_ip_external", label: "Every read by the SA carries caller_ip 185.129.62.66, an internet address, while the pipeline's real work originates inside Google's network" },
        { value: "role_missing", label: "The SA no longer held storage.objects.get at the time, so the successful reads must have been made by a different, forged identity using its name" },
        { value: "wrong_bucket", label: "The reads targeted a bucket the SA had never been granted access to, and access outside its IAM bindings is what proves the run was hostile" },
        { value: "night_hours", label: "The reads happened overnight, well outside business hours, and service-account activity at that time is enough on its own to declare an incident" },
      ],
      answer: "caller_ip_external",
      explanation:
        "Because the identity is genuinely authorized, the discriminator is the origin, not the permission. This account's real reads come from inside the project's network, but here storage.objects.list, storage.objects.get and AccessSecretVersion all carry request_metadata.caller_ip 185.129.62.66 — an internet address — and Event Threat Detection's New Geography finding reports exactly that origin on the service account. (b) is false: authorization_info.granted is true on every call, the role is intact — that is exactly why nothing was blocked. (c) is wrong — the datalake is a bucket the SA is entitled to, which is what makes the abuse quiet. (d) over-reads timing; a nightly pipeline legitimately runs at those hours, so the hour alone is not a verdict.",
    },
    {
      id: "gcpq4",
      xp: 60,
      kind: "single",
      prompt:
        "Event Threat Detection produced two findings, both Low severity: Persistence: Service Account Key Created and Persistence: New Geography. What does each tell you about a different stage of the incident?",
      hint: "One fires on the Admin Activity write that created a credential; the other on the service account then working from a country it has never used.",
      options: [
        { value: "key_then_use", label: "The first marks a durable credential planted on the account, the second that account then operating from a new country — the foothold, and its use" },
        { value: "duplicate_finding", label: "Both findings describe the same key-creation event raised by two detectors, so one can be closed as a duplicate of the other without further review" },
        { value: "geo_causes_key", label: "The geography finding fires first and triggers the key finding, because activity from a new country is what makes GCP flag the new key" },
        { value: "separate_incidents", label: "The two findings are on unrelated resources in different projects and should be tracked as two independent incidents with no shared root cause" },
      ],
      answer: "key_then_use",
      explanation:
        "The two findings map onto the two halves of the case. Persistence: Service Account Key Created (gcpkey_08) fires on the CreateServiceAccountKey admin write, the moment a durable credential was planted on the account. Persistence: New Geography (gcpkey_09) fires when that service account starts making calls from a country it has never operated from, the minted key in use from 185.129.62.66. Both are Low severity by default, so neither one pages anyone alone; on the same account within minutes, together, they are the case. Notice what Event Threat Detection does not give you: it has no finding for reading Cloud Storage objects, so the drain itself is evidenced only by the storage.objects.get entries in the Data Access log. (b) is wrong: they key on different calls (CreateServiceAccountKey vs the service account's later API calls) at different times. (c) reverses the order; the key was minted first. (d) is false: both name the same service account and the same 185.129.62.66 caller, one chain.",
    },
    {
      id: "gcpq5",
      xp: 70,
      kind: "single",
      prompt:
        "You are scoping containment. A developer login from the internet minted a user-managed key on an over-permissioned service account and used it to read a datalake and a stored secret. Which response matches the evidence?",
      hint: "Think about the durable key that survives a password reset, the secret that was read, and everything the SA's roles could reach — not just the objects you watched leave.",
      options: [
        { value: "delete_key_rotate_scope", label: "Delete the SA's user-managed key, reset and revoke t.levy, rotate the secret that was read, and scope to everything the SA's roles could reach" },
        { value: "reset_dev_only", label: "Reset t.levy@rocketstack.io's password and revoke its sessions; since that login started the intrusion, changing it invalidates the key and closes the incident" },
        { value: "block_ip_only", label: "Block 185.129.62.66 at the perimeter; because every call came from that one address, blocking it contains the incident and no credential change is needed" },
        { value: "rotate_ci_sa", label: "Rotate the terraform-ci-sa credentials from the benign control, since it is the account that routinely creates service-account keys in this project" },
      ],
      answer: "delete_key_rotate_scope",
      explanation:
        "The durable artifact is the minted key, and it keeps working no matter what happens to the developer's password — so containment has to delete that key first, then reset and revoke the developer identity, rotate the warehouse secret that was read (it must be treated as known to the operator), and scope the loss to everything the SA's roles reach rather than the one prefix in the log. Right-sizing the over-broad roles closes the door for next time. (b) is the classic miss: resetting t.levy leaves the user-managed key valid, so the operator keeps the SA. (c) leaves both the key and the exposed secret live and would break legitimate traffic sharing that egress. (d) targets the benign CI account, which did nothing wrong.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title,
    threat_actor: "Operator abusing a compromised developer identity to key an over-permissioned GCP service account",
    attack_kind: "cloud_credential_theft",
    briefing:
      "Google Cloud threat detection fired overnight: the data-pipeline service account is reading a production bucket and pulling a stored secret from an address that has never hosted it, and a new key for that account was created minutes earlier. It normally runs only inside the pipeline. Work out how the account was taken over, what it touched, and how far it reached before you contain it.",
    narrative: `The project rocketstack-data-prod runs its analytics on a service account, data-pipeline-sa, that carries storage-admin, BigQuery-viewer and Secret Manager access — far more than it needs. Its real work only ever runs from inside the pipeline's network. The one legitimate comparison in the data is the night before: the Terraform CI account, terraform-ci-sa, mints a user-managed key during a routine apply — the same CreateServiceAccountKey call — but from a Google Cloud Build address, with a Terraform user agent, inside a change-tracked run.

The incident begins with a developer whose gcloud credentials were phished. At 01:00 that identity, t.levy@rocketstack.io, appears from 185.129.62.66 — an internet address — and lists every service account in the project, then lists its buckets. At 01:04 it does the thing the whole case turns on: a CreateServiceAccountKey call on data-pipeline-sa mints a new long-lived, user-managed JSON key. It is one quiet line in the Admin Activity log, and it hands the operator a credential that will keep working after the developer's password is reset. A minute and a half later the same identity mints a short-lived access token for the account as well.

From 01:07 the acting principal changes: the calls that list and read rocketstack-prod-datalake, and the one that reads the prod-warehouse-dsn secret, all carry principalEmail data-pipeline-sa — the service account itself — because the operator now holds its credentials. The constant across every step is 185.129.62.66. A burst of storage.objects.get entries walks the datalake's export prefix object by object, and the Secret Manager read lifts a warehouse connection string.

Event Threat Detection raised two Low-severity findings: at 01:15 Persistence: Service Account Key Created on the mint, and at 01:24 Persistence: New Geography on the service account working from the Netherlands. Neither pages anyone on its own, and there is no detection for the object reads themselves: the drain is visible only in the Data Access log. Read as a whole, the case has a clean shape — the Admin Activity key-mint is the quiet persistence pivot, and the Data Access reads from outside the network on the service account are the blast radius. The tell throughout is a from-outside-GCP caller IP on an account whose work never leaves the project.`,
    learning_objectives: [
      "Separate a malicious CreateServiceAccountKey from a legitimate one using the calling principal and request_metadata.caller_ip (a developer login from the internet vs a CI identity from Google's network), not the method name",
      "Recognise a user-managed service-account key minted in the Admin Activity log as a quiet persistence foothold that survives the compromised user's password reset",
      "Explain why the acting principalEmail switches to the service account after the key and access token are obtained, and use the constant caller_ip to keep the chain tied to one operator",
      "Read GCP Event Threat Detection findings (Service Account Key Created, New Geography) as markers of distinct incident stages, the credential planted and then used from outside, and know that no ETD finding covers Cloud Storage object reads, so the Data Access log is the evidence of the drain",
      "Scope containment for a stolen GCP service-account credential — delete the user-managed key, reset the developer identity, rotate the secret that was read, and treat everything the SA's roles reach as exposed",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-30T02:12:00.000Z", phase: "Baseline", action: `${ciSa} mints a user-managed key during a Terraform apply from Cloud Build — routine rotation (control case)` },
      { ts: T(0), phase: "Discovery", action: `Compromised ${devUser} lists service accounts from ${attackerIp} (T1526)` },
      { ts: T(2 * MIN), phase: "Discovery", action: `storage.buckets.list enumerates project buckets from ${attackerIp} (T1580)` },
      { ts: T(4 * MIN), phase: "Persistence", action: `CreateServiceAccountKey mints a user-managed key on ${targetSa} (T1098.001)` },
      { ts: T(5 * MIN + 30 * SEC), phase: "Privilege Escalation", action: `GenerateAccessToken mints a token to act as ${targetSa} (T1078.004)` },
      { ts: T(7 * MIN), phase: "Discovery", action: `storage.objects.list indexes ${bucket} as the SA from ${attackerIp} (T1619)` },
      { ts: T(9 * MIN), phase: "Collection", action: `storage.objects.get burst across ${bucket} (T1530)` },
      { ts: T(12 * MIN), phase: "Credential Access", action: `AccessSecretVersion reads ${secretName} as the SA (T1555.006)` },
      { ts: T(15 * MIN), phase: "Detection", action: "Event Threat Detection — Persistence: Service Account Key Created, Low (T1098.001)" },
      { ts: T(24 * MIN), phase: "Detection", action: "Event Threat Detection — Persistence: New Geography, Low (T1078.004)" },
    ],
    questions,
  };
}
