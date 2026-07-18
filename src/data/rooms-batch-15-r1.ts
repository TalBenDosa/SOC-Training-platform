import type { TelemetryEvent } from "@/lib/sim/types";

// ── Privileged pod creation event ────────────────────────────────────────────
const k8sPrivilegedPodEvent: TelemetryEvent = {
  id: "evt-k8s-privpod-001",
  ts: "2024-12-02T03:41:17.000Z",
  source: "k8s_audit",
  vendor: "Kubernetes Audit (EKS)",
  event_type: "k8s_pod_create",
  severity: "critical",
  hostname: "kube-system",
  user_email: "ci-deploy-token@nexacorp.com",
  description:
    "ci-deploy-token created a pod named svc-monitoring-backup in kube-system with hostPID, hostNetwork, and privileged:true, pulling its image from an external, unauthenticated registry",
  mitre_technique: "T1610",
  mitre_tactic: "Execution",
  raw: {
    "kubernetes.audit.verb": "create",
    "kubernetes.audit.objectRef.resource": "pods",
    "kubernetes.audit.objectRef.namespace": "kube-system",
    "kubernetes.audit.objectRef.name": "svc-monitoring-backup",
    "kubernetes.audit.user.username": "system:serviceaccount:kube-system:ci-deploy-token",
    "kubernetes.audit.sourceIPs": ["10.128.4.201"],
    "kubernetes.audit.requestObject.spec.hostPID": true,
    "kubernetes.audit.requestObject.spec.hostNetwork": true,
    "kubernetes.audit.requestObject.spec.containers[0].image": "185.220.101.47:5000/monitor:latest",
    "kubernetes.audit.requestObject.spec.containers[0].securityContext.privileged": true,
    "kubernetes.audit.responseStatus.code": 201,
  },
};

// ── kubectl exec into a running pod event ───────────────────────────────────
const k8sExecEvent: TelemetryEvent = {
  id: "evt-k8s-exec-001",
  ts: "2024-12-02T03:38:04.000Z",
  source: "k8s_audit",
  vendor: "Kubernetes Audit (EKS)",
  event_type: "k8s_exec",
  severity: "medium",
  hostname: "prod-checkout-6f9c",
  user_email: "d.abrams@nexacorp.com",
  description:
    "d.abrams ran kubectl exec into pod prod-checkout-6f9c to install a curl-based debugging tool — outside their normal working hours and namespace scope",
  mitre_technique: "T1610",
  mitre_tactic: "Execution",
  raw: {
    "kubernetes.audit.verb": "create",
    "kubernetes.audit.objectRef.subresource": "exec",
    "kubernetes.audit.objectRef.resource": "pods",
    "kubernetes.audit.objectRef.namespace": "prod",
    "kubernetes.audit.objectRef.name": "prod-checkout-6f9c",
    "kubernetes.audit.user.username": "d.abrams@nexacorp.com",
    "kubernetes.audit.requestObject.command": ["/bin/sh", "-c", "apt-get install -y curl"],
    "kubernetes.audit.sourceIPs": ["10.20.14.55"],
    "kubernetes.audit.responseStatus.code": 200,
  },
};

const k8sSecurityRoom = {
  id: "kubernetes-container-security",
  title: "Kubernetes & Container Security",
  description:
    "Learn how attackers escalate from a compromised container to the underlying node and the cloud account behind it — privileged pods, hostPath/hostPID/hostNetwork abuse, RBAC over-permissioning, and the metadata-service theft path that ties container security back into cloud security monitoring.",
  difficulty: "advanced" as const,
  category: "Cloud Security",
  estimatedMinutes: 55,
  xp: 550,
  icon: "🐳",
  prerequisites: ["cloud-security-monitoring"],
  tasks: [
    // -------------------------------------------------------------------------
    // Reading 1 — Containers, Pods, and Why They Are Not a Security Boundary
    // -------------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "k8s-r1",
      heading: "Containers Are Not Virtual Machines — Why That Matters for Security",
      content:
        "**Analogy:** Think of a virtual machine as a fully separate apartment with its own walls, plumbing, and front door — a tenant inside one apartment cannot casually walk into the apartment next door. A container is much closer to a cubicle in an open-plan office: there are dividers giving the illusion of separation, and everyone behaves as if they're isolated, but underneath, everyone is still breathing the same air, standing on the same floor, and sharing the same building infrastructure. That shared floor is the **host operating system's kernel**.\n\nA **container** is not a lightweight virtual machine. It is a set of Linux kernel features — namespaces (which give a process its own view of process IDs, network interfaces, and mount points) and cgroups (which limit how much CPU/memory a process can use) — layered on top of a single, shared kernel. Every container running on a given node is, at the kernel level, just another process on that same machine. This is *why* containers start in milliseconds and VMs take tens of seconds — there's no second operating system to boot. It's also why a container escape is fundamentally more dangerous than a VM escape: the attacker doesn't need to find a hypervisor vulnerability, they just need to find a way to interact with the one kernel that was never truly separated from them in the first place.\n\n**Kubernetes** is the orchestration layer that decides which containers (grouped into **Pods** — one or more containers that share networking and storage) run on which physical or virtual machines (**Nodes**), and manages scaling, networking, and recovery across a whole fleet of nodes (a **Cluster**). As a SOC analyst, you don't need to operate Kubernetes — but you absolutely need to understand its security model, because container adoption means a growing share of an organisation's production workloads run inside clusters, and the attack paths are meaningfully different from the Windows/AD attacks you've studied so far.\n\n**The core security assumption to unlearn:** in a traditional Windows environment, a workstation compromise and a Domain Controller compromise are separated by many defensive layers — network segmentation, Kerberos, privileged access management. In a poorly configured Kubernetes cluster, a single compromised container can be only **one misconfiguration away** from full control of the node it runs on, and from there, one more short hop away from the cloud account hosting the entire cluster. This room walks that exact chain, because it is the single most common way a 'contained' application compromise turns into a full cloud breach.\n\n**The three building blocks you need before anything else:**\n- **Pod** — the smallest deployable unit in Kubernetes; one or more containers, sharing an IP address and storage volumes, always scheduled together onto the same node.\n- **Node** — a physical or virtual machine (often an AWS EC2 instance or GCP Compute Engine VM, tying directly back into what you learned in the AWS/GCP rooms) that actually runs the pods' containers.\n- **kubelet** — the agent running on every node that takes instructions from the Kubernetes control plane and starts/stops containers accordingly. The kubelet is itself a high-value target: control the kubelet, and you control every pod on that node.\n\nEvery attack technique in this room exploits the gap between what a container is *supposed* to be able to see (its own isolated slice) and what it is *actually* able to see, when specific settings are enabled that weaken or remove the namespace boundary entirely.",
    },

    // -------------------------------------------------------------------------
    // Reading 2 — Privileged Pods, hostPID, hostNetwork, hostPath
    // -------------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "k8s-r2",
      heading: "Privileged Pods and the hostPID / hostNetwork / hostPath Escape Hatches",
      content:
        "Kubernetes gives operators several legitimate settings that intentionally *weaken* the isolation between a container and its host node. They exist for real operational reasons — a monitoring agent that needs to see every process on the node, a networking tool that needs raw access to the host's network stack. The problem is that these same settings, when granted to a pod an attacker controls (or can create), hand over the keys to the node with almost no additional effort.\n\n**'privileged: true'** — This is the single most dangerous pod setting that exists. A privileged container runs with essentially all Linux kernel capabilities enabled and with SELinux/AppArmor confinement disabled — it is functionally equivalent to running as root directly on the node, with the ability to access every device file, load kernel modules, and modify low-level system settings. There is almost never a legitimate reason for an application workload to need this; it is reserved for specialist infrastructure components (certain CNI/storage plugins) and should never appear on a general-purpose application pod.\n\n**'hostPID: true'** — Normally, a container's process namespace is isolated: it can only see its own processes, numbered starting from PID 1. Setting 'hostPID: true' removes this isolation, letting the container see (and, combined with sufficient privileges, interact with — including sending signals to, or attaching a debugger to) **every process running on the node**, including processes belonging to completely unrelated pods and the node's own system processes. An attacker with 'hostPID' access can potentially read another pod's process memory, exactly like the LSASS-dumping techniques you studied in Windows environments, just aimed at a different kernel.\n\n**'hostNetwork: true'** — Normally, every pod gets its own isolated virtual network interface. 'hostNetwork: true' makes the pod share the node's actual network namespace directly — the container can bind to any port on the node's real network interface and see all network traffic the node itself sees, bypassing the network policies that would otherwise apply to isolated pod networking.\n\n**'hostPath' volume mounts** — A 'hostPath' volume mounts a directory from the *node's own filesystem* directly into the container. If an attacker can create a pod with a 'hostPath' mount pointing at a sensitive location — the node's '/etc', its Docker/containerd socket, or (most dangerously) the root filesystem '/' itself — they can read or write files on the underlying node from inside what looks like an isolated container. Mounting the container runtime's socket ('/var/run/docker.sock' or the containerd equivalent) is especially catastrophic: it hands the container the ability to create and control *other* containers on the node directly through the runtime's own API, which is a well-known, fully documented path to a complete node takeover.\n\n**Putting it together — why this looks so 'normal' in logs:** none of these settings require exploiting a software vulnerability. A pod with 'privileged: true' and 'hostPID: true' is created through a completely ordinary, successfully-authorized Kubernetes API call — the exact same API call type used to launch any legitimate pod. The Kubernetes audit log records it as a standard 'create' event on the 'pods' resource, with HTTP 201 (Created) — a clean success. The only way to catch this is to actually look **inside** the pod specification the API call is creating, not just at the fact that a pod-creation call succeeded.",
    },

    // -------------------------------------------------------------------------
    // Reading 3 — RBAC Over-Permissioning and the Kubernetes Audit Log
    // -------------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "k8s-r3",
      heading: "Kubernetes RBAC and Reading the Audit Log Like a SOC Analyst",
      content:
        "**Kubernetes RBAC (Role-Based Access Control)** governs who — human users, or **ServiceAccounts** (the non-human identity a pod uses to talk to the Kubernetes API, directly analogous to the AD service accounts you've already studied) — is allowed to do what, against which resources, in which namespaces. A **Role** (or **ClusterRole**, for cluster-wide scope) defines a set of permitted verbs ('get', 'list', 'create', 'delete', 'exec', ...) against specific resource types ('pods', 'secrets', 'deployments', ...). A **RoleBinding** (or **ClusterRoleBinding**) then attaches that Role to a specific user or ServiceAccount.\n\n**The over-permissioning problem, in one sentence:** it is extremely common for a CI/CD pipeline's ServiceAccount — the equivalent of the 'ci-pipeline-role' you saw abused in the AWS room — to be granted 'cluster-admin' (the built-in, all-powerful ClusterRole) simply because it was the fastest way to get a deployment pipeline working, with nobody ever revisiting the decision afterward. A ServiceAccount that only needs to create Deployments in one namespace, but instead holds 'cluster-admin', is exactly the kind of standing over-privilege that the Privileged Access Monitoring room taught you to treat as a priority finding — the same principle, in a different platform.\n\nIf an attacker compromises an application that has a token for such an over-privileged ServiceAccount mounted into it (every pod, by default, has its ServiceAccount token automatically mounted at '/var/run/secrets/kubernetes.io/serviceaccount/token' unless explicitly disabled), they inherit whatever that ServiceAccount can do against the Kubernetes API — including, in the worst case, creating brand-new privileged pods anywhere in the cluster, which is exactly the escalation path in Reading 2.\n\n**Reading the Kubernetes audit log.** Every request to the Kubernetes API server — whether from 'kubectl', a CI/CD pipeline, or a pod's own ServiceAccount — is logged. The key fields a SOC analyst filters on:\n- 'verb' — the action requested: 'create', 'get', 'list', 'delete', 'exec', 'update'.\n- 'objectRef.resource' — the resource type being acted on: 'pods', 'secrets', 'clusterrolebindings', 'serviceaccounts'.\n- 'objectRef.subresource' — critically, 'exec' (running a command inside an already-running pod, functionally equivalent to an interactive shell) is logged as a *subresource* of 'pods', distinct from creating a new pod.\n- 'user.username' — for a human, this is their identity provider username; for a ServiceAccount, it follows the pattern 'system:serviceaccount:<namespace>:<name>' — always check whether that namespace and name match what you'd expect for the activity you're seeing.\n- 'sourceIPs' — the network origin of the API call. A request claiming to be a known CI/CD ServiceAccount, but arriving from an IP outside your CI infrastructure's known range, is exactly the same class of red flag as the AWS 'CreateUser from a Tor exit node' pattern you already learned.\n- 'requestObject.spec.*' — the actual pod specification being created or modified. This is where you must look for 'privileged: true', 'hostPID: true', 'hostNetwork: true', and 'hostPath' volumes — none of which are visible from the 'verb'/'resource' fields alone.\n- 'responseStatus.code' — 201 (Created) or 200 (OK) means the action *succeeded*. Unlike Windows failed-logon monitoring, most Kubernetes attack techniques do not generate failures at all — the attacker is usually using a legitimately over-permissioned identity, so every request they make succeeds normally.\n\n**The detection principle to carry forward:** just as you learned to check the *content* of a DLP-flagged file rather than trusting the alert category alone, and to check the *scopes* requested in an OAuth consent grant rather than trusting the event type alone, Kubernetes pod-creation events require you to inspect the **pod specification itself** — verb and resource type alone tell you almost nothing about whether a 'create pods' call was benign or catastrophic.",
    },

    // -------------------------------------------------------------------------
    // Reading 4 — From Container to Cloud: The Full Escalation Chain
    // -------------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "k8s-r4",
      heading: "From Compromised Container to Stolen Cloud Credentials — The Full Chain",
      content:
        "This reading connects everything in this room back to the AWS and GCP security rooms you've already completed, because container compromise rarely stays contained to the cluster — it is one of the most common on-ramps into a full cloud account takeover.\n\n**The chain, step by step:**\n\n**Step 1 — Initial foothold inside a container.** An attacker gains code execution inside a single application container — through a vulnerable web application dependency, a supply-chain-compromised package (exactly like the dependency-confusion attack you studied in the edge-case-usecases room), or a stolen CI/CD credential that lets them deploy their own pod.\n\n**Step 2 — Escalate from container to node.** If the pod the attacker controls has 'privileged: true', 'hostPID: true', or a dangerous 'hostPath' mount (Reading 2), they use it to break out of the container's isolation and gain code execution directly on the **node** — the underlying virtual machine, no longer just a fenced-off slice of it.\n\n**Step 3 — Steal the node's cloud identity via the metadata service.** Here is the connection to what you already learned in the AWS and GCP rooms: Kubernetes nodes are themselves cloud compute instances (EC2 instances, GCE VMs), and cloud compute instances have their own IAM role/service-account identity, retrievable from the **instance metadata service** at the well-known link-local address '169.254.169.254' — the exact same IMDS endpoint you studied for EC2 credential theft. From inside a process running directly on the node (achieved in Step 2), the attacker simply queries 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' (AWS) or the GCP metadata equivalent, and receives live, valid cloud credentials for whatever role is attached to that node.\n\n**Step 4 — Full cloud account access.** Kubernetes nodes are frequently granted broad IAM permissions — to pull container images, write logs, or manage other cluster resources — because it is operationally easier than scoping permissions tightly per-workload. An attacker who has stolen the node's role credentials via Step 3 can now make AWS/GCP API calls with those permissions: enumerating S3 buckets, reading secrets from Secrets Manager, or — in the worst-documented real-world cases — pivoting to create their own IAM backdoor user, exactly as covered in the AWS Security room's IAM backdoor pattern.\n\n**Why this chain is uniquely dangerous:** each individual step, viewed in isolation, can look like unremarkable infrastructure activity. A pod being created (Step 1/2) is routine. A process on a node querying the instance metadata service (Step 3) is *also* routine — legitimate applications query IMDS constantly to refresh their own credentials. The only way to catch Step 3 as malicious is context: does this specific process, on this specific node, at this specific time, have any legitimate reason to be querying the metadata endpoint? If the querying process traces back to a container that was created moments earlier with 'hostPID'/'privileged' set, and that container's image came from an unrecognised external registry, the metadata-service query is the last, most damning link in a chain that was suspicious from Step 1 — but only if the analyst has already connected Steps 1 through 3 together.\n\n**The SOC takeaway:** never evaluate a Kubernetes alert, an AWS/GCP metadata-service alert, and a suspicious-pod alert as three separate tickets. If they involve the same node, the same time window, and the same identity chain, they are almost certainly one incident — container escape leading to cloud credential theft — and should be investigated, contained, and reported as a single continuous kill chain.",
    },

    // -------------------------------------------------------------------------
    // Question 1
    // -------------------------------------------------------------------------
    {
      type: "question" as const,
      id: "k8s-q1",
      question:
        "A pod specification includes 'hostPID: true'. What does this setting actually allow the container to do, and why is it dangerous?",
      options: [
        "It allows the pod to use a fixed, predictable process ID instead of a randomly assigned one — a minor convenience setting with no security implications",
        "It removes the container's process-namespace isolation, letting it see and potentially interact with every process running on the underlying node — including processes belonging to completely unrelated pods and the node's own system processes",
        "It grants the pod permission to run as PID 1 inside its own container, which is required for most standard container images to start correctly",
        "It restricts the pod to only viewing its own single process, which improves security by default",
      ],
      answer: 1,
      explanation:
        "hostPID: true removes the process-namespace boundary that normally isolates a container so it can only see its own processes. With this setting, the container can see (and depending on other privileges, interact with) every process on the node — a serious escalation because it breaks the fundamental assumption that a container is isolated from its neighbours and from the host itself.",
      xp: 25,
    },

    // -------------------------------------------------------------------------
    // Question 2
    // -------------------------------------------------------------------------
    {
      type: "question" as const,
      id: "k8s-q2",
      question:
        "Why can't a SOC analyst rely on the Kubernetes audit log's 'verb' and 'objectRef.resource' fields alone (e.g. verb=create, resource=pods) to decide whether a pod-creation event is malicious?",
      options: [
        "Because those fields are frequently missing or corrupted in Kubernetes audit logs",
        "Because a completely ordinary, successfully authorised 'create pods' API call looks identical whether the pod being created is a harmless application container or a privileged, hostPID, hostNetwork pod designed to escape to the node — the dangerous settings only appear inside the requestObject.spec fields, which must be inspected directly",
        "Because Kubernetes does not log pod creation events by default in any configuration",
        "Because verb and resource fields only apply to delete operations, not create operations",
      ],
      answer: 1,
      explanation:
        "The verb (create) and resource (pods) fields only tell you that a pod-creation request succeeded — they say nothing about what that pod is actually configured to do. A benign application pod and an attacker's node-escape pod both produce an identical create/pods/201 audit entry. The only way to tell them apart is to inspect the actual pod specification in requestObject.spec for dangerous settings like privileged, hostPID, hostNetwork, or hostPath mounts.",
      xp: 25,
    },

    // -------------------------------------------------------------------------
    // Log Analysis 1 — Privileged pod creation
    // -------------------------------------------------------------------------
    {
      type: "log_analysis" as const,
      id: "k8s-la1",
      heading: "A ServiceAccount Creates a Privileged Pod in kube-system",
      context:
        "Your SIEM ingests Kubernetes audit logs from the production EKS cluster. An alert fires for a pod-creation event in the sensitive 'kube-system' namespace. Review the event below and answer the questions — pay close attention to the requestObject.spec fields, not just the verb and resource type.",
      event: k8sPrivilegedPodEvent,
      questions: [
        {
          question:
            "Looking at the requestObject.spec fields, what combination of settings makes this pod creation a near-certain node-escape attempt rather than routine deployment activity?",
          options: [
            "The pod was created in the kube-system namespace, which alone is always malicious regardless of configuration",
            "The pod specification sets hostPID: true, hostNetwork: true, and containers[0].securityContext.privileged: true simultaneously — this combination removes process isolation, network isolation, and kernel-capability restrictions all at once, which is never required for a legitimate monitoring or application workload",
            "The response code is 201, which by itself indicates a security violation",
            "The pod name 'svc-monitoring-backup' is inherently suspicious because it contains the word 'backup'",
          ],
          answer: 1,
          explanation:
            "Any one of these settings alone might have a narrow legitimate use case for specialised infrastructure pods. All three together — hostPID, hostNetwork, and privileged:true — on a single pod is the textbook configuration for deliberately breaking every isolation boundary Kubernetes provides, consistent with an attacker preparing to pivot from the container to the node itself. The kube-system namespace additionally means this pod runs with elevated trust by convention, making the combination even more severe.",
          xp: 30,
        },
        {
          question:
            "The container image is pulled from '185.220.101.47:5000/monitor:latest' — a bare IP address rather than a named registry like docker.io or a private ECR repository. Why does this detail matter for your investigation?",
          options: [
            "It doesn't matter — container images are frequently pulled from IP addresses in legitimate CI/CD pipelines",
            "A bare IP address acting as a container registry, with no corporate DNS name and no association with any approved image source, is exactly the same red flag pattern as a raw-IP-over-plain-HTTP payload download you learned about in the supply-chain reading — legitimate container infrastructure uses named, trusted registries with proper certificates, not disposable IP-addressed servers",
            "The port number 5000 is inherently a sign of compromise regardless of what is hosted there",
            "Container images can only be pulled from IP addresses when the cluster has no internet connectivity",
          ],
          answer: 1,
          explanation:
            "This mirrors the exact detection principle from the edge-case-usecases room: raw IP addresses hosting payloads or, here, container images, are cheap, disposable attacker infrastructure with no legitimate registry reputation, TLS certificate, or DNS presence. Combined with the privileged/hostPID/hostNetwork pod specification, an image pulled from an unrecognised bare-IP registry confirms this is very unlikely to be legitimate monitoring tooling.",
          xp: 30,
        },
        {
          question:
            "The requesting identity is 'system:serviceaccount:kube-system:ci-deploy-token'. What should the analyst check next, based on what you learned about RBAC over-permissioning?",
          options: [
            "Nothing further is needed — ServiceAccount names ending in '-token' are always considered trusted by Kubernetes",
            "Whether this ServiceAccount's RBAC bindings grant it the ability to create privileged pods at all, and whether a CI/CD deployment pipeline has any legitimate business reason to hold that level of permission — an over-permissioned CI ServiceAccount is the Kubernetes equivalent of the over-permissioned CI IAM role you studied in the AWS room",
            "Whether the ServiceAccount's password meets complexity requirements",
            "Whether the ServiceAccount is a member of the Windows Domain Admins group",
          ],
          answer: 1,
          explanation:
            "ServiceAccounts don't have passwords — they authenticate via mounted tokens, and their permissions come entirely from RBAC RoleBindings/ClusterRoleBindings. The critical follow-up question is whether ci-deploy-token was ever supposed to be able to create privileged pods with hostPID/hostNetwork in kube-system — if its RBAC grants far exceed what a deployment pipeline needs (a common real-world misconfiguration, exactly like an over-permissioned cloud IAM role), that over-permissioning is itself a finding requiring remediation, independent of whether this specific pod turns out to be a confirmed compromise.",
          xp: 25,
        },
      ],
    },

    // -------------------------------------------------------------------------
    // Log Analysis 2 — kubectl exec anomaly
    // -------------------------------------------------------------------------
    {
      type: "log_analysis" as const,
      id: "k8s-la2",
      heading: "An Unexpected kubectl exec Into a Production Pod",
      context:
        "A medium-severity alert fires for a 'kubectl exec' session into a production pod. Review the event below — note that this is logged as a subresource action on an existing pod, not a new pod creation.",
      event: k8sExecEvent,
      questions: [
        {
          question:
            "The event shows objectRef.subresource = 'exec' rather than a plain pod creation. What does this specifically mean happened, and why is it functionally similar to an interactive remote-desktop or SSH session in a traditional Windows/Linux environment?",
          options: [
            "It means a new pod was created and immediately deleted — exec has nothing to do with existing pods",
            "It means the user opened an interactive command session inside an already-running production pod, executing shell commands directly inside a live workload — the direct container equivalent of an interactive RDP or SSH session onto a running server, and just as significant an event to have visibility into",
            "It means the pod's exec permission was revoked for this user",
            "It means the pod automatically restarted due to a health-check failure",
          ],
          answer: 1,
          explanation:
            "kubectl exec (logged as the 'exec' subresource of the pods resource) opens an interactive shell session directly inside a running container — conceptually identical to RDP'ing into a Windows server or SSH'ing into a Linux host. This gives whoever runs it live, interactive command execution inside a production workload, which is exactly the kind of high-impact action that deserves the same scrutiny as any other interactive privileged session in your environment.",
          xp: 25,
        },
        {
          question:
            "Given that d.abrams' command was 'apt-get install -y curl' inside a production checkout-service pod, what is the most appropriate analyst action, consistent with the investigative habits taught elsewhere in this platform?",
          options: [
            "Close immediately as benign — installing curl is a harmless, everyday administrative action",
            "Escalate immediately to law enforcement without further investigation",
            "Treat this as worth verifying rather than an automatic false positive or automatic true positive: confirm whether d.abrams has a legitimate, documented reason (an open incident ticket, a debugging task) to be interactively execing into a production pod outside their normal working pattern, since installing network tooling like curl inside a production container is unusual even when the actor is a real, known engineer — and unverified interactive access to production is exactly the kind of event the 'IT verify' workflow exists for",
            "Automatically revoke d.abrams' Kubernetes RBAC permissions without any investigation",
          ],
          answer: 2,
          explanation:
            "This mirrors the exact triage discipline taught throughout the platform (DLP triage, privileged access monitoring, analyst mindset): a known, real user performing an unusual action is neither an automatic false positive nor an automatic true positive. Installing curl inside a production pod could be legitimate incident debugging — or could be an attacker who has compromised d.abrams' credentials staging further tooling. The correct step is verification against a ticket or manager confirmation before closing the alert either way.",
          xp: 25,
        },
      ],
    },

    // -------------------------------------------------------------------------
    // Matching Task
    // -------------------------------------------------------------------------
    {
      type: "matching" as const,
      id: "k8s-m1",
      heading: "Match Each Kubernetes Setting or Concept to What It Actually Does",
      instructions:
        "Match each Kubernetes concept on the left to the correct description of its function and risk on the right.",
      pairs: [
        {
          id: "privileged",
          left: "privileged: true",
          right: "Runs the container with nearly all Linux kernel capabilities and confinement disabled — functionally equivalent to root on the node itself",
        },
        {
          id: "hostpid",
          left: "hostPID: true",
          right: "Removes process-namespace isolation, letting the container see every process running on the node, not just its own",
        },
        {
          id: "hostpath",
          left: "hostPath volume",
          right: "Mounts a directory from the node's own filesystem directly into the container, potentially exposing sensitive host files or the container runtime socket",
        },
        {
          id: "rbac",
          left: "RBAC RoleBinding",
          right: "Attaches a defined set of permitted verbs and resources (a Role) to a specific user or ServiceAccount",
        },
        {
          id: "imds",
          left: "Instance metadata service (169.254.169.254)",
          right: "Endpoint queried from a compromised node to steal that node's live cloud IAM role/service-account credentials — the same technique used against standalone EC2 instances",
        },
      ],
      explanation:
        "Every one of these mechanisms exists for a legitimate operational reason, which is exactly what makes them dangerous when granted too broadly: they are indistinguishable, at the level of a single audit-log entry, from their malicious use. The analyst's job is to recognise which combinations of these settings, applied together, indicate an attacker deliberately dismantling container isolation rather than an operator running specialised infrastructure.",
      xp: 35,
    },

    // -------------------------------------------------------------------------
    // Flag Task
    // -------------------------------------------------------------------------
    {
      type: "flag" as const,
      id: "k8s-f1",
      prompt:
        "Look at the privileged pod creation event analysed earlier in this room. What is the exact IP address (including port) that the malicious container image was pulled from? Enter it exactly as it appears in the requestObject.spec.containers[0].image field.",
      answer: "185.220.101.47:5000",
      hint: "Look at the 'kubernetes.audit.requestObject.spec.containers[0].image' field in the raw log. It is an IP address followed by a colon and a port number, not a normal registry domain name.",
      xp: 30,
    },
  ],
};

export default [k8sSecurityRoom];
