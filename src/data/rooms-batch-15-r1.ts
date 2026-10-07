import type { TelemetryEvent } from "@/lib/sim/types";

// ── Privileged pod creation event ────────────────────────────────────────────
const k8sPrivilegedPodEvent: TelemetryEvent = {
  id: "evt-k8s-privpod-001",
  ts: "2024-12-02T03:41:17.000Z",
  source: "k8s_audit",
  vendor: "Kubernetes Audit",
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
  vendor: "Kubernetes Audit",
  event_type: "k8s_exec",
  severity: "medium",
  hostname: "prod-checkout-6f9c",
  user_email: "d.abrams@nexacorp.com",
  description:
    "d.abrams ran kubectl exec into pod prod-checkout-6f9c to install a curl-based debugging tool. Outside their normal working hours and namespace scope",
  mitre_technique: "T1610",
  mitre_tactic: "Execution",
  raw: {
    "kubernetes.audit.verb": "create",
    "kubernetes.audit.objectRef.subresource": "exec",
    "kubernetes.audit.objectRef.resource": "pods",
    "kubernetes.audit.objectRef.namespace": "prod",
    "kubernetes.audit.objectRef.name": "prod-checkout-6f9c",
    "kubernetes.audit.user.username": "d.abrams@nexacorp.com",
    "kubernetes.audit.requestURI": "/api/v1/namespaces/prod/pods/prod-checkout-6f9c/exec?command=%2Fbin%2Fsh&command=-c&command=apt-get+install+-y+curl&container=checkout&stdin=true&stdout=true&tty=true",
    "kubernetes.audit.sourceIPs": ["10.20.14.55"],
    "kubernetes.audit.responseStatus.code": 101,
  },
};

const k8sSecurityRoom = {
  id: "kubernetes-container-security",
  title: "Kubernetes & Container Security",
  description:
    "Learn how attackers escalate from a compromised container to the underlying node and the cloud account behind it. Privileged pods, hostPath/hostPID/hostNetwork abuse, RBAC over-permissioning, and the metadata-service theft path that ties container security back into cloud security monitoring.",
  difficulty: "advanced" as const,
  category: "Cloud Security",
  estimatedMinutes: 55,
  xp: 250,
  icon: "🐳",
  prerequisites: ["cloud-security-monitoring"],
  tasks: [
    // -------------------------------------------------------------------------
    // Reading 1 — Containers, Pods, and Why They Are Not a Security Boundary
    // -------------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "k8s-r1",
      heading: "Containers Are Not Virtual Machines: Why That Matters for Security",
      content:
        "**Analogy:** Think of a virtual machine as a fully separate apartment with its own walls, plumbing, and front door: a tenant inside one apartment cannot casually walk into the apartment next door. A container is much closer to a cubicle in an open-plan office: there are dividers giving the illusion of separation, and everyone behaves as if they're isolated, but underneath, everyone is still breathing the same air, standing on the same floor, and sharing the same building infrastructure. That shared floor is the **host operating system's kernel**.\n\nA **container** is not a lightweight virtual machine. It is a set of Linux kernel features. Namespaces (which give a process its own view of process IDs, network interfaces, and mount points) and cgroups (which limit how much CPU/memory a process can use): layered on top of a single, shared kernel. Every container running on a given node is, at the kernel level, just another process on that same machine. This is *why* containers start in milliseconds and VMs take tens of seconds. There's no second operating system to boot. It's also why a container escape is fundamentally more dangerous than a VM escape: the attacker doesn't need to find a hypervisor vulnerability, they just need to find a way to interact with the one kernel that was never truly separated from them in the first place.\n\n**Kubernetes** is the orchestration layer that decides which containers (grouped into **Pods**, one or more containers that share networking and storage) run on which physical or virtual machines (**Nodes**), and manages scaling, networking, and recovery across a whole fleet of nodes (a **Cluster**). As a SOC analyst, you don't need to operate Kubernetes, but you absolutely need to understand its security model, because container adoption means a growing share of an organisation's production workloads run inside clusters, and the attack paths are meaningfully different from the Windows/AD attacks you've studied so far.\n\n**The core security assumption to unlearn:** in a traditional Windows environment, a workstation compromise and a Domain Controller compromise are separated by many defensive layers: network segmentation, Kerberos, privileged access management. In a poorly configured Kubernetes cluster, a single compromised container can be only **one misconfiguration away** from full control of the node it runs on, and from there, one more short hop away from the cloud account hosting the entire cluster. This room walks that exact chain, because it is the single most common way a 'contained' application compromise turns into a full cloud breach.\n\n**The three building blocks you need before anything else:**\n- **Pod**: the smallest deployable unit in Kubernetes; one or more containers, sharing an IP address and storage volumes, always scheduled together onto the same node.\n- **Node**, a physical or virtual machine (often an AWS EC2 instance or GCP Compute Engine VM, tying directly back into what you learned in the AWS/GCP rooms) that actually runs the pods' containers.\n- **kubelet**, the agent running on every node that takes instructions from the Kubernetes control plane and starts/stops containers accordingly. The kubelet is itself a high-value target: control the kubelet, and you control every pod on that node.\n\nEvery attack technique in this room exploits the gap between what a container is *supposed* to be able to see (its own isolated slice) and what it is *actually* able to see, when specific settings are enabled that weaken or remove the namespace boundary entirely.",
      checkpoint: {
        question: "According to the reading, what is the kubelet, and why is it a high-value target for an attacker?",
        options: [
          "The per-node agent that starts and stops containers on control-plane orders. Own it and you own every pod on that node",
          "The kubectl tool admins run on their workstations. Steal it and you can send commands to the whole cluster as them",
          "The pod-level network policy engine: disable it and every pod can reach every other pod without restriction",
          "The control-plane scheduler that places pods onto nodes. Own it and you choose where every new workload runs",
        ],
        answer: 0,
        explanation: "The reading defines the kubelet as the agent on every node that takes instructions from the control plane and starts/stops containers, so controlling it means controlling every pod on that node. “The kubectl tool” is the admin's client, not something running on nodes, and it is the admin's credentials that matter, not the tool. “The pod-level network policy engine” and “the control-plane scheduler” are real cluster components, but neither is the per-node agent the reading calls the kubelet.",
      },
    },

    // -------------------------------------------------------------------------
    // Reading 2 — Privileged Pods, hostPID, hostNetwork, hostPath
    // -------------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "k8s-r2",
      heading: "Privileged Pods and the hostPID / hostNetwork / hostPath Escape Hatches",
      content:
        "Kubernetes gives operators several legitimate settings that intentionally *weaken* the isolation between a container and its host node. They exist for real operational reasons: a monitoring agent that needs to see every process on the node, a networking tool that needs raw access to the host's network stack. The problem is that these same settings, when granted to a pod an attacker controls (or can create), hand over the keys to the node with almost no additional effort.\n\n**'privileged: true'**, This is the single most dangerous pod setting that exists. A privileged container runs with essentially all Linux kernel capabilities enabled and with SELinux/AppArmor confinement disabled. It is functionally equivalent to running as root directly on the node, with the ability to access every device file, load kernel modules, and modify low-level system settings. There is almost never a legitimate reason for an application workload to need this; it is reserved for specialist infrastructure components (certain CNI/storage plugins) and should never appear on a general-purpose application pod.\n\n**'hostPID: true'**, Normally, a container's process namespace is isolated: it can only see its own processes, numbered starting from PID 1. Setting 'hostPID: true' removes this isolation, letting the container see (and, combined with sufficient privileges, interact with, including sending signals to, or attaching a debugger to) **every process running on the node**, including processes belonging to completely unrelated pods and the node's own system processes. An attacker with 'hostPID' access can potentially read another pod's process memory, exactly like the LSASS-dumping techniques you studied in Windows environments, just aimed at a different kernel.\n\n**'hostNetwork: true'**, Normally, every pod gets its own isolated virtual network interface. 'hostNetwork: true' makes the pod share the node's actual network namespace directly, the container can bind to any port on the node's real network interface and see all network traffic the node itself sees, bypassing the network policies that would otherwise apply to isolated pod networking.\n\n**'hostPath' volume mounts**, A 'hostPath' volume mounts a directory from the *node's own filesystem* directly into the container. If an attacker can create a pod with a 'hostPath' mount pointing at a sensitive location: the node's '/etc', its Docker/containerd socket, or (most dangerously) the root filesystem '/' itself. They can read or write files on the underlying node from inside what looks like an isolated container. Mounting the container runtime's socket ('/var/run/docker.sock' or the containerd equivalent) is especially catastrophic: it hands the container the ability to create and control *other* containers on the node directly through the runtime's own API, which is a well-known, fully documented path to a complete node takeover.\n\n**Putting it together. Why this looks so 'normal' in logs:** none of these settings require exploiting a software vulnerability. A pod with 'privileged: true' and 'hostPID: true' is created through a completely ordinary, successfully-authorized Kubernetes API call, the exact same API call type used to launch any legitimate pod. The Kubernetes audit log records it as a standard 'create' event on the 'pods' resource, with HTTP 201 (Created): a clean success. The only way to catch this is to actually look **inside** the pod specification the API call is creating, not just at the fact that a pod-creation call succeeded.",
    },

    // -------------------------------------------------------------------------
    // Reading 3 — RBAC Over-Permissioning and the Kubernetes Audit Log
    // -------------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "k8s-r3",
      heading: "Kubernetes RBAC and Reading the Audit Log Like a SOC Analyst",
      content:
        "**Kubernetes RBAC (Role-Based Access Control)** governs who. Human users, or **ServiceAccounts** (the non-human identity a pod uses to talk to the Kubernetes API, directly analogous to the AD service accounts you've already studied): is allowed to do what, against which resources, in which namespaces. A **Role** (or **ClusterRole**, for cluster-wide scope) defines a set of permitted verbs ('get', 'list', 'create', 'delete', ...) against specific resource types ('pods', 'secrets', 'deployments', ...) and subresources. E.g., the right to exec into pods is granted as verb 'create' on the 'pods/exec' subresource. A **RoleBinding** (or **ClusterRoleBinding**) then attaches that Role to a specific user or ServiceAccount.\n\n**The over-permissioning problem, in one sentence:** it is extremely common for a CI/CD pipeline's ServiceAccount (the equivalent of the 'ci-pipeline-role' you saw abused in the AWS room) to be granted 'cluster-admin' (the built-in, all-powerful ClusterRole) simply because it was the fastest way to get a deployment pipeline working, with nobody ever revisiting the decision afterward. A ServiceAccount that only needs to create Deployments in one namespace, but instead holds 'cluster-admin', is exactly the kind of standing over-privilege that the Privileged Access Monitoring room taught you to treat as a priority finding: the same principle, in a different platform.\n\nIf an attacker compromises an application that has a token for such an over-privileged ServiceAccount mounted into it (every pod, by default, has its ServiceAccount token automatically mounted at '/var/run/secrets/kubernetes.io/serviceaccount/token' unless explicitly disabled), they inherit whatever that ServiceAccount can do against the Kubernetes API, including, in the worst case, creating brand-new privileged pods anywhere in the cluster, which is exactly the escalation path in Reading 2.\n\n**Reading the Kubernetes audit log.** Every request to the Kubernetes API server (whether from 'kubectl', a CI/CD pipeline, or a pod's own ServiceAccount) is logged. The key fields a SOC analyst filters on:\n- 'verb', the action requested: 'create', 'get', 'list', 'delete', 'update', 'patch'. (exec is not a verb: kubectl exec is logged as verb 'create' (or 'get' for a websocket upgrade) on the 'exec' subresource of 'pods'.)\n- 'objectRef.resource', the resource type being acted on: 'pods', 'secrets', 'clusterrolebindings', 'serviceaccounts'.\n- 'objectRef.subresource'. Critically, 'exec' (running a command inside an already-running pod, functionally equivalent to an interactive shell) is logged as a *subresource* of 'pods', distinct from creating a new pod.\n- 'user.username', for a human, this is their identity provider username; for a ServiceAccount, it follows the pattern 'system:serviceaccount:<namespace>:<name>', always check whether that namespace and name match what you'd expect for the activity you're seeing.\n- 'sourceIPs': the network origin of the API call. A request claiming to be a known CI/CD ServiceAccount, but arriving from an IP outside your CI infrastructure's known range, is exactly the same class of red flag as the AWS 'CreateUser from a Tor exit node' pattern you already learned.\n- 'requestObject.spec.*': the actual pod specification being created or modified. This is where you must look for 'privileged: true', 'hostPID: true', 'hostNetwork: true', and 'hostPath' volumes, none of which are visible from the 'verb'/'resource' fields alone.\n- 'responseStatus.code', 201 (Created) or 200 (OK) means the action *succeeded*. Unlike Windows failed-logon monitoring, most Kubernetes attack techniques do not generate failures at all: the attacker is usually using a legitimately over-permissioned identity, so every request they make succeeds normally.\n\n**The detection principle to carry forward:** just as you learned to check the *content* of a DLP-flagged file rather than trusting the alert category alone, and to check the *scopes* requested in an OAuth consent grant rather than trusting the event type alone, Kubernetes pod-creation events require you to inspect the **pod specification itself**. Verb and resource type alone tell you almost nothing about whether a 'create pods' call was benign or catastrophic.",
      checkpoint: {
        question: "According to the reading, where is a pod's ServiceAccount token mounted by default, unless explicitly disabled?",
        options: [
          "/var/run/secrets/kubernetes.io/serviceaccount/token",
          "/etc/kubernetes/pki/apiserver-kubelet-client.crt",
          "/etc/kubernetes/kubelet.conf",
          "/var/lib/kubelet/pods/<pod-uid>/volumes/serviceaccount.token",
        ],
        answer: 0,
        explanation: "The reading states that every pod, by default, has its ServiceAccount token automatically mounted at /var/run/secrets/kubernetes.io/serviceaccount/token unless explicitly disabled, which is how a compromised application inherits its ServiceAccount's permissions. The other paths belong elsewhere: /etc/kubernetes/pki holds control-plane certificates, /etc/kubernetes/kubelet.conf is the kubelet's own credentials file on the node, and /var/lib/kubelet/pods/... is the node-side directory, not the path the container sees.",
      },
    },

    // -------------------------------------------------------------------------
    // Reading 4 — From Container to Cloud: The Full Escalation Chain
    // -------------------------------------------------------------------------
    {
      type: "reading" as const,
      id: "k8s-r4",
      heading: "From Compromised Container to Stolen Cloud Credentials: The Full Chain",
      content:
        "This reading connects everything in this room back to the AWS and GCP security rooms you've already completed, because container compromise rarely stays contained to the cluster. It is one of the most common on-ramps into a full cloud account takeover.\n\n**The chain, step by step:**\n\n**Step 1. Initial foothold inside a container.** An attacker gains code execution inside a single application container. Through a vulnerable web application dependency, a supply-chain-compromised package (exactly like the dependency-confusion attack you studied in the edge-case-usecases room), or a stolen CI/CD credential that lets them deploy their own pod.\n\n**Step 2. Escalate from container to node.** If the pod the attacker controls has 'privileged: true', 'hostPID: true', or a dangerous 'hostPath' mount (Reading 2), they use it to break out of the container's isolation and gain code execution directly on the **node**, the underlying virtual machine, no longer just a fenced-off slice of it.\n\n**Step 3. Steal the node's cloud identity via the metadata service.** Here is the connection to what you already learned in the AWS and GCP rooms: Kubernetes nodes are themselves cloud compute instances (EC2 instances, GCE VMs), and cloud compute instances have their own IAM role/service-account identity, retrievable from the **instance metadata service** at the well-known link-local address '169.254.169.254', the exact same IMDS endpoint you studied for EC2 credential theft. From inside a process running directly on the node (achieved in Step 2), the attacker simply queries 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' (AWS) or the GCP metadata equivalent, and receives live, valid cloud credentials for whatever role is attached to that node.\n\n**Step 4. Full cloud account access.** Kubernetes nodes are frequently granted broad IAM permissions (to pull container images, write logs, or manage other cluster resources) because it is operationally easier than scoping permissions tightly per-workload. An attacker who has stolen the node's role credentials via Step 3 can now make AWS/GCP API calls with those permissions: enumerating S3 buckets, reading secrets from Secrets Manager, or, in the worst-documented real-world cases, pivoting to create their own IAM backdoor user, exactly as covered in the AWS Security room's IAM backdoor pattern.\n\n**Why this chain is uniquely dangerous:** each individual step, viewed in isolation, can look like unremarkable infrastructure activity. A pod being created (Step 1/2) is routine. A process on a node querying the instance metadata service (Step 3) is *also* routine. Legitimate applications query IMDS constantly to refresh their own credentials. The only way to catch Step 3 as malicious is context: does this specific process, on this specific node, at this specific time, have any legitimate reason to be querying the metadata endpoint? If the querying process traces back to a container that was created moments earlier with 'hostPID'/'privileged' set, and that container's image came from an unrecognised external registry (production clusters pull from named, approved registries such as ECR or an internal mirror; an image reference that starts with a bare IP and port, like '203.0.113.9:5000/tool:latest', points at a server with no DNS name, certificate or reputation behind it), the metadata-service query is the last, most damning link in a chain that was suspicious from Step 1, but only if the analyst has already connected Steps 1 through 3 together.\n\n**The SOC takeaway:** never evaluate a Kubernetes alert, an AWS/GCP metadata-service alert, and a suspicious-pod alert as three separate tickets. If they involve the same node, the same time window, and the same identity chain, they are almost certainly one incident (container escape leading to cloud credential theft) and should be investigated, contained, and reported as a single continuous kill chain.",
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
        "It pins the pod's main process to a fixed PID instead of a random one, which can affect PID-based monitoring but gives the container no extra visibility",
        "It removes process-namespace isolation, letting the container see, and with other privileges act on, every process on the node including other pods' processes",
        "It shares the host's network stack with the container, exposing node-level listening ports and the metadata endpoint without crossing the pod network",
        "It mounts the node's /proc filesystem read-only for diagnostics, so the container can read host statistics but cannot see processes outside the pod",
      ],
      answer: 1,
      explanation:
        "hostPID: true removes the process-namespace boundary that normally isolates a container so it can only see its own processes. With this setting, the container can see (and depending on other privileges, interact with) every process on the node: a serious escalation because it breaks the fundamental assumption that a container is isolated from its neighbours and from the host itself. “It shares the host's network stack” describes hostNetwork, a different setting. “It pins the pod's main process to a fixed PID” and “It mounts the node's /proc filesystem read-only” both assume the container's view stays limited to its own pod, which is exactly the boundary hostPID removes.",
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
        "Because attackers usually hit RBAC denials first, so the 403 failures before the create matter more than the create itself",
        "Because a benign pod and a node-escape pod both log the same create/pods/201 entry; the risk is only in requestObject.spec",
        "Because the namespace, not the verb or resource, decides whether a new pod runs privileged, so check the namespace instead",
        "Because sourceIPs decides it: a create arriving from inside the cluster network comes from trusted infrastructure",
      ],
      answer: 1,
      explanation:
        "Verb and resource only say a pod-creation request succeeded; a harmless application pod and a privileged hostPID/hostNetwork escape pod produce identical create/pods/201 entries, so the settings in requestObject.spec must be inspected. “Attackers usually hit RBAC denials first” is the Windows failed-logon habit; the reading stresses that Kubernetes attackers mostly use over-permissioned identities, so every request succeeds. “The namespace ... decides whether a new pod runs privileged” is false. Privilege comes from the pod spec's securityContext and host settings. “A create arriving from inside the cluster network” is not proof of trust: stolen tokens and compromised pods also call the API from inside.",
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
        "Your SIEM ingests Kubernetes audit logs from the production EKS cluster. An alert fires for a pod-creation event in the sensitive 'kube-system' namespace. Review the event below and answer the questions: pay close attention to the requestObject.spec fields, not just the verb and resource type.",
      event: k8sPrivilegedPodEvent,
      questions: [
        {
          question:
            "Looking at the requestObject.spec fields together with who created the pod and from where, what makes this pod creation look like a node-escape attempt rather than routine deployment activity?",
          options: [
            "Its kube-system placement alone, since every pod created in that namespace runs with cluster-admin rights",
            "hostPID, hostNetwork and privileged together, created by a CI token with an image from a bare-IP registry",
            "The hostPID, hostNetwork and privileged settings alone, since real workloads never combine all three",
            "Its in-cluster source IP, since a create sent from inside the cluster network means a pod was compromised",
          ],
          answer: 1,
          explanation:
            "hostPID, hostNetwork and privileged:true together remove process, network and capability isolation. What an attacker needs to reach the node. The context makes it suspicious: a CI deploy token, a one-off pod rather than a managed DaemonSet, and an image from an external registry addressed by bare IP instead of your approved registry. “The hostPID, hostNetwork and privileged settings alone” overclaims: legitimate DaemonSets such as CNI agents (Cilium, Calico) and runtime sensors (Falco) run with exactly this combination. “Its kube-system placement alone” is wrong: a pod's API rights come from its ServiceAccount's RBAC bindings, not the namespace. “Its in-cluster source IP” is normal: CI runners and controllers call the API from inside the network.",
          xp: 30,
        },
        {
          question:
            "Look at where the container image reference in this event points. Why does the registry part of that reference matter for your investigation?",
          options: [
            "It adds little: the kubelet checks image signatures before pulling, so an image that started is already trusted",
            "Approved clusters pull from named registries; a bare IP:port has no DNS name, certificate or reputation behind it",
            "It shows the image came from an in-cluster registry over the pod network, so nothing external was contacted",
            "Its port points to a plain-HTTP pull, so the risk is interception in transit rather than who runs the registry",
          ],
          answer: 1,
          explanation:
            "Reading 4 points out that production clusters pull from named, approved registries, while an image reference starting with a bare IP and port leads to a server with no DNS name, certificate or reputation: cheap, disposable infrastructure. Together with the privileged spec, that makes legitimate monitoring tooling very unlikely. “The kubelet checks image signatures” is not default behaviour; signature enforcement needs an admission policy you would have to deploy. “An in-cluster registry over the pod network” does not fit a public internet address like the one in this reference. “The risk is interception in transit” misses the point: the danger is that an unknown party chose and served the image.",
          xp: 30,
        },
        {
          question:
            "Look at the identity that made this request. Based on what you learned about RBAC over-permissioning, what is the most useful next step?",
          options: [
            "Check when the ServiceAccount's token was last rotated, since a stale token is how a pod becomes privileged",
            "Check whether its RBAC bindings let it create privileged pods in kube-system, and whether CI should hold that right",
            "Compare the pod's image digest with the last approved build, and close the alert if the two match",
            "Delete the pod and close the alert, since removing the workload removes the attacker's foothold",
          ],
          answer: 1,
          explanation:
            "The requester is the ci-deploy-token ServiceAccount, and a ServiceAccount's power comes entirely from its RoleBindings/ClusterRoleBindings. If a deployment pipeline can create privileged pods in kube-system, that over-permissioning is a finding in its own right, and it is what an attacker with the token would exploit again. “Token was last rotated” confuses credential age with privilege: a pod's privileges come from its spec and the creator's RBAC, not token age. “Compare the pod's image digest” can't clear a pod pulled from an unapproved bare-IP registry. “Delete the pod and close the alert” leaves the over-permissioned token in place for the next attempt.",
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
        "A medium-severity alert fires for a 'kubectl exec' session into a production pod. Review the event below, note that this is logged as a subresource action on an existing pod, not a new pod creation.",
      event: k8sExecEvent,
      questions: [
        {
          question:
            "The event shows objectRef.subresource = 'exec' rather than a plain pod creation. What does this specifically mean happened, and why is it functionally similar to an interactive remote-desktop or SSH session in a traditional Windows/Linux environment?",
          options: [
            "A short-lived pod was created to run one command, Job-style, and was removed once it finished",
            "A command session was opened inside an already-running pod, like SSH or RDP onto a live server",
            "The kubelet ran a liveness-probe command inside the container as part of a routine health check",
            "The user read the pod's output with kubectl logs, which the audit log records under this subresource",
          ],
          answer: 1,
          explanation:
            "kubectl exec, logged as the 'exec' subresource of pods (verb create, response 101 as the connection upgrades to a stream), runs commands inside a container that is already running: the container equivalent of SSH or RDP onto a live server. “A short-lived pod was created” would be a plain create on pods with no subresource. “A liveness-probe command” is run by the kubelet through the container runtime on the node, not through an API-server exec, and would not carry a human username like d.abrams. “kubectl logs” is recorded under the separate 'log' subresource.",
          xp: 25,
        },
        {
          question:
            "Read the command carried in the exec request URI and who issued it. What is the most appropriate analyst action for this medium-severity alert?",
          options: [
            "Close it as benign: d.abrams is a known engineer, and a package install in a cluster they work on is routine",
            "Declare a confirmed compromise and isolate the node, since curl is a common attacker tool for fetching payloads",
            "Verify with d.abrams or their manager whether a ticket or debugging task explains this exec before deciding",
            "Revoke all of d.abrams' cluster access now and investigate afterwards, since that is the safest default",
          ],
          answer: 2,
          explanation:
            "The request URI shows a shell running 'apt-get install -y curl' inside a production pod, issued by a real, known engineer outside their usual pattern. That could be incident debugging or a stolen account staging tooling, so the next step is to verify against a ticket or with a manager before closing either way. “Close it as benign” trusts the identity without checking it, which is exactly how a compromised engineer account gets waved through. “Declare a confirmed compromise” jumps past the evidence: curl is also a standard debugging tool. “Revoke all of d.abrams' cluster access now” is a disproportionate first move for an unverified medium alert and could break live production support.",
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
          right: "Runs the container with nearly all Linux kernel capabilities and confinement disabled. Functionally equivalent to root on the node itself",
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
          right: "Endpoint queried from a compromised node to steal that node's live cloud IAM role/service-account credentials: the same technique used against standalone EC2 instances",
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
        "To block the attacker's image source at the egress firewall, you need the registry endpoint behind the privileged pod in kube-system. Enter only the registry host and port (host:port), not the image name or tag.",
      answer: "185.220.101.47:5000",
      hint: "An image reference has the form registry/repository:tag. Find the image the privileged pod pulled and keep only the part before the first slash.",
      xp: 30,
    },
  ],
};

export default [k8sSecurityRoom];
