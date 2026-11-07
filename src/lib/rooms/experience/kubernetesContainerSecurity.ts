import type { RoomExperience } from "./types";

// "Operation Container Break" for the "kubernetes-container-security" room.
// Script: docs/campaign/106-kubernetes-container-security.md.
// Station task ids must match the room's task order exactly (see getRoomExperience).
//
// Northlight Streaming (fictional), not the graded tasks' NexaCorp records.
// Signature: From Pod to Node. A pathway from an exposed pod through its mounted ServiceAccount
// token and RBAC to a privileged pod and the node, and a spotdiff of a reviewed pod spec beside a
// dangerous copy (hostPID, privileged, hostPath). Audit data uses the real fields: verb, objectRef,
// user.username, sourceIPs, requestObject, responseStatus.code.
// Game mix: codebreak + intercept + pathway + spotdiff. Other labs: anatomy, inspect, queue,
// simulate, sort, trace, worksheet.
//
// Task order changed. The source lists r1, r2, r3, r4, q1, q2, la1, la2, m1, f1: four readings in
// a row, and q1 two readings away from what it tests. New order:
//   r1, r2, q1 | r3, q2, la2 | r4, m1 | la1, f1
// Readings keep their order, so "Reading 2" and "Reading 4" still point the right way. la1's
// explanation cites Reading 4, so it stays after r4. m1 needs r4 (metadata service). la2 moves
// ahead of la1: nothing refers to either by number. f1 stays right after la1, and carries
// logTask k8s-la1. Its prompt does not say "Log Analysis N". Boss: la1 + f1.
//
// Lab data differs from the graded tasks: no ci-deploy-token, no kube-system, no
// svc-monitoring-backup, no 203.0.113.47, no prod-checkout, no d.abrams, no apt-get. The node
// route starts from an application's own ServiceAccount (subtitle-upload) and a namespaced Role,
// never a CI identity. The escape pod reuses the team's own image, so its image check passes and
// the other three fail (la1 has an outside image). The change queue (q2) runs on Deployments,
// DaemonSets, Jobs and CronJobs, never a plain pod creation. The exec anatomy is kubectl cp with
// a ticket, tar not sh, and the queue that follows has port-forward and attach (la2). The image
// worksheet splits 198.51.100.23:8443 (f1). hostPID, privileged and hostPath are explained on a
// tap in the spotdiff, shown, never asked (q1, m1). The kubelet and the token path are shown in
// passing, never asked (r1 and r3 checkpoints).

/** Lab copies render without preserved spaces, so YAML keeps its indent with no-break spaces. */
const yaml = (lines: string[]) => lines.map(l => l.replace(/^ +/, m => " ".repeat(m.length)));

const UPLOAD_SA = "system:serviceaccount:captions:subtitle-upload";
const NODE_SESSION = "nl-eks-node-role/i-0c4e1a7f92b3d6058";

export const KUBERNETES_CONTAINER_SECURITY: RoomExperience = {
  roomId: "kubernetes-container-security",
  codename: "Operation Container Break",
  theme: "containerbreak",
  handler: { name: "Dae-jung Whitaker", role: "Platform Security Engineer, Northlight Streaming" },
  briefing: [
    "Northlight Streaming. One Kubernetes cluster carries every stream, every subtitle and every ad, and the finale of Glasswater goes out on Saturday night.",
    "At 01:12 on Friday a pod called subtitle-cache-warm started on a production node. Nobody on the platform team deployed it.",
    "Dae-jung Whitaker has the audit log, a sensor on the node and one question: how did a subtitle uploader get that close to the machine underneath?",
    "Learn what separates a pod from its node, walk the route the intruder took, read the audit log past its first three fields, and follow the chain off the cluster.",
  ],
  mission: "Learn what a container shares with its node, find the spec lines that take its walls down, walk from an exposed pod to the node, read what an audit entry really records, follow stolen node credentials into the cloud, then give your ruling on one pod creation.",
  estimate: "~50 min",
  look: { primary: "#ff9f5a", secondary: "#6fd3ff", warn: "#ff4d6d" },
  scene: "facilitycontainerbreak",
  layout: "facility",
  stations: [
    {
      id: "cluster",
      label: "The Cluster",
      topic: "Containers and the shared kernel · pods, nodes and the kubelet · privileged, hostPID, hostNetwork, hostPath",
      tagline: "Who deployed that pod?",
      building: "control",
      taskIds: ["k8s-r1", "k8s-r2", "k8s-q1"],
    },
    {
      id: "audit",
      label: "The Audit Trail",
      topic: "ServiceAccounts and tokens · RBAC · reading the Kubernetes audit log · kubectl exec",
      tagline: "Every request left a line",
      building: "archive",
      taskIds: ["k8s-r3", "k8s-q2", "k8s-la2"],
    },
    {
      id: "node",
      label: "The Node",
      topic: "Container to node · the instance metadata service · stolen cloud credentials · one incident, not three tickets",
      tagline: "What can the node reach?",
      building: "factory",
      taskIds: ["k8s-r4", "k8s-m1"],
    },
    {
      id: "break",
      label: "Container Break",
      topic: "Weighing a pod creation · image references",
      tagline: "One pod, your ruling",
      building: "emergency",
      taskIds: ["k8s-la1", "k8s-f1"],
      boss: true,
    },
  ],
  personas: {
    "k8s-q1": { name: "Dae-jung Whitaker", role: "Platform Security Engineer", line: "One field from a pod spec. Tell me what it really does." },
    "k8s-q2": { name: "Dae-jung Whitaker", role: "Platform Security Engineer", line: "Put this in words the on-call team will remember." },
    "k8s-la2": { name: "Dae-jung Whitaker", role: "Platform Security Engineer", line: "Medium severity, one pod. Read the event and tell me what you make of it." },
    "k8s-m1": { name: "Dae-jung Whitaker", role: "Platform Security Engineer", line: "Five terms for the handover note. Get them straight." },
    "k8s-la1": { name: "Dae-jung Whitaker", role: "Platform Security Engineer", line: "A new pod and a new alert. Take your time with this one." },
    "k8s-f1": { name: "Dae-jung Whitaker", role: "Platform Security Engineer", line: "The firewall team is waiting on one value." },
  },
  briefings: {
    // ── Reading 1: containers, pods, nodes ──
    "k8s-r1": [
      {
        kind: "codebreak",
        title: "Four Words Under Every Container",
        prompt: "Friday, 02:05. A pod nobody deployed is running on a production node, and the SOC has joined the call. Before anyone can say how far it reached, Dae-jung needs four words understood. Work each one out from its clue.",
        primer: {
          fold: true,
          title: "What a container really is",
          points: [
            "A **container** is an ordinary Linux process with kernel features around it. **Linux namespaces** give it a private view of processes, network and mounts. **cgroups** (control groups) cap the CPU and memory it can use.",
            "Every container on a machine runs on that machine's one kernel. A virtual machine boots a kernel of its own.",
            "A **pod** is one or more containers scheduled together, sharing an IP address and volumes. A **node** is the machine that runs pods, often a cloud VM. A **cluster** is the whole fleet.",
            "The **kubelet** is the agent on each node. It takes its orders from the control plane and starts or stops that node's containers.",
            "Careful with one word: a **Kubernetes namespace** groups objects in the API. A **Linux namespace** isolates what a process can see. They are different things.",
          ],
          example: {
            label: "One process, two views",
            lines: [
              "Inside a container, `ps` shows `PID 1  nginx: master`.",
              "On the node, `ps -ef` shows that same process as `PID 48213`.",
              "One process, two numbers. The container's view is private, and the node's view is not.",
            ],
          },
        },
        rounds: [
          { id: "c1", clue: "Two containers on one node print the same uname -r. What are they both running on?", answer: "KERNEL", why: "There is one kernel per machine, and every container on the machine uses it. A flaw or a setting at that level touches all of them." },
          { id: "c2", clue: "The Linux feature that lets a container believe its app is PID 1.", answer: "NAMESPACE", why: "A Linux namespace gives a process its own view of something: process IDs, network interfaces, mount points. The process is still on the host." },
          { id: "c3", clue: "An encoder hits its memory limit and is OOMKilled. Which kernel feature enforced the limit?", answer: "CGROUPS", why: "Control groups meter and cap CPU and memory. They limit how much a process uses, and say nothing about what it can see." },
          { id: "c4", clue: "Two containers share one IP address and always land on the same machine. What are they grouped in?", answer: "POD", why: "The pod is the smallest unit Kubernetes schedules. Its containers share networking and volumes, and they move together." },
        ],
        lesson: "A container is a process and a set of kernel settings, on a kernel it shares with everything else on that machine. That is why it starts in milliseconds, and it is also why a setting can take its isolation away.",
      },
      {
        kind: "worksheet",
        title: "What Sits on One Node?",
        prompt: "Dae-jung pastes the cluster's pods into the call. Teams and namespaces look like walls in this list. Work out what a single machine really holds.",
        caption: "kubectl get pods -A -o wide · nl-prod-1 · trimmed",
        columns: ["NAMESPACE", "NAME", "STATUS", "IP", "NODE"],
        rows: [
          ["captions", "subtitle-upload-6d8f7c9b5-x2kqp", "Running", "10.42.71.14", "ip-10-42-7-19.ec2.internal"],
          ["captions", "caption-db-0", "Running", "10.42.31.9", "ip-10-42-3-8.ec2.internal"],
          ["playback", "manifest-api-7d4b8f6c9-hv5rd", "Running", "10.42.71.22", "ip-10-42-7-19.ec2.internal"],
          ["playback", "edge-cache-58c6d7f4b-p9tmz", "Running", "10.42.31.40", "ip-10-42-3-8.ec2.internal"],
          ["artwork", "thumb-render-5b7d9c8f6-tq8zv", "Running", "10.42.71.35", "ip-10-42-7-19.ec2.internal"],
          ["billing", "invoice-api-6f7d5b9c4-l2wsn", "Running", "10.42.52.11", "ip-10-42-5-2.ec2.internal"],
          ["billing", "invoice-db-0", "Running", "10.42.52.18", "ip-10-42-5-2.ec2.internal"],
          ["logging", "log-shipper-7xq2p", "Running", "10.42.7.19", "ip-10-42-7-19.ec2.internal"],
          ["logging", "log-shipper-k4d9w", "Running", "10.42.3.8", "ip-10-42-3-8.ec2.internal"],
          ["logging", "log-shipper-z8m1c", "Running", "10.42.5.2", "ip-10-42-5-2.ec2.internal"],
        ],
        questions: [
          { id: "count", q: "How many pods run on ip-10-42-7-19.ec2.internal?", hint: "Read the NODE column, not the NAMESPACE column.", answer: ["4", "four"], why: "subtitle-upload, manifest-api, thumb-render and a log shipper: four teams' work on one machine. The NODE column shows what sits together." },
          { id: "ns", q: "An intruder gets root on ip-10-42-5-2.ec2.internal. How many Kubernetes namespaces have a pod within reach?", hint: "Find that node's rows, then count the different namespaces.", answer: ["2", "two"], why: "billing and logging. Kubernetes namespaces organise the API. On the node, both are processes on one kernel, so root on the machine reaches both." },
        ],
      },
    ],
    // ── Reading 2: the settings that weaken isolation ──
    "k8s-r2": [
      {
        kind: "spotdiff",
        title: "Safe Spec, Dangerous Spec",
        prompt: "Friday, 02:20. On the left, the captions team's reviewed cache pod, from Git. On the right, what is running on ip-10-42-7-19. Someone copied the file and changed it. Tap the lines that take away a wall between the container and the node.",
        primer: {
          fold: true,
          title: "Where a pod spec sets its walls",
          points: [
            "Pod-level fields sit directly under `spec:`. Container fields sit under each entry in `containers:`. Volumes are declared in `spec.volumes` and mounted by name through `volumeMounts`.",
            "By default a container gets its own Linux namespaces, a cut-down set of capabilities, and no view of the node's disk.",
            "A **capability** is one slice of root's power. A process can hold some and not others.",
            "Some spec fields change those defaults on purpose. For each line ask: what could this container see or touch before, and what can it now?",
            "A volume's `name` and its `mountPath` are labels. What is really there depends on the volume's source.",
          ],
          example: {
            label: "One line, read that way: runAsUser",
            lines: [
              "`securityContext: { runAsUser: 0 }`",
              "Where: container level, so it applies to this container only.",
              "Before: whichever user the image chose. After: UID 0 inside the container.",
              "What stays the same: its Linux namespaces and its reduced capabilities.",
            ],
          },
        },
        goodTitle: "captions/subtitle-cache · reviewed, in Git",
        suspectTitle: "captions/subtitle-cache-warm · running",
        good: yaml([
          "kind: Pod",
          "metadata:",
          "  name: subtitle-cache",
          "  namespace: captions",
          "spec:",
          "  hostPID: false",
          "  containers:",
          "  - name: cache",
          "    image: registry.northlight.example/captions/cache:2.3.0",
          "    imagePullPolicy: IfNotPresent",
          "    securityContext: { privileged: false }",
          "    volumeMounts: [{ name: scratch, mountPath: /cache }]",
          "  volumes:",
          "  - { name: scratch, emptyDir: {} }",
        ]),
        suspect: yaml([
          "kind: Pod",
          "metadata:",
          "  name: subtitle-cache-warm",
          "  namespace: captions",
          "spec:",
          "  hostPID: true",
          "  containers:",
          "  - name: cache",
          "    image: registry.northlight.example/captions/cache:2.3.0",
          "    imagePullPolicy: Always",
          "    securityContext: { privileged: true }",
          "    volumeMounts: [{ name: scratch, mountPath: /cache }]",
          "  volumes:",
          "  - { name: scratch, hostPath: { path: / } }",
        ]),
        diffs: [
          { line: 5, why: "hostPID: true puts the container in the node's process namespace. ps inside it now lists the kubelet, containerd and the workloads of every other pod on the machine. With enough privilege it can signal them or attach a debugger." },
          { line: 10, why: "privileged: true gives the container the node's devices and the kernel powers that are normally stripped away, and SELinux and AppArmor stop applying to it. It can load a kernel module. At that point the container is a formality." },
          { line: 13, why: "The volume name and the mount path never changed, which is why this one is easy to miss. The source did: an emptyDir became a hostPath of /, so /cache is now the node's whole filesystem, and writing to /cache/etc writes to the node." },
        ],
        decoys: [
          { line: 2, why: "Worth noticing, and it proves nothing. A pod name is free text. It takes no wall away, and the next pod could be called anything." },
          { line: 9, why: "imagePullPolicy only decides when the node fetches the image. The image itself is unchanged, so this gives the container nothing new." },
        ],
        hud: "Tap the lines that remove a wall between container and node",
        sameLine: "That line is the same in both specs.",
        winTitle: "Every wall found",
        howTo: [
          "Compare the running spec with the reviewed one, line by line.",
          "Tap each line that takes away isolation from the node.",
          "Some lines changed and do no harm. Tapping one costs a life and says why.",
        ],
        lesson: "None of these lines needs a vulnerability. They are ordinary fields in an ordinary request, and each one takes a wall down on purpose. A line that changed is not always a line that matters, so read what it does.",
      },
      {
        kind: "inspect",
        title: "Why a Node Agent Asks for Host Access",
        prompt: "Settings like those exist for a reason. Tap through the spec of Northlight's log shipper, plus one line from its security sensor, and see what each one does.",
        artifact: "DaemonSet · logging/log-shipper, and one line from security/runtime-sensor",
        items: [
          { id: "kind", text: "kind: DaemonSet", tag: "Workload", tone: "info", note: "A DaemonSet runs one copy of a pod on each node. Software that works on the node itself is shipped this way." },
          { id: "net", text: "hostNetwork: true", tag: "Network", tone: "warn", note: "The pod uses the node's network interfaces instead of a virtual one of its own. It shares the node's IP address, can bind ports on the node and sees the node's traffic. Policies written for pod networking do not reliably apply to it." },
          { id: "logs", text: "hostPath: { path: /var/log, type: Directory }", tag: "Filesystem", tone: "warn", note: "A path on the node's disk appears inside the container. The path decides how much of the node shows through." },
          { id: "ro", text: "readOnly: true", tag: "Mount option", tone: "trust", note: "The container can read that mount and cannot write to it." },
          { id: "cap", text: "capabilities: { add: [NET_BIND_SERVICE] }", tag: "Capability", tone: "info", note: "One named capability: permission to bind a port below 1024. The rest of root's powers stay off." },
          { id: "img", text: "image: registry.northlight.example/logging/shipper:5.1", tag: "Image", tone: "trust", note: "The registry part names Northlight's own image store." },
          { id: "auto", text: "automountServiceAccountToken: false", tag: "API identity", tone: "trust", note: "No Kubernetes API token is placed in this pod. This build reads files and forwards them, so it never calls the API." },
          { id: "sock", text: "hostPath: { path: /run/containerd/containerd.sock }", tag: "Runtime socket", tone: "warn", note: "From the runtime sensor, not the shipper. This is the API socket of containerd, the container runtime. Whatever can reach it can ask the runtime to create and control containers on this node, without going through Kubernetes." },
        ],
      },
    ],
    // ── Reading 3: RBAC and the audit log ──
    "k8s-r3": [
      {
        kind: "pathway",
        title: "From Pod to Node",
        prompt: "Friday, 02:30. How does a subtitle upload end up with the machine underneath? Walk it the way the intruder did, from the exposed pod to ip-10-42-7-19, one hop at a time. Each hop has to be something the last one really allows.",
        primer: {
          fold: true,
          title: "Who a pod is, and what it may do",
          points: [
            "A **ServiceAccount** is the identity a pod uses to call the Kubernetes API. In the audit log it reads `system:serviceaccount:<namespace>:<name>`.",
            "A **Role** lists allowed verbs on resource types in one namespace. A **ClusterRole** is the cluster-wide form.",
            "A **RoleBinding** connects a Role to a person or a ServiceAccount, in one namespace. A **ClusterRoleBinding** does it across the cluster. An identity has the rights its bindings give it, and no others.",
            "**RBAC** (Role-Based Access Control) checks the verb and the resource, and never opens the spec. A right to `create pods` covers whatever pod you write.",
            "Reading the spec is the job of admission control. **Pod Security Admission** does it per namespace, through a label such as `pod-security.kubernetes.io/enforce: restricted`.",
          ],
          example: {
            label: "Reading one grant",
            lines: [
              "`kubectl auth can-i list configmaps -n ads --as=system:serviceaccount:ads:report-bot`",
              "Answer: `yes`. RoleBinding report-read gives Role config-reader to that ServiceAccount.",
              "Same command with `delete`: `no`. The Role lists only `get` and `list`.",
            ],
          },
        },
        goal: "reach the node ip-10-42-7-19",
        nodes: [
          { id: "web", label: "subtitle-upload pod", sub: "captions, takes files from the internet", x: 12, y: 44 },
          { id: "db", label: "caption-db", sub: "Postgres on 5432", x: 14, y: 84 },
          { id: "token", label: "Mounted token", sub: "ServiceAccount subtitle-upload", x: 32, y: 18 },
          { id: "secrets", label: "Secrets in captions", sub: "verb get", x: 34, y: 62 },
          { id: "rbac", label: "API server, RBAC", sub: "RoleBinding subtitle-jobs", x: 54, y: 18 },
          { id: "billing", label: "billing namespace", sub: "enforce: restricted", x: 54, y: 84 },
          { id: "plain", label: "A plain new pod", sub: "default spec", x: 72, y: 72 },
          { id: "priv", label: "Pod with host access", sub: "hostPID, privileged, hostPath /", x: 74, y: 42 },
          { id: "node", label: "The node", sub: "ip-10-42-7-19", x: 90, y: 14 },
        ],
        edges: [["web", "token"], ["web", "db"], ["token", "secrets"], ["token", "rbac"], ["rbac", "billing"], ["rbac", "plain"], ["rbac", "priv"], ["priv", "node"]],
        route: ["web", "token", "rbac", "priv", "node"],
        notes: {
          web: "Start here. A flaw in the subtitle parser gave the intruder code execution in this container, as an ordinary process with its own small view of the world.",
          token: "Token file: /var/run/secrets/kubernetes.io/serviceaccount/token. The app never uses it, and cat is enough to read it. Setting automountServiceAccountToken: false would have kept it out.",
          rbac: "The API server accepts the token and checks RBAC. RoleBinding subtitle-jobs gives Role job-runner to this ServiceAccount: get, list and create on pods and jobs in captions. Somebody wanted the app to start render jobs.",
          priv: "RBAC saw create on pods, which is allowed, and never read the spec. The captions namespace has no Pod Security label, so nothing else did either. Response code 201.",
          node: "nsenter into PID 1, or chroot into the mounted /, and the shell is running on ip-10-42-7-19 itself, beside the kubelet and every other pod on the machine.",
        },
        traps: {
          db: "The app can reach caption-db, and it holds subtitles. A database login gives you that database's rows, and brings you no closer to the machine underneath.",
          secrets: "The audit log shows verb get on secrets, code 403. The token is genuine, and Role job-runner names pods and jobs. Secrets are not on the list.",
          billing: "The RoleBinding lives in captions, so in billing this token gets a 403. That namespace also enforces the restricted Pod Security profile, which refuses a spec like this one.",
          plain: "The API server would accept it, and you would be in another container behind the same walls. A default spec gets you no closer to the node.",
        },
        lesson: "Four hops, and none of them was an exploit: the only flaw was the parser bug that started it. The token was already in the pod, the Role was broader than the job, RBAC does not read specs, and the namespace enforced no Pod Security profile. Each of those can be closed, and only the last one looks inside the pod.",
      },
      {
        kind: "sort",
        title: "What Did This Request Do?",
        prompt: "Dae-jung gives you a morning's audit lines from other teams, as practice before tonight's. Sort each one by what it actually did. The verb alone will not always tell you.",
        primer: {
          fold: true,
          title: "Read an audit line left to right",
          points: [
            "`verb` is the action: `get`, `list`, `create`, `update`, `patch`, `delete`.",
            "`objectRef.resource` is the type of thing. `objectRef.subresource` narrows it to one operation on that thing, and can change what the verb means.",
            "`user.username` is who sent it: a person, or `system:serviceaccount:<namespace>:<name>`. `sourceIPs` is the address the API server saw.",
            "`responseStatus.code` is the result: 200 OK, 201 Created, 403 Forbidden, and 101 when the connection became a stream.",
            "An identity that already holds a right gets a plain 200 or 201 for using it.",
          ],
          example: {
            label: "One line, read aloud",
            lines: [
              "`verb=delete objectRef.resource=services objectRef.namespace=ads user.username=t.brandt@northlight.example responseStatus.code=200`",
              "A person deleted a Service in ads, and it worked.",
            ],
          },
        },
        buckets: [
          { id: "work", label: "A workload starts or changes" },
          { id: "stream", label: "A stream opens into a live pod" },
          { id: "access", label: "Access changes" },
          { id: "read", label: "Stored data is read" },
        ],
        items: [
          { id: "s1", text: "verb=create  resource=jobs  code=201", bucket: "work", why: "A Job creates pods. The 201 says the object now exists." },
          { id: "s2", text: "verb=create  resource=pods  subresource=attach  code=101", bucket: "stream", why: "Attach joins a process that is already running. Here create means open a connection, so read the subresource before the verb." },
          { id: "s3", text: "verb=get  resource=secrets  code=200", bucket: "read", why: "One Secret returned, value included. Base64 is not encryption." },
          { id: "s4", text: "verb=create  resource=clusterrolebindings  code=201", bucket: "access", why: "A new binding across the cluster. Whoever it names now holds that role everywhere." },
          { id: "s5", text: "verb=patch  resource=daemonsets  code=200", bucket: "work", why: "A patch to a DaemonSet rolls out to every node it runs on." },
          { id: "s6", text: "verb=create  resource=serviceaccounts  subresource=token  code=201", bucket: "access", why: "The account already existed. This mints a fresh token for it, which is a new credential." },
          { id: "s7", text: "verb=create  resource=pods  subresource=portforward  code=101", bucket: "stream", why: "A tunnel from the caller's machine to a port inside a running pod. No new pod starts." },
          { id: "s8", text: "verb=list  resource=secrets  code=200", bucket: "read", why: "list returns every Secret in the namespace with its values, so it is worth more to an intruder than one get." },
          { id: "s9", text: "verb=patch  resource=rolebindings  code=200", bucket: "access", why: "Adding a subject to a binding hands out a role with no new object created." },
        ],
      },
      {
        kind: "worksheet",
        title: "Whose Binding Is Too Big?",
        prompt: "Friday, 02:40. subtitle-upload could do more than its job needed. Dae-jung wants every binding like that found before Saturday. Read the table and answer the way kubectl auth can-i would.",
        caption: "Bindings review · nl-prod-1",
        columns: ["Binding", "Kind", "Scope", "Role", "Role allows", "Subject", "Job"],
        rows: [
          ["scrape-read", "RoleBinding", "ingest", "pod-reader", "get, list pods", "ingest/metrics-scraper", "Reads pod status"],
          ["subtitle-jobs", "RoleBinding", "captions", "job-runner", "get, list, create pods and jobs", "captions/subtitle-upload", "Parses uploads, starts render Jobs"],
          ["transcode-temp", "ClusterRoleBinding", "whole cluster", "cluster-admin", "every verb on every resource", "transcode/farm-controller", "Starts Jobs in transcode"],
          ["gitops-apply", "ClusterRoleBinding", "whole cluster", "gitops-deployer", "create, update, patch workloads", "gitops/deploy-controller", "Applies reviewed manifests"],
          ["report-read", "RoleBinding", "ads", "config-reader", "get, list configmaps", "ads/report-bot", "Reads report settings"],
        ],
        questions: [
          { id: "big", q: "Which ServiceAccount holds the most beyond its job? Give its name.", hint: "Compare the Role allows column with the Job column, row by row.", answer: ["farm-controller", "transcode/farm-controller"], why: "cluster-admin is the built-in role with every right there is, given to a controller that starts Jobs in one namespace. The binding says temp, and nobody came back to it. A Role in transcode would do the job." },
          { id: "can1", q: "kubectl auth can-i create pods -n billing --as=system:serviceaccount:captions:subtitle-upload. Yes or no?", hint: "What is the scope of its binding?", answer: ["no"], why: "subtitle-jobs is a RoleBinding in captions, so its rights stop at that namespace." },
          { id: "can2", q: "Same command, but --as=system:serviceaccount:transcode:farm-controller. Yes or no?", hint: "What is the scope of this binding?", answer: ["yes"], why: "A ClusterRoleBinding to cluster-admin reaches every namespace. When an identity does something odd, this is the next thing to open: what it can do tells you how far its token goes, and who decided it should." },
        ],
      },
    ],
    // ── q2 drill: what sits behind the first three fields ──
    "k8s-q2": [
      {
        kind: "intercept",
        title: "The Change Queue",
        prompt: "Friday, 02:55. Dae-jung exports every workload change from the past week. All ten came back with a success code. Open the body, see who sent it, and pull the ones a person must look at before they land. Clear the rest.",
        primer: {
          fold: true,
          title: "Where a request's body is kept",
          points: [
            "At audit level `Metadata` an event records who did what, with no body. At `Request` or `RequestResponse` it also carries `requestObject`, the object as submitted.",
            "A Deployment, DaemonSet or Job wraps a pod template, so the pod's fields sit deeper: `requestObject.spec.template.spec`.",
            "A `patch` body carries only what is being changed, so it is short and quick to read.",
            "Northlight's images come from `registry.northlight.example`. Reviewed changes reach the cluster through `system:serviceaccount:gitops:deploy-controller`.",
          ],
          example: {
            label: "Finding a field inside a CronJob",
            lines: [
              "`requestObject.spec.schedule`: the timetable.",
              "`requestObject.spec.jobTemplate.spec.template.spec.containers[0].image`: the image.",
              "`requestObject.spec.jobTemplate.spec.template.spec.volumes`: the volumes.",
              "A CronJob wraps a Job, which wraps a pod, so the path is two levels longer.",
            ],
          },
        },
        protect: "nl-prod-1",
        blockLabel: "Pull",
        passLabel: "Clear",
        seconds: 12,
        items: [
          { id: "i1", text: "create daemonsets/log-shipper · 201", sub: "hostPath /var/log, read-only. Image from registry.northlight.example. Sent by gitops:deploy-controller", bad: false, why: "One log directory, read-only, for an agent that lives on every node, through the reviewed path." },
          { id: "i2", text: "patch deployments/manifest-api · 200", sub: "Body: image tag 8.4.1 to 8.4.2, same registry. Sent by gitops:deploy-controller", bad: false, why: "A version bump through the reviewed path. This is what most lines in this queue look like." },
          { id: "i3", text: "patch deployments/manifest-api · 200", sub: "Body: template.spec.hostPID: true. Sent by j.lindqvist@northlight.example", bad: true, why: "Same verb, same resource, same code and the same Deployment as the version bump. The body gives every replica a view of the node's processes." },
          { id: "i4", text: "create jobs/report-0412 · 201", sub: "No host settings. Image 198.51.100.23:8443/ops/agent:3.2. Sent by ads:campaign-runner", bad: true, why: "The spec is clean, and the code it runs came from an address and a port that no team here can put a name to. Host settings are only part of what the body tells you." },
          { id: "i5", text: "create jobs/render-2204 · 201", sub: "emptyDir, memory limit 2Gi. Image from registry.northlight.example. Sent by captions:subtitle-upload", bad: false, why: "A render Job, from the app that starts them, with nothing but scratch space." },
          { id: "i6", text: "create deployments/thumb-worker · 201", sub: "hostPath /run/containerd/containerd.sock. Sent by a.mensah@northlight.example", bad: true, why: "An image-resizing worker has no use for the container runtime's socket. Anything holding it can start containers on the node." },
          { id: "i7", text: "create daemonsets/runtime-sensor · 201", sub: "privileged, hostPID. Image from registry.northlight.example. Sent by gitops:deploy-controller, change CHG-4127", bad: false, why: "A security sensor has to see the node to do its job. It came as a DaemonSet, from the reviewed path, on a ticket, from your own registry." },
          { id: "i8", text: "patch cronjobs/invoice-run · 200", sub: "Body: jobTemplate...spec.hostNetwork: true. Sent by s.iyer@northlight.example", bad: true, why: "A nightly invoice job has no reason to sit on the node's network interfaces. The field sits deep in the template, so a rule that stops at the top of spec never sees it." },
          { id: "i9", text: "create deployments/edge-cache · 201", sub: "CPU and memory limits. Image from registry.northlight.example. Sent by gitops:deploy-controller", bad: false, why: "An ordinary workload through the ordinary path." },
          { id: "i10", text: "patch daemonsets/log-shipper · 200", sub: "Body: hostPath /var/log changed to /. Sent by gitops:deploy-controller", bad: true, why: "A trusted agent and a trusted identity, and its mount just grew from one directory to the node's whole disk, on every node. A familiar sender is a reason to look at the body, never a reason to skip it." },
        ],
        lesson: "Ten requests, nearly the same three fields. What separated them was inside requestObject, together with who sent it and where its image came from. A host setting raises the question, and the job, the sender and the path it took answer it.",
      },
    ],
    // ── la2 drills: an exec record, and who can explain it ──
    "k8s-la2": [
      {
        kind: "anatomy",
        title: "Anatomy of a Session Into a Pod",
        prompt: "Yesterday afternoon m.okoye on the artwork team copied exports out of a running pod with kubectl cp. Read the audit record field by field.",
        source: "Kubernetes audit log · nl-prod-1",
        fields: [
          { key: "requestReceivedTimestamp", value: "2026-10-29T16:42:09.118Z", label: "When" },
          { key: "stage", value: "ResponseStarted", note: "Long-running requests log one event when the stream opens and another when it ends." },
          { key: "verb", value: "create", label: "Action", note: "Newer kubectl versions connect over WebSocket, and the same action is then logged as get." },
          { key: "objectRef.resource", value: "pods" },
          { key: "objectRef.subresource", value: "exec", label: "Operation", note: "A command in a container that is already up: the cluster's version of a remote shell. No new pod starts, so the event has no pod spec in it." },
          { key: "objectRef.namespace", value: "artwork" },
          { key: "objectRef.name", value: "thumb-render-5b7d9c8f6-tq8zv", label: "Target" },
          { key: "user.username", value: "m.okoye@northlight.example", label: "Who", note: "The identity that signed in, as the identity provider named it." },
          { key: "sourceIPs", value: "[\"10.42.60.21\"]", label: "From", note: "The address the API server saw. Requests from pods and in-cluster controllers show internal addresses too." },
          { key: "requestURI", value: "/api/v1/namespaces/artwork/pods/thumb-render-5b7d9c8f6-tq8zv/exec?command=tar&command=cf&command=-&command=%2Fdata%2Fexports&container=render&stdout=true&stderr=true", label: "What ran", note: "Each command= is one word of the command line, percent-encoded: %2F is a slash. Decoded, this is tar cf - /data/exports, which is what kubectl cp sends." },
          { key: "responseStatus.code", value: "101", label: "Result", note: "Switching Protocols: the HTTP request became a two-way stream." },
          { key: "annotations.authorization.k8s.io/reason", value: "RBAC: allowed by RoleBinding \"artwork-dev/artwork\" of ClusterRole \"edit\" to User \"m.okoye@northlight.example\"", label: "Why allowed", note: "Names the exact binding that let the request through." },
        ],
        summary: "A session into a pod has a shape: verb create, the exec subresource, code 101, and a URI that spells out the command. The record says what ran and who ran it, and the reason annotation says which binding allowed it. Why it happened is not in the record at all.",
      },
      {
        kind: "queue",
        title: "Who Can Explain This?",
        prompt: "Five sessions from this week's review queue. The audit log can tell you what happened, and the reason has to come from somewhere else. Open each one, read the context and take the call Dae-jung would.",
        primer: {
          fold: true,
          title: "What counts as a reason",
          points: [
            "A **change ticket** names a person, a target and a time window. It explains an event only when all three match.",
            "An **on-call rota** says who may be working at odd hours, and an open incident says on what.",
            "Records outside the cluster, such as HR and the identity provider, say whether an account should exist at all.",
          ],
          example: {
            label: "Checking a ticket against an event",
            lines: [
              "CHG-3902: t.brandt, ads/report-api, Tuesday 14:00 to 15:00.",
              "An exec by t.brandt into that pod at 14:20: person, target and window all match.",
              "The same exec at 19:00: two out of three, so the ticket does not cover it.",
            ],
          },
        },
        console: "Platform audit · Review queue",
        actions: [
          { id: "close", label: "Close, explained", tone: "close" },
          { id: "ask", label: "Ask the owner", tone: "escalate" },
          { id: "contain", label: "Contain now", tone: "contain" },
        ],
        alerts: [
          {
            id: "a1", time: "Thu 16:42", severity: "Medium", rule: "Exec into a running pod", entity: "artwork/thumb-render-5b7d9c8f6-tq8zv",
            fields: [{ k: "user.username", v: "m.okoye@northlight.example" }, { k: "objectRef.subresource", v: "exec" }, { k: "Decoded command", v: "tar cf - /data/exports" }, { k: "responseStatus.code", v: "101" }],
            context: "Change CHG-4188 names m.okoye, this pod, and Thursday 16:00 to 17:00. m.okoye works on the artwork team.",
            answer: "close",
            why: "Person, target and window all match a ticket raised before the event. It closes with the ticket number in the note.",
          },
          {
            id: "a2", time: "Tue 02:40", severity: "Medium", rule: "Port-forward to a database pod", entity: "billing/invoice-db-0",
            fields: [{ k: "user.username", v: "r.santos@northlight.example" }, { k: "objectRef.subresource", v: "portforward" }, { k: "sourceIPs", v: "10.42.60.33" }, { k: "responseStatus.code", v: "101" }],
            context: "r.santos is a billing engineer who connects from this VPN pool every day. There is no ticket and no open incident, and r.santos is not on the rota.",
            answer: "ask",
            why: "Nothing here shows harm and nothing explains it. A message to r.santos or the team lead costs minutes and settles it either way.",
          },
          {
            id: "a3", time: "Wed 03:15", severity: "High", rule: "Exec into a running pod", entity: "playback/manifest-api-7d4b8f6c9-hv5rd",
            fields: [{ k: "user.username", v: "v.haddad@northlight.example" }, { k: "objectRef.subresource", v: "exec" }, { k: "Decoded command", v: "sh" }, { k: "sourceIPs", v: "198.51.100.140" }],
            context: "HR closed v.haddad's employment on 14 October. The address is in no Northlight range.",
            answer: "contain",
            why: "An account that should be gone, an outside address and a live shell in a running service. There is nobody to ask. Cut the session and disable the account, then investigate.",
          },
          {
            id: "a4", time: "Wed 21:10", severity: "Low", rule: "Ephemeral container added", entity: "playback/edge-cache-58c6d7f4b-p9tmz",
            fields: [{ k: "user.username", v: "e.ono@northlight.example" }, { k: "verb", v: "patch" }, { k: "objectRef.subresource", v: "ephemeralcontainers" }, { k: "responseStatus.code", v: "200" }],
            context: "e.ono is this week's on-call SRE (Site Reliability Engineer) and owns INC-7731, a cache latency incident opened at 20:55 against this service.",
            answer: "close",
            why: "A debug container is how kubectl debug works. The rota and the open incident both put e.ono on this service at this hour.",
          },
          {
            id: "a5", time: "Mon 23:05", severity: "Medium", rule: "Attach to a process in a running pod", entity: "billing/invoice-api-6f7d5b9c4-l2wsn",
            fields: [{ k: "user.username", v: "k.nowak@northlight.example" }, { k: "objectRef.subresource", v: "attach" }, { k: "sourceIPs", v: "10.42.60.47" }, { k: "responseStatus.code", v: "101" }],
            context: "k.nowak is a long-serving artwork engineer with no earlier requests in billing. There is no ticket, and the group that allowed this was added last month.",
            answer: "ask",
            why: "A real employee, a normal VPN address, and a namespace they have never touched. That could be a loan to another team or a borrowed account, and the record cannot tell you which.",
          },
        ],
      },
    ],
    // ── Reading 4: off the node and into the cloud ──
    "k8s-r4": [
      {
        kind: "trace",
        title: "Follow It Off the Node",
        prompt: "Friday, 03:05. A second alert arrives, this one from the cloud account. Dae-jung wants one story, not two. Start at the Kubernetes audit log and follow it across three sources. Click the row that answers each step.",
        primer: {
          fold: true,
          title: "What a node can ask for",
          points: [
            "A node is usually a cloud VM with an IAM (Identity and Access Management) role attached, so it can pull images and write logs.",
            "The VM asks the **instance metadata service** (IMDS), at `169.254.169.254`, for details about itself, including temporary credentials for that role. Software on a node does this all day.",
            "**IMDSv1** answers a plain GET. **IMDSv2** wants a PUT for a session token first, and a hop limit of 1 keeps that token from reaching a pod on the bridged pod network.",
            "The credentials are ordinary temporary keys. They work from wherever they are carried until they expire.",
            "In CloudTrail they appear as `assumed-role/<role>/<session>`, and for an EC2 instance the session is its instance ID.",
          ],
          example: {
            label: "One join key across three records",
            lines: [
              "Audit log: `spec.nodeName: ip-10-9-1-4.ec2.internal`",
              "Cloud inventory: that private DNS name belongs to instance `i-05be77c1a2d4e6f80`.",
              "CloudTrail: `assumed-role/build-node-role/i-05be77c1a2d4e6f80`",
              "Same instance ID, so all three records are about one machine.",
            ],
          },
        },
        lead: "subtitle-cache-warm started on ip-10-42-7-19 (instance i-0c4e1a7f92b3d6058) on Friday at about 01:12.",
        steps: [
          {
            id: "create",
            ask: "Which request brought the pod to life?",
            source: "Kubernetes audit log · captions · Friday 01:00 to 01:15",
            columns: ["Time", "verb", "objectRef.resource", "objectRef.name", "user.username", "responseStatus.code"],
            rows: [
              ["01:03:51", "list", "pods", "-", UPLOAD_SA, "200"],
              ["01:06:12", "get", "secrets", "caption-db-auth", UPLOAD_SA, "403"],
              ["01:09:40", "create", "jobs", "render-2291", UPLOAD_SA, "201"],
              ["01:12:07", "create", "pods", "subtitle-cache-warm", UPLOAD_SA, "201"],
              ["01:12:11", "get", "pods", "subtitle-cache-warm", UPLOAD_SA, "200"],
            ],
            answer: 3,
            why: "Create on pods, code 201, from the upload app's own ServiceAccount: the identity in that mounted token. The Job at 01:09 is its normal work, and the 403 at 01:06 is the same identity feeling around.",
            learned: "01:12:07: the subtitle-upload ServiceAccount created subtitle-cache-warm.",
          },
          {
            id: "imds",
            ask: "Several processes on this node asked the metadata service. Which one has no business doing it?",
            source: "Node runtime sensor · ip-10-42-7-19 · connections to 169.254.169.254",
            columns: ["Time", "Process", "Parent", "Container", "Path"],
            rows: [
              ["01:11:30", "aws-k8s-agent", "aws-vpc-cni", "aws-node", "/latest/meta-data/network/interfaces/macs/"],
              ["01:12:44", "ecr-credential-provider", "kubelet", "(host)", "/latest/meta-data/iam/security-credentials/nl-eks-node-role"],
              ["01:13:41", "wget", "sh", "subtitle-cache-warm", "/latest/meta-data/iam/security-credentials/nl-eks-node-role"],
              ["01:14:30", "aws-k8s-agent", "aws-vpc-cni", "aws-node", "/latest/meta-data/network/interfaces/macs/"],
            ],
            answer: 2,
            why: "Same address and even the same path as ecr-credential-provider, which fetches image-pull credentials for the kubelet. The difference is context: wget, from a shell, in a pod under two minutes old with host access. This node group still allows IMDSv1, so a plain GET was enough.",
            learned: "01:13:41: wget in subtitle-cache-warm fetched the credentials of nl-eks-node-role.",
          },
          {
            id: "outside",
            ask: "Same role session, more than one address. Click the first call that did not come from the node.",
            source: "CloudTrail · session nl-eks-node-role/i-0c4e1a7f92b3d6058 · Friday",
            columns: ["eventTime", "eventName", "sourceIPAddress", "userIdentity.arn (end)"],
            rows: [
              ["01:10:02", "GetAuthorizationToken", "10.42.7.19", NODE_SESSION],
              ["01:14:19", "GetCallerIdentity", "203.0.113.58", NODE_SESSION],
              ["01:15:02", "ListBuckets", "203.0.113.58", NODE_SESSION],
              ["01:15:40", "GetAuthorizationToken", "10.42.7.19", NODE_SESSION],
            ],
            answer: 1,
            why: "The node is 10.42.7.19, and it carries on with its normal work at 01:15. 203.0.113.58 holds the same session from outside, 38 seconds after the wget. GetCallerIdentity is the first thing anyone runs on keys they have just stolen: whose are these?",
            learned: "From 01:14:19 the node's credentials are in use from 203.0.113.58.",
          },
          {
            id: "object",
            ask: "What actually left? Click the one object read that succeeded.",
            source: "CloudTrail · S3 calls · same session",
            columns: ["eventTime", "eventName", "bucketName", "key", "errorCode"],
            rows: [
              ["01:15:02", "ListBuckets", "-", "-", "-"],
              ["01:15:21", "GetBucketLocation", "nl-masters", "-", "-"],
              ["01:16:05", "GetObject", "nl-billing-exports", "2026-10/invoices.csv", "AccessDenied"],
              ["01:16:12", "GetObject", "nl-billing-exports", "2026-10/payouts.csv", "AccessDenied"],
              ["01:16:33", "GetObject", "nl-masters", "glasswater/s02e10-master.mxf", "-"],
            ],
            answer: 4,
            why: "An empty errorCode means it worked. The node role could read the masters bucket because someone once made it the easy way to give pods access. That is the finale, read from outside the company.",
            learned: "01:16:33: the Glasswater finale master was read from 203.0.113.58.",
          },
        ],
      },
      {
        kind: "sort",
        title: "One Incident or Separate Tickets?",
        prompt: "Friday, 03:40. The queue holds these eight items, and each one looks like some other team's problem. Decide which belong to Dae-jung's one chain, and which stand alone. Join them by node, time and identity.",
        buckets: [
          { id: "chain", label: "Part of this chain" },
          { id: "other", label: "Stands alone" },
        ],
        items: [
          { id: "n1", text: "Runtime sensor: pod with host access started on ip-10-42-7-19, 01:12", bucket: "chain", why: "The pod the whole night hangs on." },
          { id: "n2", text: "Metadata request from aws-k8s-agent on ip-10-42-7-19, every few minutes", bucket: "other", why: "Same node and same address as the theft, and routine. The network plugin does this all day, so the endpoint alone joins nothing." },
          { id: "n3", text: "Runtime sensor: nsenter against PID 1 in subtitle-cache-warm, 01:13", bucket: "chain", why: "Same pod, one minute later: the step from container to node." },
          { id: "n4", text: "Job render-2291 created by the subtitle-upload ServiceAccount, 01:09", bucket: "other", why: "Same identity, same hour, and its real job. Sharing one field is not a link: this is what the Role was granted for." },
          { id: "n5", text: "GuardDuty: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS on nl-eks-node-role", bucket: "chain", why: "Credentials issued to an instance, used from outside AWS. Same role as the node's, and the same window." },
          { id: "n6", text: "edge-cache OOMKilled on ip-10-42-3-8, 01:14", bucket: "other", why: "Right time, wrong node, no shared identity. A memory limit doing its job." },
          { id: "n7", text: "CloudTrail: GetObject on nl-masters from 203.0.113.58, 01:16", bucket: "chain", why: "The same session, at the far end of the chain. The object read is why this incident matters." },
          { id: "n8", text: "SSH password failures against a bastion from a scanner, 00:50", bucket: "other", why: "Nothing connects it: another host, another identity, and it never got in." },
        ],
      },
    ],
    // ── la1 drills: the parts of an image reference, and the questions for a pod ──
    "k8s-la1": [
      {
        kind: "worksheet",
        title: "Split the Image Reference",
        prompt: "Every pod names the image it runs, and the name says where the node went to get it. Here is part of this week's image inventory. Work out what each reference is really pointing at.",
        primer: {
          fold: true,
          title: "The parts of an image reference",
          points: [
            "The full form is `registry/repository:tag`. The registry is the server, the repository is a path on it, and the tag names a version.",
            "Everything before the first `/` is the registry, as long as it holds a dot or a colon, or is `localhost`. A port, when there is one, is part of it.",
            "With no such part, the name is a path on Docker Hub, whose registry host is `docker.io`.",
            "Allowlists and egress rules work on the registry part. The repository and the tag mean nothing to a firewall.",
          ],
          example: {
            label: "One reference, split",
            lines: [
              "`mirror.corp.example:5050/base/alpine:3.20`",
              "Registry: `mirror.corp.example:5050`",
              "Repository: `base/alpine`",
              "Tag: `3.20`",
            ],
          },
        },
        caption: "Image inventory · nl-prod-1",
        columns: ["Row", "Pod", "Namespace", "Image"],
        rows: [
          ["1", "edge-cache-58c6d7f4b-p9tmz", "playback", "registry.northlight.example/playback/cache:8.4.2"],
          ["2", "log-shipper-7xq2p", "logging", "registry.northlight.example/logging/shipper:5.1"],
          ["3", "report-0412-7hw2c", "ads", "198.51.100.23:8443/ops/agent:3.2"],
          ["4", "lint-sandbox", "dev-tools", "nginx:1.27"],
        ],
        questions: [
          { id: "split", q: "Split row 3's image at the first slash. What is the registry part?", hint: "A port belongs to the registry part.", answer: ["198.51.100.23:8443"], why: "Everything before the first slash names the server the node connected to. ops/agent is a path on that server, and 3.2 is a tag." },
          { id: "hub", q: "Row 4 names no registry. Which registry host does the pull go to?", hint: "nginx holds no dot or colon, so it is not a server name.", answer: ["docker.io", "docker hub", "dockerhub", "registry-1.docker.io"], why: "With no registry part, the runtime reads the name as a path on Docker Hub. That is a third party's service, even though the line looks local." },
          { id: "ours", q: "How many of the four rows come from a registry Northlight runs?", hint: "Compare each registry part with Northlight's own registry name.", answer: ["2", "two"], why: "Rows 1 and 2. To trust an image you need to know who published it. With your own registry a team can tell you. Row 3 leads to nobody you can name, so what it serves is unknown code until someone shows otherwise." },
        ],
      },
      {
        kind: "simulate",
        title: "Four Questions for a Pod",
        prompt: "Dae-jung has one habit for any pod that looks off: no single field gets to decide. Put four pods from this week through the same four questions and see what each answer is worth.",
        primer: {
          fold: true,
          title: "Who owns a pod",
          points: [
            "Most pods have an owner, shown in `metadata.ownerReferences`: a ReplicaSet, a DaemonSet or a Job. The owner recreates them when they die.",
            "A pod with no owner was named directly by someone's request.",
            "Some software exists to manage the node: network plugins, storage drivers, security sensors. Host access is how that software works.",
            "`kubectl debug node/<name>` makes an ownerless pod with host namespaces and the node's disk mounted, for a person doing maintenance.",
          ],
          example: {
            label: "Reading ownership",
            lines: [
              "`ownerReferences: [{ kind: ReplicaSet, name: edge-cache-58c6d7f4b }]`",
              "A ReplicaSet made it, and a Deployment made that.",
              "No `ownerReferences` at all: follow `user.username` on the create event instead.",
            ],
          },
        },
        checks: [
          { name: "Sender", question: "Is this the identity that normally makes this change?" },
          { name: "Owner", question: "Does a controller own the pod?" },
          { name: "Host access", question: "Does the pod's job explain what its spec asks for?" },
          { name: "Image", question: "Did the image come from a registry Northlight runs?" },
        ],
        scenarios: [
          {
            id: "sensor",
            label: "runtime-sensor on each node",
            detail: "Sent by the DaemonSet controller, from a DaemonSet that gitops:deploy-controller applied. Owned by that DaemonSet. privileged and hostPID. Image from registry.northlight.example.",
            results: ["pass", "pass", "pass", "pass"],
            why: ["The DaemonSet controller makes a DaemonSet's pods, and this DaemonSet came through the reviewed path.", "A DaemonSet keeps one copy on each node.", "A sensor that watches the node has to see the node.", "Northlight's own registry."],
            verdict: "Four passes, with the same fields that frightened you an hour ago.",
          },
          {
            id: "debug",
            label: "node-debugger-ip-10-42-3-8-x7k2p",
            detail: "Sent by e.ono@northlight.example, on call, during INC-7731. No owner. hostPID, hostNetwork, the node's disk mounted. Image from registry.northlight.example.",
            results: ["pass", "fail", "pass", "pass"],
            why: ["The on-call engineer, on a service in an open incident.", "kubectl debug makes a one-off pod, so there is no controller.", "Maintenance on the node is what this tool is for.", "Northlight's debug image."],
            verdict: "One miss, and the tool explains it. The rota and the incident do the rest.",
          },
          {
            id: "warm",
            label: "subtitle-cache-warm",
            detail: "Sent by the subtitle-upload ServiceAccount. No owner. hostPID, privileged, a hostPath of /. Image from registry.northlight.example, the cache team's own.",
            results: ["fail", "fail", "fail", "pass"],
            why: ["An upload parser has no reason to write its own pod manifests.", "Nothing owns it, so one request made it.", "A cache needs scratch space, not the node's disk.", "It reused the image the team already runs."],
            verdict: "Three misses that tell one story. The passing image only means the intruder copied a manifest that was lying around.",
          },
          {
            id: "report",
            label: "report-0412-7hw2c",
            detail: "Sent by the Job controller for ads/report-0412. Owned by that Job. No host settings. Image 198.51.100.23:8443/ops/agent:3.2.",
            results: ["pass", "pass", "pass", "fail"],
            why: ["The Job controller makes a Job's pods.", "Owned by its Job.", "Nothing host-level in the spec.", "An address that no team here can put a name to."],
            verdict: "One miss, and it still needs an owner: who put that address in a job, and what does the code do?",
          },
        ],
      },
    ],
  },
};
