/**
 * Scenario pack: "Container Escape to the Node — a Poisoned Image that Mines and
 * Breaks Out of Kubernetes" (ADVANCED)
 *
 * A runtime attack that starts in the Kubernetes control plane and lands on the
 * worker node's operating system. A poisoned image is deployed into the
 * data-pipeline namespace as an over-permissive pod — privileged: true, hostPID,
 * and a hostPath volume mounting the node's root filesystem. The container's
 * entrypoint runs an XMRig-style cryptominer, and from inside the privileged pod
 * the operator uses nsenter to join the host's namespaces (--target 1) and drops
 * a shell onto the EC2 worker node itself. The miner reaches an external Monero
 * pool, and GuardDuty independently flags the node querying a cryptocurrency
 * domain.
 *
 * TEACHING ARC:
 *   - ORIGIN is in the K8s audit trail: a privileged pod was created and exec'd
 *     by an application service account, carrying a sensitive hostPath mount and
 *     hostPID — the misconfiguration that makes a breakout possible.
 *   - IMPACT is in the runtime telemetry: the xmrig process, the nsenter escape
 *     to the node, and the outbound mining-pool traffic.
 *   - The single hardest read is proving the workload CROSSED the container
 *     boundary (nsenter joining the host's namespaces) versus merely running as
 *     root while still contained inside the pod.
 *
 * This is deliberately DISTINCT from k8s-pod-escape-imds: there the breakout
 * exists to steal the node's IAM credentials from IMDS and pivot into the cloud
 * account. Here the goal is node compromise and cryptomining — resource
 * hijacking — not credential theft.
 *
 * BENIGN CONTROL (evt_ce_00): a cilium CNI DaemonSet pod that is ALSO privileged
 * and ALSO mounts a hostPath, created by the kube-system cilium service account.
 * Same "privileged pod on the node" shape, opposite verdict — it runs no miner
 * and opens no external pool connection.
 *
 * SOURCES (registry keys): kubernetes-audit (vendor "Kubernetes Audit" — the
 * API-server audit trail), crowdstrike-falcon (vendor "CrowdStrike Falcon" — the
 * container-runtime detections), and one aws-cloudtrail node-context event
 * (vendor "AWS GuardDuty").
 *
 * NOTE: register in scenarios.ts with difficulty "advanced". The ScenarioBundle
 * itself carries no difficulty field.
 */

import type { ScenarioBundle, TelemetryEvent, IOC, ScenarioQuestion } from "@/lib/sim/types";
import { makeSha256 } from "@/lib/sim/iocs";

export function buildContainerEscapeCryptominingScenario(
  scenarioId = "container-escape-cryptomining-2026",
): ScenarioBundle {
  const B = new Date("2026-08-31T01:30:00Z").getTime();
  const T = (ms: number) => new Date(B + ms).toISOString();
  const MIN = 60_000;
  const SEC = 1_000;

  // One incident — the whole runtime chain is a single case.
  const INCIDENT = "inc:container-escape-cryptomining:1";

  // The cluster, the worker node, and the two pods.
  const cluster = "prod-eks-payments";
  const node = { name: "ip-10-0-42-17.ec2.internal", instanceId: "i-0a4b7c2e9f13d5a80" };
  const badPod = "etl-metrics-agent-xk29d";
  const benignPod = "cilium-7g4mp";

  // The application service account that deployed the poisoned image, and the
  // sanctioned CNI service account behind the benign control.
  const badSa = "system:serviceaccount:data-pipeline:etl-runner";
  const cniSa = "system:serviceaccount:kube-system:cilium";
  const badImage = "registry.internal/etl-metrics:latest";
  const containerId = "3f9a2c7e1b4d8e05a1c6f0b93d2e7a41";

  // The operator's control host and the mining infrastructure.
  const opIp = "45.83.192.44";
  const poolDomain = "pool.supportxmr.com";
  const poolUrl = "stratum+tcp://pool.supportxmr.com:3333";
  const poolIp = "185.65.244.9";
  // Monero wallet the miner pays out to — carried in the cmdline, not an IOC.
  const wallet = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP";

  const minerHash = makeSha256("container_escape_cryptomining_xmrig_binary_2026");
  const sensorId = "d41e9a2b7c8f45031e6a2d90bc74f158";

  const events: TelemetryEvent[] = [
    // ─────────────────────────────────────────────────────────────────────
    // 0. BENIGN CONTROL — a sanctioned privileged DaemonSet pod.
    //    The cilium CNI agent is privileged and mounts a hostPath BY DESIGN,
    //    created by the kube-system cilium service account. Same "privileged
    //    pod on the node" shape as the attack, opposite verdict: no miner, no
    //    external pool connection.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ce_00_benign_cni",
      ts: "2026-08-30T09:14:52Z",
      source: "k8s_audit",
      vendor: "Kubernetes Audit",
      event_type: "k8s_pod_create",
      hostname: benignPod,
      severity: "informational",
      expected_verdict: "fp",
      fp_explanation:
        "This is the control case, and what every privileged pod should be measured against. The cilium CNI agent is a cluster-wide DaemonSet that legitimately runs privileged and mounts hostPath paths so it can program the node's networking — that is how the CNI works. It is created by the kube-system cilium service account, from an in-cluster address, and it runs no miner and opens no external connection. An analyst who alerts on 'a privileged pod with a hostPath was created' alone will flag this and be wrong: the signal is the workload's behaviour and who owns it, not the privileged flag.",
      description:
        "A create for the cilium-7g4mp pod in kube-system: privileged with hostPath mounts, admitted for the cilium DaemonSet by the kube-system cilium service account.",
      raw: {
        "kubernetes.audit.verb": "create",
        "kubernetes.audit.objectRef.resource": "pods",
        "kubernetes.audit.objectRef.namespace": "kube-system",
        "kubernetes.audit.objectRef.name": benignPod,
        "kubernetes.audit.user.username": cniSa,
        "kubernetes.audit.user.groups[0]": "system:serviceaccounts:kube-system",
        "kubernetes.audit.sourceIPs[0]": "10.0.42.17",
        "kubernetes.audit.requestObject.metadata.ownerReferences[0].kind": "DaemonSet",
        "kubernetes.audit.requestObject.metadata.ownerReferences[0].name": "cilium",
        "kubernetes.audit.requestObject.spec.containers[0].image": "quay.io/cilium/cilium:v1.15.6",
        "kubernetes.audit.requestObject.spec.containers[0].securityContext.privileged": true,
        "kubernetes.audit.requestObject.spec.volumes[0].name": "cni-path",
        "kubernetes.audit.requestObject.spec.volumes[0].hostPath.path": "/opt/cni/bin",
        "kubernetes.audit.responseStatus.code": 201,
        "kubernetes.audit.stage": "ResponseComplete",
        "kubernetes.audit.userAgent": "cilium-operator/v1.15.6 (linux/amd64)",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 1. THE ESCAPE ORIGIN — an over-permissive pod is created from a poisoned
    //    image by an application service account. privileged, hostPID, and a
    //    hostPath mounting the node root filesystem. This is the pod spec that
    //    makes a breakout to the node possible (T1610 Deploy Container).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ce_01_privileged_pod_create",
      ts: T(0),
      source: "k8s_audit",
      vendor: "Kubernetes Audit",
      event_type: "k8s_pod_create",
      hostname: badPod,
      src_ip: opIp,
      severity: "high",
      mitre_technique: "T1610",
      mitre_tactic: "Execution",
      incident_id: INCIDENT,
      description:
        "A create for the etl-metrics-agent-xk29d pod in data-pipeline from the etl-runner service account: privileged true, hostPID true, and a hostPath volume mapping the node root filesystem into the container.",
      raw: {
        "kubernetes.audit.verb": "create",
        "kubernetes.audit.objectRef.resource": "pods",
        "kubernetes.audit.objectRef.namespace": "data-pipeline",
        "kubernetes.audit.objectRef.name": badPod,
        "kubernetes.audit.user.username": badSa,
        "kubernetes.audit.user.groups[0]": "system:serviceaccounts:data-pipeline",
        "kubernetes.audit.sourceIPs[0]": opIp,
        "kubernetes.audit.requestObject.spec.hostPID": true,
        "kubernetes.audit.requestObject.spec.hostNetwork": true,
        "kubernetes.audit.requestObject.spec.containers[0].image": badImage,
        "kubernetes.audit.requestObject.spec.containers[0].securityContext.privileged": true,
        "kubernetes.audit.requestObject.spec.containers[0].volumeMounts[0].name": "host-root",
        "kubernetes.audit.requestObject.spec.containers[0].volumeMounts[0].mountPath": "/host",
        "kubernetes.audit.requestObject.spec.volumes[0].name": "host-root",
        "kubernetes.audit.requestObject.spec.volumes[0].hostPath.path": "/",
        "kubernetes.audit.responseStatus.code": 201,
        "kubernetes.audit.stage": "ResponseComplete",
        "kubernetes.audit.userAgent": "kubectl/v1.28.4 (linux/amd64) kubernetes/8b3644d",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 2. THE OPERATOR DRIVES THE POD — a pods/exec into the privileged pod.
    //    A shell inside the container the operator will break out of
    //    (T1609 Container Administration Command).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ce_02_pod_exec",
      ts: T(1 * MIN),
      source: "k8s_audit",
      vendor: "Kubernetes Audit",
      event_type: "k8s_exec",
      hostname: badPod,
      src_ip: opIp,
      severity: "high",
      mitre_technique: "T1609",
      mitre_tactic: "Execution",
      incident_id: INCIDENT,
      description:
        "A pods/exec into etl-metrics-agent-xk29d in data-pipeline by the etl-runner service account from 45.83.192.44, attaching an interactive shell to the container.",
      raw: {
        "kubernetes.audit.verb": "create",
        "kubernetes.audit.objectRef.resource": "pods/exec",
        "kubernetes.audit.objectRef.subresource": "exec",
        "kubernetes.audit.objectRef.namespace": "data-pipeline",
        "kubernetes.audit.objectRef.name": badPod,
        "kubernetes.audit.user.username": badSa,
        "kubernetes.audit.sourceIPs[0]": opIp,
        "kubernetes.audit.requestURI":
          "/api/v1/namespaces/data-pipeline/pods/etl-metrics-agent-xk29d/exec?command=sh&container=agent&stdin=true&stdout=true&tty=true",
        "kubernetes.audit.responseStatus.code": 101,
        "kubernetes.audit.stage": "ResponseComplete",
        "kubernetes.audit.userAgent": "kubectl/v1.28.4 (linux/amd64) kubernetes/8b3644d",
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 3. THE MINER — xmrig launches inside the container, pointed at an
    //    external Monero pool. Note the populated ContainerId: at this point
    //    the process is still CONTAINED inside the pod (T1496).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ce_03_xmrig_launch",
      ts: T(2 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: node.name,
      src_ip: opIp,
      severity: "high",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      incident_id: INCIDENT,
      is_detection: true,
      description:
        "Falcon flagged an xmrig process starting in container 3f9a2c7e1b4d from the etl-metrics image, its command line pointed at pool.supportxmr.com over stratum with a Monero wallet.",
      process: {
        name: "xmrig",
        pid: 24817,
        path: "/tmp/.xmr/xmrig",
        parent_name: "sh",
        parent_pid: 24790,
        cmdline: `./xmrig -o ${poolUrl} -u ${wallet} -k --tls --coin monero`,
        user: "root",
        hash: { sha256: minerHash },
      },
      raw: {
        "crowdstrike.DetectName": "Cryptocurrency Mining Tool",
        "crowdstrike.Tactic": "Impact",
        "crowdstrike.Technique": "Resource Hijacking",
        "crowdstrike.Objective": "Follow Through",
        "crowdstrike.SeverityName": "High",
        "crowdstrike.ComputerName": node.name,
        "crowdstrike.ContainerId": containerId,
        "crowdstrike.ContainerImageName": badImage,
        "crowdstrike.FileName": "xmrig",
        "crowdstrike.FilePath": "/tmp/.xmr/xmrig",
        "crowdstrike.CommandLine": `./xmrig -o ${poolUrl} -u ${wallet} -k --tls --coin monero`,
        "crowdstrike.ParentProcessName": "sh",
        "crowdstrike.UserName": "root",
        "process.hash.sha256": minerHash,
        "crowdstrike.SensorId": sensorId,
        "crowdstrike.aid": sensorId,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 4. THE ESCAPE — nsenter joins the HOST's namespaces (--target 1, the
    //    node's init) and drops a bash shell onto the worker node. THIS is the
    //    crossing of the container boundary: the shell runs in the node's own
    //    mount/PID/net namespaces, not the pod's (T1611 Escape to Host).
    //    Primary detection → is_detection + edr_scope "hybrid".
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ce_04_nsenter_escape",
      ts: T(4 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: node.name,
      src_ip: opIp,
      severity: "critical",
      mitre_technique: "T1611",
      mitre_tactic: "Privilege Escalation",
      incident_id: INCIDENT,
      is_detection: true,
      edr_scope: "hybrid",
      description:
        "Falcon detected nsenter run from inside container 3f9a2c7e1b4d joining the host's namespaces via --target 1 and spawning /bin/bash, which then executed against the node's own filesystem outside the pod.",
      process: {
        name: "nsenter",
        pid: 24990,
        path: "/usr/bin/nsenter",
        parent_name: "sh",
        parent_pid: 24790,
        cmdline: "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash",
        user: "root",
      },
      raw: {
        "crowdstrike.DetectName": "Container Escape to Host",
        "crowdstrike.Tactic": "Privilege Escalation",
        "crowdstrike.Technique": "Escape to Host",
        "crowdstrike.Objective": "Gain Access",
        "crowdstrike.SeverityName": "Critical",
        "crowdstrike.PatternDispositionDescription": "Detection, No Action",
        "crowdstrike.ComputerName": node.name,
        "crowdstrike.FileName": "nsenter",
        "crowdstrike.FilePath": "/usr/bin/nsenter",
        "crowdstrike.CommandLine": "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash",
        "crowdstrike.ParentProcessName": "sh",
        "crowdstrike.ParentBaseFileName": "sh",
        "crowdstrike.TargetNamespacePid": "1",
        "crowdstrike.UserName": "root",
        "crowdstrike.SensorId": sensorId,
        "crowdstrike.aid": sensorId,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 5. DISCOVERY ON THE NODE — from the host shell the operator enumerates
    //    the node's other containers and workloads (T1613 Container and
    //    Resource Discovery).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ce_05_node_discovery",
      ts: T(5 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "process_create",
      hostname: node.name,
      src_ip: opIp,
      severity: "medium",
      mitre_technique: "T1613",
      mitre_tactic: "Discovery",
      incident_id: INCIDENT,
      description:
        "From the node shell, crictl was run to list every running container on ip-10-0-42-17, enumerating the other workloads scheduled on the worker.",
      process: {
        name: "crictl",
        pid: 25044,
        path: "/usr/bin/crictl",
        parent_name: "bash",
        parent_pid: 24991,
        cmdline: "crictl ps -a -o json",
        user: "root",
      },
      raw: {
        "crowdstrike.DetectName": "Container Enumeration On Host",
        "crowdstrike.Tactic": "Discovery",
        "crowdstrike.Technique": "Container and Resource Discovery",
        "crowdstrike.SeverityName": "Medium",
        "crowdstrike.ComputerName": node.name,
        "crowdstrike.FileName": "crictl",
        "crowdstrike.CommandLine": "crictl ps -a -o json",
        "crowdstrike.ParentProcessName": "bash",
        "crowdstrike.UserName": "root",
        "crowdstrike.SensorId": sensorId,
        "crowdstrike.aid": sensorId,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 6. THE IMPACT ON THE WIRE — the miner's outbound connection to the
    //    Monero pool, from the node (T1496). Surfaces the pool domain/IP/URL.
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ce_06_pool_connection",
      ts: T(6 * MIN),
      source: "edr",
      vendor: "CrowdStrike Falcon",
      event_type: "net_connection",
      hostname: node.name,
      src_ip: "10.0.42.17",
      dst_ip: poolIp,
      dst_port: 3333,
      protocol: "tcp",
      severity: "high",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      incident_id: INCIDENT,
      description:
        "Falcon recorded xmrig on ip-10-0-42-17 opening a persistent outbound TCP/3333 session to pool.supportxmr.com (185.65.244.9) — the Monero mining pool the wallet pays out to.",
      raw: {
        "crowdstrike.DetectName": "Cryptocurrency Mining Network Activity",
        "crowdstrike.Tactic": "Impact",
        "crowdstrike.Technique": "Resource Hijacking",
        "crowdstrike.SeverityName": "High",
        "crowdstrike.ComputerName": node.name,
        "crowdstrike.FileName": "xmrig",
        "crowdstrike.CommandLine": `./xmrig -o ${poolUrl} -u ${wallet} -k --tls --coin monero`,
        "crowdstrike.DomainName": poolDomain,
        "crowdstrike.RemoteAddressIP4": poolIp,
        "crowdstrike.RemotePort": "3333",
        "crowdstrike.ConnectionDirection": "outbound",
        "crowdstrike.Protocol": "tcp",
        "crowdstrike.UserName": "root",
        "crowdstrike.SensorId": sensorId,
        "crowdstrike.aid": sensorId,
      },
    },

    // ─────────────────────────────────────────────────────────────────────
    // 7. NODE / CLOUD CONTEXT — GuardDuty independently flags the EKS worker
    //    EC2 instance querying a cryptocurrency-associated domain. Corroborates
    //    the mining impact from the cloud control plane (T1496).
    // ─────────────────────────────────────────────────────────────────────
    {
      id: "evt_ce_07_guardduty_node",
      ts: T(9 * MIN),
      source: "cloudtrail",
      vendor: "AWS GuardDuty",
      event_type: "cloud_api_call",
      hostname: node.name,
      severity: "high",
      mitre_technique: "T1496",
      mitre_tactic: "Impact",
      incident_id: INCIDENT,
      is_detection: true,
      description:
        "GuardDuty raised CryptoCurrency:EC2/BitcoinTool.B!DNS: the EKS worker instance i-0a4b7c2e9f13d5a80 resolved pool.supportxmr.com, a domain associated with cryptocurrency mining.",
      raw: {
        "aws.guardduty.type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "aws.guardduty.severity": "8",
        "aws.guardduty.title":
          "EC2 instance i-0a4b7c2e9f13d5a80 is querying a domain name associated with a known cryptocurrency mining pool.",
        "aws.guardduty.service.action.actionType": "DNS_REQUEST",
        "aws.guardduty.service.action.dnsRequestAction.domain": poolDomain,
        "aws.guardduty.service.action.dnsRequestAction.protocol": "UDP",
        "aws.guardduty.resource.resourceType": "Instance",
        "aws.guardduty.resource.instanceDetails.instanceId": node.instanceId,
        "aws.guardduty.resource.instanceDetails.tags.eks:cluster-name": cluster,
        "aws.guardduty.service.count": "6",
        "cloud.account.id": "402183776925",
        "cloud.region": "us-east-1",
      },
    },
  ];

  const iocs: IOC[] = [
    {
      type: "url",
      value: poolUrl, // stratum+tcp://pool.supportxmr.com:3333 — the miner target
      first_seen: T(2 * MIN),
      last_seen: T(6 * MIN),
      reputation: "malicious",
      tags: ["mining-pool", "monero", "stratum"],
    },
    {
      type: "domain",
      value: poolDomain, // pool.supportxmr.com
      first_seen: T(6 * MIN),
      last_seen: T(9 * MIN),
      reputation: "malicious",
      tags: ["mining-pool", "monero"],
    },
    {
      type: "ip",
      value: poolIp, // 185.65.244.9 — the pool endpoint
      first_seen: T(6 * MIN),
      last_seen: T(9 * MIN),
      reputation: "malicious",
      tags: ["mining-pool", "external"],
    },
    {
      type: "sha256",
      value: minerHash, // the xmrig binary
      first_seen: T(2 * MIN),
      last_seen: T(6 * MIN),
      reputation: "malicious",
      tags: ["miner", "xmrig"],
    },
    {
      type: "host",
      value: node.name, // ip-10-0-42-17.ec2.internal — the broken-out worker node
      first_seen: T(2 * MIN),
      last_seen: T(9 * MIN),
      reputation: "suspicious",
      tags: ["worker-node", "affected", "eks"],
    },
    {
      type: "user",
      value: badSa, // system:serviceaccount:data-pipeline:etl-runner
      first_seen: T(0),
      last_seen: T(1 * MIN),
      reputation: "suspicious",
      tags: ["service-account", "over-permissive"],
    },
  ];

  const questions: ScenarioQuestion[] = [
    {
      id: "ce_q1",
      xp: 65,
      kind: "single",
      prompt:
        "Two Falcon detections fire on the same node: the xmrig process (evt_ce_03) and an nsenter process (evt_ce_04). Which observation proves the workload crossed out of its container onto the worker node, rather than merely running as root while still inside the pod?",
      hint: "Compare the ContainerId recorded on the miner with what the nsenter command line actually joins.",
      options: [
        { value: "nsenter_hostns", label: "The nsenter command line joins the host's namespaces via --target 1, the node's init process, so the shell it spawns runs against the node's own mount, PID and network namespaces" },
        { value: "root_in_container", label: "The xmrig process runs as UserName root, and any process that reaches root has by definition already left its container onto the underlying node" },
        { value: "privileged_flag", label: "The pod spec carries securityContext.privileged true, which on its own means every process in the pod is already executing directly on the node" },
        { value: "pool_egress", label: "The outbound session to the mining pool leaves the node, which shows the miner must be running on the host and not inside a container" },
      ],
      answer: "nsenter_hostns",
      explanation:
        "Running as root inside a pod is still contained — the miner in evt_ce_03 carries a populated ContainerId, so despite root it is confined to the pod's namespaces. The boundary is crossed in evt_ce_04: nsenter --target 1 attaches to PID 1, the node's init, and enters the host's mount, PID, IPC and network namespaces, so the /bin/bash it launches operates on the node's own filesystem. That namespace join is the proof of escape. (b) confuses root with host access — root in a container is not root on the node. (c) names the enabling misconfiguration, not evidence the escape happened; a privileged pod can sit privileged and never break out. (d) is impact traffic that would look the same whether the miner ran inside the pod or on the host, so it proves nothing about the boundary.",
    },
    {
      id: "ce_q2",
      xp: 60,
      kind: "single",
      prompt:
        "evt_ce_01 records the creation of the etl-metrics pod. Which combination in its spec is what made a breakout to the node possible in the first place?",
      hint: "Look at the securityContext, the host namespace flags, and where the hostPath volume points.",
      options: [
        { value: "priv_hostpid_hostpath", label: "privileged true, hostPID true, and a hostPath volume mapping the node root filesystem at /host — the container is handed the node's process namespace and its disk" },
        { value: "lb_ingress", label: "A LoadBalancer service and a public ingress rule that exposed the pod directly to inbound traffic from the internet" },
        { value: "no_limits", label: "A missing readiness probe and an unset CPU limit, which let the container consume the entire node's compute" },
        { value: "latest_tag", label: "An imagePullPolicy of Always pointing at the latest tag, which allowed a fresh image to be pulled on every pod restart" },
      ],
      answer: "priv_hostpid_hostpath",
      explanation:
        "The escape is only reachable because of what the pod was granted at admission. evt_ce_01 shows securityContext.privileged true (which brings CAP_SYS_ADMIN and the ability to call setns), hostPID true (so the container shares the node's process namespace and /proc/1 is the node's init), and a hostPath volume mounting / into the container. Together those give the workload the node's process namespace to enter and its filesystem to write, which is exactly what nsenter --target 1 then uses. (b) and (c) are availability/exposure problems, not privilege boundaries. (d) is a supply-chain hygiene concern that governs which image runs, but by itself grants no path off the pod.",
    },
    {
      id: "ce_q3",
      xp: 60,
      kind: "single",
      prompt:
        "evt_ce_00 is a cilium pod in kube-system that is also privileged and also mounts a hostPath — yet it is expected. Beyond both being privileged, what actually separates it from the etl-metrics pod?",
      hint: "Weigh who owns each workload and what each one does after it starts, not the privileged flag they share.",
      options: [
        { value: "owner_and_behaviour", label: "cilium is a sanctioned CNI DaemonSet owned by the kube-system service account and runs no miner and no external connection; etl-metrics is an app-namespace pod that launches xmrig and reaches an outside pool" },
        { value: "cilium_denied", label: "cilium is not actually privileged — the audit only requests it and the API server denies admission, so no privileged container is ever created" },
        { value: "identical_time", label: "The two records are identical in every field, so the only way to tell them apart is that cilium was created earlier in the day" },
        { value: "namespace_trust", label: "cilium sits in kube-system, and any pod in kube-system is trusted while any pod outside it is malicious, whatever it does" },
      ],
      answer: "owner_and_behaviour",
      explanation:
        "Privileged plus hostPath is the shape of a legitimate node agent as much as an attack, which is the whole point of the control. cilium is a CNI DaemonSet — its ownerReferences name the cilium DaemonSet, its service account is the kube-system cilium identity, its hostPath is the CNI binary directory, and it does nothing hostile after starting. etl-metrics is an ordinary application pod in data-pipeline whose service account had no business running privileged, and it launches a miner and dials an external pool. Owner plus behaviour is the discriminator. (b) misreads the record — responseStatus.code 201 shows cilium was admitted. (c) is false; the two differ in namespace, owner, image and behaviour. (d) is an unsafe rule: kube-system membership is not a licence, and plenty of benign workloads live outside it.",
    },
    {
      id: "ce_q4",
      xp: 55,
      kind: "single",
      prompt:
        "Setting the breakout mechanics aside, what is the operator actually using this node for?",
      hint: "Read the miner's command line and the corroborating cloud finding together.",
      options: [
        { value: "hijack_compute", label: "Hijacking the node's CPU to mine Monero — xmrig is aimed at an external stratum pool, and GuardDuty separately flagged the node resolving a cryptocurrency domain" },
        { value: "imds_creds", label: "Stealing the node's IAM role credentials from the instance metadata service to pivot into the wider AWS account" },
        { value: "db_exfil", label: "Copying the payments database out of the cluster to an attacker-controlled storage bucket" },
        { value: "ransom_pv", label: "Encrypting the node's persistent volumes and leaving a ransom note for the cluster operators" },
      ],
      answer: "hijack_compute",
      explanation:
        "The command line in evt_ce_03 and evt_ce_06 points xmrig at a Monero pool over stratum with a payout wallet, and evt_ce_07 is an independent GuardDuty finding that the worker resolved that same mining domain — two sources agreeing the node's compute is being stolen to mine cryptocurrency. (b) is the plausible-looking trap: it is exactly what the separate k8s-pod-escape-imds case does, but there is no IMDS request or credential read anywhere in this timeline. (c) and (d) describe exfiltration and ransomware, and nothing here reads data out or encrypts anything.",
    },
    {
      id: "ce_q5",
      xp: 70,
      kind: "single",
      prompt:
        "You are scoping containment. The workload broke out onto ip-10-0-42-17, and the pod is backed by a Deployment pulling registry.internal/etl-metrics:latest. Which response matches the evidence?",
      hint: "Think about what respawns the pod, and the fact that code already ran on the node itself.",
      options: [
        { value: "cordon_drain_fix", label: "Cordon and drain the node and treat it as compromised, remove the Deployment and quarantine the poisoned image, block egress to the pool domain and IP, and add an admission policy denying privileged/hostPath for app namespaces" },
        { value: "delete_pod", label: "Delete the running pod; once it is gone the miner stops and the case is closed, since the pod was the only place the code ever executed" },
        { value: "block_ip", label: "Block the pool IP at the perimeter; with the pool unreachable the miner is neutralised and no host-level action is required" },
        { value: "scale_zero", label: "Scale the Deployment to zero replicas; no credentials leaked, so stopping the workload is all that is needed" },
      ],
      answer: "cordon_drain_fix",
      explanation:
        "Two facts drive the scope. First, a shell already ran on the node's own OS, so the worker has to be treated as compromised — cordon and drain it and replace it rather than trusting it. Second, the pod is owned by a Deployment pulling a poisoned latest image, so deleting the pod alone just lets the controller reschedule it and the miner returns; the Deployment and the image both have to go. On top of that, block the pool domain and IP to cut the impact channel, and close the door that admitted the pod with an admission policy denying privileged/hostPath in application namespaces. (b) and (d) ignore both the reschedule and the node-level execution. (c) treats a control-plane and host compromise as a firewall problem and leaves the breakout intact.",
    },
  ];

  return {
    scenario_id: scenarioId,
    title: "Container Escape to the Node — a Poisoned Image that Mines and Breaks Out",
    threat_actor: "Cloud-native intrusion operator (resource-hijacking, runtime breakout)",
    attack_kind: "container_escape",
    briefing:
      "GuardDuty flagged the production EKS worker node ip-10-0-42-17 emitting cryptocurrency-related DNS traffic, and Falcon raised a runtime alert on a pod in the data-pipeline namespace on that same node. The worker is shared by many services. Work out what the pod is running, whether the activity stayed inside its container, and how far onto the node it reached before you contain it.",
    narrative: `The worker node ip-10-0-42-17 is an ordinary EC2 instance in the prod-eks-payments cluster, running a mix of production pods. What landed on it began in the Kubernetes control plane.

At 01:30 the etl-runner service account — an ordinary application identity in the data-pipeline namespace — created a pod, etl-metrics-agent-xk29d, from a poisoned image (registry.internal/etl-metrics:latest). The pod spec is the whole story: privileged true, hostPID true, and a hostPath volume mapping the node's root filesystem into the container at /host. Those three grants hand the container CAP_SYS_ADMIN, the node's process namespace, and its disk. A minute later the same account exec'd an interactive shell into the pod.

Inside the container the image's payload launched an XMRig miner as root, pointed at pool.supportxmr.com over stratum with a Monero wallet. At that moment the miner was still contained — Falcon recorded it with a populated ContainerId, confined to the pod. Then, at 01:34, the operator crossed the boundary: nsenter --target 1 --mount --uts --ipc --net --pid attached to PID 1, the node's own init process, and spawned /bin/bash in the host's namespaces. That shell was no longer in the pod; it was operating on the node's filesystem. From it, crictl enumerated the other containers scheduled on the worker.

The miner's outbound TCP/3333 session to pool.supportxmr.com (185.65.244.9) is the impact on the wire, and GuardDuty corroborated it independently with a CryptoCurrency:EC2/BitcoinTool.B!DNS finding for instance i-0a4b7c2e9f13d5a80 resolving that same domain.

The one legitimate comparison in the data is the cilium CNI pod in kube-system: also privileged, also mounting a hostPath, and entirely expected — a node agent that has to touch the host to do its job, owned by the kube-system cilium service account, running no miner and opening no external connection. Same privileged shape, opposite meaning: the signal is the workload's owner and behaviour, not the privileged flag they share.

This is deliberately not the IMDS-credential-theft breakout: nothing here reads the node's IAM credentials. The objective is the node's compute — resource hijacking to mine Monero.`,
    learning_objectives: [
      "Read a Kubernetes audit trail to identify the pod-spec grants (privileged, hostPID, hostPath to the node root) that make a container breakout possible, and separate them from a sanctioned privileged node agent",
      "Distinguish a process running as root while still contained (populated ContainerId) from one that has entered the host's namespaces via nsenter --target 1 — the field-level proof that the container boundary was crossed",
      "Trace a runtime cryptomining impact from the miner command line and stratum pool traffic to an independent GuardDuty cloud finding on the worker node",
      "Recognise that a privileged pod with a hostPath is not malicious by shape — the verdict comes from the workload's owner and behaviour, tested against a benign CNI DaemonSet control",
      "Scope containment for a host breakout: treat the node as compromised, remove the Deployment and poisoned image that respawn the pod, cut the pool egress, and close the admission gap that admitted the pod",
    ],
    alerts: [],
    events,
    iocs,
    killchain: [
      { ts: "2026-08-30T09:14:52Z", phase: "Baseline", action: `Sanctioned cilium CNI pod admitted in kube-system — privileged + hostPath by design (control case)` },
      { ts: T(0), phase: "Execution", action: `${badSa} creates a privileged pod from ${badImage} — hostPID + hostPath to the node root (T1610)` },
      { ts: T(1 * MIN), phase: "Execution", action: `pods/exec into ${badPod} — interactive shell attached to the container (T1609)` },
      { ts: T(2 * MIN), phase: "Impact", action: `xmrig launches inside the container, aimed at ${poolDomain} — still contained (T1496)` },
      { ts: T(4 * MIN), phase: "Privilege Escalation", action: `nsenter --target 1 joins the host namespaces — /bin/bash on the node ${node.name} (T1611)` },
      { ts: T(5 * MIN), phase: "Discovery", action: `crictl ps enumerates the node's other containers from the host shell (T1613)` },
      { ts: T(6 * MIN), phase: "Impact", action: `xmrig outbound TCP/3333 to ${poolDomain} (${poolIp}) — mining pool traffic (T1496)` },
      { ts: T(9 * MIN), phase: "Detection", action: `GuardDuty CryptoCurrency:EC2/BitcoinTool.B!DNS on ${node.instanceId} — node resolving the mining domain (T1496)` },
    ],
    questions,
  };
}
