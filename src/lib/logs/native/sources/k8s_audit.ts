/**
 * Kubernetes API-server audit log (EKS / AKS / GKE) — native source module.
 *
 * Card: docs/log-schemas/k8s-audit.md. Native format = the `audit.k8s.io/v1`
 * `Event` object, nested exactly as the API server writes it. The AKS diagnostic
 * wrapper (`category:"kube-audit"`, raw event JSON embedded as a string in
 * `properties.log`) is a second supported kind. No `kubernetes.audit.*` ECS
 * flattening, no Wazuh `data.*` envelope.
 *
 * The legacy `ev.raw` holds the event already flattened (and inconsistently:
 * `user.groups[0]` vs `user.groups` as an array). We rebuild the real nested
 * `Event`, so detections can match `requestObject.spec.containers[].securityContext.privileged`.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { entitySeed, rb, rn, rs, underPrefix } from "./cloud-shared";

// ── schema ───────────────────────────────────────────────────────────────────

const eventKind: KindSchema = {
  required: ["kind", "apiVersion", "level", "auditID", "stage", "verb", "user", "requestReceivedTimestamp", "stageTimestamp"],
  optional: [
    "requestURI", "userAgent",
    "sourceIPs[]", "user.username", "user.uid", "user.groups[]",
    "impersonatedUser.username", "impersonatedUser.uid", "impersonatedUser.groups[]",
    "objectRef.resource", "objectRef.namespace", "objectRef.name", "objectRef.uid",
    "objectRef.apiGroup", "objectRef.apiVersion", "objectRef.resourceVersion", "objectRef.subresource",
    "responseStatus.metadata", "responseStatus.code", "responseStatus.status", "responseStatus.reason", "responseStatus.message",
  ],
  openPrefixes: ["requestObject", "responseObject", "annotations", "user.extra", "impersonatedUser.extra"],
};

const kinds: Record<string, KindSchema> = {
  Event: eventKind,
  AKSAudit: { required: ["category", "operationName", "resourceId", "time", "properties"], optional: [], openPrefixes: ["properties"] },
};

const schema: SourceSchema = {
  sourceId: "k8s_audit",
  category: "k8s",
  card: "k8s-audit.md",
  product: "Kubernetes Audit",
  format: "json",
  vendorMatch: ["kubernetes"],
  telemetrySources: ["k8s_audit"],
  kinds,
};

export function kindOf(record: Record<string, unknown>): string | null {
  if (record["apiVersion"] === "audit.k8s.io/v1" && record["kind"] === "Event") return "Event";
  if (record["category"] === "kube-audit" && record["properties"] && typeof record["properties"] === "object") return "AKSAudit";
  return null;
}

// ── conversion ────────────────────────────────────────────────────────────────

/** Split "spec.containers[0].securityContext.privileged" into path tokens. */
function tokens(key: string): (string | number)[] {
  return (key.match(/[^.[\]]+|\[\d+\]/g) ?? []).map(t => (/^\[\d+\]$/.test(t) ? Number(t.slice(1, -1)) : t));
}
/** Rebuild a nested object/array tree from a flat {dotted/indexed: value} map. */
function unflatten(flat: Record<string, unknown>): Record<string, unknown> {
  const root: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(flat)) {
    const ts = tokens(k);
    let cur: Record<string, unknown> | unknown[] = root;
    for (let i = 0; i < ts.length; i++) {
      const t = ts[i];
      if (i === ts.length - 1) { (cur as Record<string | number, unknown>)[t] = v; break; }
      const next = ts[i + 1];
      const holder = cur as Record<string | number, unknown>;
      if (holder[t] == null) holder[t] = typeof next === "number" ? [] : {};
      cur = holder[t] as Record<string, unknown> | unknown[];
    }
  }
  return root;
}

const K = (ev: TelemetryEvent, name: string) => rs(ev.raw, `kubernetes.audit.${name}`);

/** Collect an array that the raw map may hold either as a real array or as foo[0], foo[1]... keys. */
function collectArray(raw: Record<string, unknown>, base: string): string[] {
  const direct = raw[`kubernetes.audit.${base}`];
  if (Array.isArray(direct)) return direct.map(String);
  const out: string[] = [];
  for (let i = 0; i < 16; i++) { const v = raw[`kubernetes.audit.${base}[${i}]`]; if (v === undefined) break; out.push(String(v)); }
  return out;
}

function microTs(ts: string, ctx: NativeCtx, seed: string, addSec = 0): string {
  const d = new Date(Date.parse(ts) + addSec * 1000).toISOString(); // ...ss.mmmZ
  return `${d.slice(0, 23)}${String(ctx.int(seed, 0, 999)).padStart(3, "0")}Z`;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw = ev.raw ?? {};
  const verb = K(ev, "verb");
  if (!verb) return null; // only k8s audit events belong here

  const resource = K(ev, "objectRef.resource");
  const objectRef: Record<string, unknown> = {};
  if (resource) objectRef.resource = resource;
  const ns = K(ev, "objectRef.namespace"); if (ns !== undefined) objectRef.namespace = ns;
  const name = K(ev, "objectRef.name"); if (name) objectRef.name = name;
  const sub = K(ev, "objectRef.subresource"); if (sub) objectRef.subresource = sub;
  objectRef.apiGroup = K(ev, "objectRef.apiGroup") ?? (resource && /roles|rolebindings|clusterrole/.test(resource) ? "rbac.authorization.k8s.io" : "");
  objectRef.apiVersion = K(ev, "objectRef.apiVersion") ?? "v1";

  // Default to the API server, never to system:anonymous — anonymous is a real,
  // high-signal value and must only appear when the source event actually said so.
  const username = K(ev, "user.username") ?? ev.user?.email ?? ev.user_email ?? "system:apiserver";
  const groups = collectArray(raw, "user.groups");
  const user: Record<string, unknown> = { username };
  const uid = K(ev, "user.uid"); if (uid) user.uid = uid;
  if (groups.length) user.groups = groups;
  else if (username.startsWith("system:serviceaccount:")) user.groups = ["system:serviceaccounts", "system:authenticated"];
  else if (username === "system:anonymous") user.groups = ["system:unauthenticated"];
  else user.groups = ["system:authenticated"];

  const sourceIPs = collectArray(raw, "sourceIPs");
  if (!sourceIPs.length && ev.src_ip) sourceIPs.push(ev.src_ip);

  const reqFlat = underPrefix(raw, "kubernetes.audit.requestObject.");
  const respFlat = underPrefix(raw, "kubernetes.audit.responseObject.");
  const requestObject = Object.keys(reqFlat).length ? unflatten(reqFlat) : undefined;
  const responseObject = Object.keys(respFlat).length ? unflatten(respFlat) : undefined;

  const level = K(ev, "level") ?? (requestObject && responseObject ? "RequestResponse" : requestObject || responseObject ? "Request" : "Metadata");
  const code = rn(raw, "kubernetes.audit.responseStatus.code") ?? (verb === "create" ? 201 : 200);
  const responseStatus: Record<string, unknown> = { metadata: {}, code };
  const rStatus = K(ev, "responseStatus.status"); if (rStatus) responseStatus.status = rStatus;
  const rReason = K(ev, "responseStatus.reason"); if (rReason) responseStatus.reason = rReason;
  const rMsg = K(ev, "responseStatus.message"); if (rMsg) responseStatus.message = rMsg;

  const requestURI = K(ev, "requestURI") ?? `/api/v1/namespaces/${ns ?? "default"}/${resource ?? "pods"}${name ? "/" + name : ""}${sub ? "/" + sub : ""}`;
  const userAgent = K(ev, "userAgent") ?? "kubectl/v1.30.0 (linux/amd64)";

  const record: Record<string, unknown> = {
    kind: "Event",
    apiVersion: "audit.k8s.io/v1",
    level,
    auditID: K(ev, "auditID") ?? ctx.uuid(ev.id + ":audit"),
    stage: K(ev, "stage") ?? "ResponseComplete",
    requestURI,
    verb,
    user,
    objectRef,
    responseStatus,
    requestReceivedTimestamp: microTs(ev.ts, ctx, ev.id + ":recv"),
    stageTimestamp: microTs(ev.ts, ctx, ev.id + ":stage", 0),
    userAgent,
  };
  if (sourceIPs.length) record.sourceIPs = sourceIPs;
  if (requestObject) record.requestObject = { ...(resource === "pods" ? { kind: "Pod", apiVersion: "v1" } : {}), ...requestObject };
  if (responseObject) record.responseObject = responseObject;
  // Authorizer decision annotation (the authoritative allow/deny).
  const decision = rs(raw, "kubernetes.audit.annotations.authorization.k8s.io/decision") ?? (code === 403 ? "forbid" : "allow");
  record.annotations = { "authorization.k8s.io/decision": decision, "authorization.k8s.io/reason": rs(raw, "kubernetes.audit.annotations.authorization.k8s.io/reason") ?? "" };

  return { sourceId: "k8s_audit", kind: "Event", format: "json", record, timeMs: Date.parse(ev.ts) };
}

// ── use cases ─────────────────────────────────────────────────────────────────

const useCases: UseCase[] = [
  {
    id: "k8s_audit.pod_exec",
    title: "Shell / exec into a running pod",
    sourceId: "k8s_audit", severity: "medium", mitre: ["T1609"],
    kinds: ["Event"],
    description: "verb=create on the pods/exec subresource — a shell opened inside a container. Legitimate for debugging, high-signal from an unexpected identity or a Tor/foreign source IP.",
    logic: "LogScale: verb=create AND objectRef.subresource=exec (resource=pods)",
    match: { all: [{ field: "verb", op: "eq", value: "create" }, { field: "objectRef.subresource", op: "eq", value: "exec" }] },
    falsePositives: ["An on-call engineer legitimately exec-ing into a pod to troubleshoot."],
  },
  {
    id: "k8s_audit.privileged_pod",
    title: "Privileged / host-namespace pod created",
    sourceId: "k8s_audit", severity: "critical", mitre: ["T1610", "T1611"],
    kinds: ["Event"],
    description: "A pod created (or whose spec is read) with privileged:true, hostPID, hostNetwork, or a hostPath mount of / — a container built to break out onto the node.",
    logic: "LogScale: verb IN (create,get) resource=pods AND (spec.containers[].securityContext.privileged=true OR spec.hostPID=true OR spec.hostNetwork=true)",
    match: { all: [{ field: "objectRef.resource", op: "eq", value: "pods" }, { any: [
      { field: "requestObject.spec.containers[].securityContext.privileged", op: "eq", value: true },
      { field: "requestObject.spec.hostPID", op: "eq", value: true },
      { field: "requestObject.spec.hostNetwork", op: "eq", value: true },
      { field: "responseObject.spec.containers[].securityContext.privileged", op: "eq", value: true },
      { field: "responseObject.spec.hostPID", op: "eq", value: true },
    ] }] },
    falsePositives: ["Legitimate privileged infrastructure pods (CNI, CSI, node agents) — scope by namespace/service-account allow-list."],
  },
  {
    id: "k8s_audit.cluster_admin_binding",
    title: "Binding to a cluster-admin / admin role",
    sourceId: "k8s_audit", severity: "high", mitre: ["T1098"],
    kinds: ["Event"],
    description: "A (cluster)rolebinding created whose roleRef grants cluster-admin or admin — attacker persistence that escalates a compromised service account to full control.",
    logic: "LogScale: verb=create resource IN (clusterrolebindings,rolebindings) AND requestObject.roleRef.name IN (cluster-admin,admin)",
    match: { all: [{ field: "verb", op: "eq", value: "create" }, { field: "objectRef.resource", op: "in", value: ["clusterrolebindings", "rolebindings"] }, { any: [
      { field: "requestObject.roleRef.name", op: "in", value: ["cluster-admin", "admin"] },
      { field: "responseObject.roleRef.name", op: "in", value: ["cluster-admin", "admin"] },
    ] }] },
    falsePositives: ["A cluster operator legitimately granting admin to a new platform engineer (verify the subject and change ticket)."],
  },
  {
    id: "k8s_audit.secrets_access_kube_system",
    title: "Secrets enumerated in kube-system",
    sourceId: "k8s_audit", severity: "high", mitre: ["T1552.007"],
    kinds: ["Event"],
    description: "list / get on secrets in the kube-system namespace — credential access against the cluster's most sensitive secrets, typical after a service-account compromise.",
    logic: "LogScale: verb IN (list,get) objectRef.resource=secrets objectRef.namespace=kube-system",
    match: { all: [{ field: "verb", op: "in", value: ["list", "get"] }, { field: "objectRef.resource", op: "eq", value: "secrets" }, { field: "objectRef.namespace", op: "eq", value: "kube-system" }] },
    falsePositives: ["A cluster-management controller that legitimately reads kube-system secrets (scope by service account)."],
  },
  {
    id: "k8s_audit.anonymous_access",
    title: "Anonymous / unauthenticated API access",
    sourceId: "k8s_audit", severity: "high", mitre: ["T1078.001"],
    kinds: ["Event"],
    description: "A request by system:anonymous or group system:unauthenticated reaching the API server — a misconfigured cluster exposed to the internet; maps to GuardDuty's SuccessfulAnonymousAccess.",
    logic: "LogScale: user.username=system:anonymous OR user.groups=system:unauthenticated",
    match: { any: [{ field: "user.username", op: "eq", value: "system:anonymous" }, { field: "user.groups[]", op: "eq", value: "system:unauthenticated" }] },
    falsePositives: ["Health-check / unauthenticated readiness probes on allow-listed non-resource URLs (should be scoped out)."],
  },
  {
    id: "k8s_audit.rbac_change",
    title: "RBAC role / binding modification",
    sourceId: "k8s_audit", severity: "medium", mitre: ["T1098"],
    kinds: ["Event"],
    description: "create / update / patch / delete on roles, rolebindings, clusterroles or clusterrolebindings — a change to who can do what in the cluster, worth confirming against change control.",
    logic: "LogScale: verb IN (create,update,patch,delete) objectRef.resource IN (roles,rolebindings,clusterroles,clusterrolebindings)",
    match: { all: [{ field: "verb", op: "in", value: ["create", "update", "patch", "delete"] }, { field: "objectRef.resource", op: "in", value: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"] }] },
    falsePositives: ["Routine access-management changes approved via ticket."],
  },
  {
    id: "k8s_audit.exec_from_external_ip",
    title: "Pod exec from a non-cluster source IP",
    sourceId: "k8s_audit", severity: "high", mitre: ["T1609"],
    kinds: ["Event"],
    description: "A pods/exec from a source IP outside the cluster's private ranges — a shell-in driven from the internet (e.g. a Tor exit node), far more suspicious than an exec from an internal admin host.",
    logic: "LogScale: verb=create objectRef.subresource=exec AND NOT cidr(sourceIPs, 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12)",
    match: { all: [
      { field: "verb", op: "eq", value: "create" },
      { field: "objectRef.subresource", op: "eq", value: "exec" },
      { field: "sourceIPs[]", op: "notCidr", value: ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"] },
    ] },
    falsePositives: ["An admin exec-ing through a bastion whose egress IP is outside the cluster CIDR."],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
