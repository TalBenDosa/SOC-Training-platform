/**
 * Kubernetes Audit Log EMITTER.
 *
 * The cluster control-plane audit trail — pod creates, exec-into-pod, RBAC and
 * secret access an analyst reads for container escape, cryptojacking and cluster
 * takeover. Audit events are request-shaped and highly heterogeneous, so the
 * emitter renders the COMMON envelope (verb, objectRef.*, user.username,
 * sourceIPs, responseStatus, stage, userAgent) and takes every request-specific
 * field (requestObject.spec.*, groups, ownerReferences, requestURI) through
 * `extra` — every key checked to be one the registry allows (the k8s. /
 * kubernetes. prefixes + shared fields).
 *
 * Kubernetes audit is source:"k8s_audit" and carries no process.
 */
import type { TelemetryEvent, Severity, EventType } from "../types";
import type { Ctx } from "./_core";

const VENDOR = "Kubernetes Audit";

export interface K8sAuditOpts extends Ctx {
  verb: string;                     // audit.verb (create, get, delete, watch …)
  resource: string;                 // objectRef.resource (pods, pods/exec, secrets …)
  subresource?: string;             // objectRef.subresource (exec, log …)
  namespace?: string;
  name?: string;                    // objectRef.name (the pod / object)
  username: string;                 // user.username (usually a service account)
  podName?: string;                 // the event's hostname (the pod)
  srcIp?: string;                   // sourceIPs[0]
  userAgent?: string;
  responseCode?: number;            // responseStatus.code (201, 101, 403 …)
  requestUri?: string;
  eventType?: EventType;            // k8s_pod_create | k8s_exec | k8s_pod_delete | …
  /** request-specific k8s fields: requestObject.spec.*, user.groups[0], ownerReferences… */
  extra?: Record<string, string | number | boolean>;
  mitre?: string;
  tactic?: string;
  severity?: Severity;
  description?: string;
}
export function k8sAudit(o: K8sAuditOpts): TelemetryEvent {
  return {
    id: o.id, ts: o.ts, source: "k8s_audit", vendor: VENDOR, event_type: o.eventType ?? "k8s_pod_create",
    severity: o.severity ?? "medium", hostname: o.podName ?? o.host, src_ip: o.srcIp,
    mitre_technique: o.mitre, mitre_tactic: o.tactic, incident_id: o.incidentId,
    description: o.description ?? `${o.username} ${o.verb} ${o.resource}${o.name ? ` ${o.name}` : ""}`,
    raw: {
      "kubernetes.audit.verb": o.verb,
      "kubernetes.audit.objectRef.resource": o.resource,
      ...(o.subresource ? { "kubernetes.audit.objectRef.subresource": o.subresource } : {}),
      ...(o.namespace ? { "kubernetes.audit.objectRef.namespace": o.namespace } : {}),
      ...(o.name ? { "kubernetes.audit.objectRef.name": o.name } : {}),
      "kubernetes.audit.user.username": o.username,
      ...(o.srcIp ? { "kubernetes.audit.sourceIPs[0]": o.srcIp } : {}),
      ...(o.requestUri ? { "kubernetes.audit.requestURI": o.requestUri } : {}),
      ...(o.responseCode !== undefined ? { "kubernetes.audit.responseStatus.code": o.responseCode } : {}),
      "kubernetes.audit.stage": "ResponseComplete",
      ...(o.userAgent ? { "kubernetes.audit.userAgent": o.userAgent } : {}),
      ...(o.srcIp ? { "source.ip": o.srcIp } : {}),
      ...(o.extra ?? {}),
    },
  };
}
