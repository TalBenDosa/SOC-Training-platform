# Kubernetes audit log (EKS / AKS / GKE) — log schema card

Kubernetes API-server audit events are **JSON-native**: each event is an `audit.k8s.io/v1` `Event` object.
The log backend writes them as JSON Lines (one Event per line); the webhook backend sends an `EventList`.
Show the native `Event` object. Do **not** flatten to ECS `kubernetes.audit.*` or wrap in a Wazuh `data.*`
envelope. (Note: the managed-service transports wrap the event — see §2 — but the audit payload itself is the
same `audit.k8s.io/v1` object.)

## 1. Official sources

- Audit Event schema (`audit.k8s.io/v1`), all fields, Level & Stage enums, ObjectReference, UserInfo:
  https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- Auditing task (stage meanings, level meanings, log vs webhook backend, exec as `create` on `pods/exec`):
  https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- Event shape + managed-service transports cross-checked against elastic/integrations
  `kubernetes/data_stream/audit_logs` raw test inputs (plain audit line + AKS `kube-audit` wrapper).

## 2. Native format & delivery

- Each event is an `audit.k8s.io/v1` `Event`. The **log backend** writes JSON Lines (one Event/line) to a file;
  the **webhook backend** POSTs an `EventList` (`{"apiVersion":"audit.k8s.io/v1","kind":"EventList","items":[...]}`).
- A single request can emit **multiple** events — one per stage (e.g. `RequestReceived` then `ResponseComplete`),
  sharing the same `auditID`.
- **Managed services wrap the raw event** for delivery, but the inner payload is the same object:
  - **EKS:** events go to CloudWatch Logs (log group `/aws/eks/<cluster>/cluster`, stream prefix `kube-apiserver-audit`);
    each CloudWatch log event's message **is** the raw `audit.k8s.io/v1` JSON.
  - **AKS:** events arrive via Azure Monitor diagnostic logs as `category:"kube-audit"` records, with the raw
    event JSON as a **string** inside `properties.log` (plus `pod`, `containerID`, `stream`, `resourceId`, `time`).
    (`kube-audit-admin` category omits read-only get/list.)
  - **GKE:** events are Cloud Audit Logs `LogEntry` with `protoPayload.@type = google.cloud.audit.AuditLog`,
    `serviceName:"k8s.io"`, `resource.type:"k8s_cluster"` (see the GCP audit card for that wrapper).
- **We standardise on the raw `audit.k8s.io/v1` Event object.** When a scenario is specifically about AKS
  diagnostic delivery, show the wrapper with the event JSON embedded as a string in `properties.log`.

## 3. Core field reference

### Event (audit.k8s.io/v1)
| Field | Type | Notes |
|---|---|---|
| `kind` | string | `Event`. |
| `apiVersion` | string | `audit.k8s.io/v1`. |
| `level` | enum | `None` \| `Metadata` \| `Request` \| `RequestResponse`. Determines whether `requestObject`/`responseObject` are present. |
| `auditID` | string (UID) | Unique per request; shared across that request's stage events. |
| `stage` | enum | `RequestReceived` \| `ResponseStarted` \| `ResponseComplete` \| `Panic`. |
| `requestURI` | string | Full request URI incl. query, e.g. `/api/v1/namespaces/default/pods?limit=500`. |
| `verb` | string | K8s verb: `get, list, watch, create, update, patch, delete, deletecollection` (or the HTTP method for non-resource URLs). **`exec` is recorded as `create` on the `pods/exec` subresource.** |
| `user` | UserInfo | The authenticated caller — `{username, uid?, groups[], extra{}}`. |
| `impersonatedUser` | UserInfo (opt) | Present when the request used impersonation (`kubectl --as`). |
| `sourceIPs` | string[] | Client (and proxy) IPs. |
| `userAgent` | string | e.g. `kubectl/v1.30.0 (linux/amd64) kubernetes/9e64410`. |
| `objectRef` | ObjectReference | `{resource, namespace?, name?, uid?, apiGroup, apiVersion, resourceVersion?, subresource?}`. `apiGroup` is `""` for the core group. `subresource` e.g. `exec`, `log`, `status`. |
| `responseStatus` | Status | `{metadata{}, code, status?, reason?, message?}` — HTTP status code of the response. |
| `requestObject` | object (opt) | The request body (only at level `Request`/`RequestResponse`). Carries its own `kind`/`apiVersion`. |
| `responseObject` | object (opt) | The response body (only at level `RequestResponse`). |
| `requestReceivedTimestamp` | string | Microsecond RFC3339, when the API server received the request. |
| `stageTimestamp` | string | When the request reached this stage. |
| `annotations` | map[string]string | Authorizer/admission annotations, notably `authorization.k8s.io/decision` (`allow`/`forbid`) and `authorization.k8s.io/reason` (e.g. the matching RBAC binding). |

### UserInfo
`{username, uid?, groups[], extra{}}`. Service-account usernames look like
`system:serviceaccount:<namespace>:<name>`; groups include `system:authenticated`, `system:masters`,
`system:serviceaccounts`, `system:serviceaccounts:<ns>`. Anonymous = `system:anonymous` / group
`system:unauthenticated`.

### Levels & stages (quick reference)
- **Level** controls data captured: `None` (nothing) → `Metadata` (who/what/when, no bodies) →
  `Request` (+request body) → `RequestResponse` (+request & response bodies).
- **Stage** marks where in handling the event fired: `RequestReceived` (arrival), `ResponseStarted`
  (headers sent — long-running/watch only), `ResponseComplete` (done), `Panic`. Most policies omit
  `RequestReceived`.

---

## 4. Realistic samples (cluster `nexacorp-prod`, attacker IP `203.0.113.77`)

### K1 — `exec` into a pod (recorded as verb `create` on `pods/exec`; status 101 upgrade)
```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Request",
  "auditID": "ad26f7bc-f1c6-4097-90f1-e0924e12f257",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/default/pods/web-7f6b8c9d4-abcde/exec?command=%2Fbin%2Fsh&container=web&stdin=true&stdout=true&tty=true",
  "verb": "create",
  "user": {
    "username": "kubernetes-admin",
    "groups": [ "system:masters", "system:authenticated" ]
  },
  "sourceIPs": [ "203.0.113.77" ],
  "userAgent": "kubectl/v1.30.0 (linux/amd64) kubernetes/9e64410",
  "objectRef": {
    "resource": "pods",
    "namespace": "default",
    "name": "web-7f6b8c9d4-abcde",
    "apiGroup": "",
    "apiVersion": "v1",
    "subresource": "exec"
  },
  "responseStatus": { "metadata": {}, "code": 101 },
  "requestReceivedTimestamp": "2026-09-30T03:10:11.643609Z",
  "stageTimestamp": "2026-09-30T03:10:11.647762Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": "RBAC: allowed by ClusterRoleBinding \"cluster-admin\" of ClusterRole \"cluster-admin\" to User \"kubernetes-admin\""
  }
}
```

### K2 — Create a privileged pod (hostNetwork + privileged container; level RequestResponse)
```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "auditID": "b1c2d3e4-f5a6-4788-99aa-bbccddeeff00",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/default/pods",
  "verb": "create",
  "user": {
    "username": "system:serviceaccount:default:default",
    "uid": "6661e893-99d5-4a9d-ac16-254a177e9516",
    "groups": [ "system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated" ]
  },
  "sourceIPs": [ "203.0.113.77" ],
  "userAgent": "kubectl/v1.30.0 (linux/amd64)",
  "objectRef": { "resource": "pods", "namespace": "default", "name": "pwn", "apiGroup": "", "apiVersion": "v1" },
  "requestObject": {
    "kind": "Pod",
    "apiVersion": "v1",
    "metadata": { "name": "pwn", "namespace": "default" },
    "spec": {
      "hostNetwork": true,
      "hostPID": true,
      "containers": [
        {
          "name": "pwn",
          "image": "alpine",
          "command": [ "/bin/sh", "-c", "sleep 1d" ],
          "securityContext": { "privileged": true },
          "volumeMounts": [ { "name": "host", "mountPath": "/host" } ]
        }
      ],
      "volumes": [ { "name": "host", "hostPath": { "path": "/" } } ]
    }
  },
  "responseObject": { "kind": "Pod", "apiVersion": "v1", "metadata": { "name": "pwn", "namespace": "default", "uid": "9a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9" }, "status": { "phase": "Pending" } },
  "responseStatus": { "metadata": {}, "code": 201 },
  "requestReceivedTimestamp": "2026-09-30T03:12:40.100000Z",
  "stageTimestamp": "2026-09-30T03:12:40.355000Z",
  "annotations": { "authorization.k8s.io/decision": "allow", "authorization.k8s.io/reason": "RBAC: allowed by RoleBinding \"default-admin/default\" of Role \"admin\" to ServiceAccount \"default/default\"" }
}
```

### K3 — List all secrets in a namespace (credential access)
```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Metadata",
  "auditID": "c2d3e4f5-a6b7-4899-aabb-ccddeeff0011",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/kube-system/secrets?limit=500",
  "verb": "list",
  "user": {
    "username": "system:serviceaccount:default:default",
    "groups": [ "system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated" ]
  },
  "sourceIPs": [ "203.0.113.77" ],
  "userAgent": "kubectl/v1.30.0 (linux/amd64)",
  "objectRef": { "resource": "secrets", "namespace": "kube-system", "apiGroup": "", "apiVersion": "v1" },
  "responseStatus": { "metadata": {}, "code": 200 },
  "requestReceivedTimestamp": "2026-09-30T03:14:02.000000Z",
  "stageTimestamp": "2026-09-30T03:14:02.050000Z",
  "annotations": { "authorization.k8s.io/decision": "allow", "authorization.k8s.io/reason": "" }
}
```

### K4 — Create a cluster-admin ClusterRoleBinding (privilege escalation / persistence)
```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "auditID": "d3e4f5a6-b7c8-4900-aabb-ccddeeff0022",
  "stage": "ResponseComplete",
  "requestURI": "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
  "verb": "create",
  "user": {
    "username": "system:serviceaccount:default:default",
    "groups": [ "system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated" ]
  },
  "sourceIPs": [ "203.0.113.77" ],
  "userAgent": "kubectl/v1.30.0 (linux/amd64)",
  "objectRef": { "resource": "clusterrolebindings", "name": "pwn-admin", "apiGroup": "rbac.authorization.k8s.io", "apiVersion": "v1" },
  "requestObject": {
    "kind": "ClusterRoleBinding",
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "metadata": { "name": "pwn-admin" },
    "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin" },
    "subjects": [ { "kind": "ServiceAccount", "name": "default", "namespace": "default" } ]
  },
  "responseStatus": { "metadata": {}, "code": 201 },
  "requestReceivedTimestamp": "2026-09-30T03:15:30.000000Z",
  "stageTimestamp": "2026-09-30T03:15:30.210000Z",
  "annotations": { "authorization.k8s.io/decision": "allow", "authorization.k8s.io/reason": "RBAC: allowed by ClusterRoleBinding \"default-escalated\" of ClusterRole \"admin\" to ServiceAccount \"default/default\"" }
}
```

### K5 — Forbidden access from anonymous (recon blocked; status 403, decision forbid)
```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Metadata",
  "auditID": "e4f5a6b7-c8d9-4a11-bbcc-ddeeff003344",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/kube-system/secrets",
  "verb": "list",
  "user": { "username": "system:anonymous", "groups": [ "system:unauthenticated" ] },
  "sourceIPs": [ "203.0.113.77" ],
  "userAgent": "curl/8.5.0",
  "objectRef": { "resource": "secrets", "namespace": "kube-system", "apiGroup": "", "apiVersion": "v1" },
  "responseStatus": { "metadata": {}, "status": "Failure", "reason": "Forbidden", "code": 403, "message": "secrets is forbidden: User \"system:anonymous\" cannot list resource \"secrets\" in API group \"\" in the namespace \"kube-system\"" },
  "requestReceivedTimestamp": "2026-09-30T03:08:00.000000Z",
  "stageTimestamp": "2026-09-30T03:08:00.020000Z",
  "annotations": { "authorization.k8s.io/decision": "forbid", "authorization.k8s.io/reason": "" }
}
```

### K6 — AKS delivery wrapper (`kube-audit` diagnostic record; raw event embedded as a string in properties.log)
```json
{
  "category": "kube-audit",
  "operationName": "Microsoft.ContainerService/managedClusters/diagnosticLogs/Read",
  "resourceId": "/SUBSCRIPTIONS/11112222-3333-4444-5555-666677778888/RESOURCEGROUPS/PROD-RG/PROVIDERS/MICROSOFT.CONTAINERSERVICE/MANAGEDCLUSTERS/NEXACORP-PROD",
  "time": "2026-09-30T03:10:11.647880072Z",
  "properties": {
    "log": "{\"kind\":\"Event\",\"apiVersion\":\"audit.k8s.io/v1\",\"level\":\"Request\",\"auditID\":\"ad26f7bc-f1c6-4097-90f1-e0924e12f257\",\"stage\":\"ResponseComplete\",\"requestURI\":\"/api/v1/namespaces/default/pods/web-7f6b8c9d4-abcde/exec?command=%2Fbin%2Fsh&container=web\",\"verb\":\"create\",\"user\":{\"username\":\"kubernetes-admin\",\"groups\":[\"system:masters\",\"system:authenticated\"]},\"sourceIPs\":[\"203.0.113.77\"],\"userAgent\":\"kubectl/v1.30.0 (linux/amd64)\",\"objectRef\":{\"resource\":\"pods\",\"namespace\":\"default\",\"name\":\"web-7f6b8c9d4-abcde\",\"apiGroup\":\"\",\"apiVersion\":\"v1\",\"subresource\":\"exec\"},\"responseStatus\":{\"metadata\":{},\"code\":101},\"requestReceivedTimestamp\":\"2026-09-30T03:10:11.643609Z\",\"stageTimestamp\":\"2026-09-30T03:10:11.647762Z\",\"annotations\":{\"authorization.k8s.io/decision\":\"allow\",\"authorization.k8s.io/reason\":\"\"}}",
    "stream": "stdout",
    "pod": "kube-apiserver-869d7bb754-kkg69",
    "containerID": "a64cba7fefbf5020788dc29d9247157585bbb64826bf7209623ca7bb49b15fe7"
  }
}
```

---

## 5. Investigation notes

- **Pivots:** actor = `user.username` (+ `user.groups`); impersonation = `impersonatedUser.username`
  (someone used `--as` — the real principal is `user`, the assumed one is `impersonatedUser`); source =
  `sourceIPs[]` + `userAgent`; action = `verb` + `objectRef.resource`/`subresource` + `objectRef.namespace`;
  outcome = `responseStatus.code` + `annotations["authorization.k8s.io/decision"]`; correlate request stages via
  `auditID`.
- **Exec detection:** a shell-in is `verb:"create"` on `objectRef.subresource:"exec"` (resource `pods`), **not**
  a verb `exec`. `pods/attach` and `pods/portforward` are similar subresources. A rule matching only
  `resource=="pods"` without the subresource misses every shell-in.
- **Privilege escalation markers:** `clusterrolebindings`/`rolebindings` `create` binding to `cluster-admin`
  (read `requestObject.roleRef.name` + `subjects`); pod `create` with
  `requestObject.spec.containers[].securityContext.privileged:true`, `hostNetwork`/`hostPID`, or a `hostPath`
  volume mounting `/`; `secrets` `list`/`get` in `kube-system`.
- **Anonymous / unauth:** `user.username == "system:anonymous"` or group `system:unauthenticated` reaching the
  API (K5) is high signal; GuardDuty's `*Kubernetes/SuccessfulAnonymousAccess` findings map onto exactly these.
- **`annotations["authorization.k8s.io/decision"]`** = `allow`/`forbid` is the authoritative allow/deny; the
  `reason` names the RBAC binding that permitted it — use it to find over-broad grants.
- **Level matters for evidence:** only `RequestResponse` events carry `requestObject`+`responseObject` (full
  manifests); `Metadata` events have neither. If you need the pod spec, the event must have been captured at
  `Request`/`RequestResponse`.
- **Managed-service correlation:** on EKS the message in CloudWatch **is** the raw event; on AKS parse the JSON
  string in `properties.log`; on GKE the same information lives under `protoPayload` of a Cloud Audit LogEntry
  (`serviceName:"k8s.io"`). The inner fields (`verb`, `objectRef`, `user`) are identical.

## 6. Common mistakes / non-existent fields

- **Do not** flatten to `kubernetes.audit.*` (Elastic ECS) or wrap in a Wazuh `data.*` envelope. Keep the native
  `audit.k8s.io/v1` Event. (The AKS/EKS/GKE *transport* wrappers in §2 are the only legitimate wrapping, and the
  inner payload stays native.)
- `verb` values are the K8s verbs (`get/list/watch/create/update/patch/delete/deletecollection`), **not** HTTP
  methods for resource requests, and **there is no `exec` verb** — exec is `create` on `pods/exec`.
- `apiVersion` is `audit.k8s.io/v1` (the audit event), distinct from `objectRef.apiVersion` (the target object's
  version, e.g. `v1`). `objectRef.apiGroup` is `""` (empty string) for core resources, not `"core"`.
- `level` is one of `None/Metadata/Request/RequestResponse`; `stage` is one of
  `RequestReceived/ResponseStarted/ResponseComplete/Panic`. Don't mix these two enums.
- `responseStatus.code` is an **HTTP status code** (200/201/403/101...), an integer — not a gRPC code and not a
  string. `201` for create, `101` for exec/attach upgrade, `403` for forbidden.
- `sourceIPs` is an **array** of strings (may include a proxy hop), not a single string.
- Don't include `requestObject`/`responseObject` on a `Metadata`-level event — they only exist at
  `Request`/`RequestResponse`. Conversely, a single request may legitimately appear as two events
  (`RequestReceived` + `ResponseComplete`) with the same `auditID`.
- Service-account usernames are `system:serviceaccount:<ns>:<name>` (colons), not `<ns>/<name>`. Anonymous is
  exactly `system:anonymous`.
