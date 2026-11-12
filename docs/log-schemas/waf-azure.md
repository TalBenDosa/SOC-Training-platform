# Azure WAF on Application Gateway: firewall and access logs

Category: Web application firewall · Vendor: Microsoft · Module: `azure_waf`
Scope: `ApplicationGatewayFirewallLog` and `ApplicationGatewayAccessLog` resource logs of a WAF_v2 Application Gateway, as a storage account or event hub delivers them. Log Analytics resource-specific tables (`AGWFirewallLogs`, `AGWAccessLogs`) carry the same facts under PascalCase columns.

## 1. Official sources

| Source | What it confirmed |
|---|---|
| Monitor logs for Azure WAF: https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/web-application-firewall-logs | Firewall log fields, `action` meanings, sample record; access log fields |
| Monitoring data reference: https://learn.microsoft.com/en-us/azure/application-gateway/monitor-application-gateway-reference | v2 access log sample (`timeStamp`, `listenerName`, `originalRequestUriWithArgs`, `requestQuery`, `WAFMode`, `serverRouted`, `serverStatus`, `error_info`) |
| CRS and DRS rule groups and rules: https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-crs-rulegroups-rules | Rule ids, groups and wording (CRS 3.2 tab); checked 2026-11-12 for the injection rules: 932100 / 932105 "Remote Command Execution: Unix Command Injection", 932110 "Remote Command Execution: Windows Command Injection" (REQUEST-932-APPLICATION-ATTACK-RCE), 944240 "Remote Command Execution: Java serialization" (REQUEST-944-APPLICATION-ATTACK-JAVA), 921150 "HTTP Header Injection Attack via payload (CR/LF detected)" (REQUEST-921-PROTOCOL-ATTACK) |
| AGWFirewallLogs / AGWAccessLogs tables: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/agwaccesslogs | The resource-specific columns the XDR console maps these records to (checked 2026-11-12) |
| Troubleshoot rule 949110: https://learn.microsoft.com/en-us/troubleshoot/azure/application-gateway/troubleshoot-waf-anomaly-scoring-rule-949110-blocks | Anomaly scoring: rule rows are `Matched`, the final row is `Blocked` or `Detected`, joined on `transactionId` |
| Troubleshoot WAF: https://learn.microsoft.com/en-us/troubleshoot/azure/web-application-firewall/web-application-firewall-troubleshoot | Wording of a blocking row (`Access denied with code 403 (phase 2). Operator GE matched 5 at TX:anomaly_score.`); a body is inspected only up to the inspection limit when the size limit is off |

## 2. Native format and delivery

JSON resource log records (`resourceId`, `operationName`, `category`, then `properties`).
**One request can write several firewall rows and they join on `transactionId`.** A rule that fires under anomaly scoring only adds to a score (`Matched`); when the score reaches the threshold, rule 949110 writes the row that says `Blocked`.
**Clean traffic has no firewall row.** It appears only in the access log, with the origin's answer in `serverStatus` and the size in `sentBytes`.

The platform's feed shows one event per request: a blocked request shows its rule row (the one with the evidence), and the raw view prints the 949110 row of the same `transactionId` under it (`companions()`).

A policy is in one mode, and the estate has one listener and policy per site (`<org>-<site>-https-listener`). On a Detection policy every rule row is `Detected` and the access log says `WAFMode: Detection`. On a Prevention policy a managed rule is `Matched`, and a custom rule that blocks is `Blocked`.

## 3. Core field reference

### Firewall log

| Field | Meaning | Values |
|---|---|---|
| `properties.clientIp`, `requestUri` | Client and URI (the URI keeps its query string) | |
| `properties.ruleSetType`, `ruleSetVersion` | Rule set | `OWASP` / `3.2` here |
| `properties.ruleId`, `ruleGroup`, `message` | The rule | `941100`, `REQUEST-941-APPLICATION-ATTACK-XSS` |
| `properties.action` | What happened | `Matched`, `Blocked`, `Detected`, `Allowed`, JS challenge values |
| `properties.details.message`, `data`, `file`, `line` | Rule detail; `data` is what matched | |
| `properties.hostname`, `transactionId` | Site; join key | |
| `properties.policyId`, `policyScope`, `policyScopeName` | The policy | `Global`, `Listener`, `Location` |

`Detected` is the only action in Detection mode: the request was logged **and passed to the backend**.

### Access log (v2)

`instanceId`, `clientIP`, `clientPort`, `httpMethod`, `originalRequestUriWithArgs`, `requestUri`, `requestQuery`, `userAgent`, `httpStatus`, `httpVersion`, `receivedBytes`, `sentBytes`, `clientResponseTime`, `timeTaken` (seconds), `WAFEvaluationTime`, `WAFMode`, `transactionId`, `sslEnabled`, `sslCipher`, `sslProtocol`, `serverRouted`, `serverStatus`, `serverResponseLatency`, `upstreamSourcePort`, `originalHost`, `host`, `error_info`.

## 4. Samples

Rule row under anomaly scoring:

```json
{
  "resourceId": "/SUBSCRIPTIONS/AAAA0A0A-BB1B-CC2C-DD3D-EEEEEE4E4E4E/RESOURCEGROUPS/RG-EDGE-PROD/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/EXAMPLE-WAF-GW",
  "operationName": "ApplicationGatewayFirewall", "time": "2026-03-17T09:14:02.2110000Z", "category": "ApplicationGatewayFirewallLog",
  "properties": {
    "instanceId": "appgw_1", "clientIp": "203.0.113.41", "requestUri": "/download?file=..%2F..%2F...", "ruleSetType": "OWASP", "ruleSetVersion": "3.2",
    "ruleId": "930100", "ruleGroup": "REQUEST-930-APPLICATION-ATTACK-LFI", "message": "Path Traversal Attack (/../)", "action": "Matched", "site": "Global",
    "details": { "message": "Warning. Pattern match at ARGS:file.", "data": "Matched Data: ../ found within ARGS:file: ../", "file": "rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf", "line": "136" },
    "hostname": "portal.example.com", "transactionId": "592d1649f75a8d480a3c4dc6a975309d",
    "policyId": "/subscriptions/aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e/resourceGroups/rg-edge-prod/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/example-waf-policy",
    "policyScope": "Listener", "policyScopeName": "example-https-listener"
  }
}
```

The blocking row of the same request:

```json
{
  "resourceId": "/SUBSCRIPTIONS/AAAA0A0A-BB1B-CC2C-DD3D-EEEEEE4E4E4E/RESOURCEGROUPS/RG-EDGE-PROD/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/EXAMPLE-WAF-GW",
  "operationName": "ApplicationGatewayFirewall", "time": "2026-03-17T09:14:02.2110000Z", "category": "ApplicationGatewayFirewallLog",
  "properties": {
    "instanceId": "appgw_1", "clientIp": "203.0.113.41", "requestUri": "/download?file=..%2F..%2F...", "ruleSetType": "OWASP", "ruleSetVersion": "3.2",
    "ruleId": "949110", "ruleGroup": "REQUEST-949-BLOCKING-EVALUATION", "message": "Mandatory rule. Cannot be disabled. Inbound Anomaly Score Exceeded (Total Score: 5)", "action": "Blocked", "site": "Global",
    "details": { "message": "Mandatory rule. Cannot be disabled. Inbound Anomaly Score Exceeded (Total Score: 5)", "data": "-", "file": "rules/REQUEST-949-BLOCKING-EVALUATION.conf", "line": "93" },
    "hostname": "portal.example.com", "transactionId": "592d1649f75a8d480a3c4dc6a975309d",
    "policyId": "/subscriptions/aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e/resourceGroups/rg-edge-prod/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/example-waf-policy",
    "policyScope": "Listener", "policyScopeName": "example-https-listener"
  }
}
```

A listener in Detection mode (logged and passed):

```json
{
  "resourceId": "/SUBSCRIPTIONS/AAAA0A0A-BB1B-CC2C-DD3D-EEEEEE4E4E4E/RESOURCEGROUPS/RG-EDGE-PROD/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/EXAMPLE-WAF-GW",
  "operationName": "ApplicationGatewayFirewall", "time": "2026-03-17T10:02:11.0420000Z", "category": "ApplicationGatewayFirewallLog",
  "properties": {
    "instanceId": "appgw_0", "clientIp": "198.51.100.23", "requestUri": "/tickets", "ruleSetType": "OWASP", "ruleSetVersion": "3.2",
    "ruleId": "941100", "ruleGroup": "REQUEST-941-APPLICATION-ATTACK-XSS", "message": "XSS Attack Detected via libinjection", "action": "Detected", "site": "Global",
    "details": { "message": "Warning. detected XSS using libinjection. at ARGS:body.", "data": "Matched Data: <svg on... found within ARGS:body: <svg on...", "file": "rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf", "line": "412" },
    "hostname": "support.example.com", "transactionId": "aa41d0c7e2f94b1d9c30a7f81b22e6d4",
    "policyId": "/subscriptions/aaaa0a0a-bb1b-cc2c-dd3d-eeeeee4e4e4e/resourceGroups/rg-edge-prod/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/example-waf-policy",
    "policyScope": "Listener", "policyScopeName": "example-https-listener"
  }
}
```

Access log row:

```json
{
  "timeStamp": "2026-03-17T09:21:40+00:00",
  "resourceId": "/SUBSCRIPTIONS/AAAA0A0A-BB1B-CC2C-DD3D-EEEEEE4E4E4E/RESOURCEGROUPS/RG-EDGE-PROD/PROVIDERS/MICROSOFT.NETWORK/APPLICATIONGATEWAYS/EXAMPLE-WAF-GW",
  "listenerName": "example-https-listener", "ruleName": "example-routing-rule", "backendPoolName": "example-web-pool", "backendSettingName": "example-https-setting",
  "operationName": "ApplicationGatewayAccess", "category": "ApplicationGatewayAccessLog",
  "properties": {
    "instanceId": "appgw_1", "clientIP": "203.0.113.41", "clientPort": 45057, "httpMethod": "GET", "originalRequestUriWithArgs": "/download?id=881", "requestUri": "/download", "requestQuery": "id=881",
    "userAgent": "python-requests/2.31.0", "httpStatus": 200, "httpVersion": "HTTP/1.1", "receivedBytes": 412, "sentBytes": 1284, "timeTaken": 0.034, "WAFEvaluationTime": "0.001", "WAFMode": "Prevention",
    "transactionId": "1d7fe0c29ab14e6b8a6c3f5d20b1c4e7", "sslEnabled": "on", "sslCipher": "ECDHE-RSA-AES256-GCM-SHA384", "sslProtocol": "TLSv1.2",
    "serverRouted": "10.20.40.21:443", "serverStatus": "200", "serverResponseLatency": "0.028", "originalHost": "portal.example.com", "host": "portal.example.com", "error_info": "ERRORINFO_NO_ERROR"
  }
}
```

## 5. Investigation notes

- Rule 949110 names no attack. Filter `Action == "Blocked"`, take the `transactionId`, and read the `Matched` rows of that transaction.
- `Detected` means nothing stopped the request. The access log and the origin's log decide what happened.
- A request the WAF did not understand has no firewall row at all: compare the client's access log rows after its last match (`sentBytes`, `serverStatus`).
- Injection rules on CRS 3.2: an operating-system command in an argument is 932100 (Unix) or 932110 (Windows); a JNDI lookup in a header is caught by 944240; CR/LF in an argument by 921150. A split or re-encoded form (caret-split `w^h^o^a^m^i`, a nested lookup, a double URL-encoded value) often matches none of them: read the access log's `timeTaken`, `sentBytes` and `serverStatus` for the request that came after the blocks.
- In the workspace these rows are `AGWFirewallLogs` (firewall) and `AGWAccessLogs` (access). The rule group has no column: it is in `FileDetails` (`rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf`).

## 6. Common mistakes and fields that do not exist

- The ECS-style names in the platform's early draft (`waf.attack.score`, `rule.name`, `url.full`) are not fields of this log.
- `timeTaken` is seconds on v2 and milliseconds on v1.
- A firewall row carries no status code. The status is in the access log.

## 7. UNVERIFIED

- A custom rule with the **Log** action on a Prevention policy prints `Matched` here. Microsoft does not list an action for it; `Matched` is its documented meaning (the decision is still to be made).
- The row of a **custom rule** (`ruleSetType: "Custom"`, `ruleId` = the rule's name, no `ruleGroup`, `details.file: "CustomRules"`): Microsoft's page documents `Allowed` and `Blocked` for custom rules but shows no custom sample and lists only `OWASP` as a `ruleSetType`. The module's custom row follows the documented field set; the values of `ruleSetType`, `ruleSetVersion` and `details.file` are unconfirmed.
- `ruleGroup` of 949110 on Application Gateway with CRS 3.2 (`REQUEST-949-BLOCKING-EVALUATION`), and the "Mandatory rule. Cannot be disabled." wording: confirmed in customer questions on Microsoft Q&A, while the only Microsoft sample (Application Gateway for Containers, DRS) reads `BLOCKING-EVALUATION`. Microsoft's older samples print `ruleId: "0"` and an empty `ruleSetType` on that row.
- `ruleGroup` with the `REQUEST-` prefix on rule rows: Microsoft's sample on the logs page reads `920-PROTOCOL-ENFORCEMENT`, while `details.file` keeps the prefix. `details.line` is a placeholder per rule, and `details.message` is a template, not a captured line.
