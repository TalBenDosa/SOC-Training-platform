# AWS WAF: web ACL traffic log

Category: Web application firewall · Vendor: Amazon Web Services · Module: `aws_waf`
Scope: the traffic log of a regional web ACL in front of an Application Load Balancer.

## 1. Official sources

| Source | What it confirmed |
|---|---|
| Log fields for protection pack (web ACL) traffic: https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html | Every field below, `action` values, `terminatingRuleType` values, `httpSourceName` values, `rateBasedRuleList` members |
| Log examples: https://docs.aws.amazon.com/waf/latest/developerguide/logging-examples.html | Nesting and value types, rate-based block, SQLi block, group rule match, `labels` as `[{ "name": … }]` |
| Baseline rule groups: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html | Rule names and labels of `AWSManagedRulesCommonRuleSet` and `AWSManagedRulesKnownBadInputsRuleSet` |
| Use-case rule groups: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html | `AWSManagedRulesSQLiRuleSet`, `AWSManagedRulesPHPRuleSet` rule names and labels |
| ATP rule group: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-atp.html | `AWSManagedRulesATPRuleSet` rules, labels and thresholds |

## 2. Native format and delivery

JSON, one record per request the web ACL inspected, delivered to CloudWatch Logs, S3 or Firehose. `timestamp` is epoch milliseconds.
**The record has no request body and no response.** It cannot say what the origin answered: a request the WAF allowed is only proven successful by the web server's log.

## 3. Core field reference

| Field | Meaning | Values |
|---|---|---|
| `timestamp`, `formatVersion` | Epoch ms; format version | `1` |
| `webaclId` | Web ACL ARN | `arn:aws:wafv2:…:regional/webacl/<name>/<id>` |
| `terminatingRuleId` | Rule that ended inspection | `Default_Action` when nothing did |
| `terminatingRuleType` | Its type | `REGULAR`, `RATE_BASED`, `GROUP`, `MANAGED_RULE_GROUP` |
| `action` | Terminating action | `ALLOW`, `BLOCK`, `CAPTCHA`, `CHALLENGE` |
| `terminatingRuleMatchDetails` | Match detail, only for SQLi and XSS match statements | array, usually empty; not populated by CRS version 2.0 XSS rules |
| `httpSourceName`, `httpSourceId` | Protected resource | `ALB`, `CF`, `APIGW`, … |
| `ruleGroupList[]` | Rule groups that acted | `ruleGroupId`, `terminatingRule`, `nonTerminatingMatchingRules`, `excludedRules` |
| `rateBasedRuleList[]` | Rate-based rules evaluated | `rateBasedRuleId`, `rateBasedRuleName`, `limitKey`, `limitValue`, `maxRateAllowed`, `evaluationWindowSec` |
| `nonTerminatingMatchingRules[]` | Rules that matched without ending inspection | `ruleId`, `action` (`COUNT`, `CAPTCHA`, `CHALLENGE`), `ruleMatchDetails`; `overriddenAction` when a group rule was overridden |
| `httpRequest` | `clientIp`, `country`, `headers[]`, `uri`, `args`, `httpVersion`, `httpMethod`, `requestId` | `requestId` is the ALB trace id |
| `labels[]` | Labels applied by rules | `awswaf:managed:aws:core-rule-set:…` |
| `ja3Fingerprint`, `ja4Fingerprint` | TLS client fingerprint | ALB and CloudFront only |

## 4. Samples

Blocked by a managed rule:

```json
{
  "timestamp": 1773738842211, "formatVersion": 1,
  "webaclId": "arn:aws:wafv2:eu-west-1:111122223333:regional/webacl/example-edge-acl/1a2b3c4d-1111-4222-8333-444455556666",
  "terminatingRuleId": "AWS-AWSManagedRulesCommonRuleSet", "terminatingRuleType": "MANAGED_RULE_GROUP", "action": "BLOCK",
  "terminatingRuleMatchDetails": [], "httpSourceName": "ALB", "httpSourceId": "111122223333-app/example-public-alb/50dc6c495c0c9188",
  "ruleGroupList": [{ "ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet", "terminatingRule": { "ruleId": "EC2MetaDataSSRF_QUERYARGUMENTS", "action": "BLOCK", "ruleMatchDetails": null }, "nonTerminatingMatchingRules": [], "excludedRules": null }],
  "rateBasedRuleList": [], "nonTerminatingMatchingRules": [], "requestHeadersInserted": null, "responseCodeSent": null,
  "httpRequest": { "clientIp": "203.0.113.17", "country": "NL", "headers": [{ "name": "Host", "value": "app.example.com" }, { "name": "User-Agent", "value": "python-requests/2.31.0" }], "uri": "/api/preview", "args": "url=http://169.254.169.254/...", "httpVersion": "HTTP/1.1", "httpMethod": "GET", "requestId": "1-65f6e1aa-7cb058b04d9bb3ee01dc4036" },
  "labels": [{ "name": "awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_QueryArguments" }]
}
```

Rule overridden to Count, request passed:

```json
{
  "timestamp": 1773738901774, "formatVersion": 1,
  "webaclId": "arn:aws:wafv2:eu-west-1:111122223333:regional/webacl/example-edge-acl/1a2b3c4d-1111-4222-8333-444455556666",
  "terminatingRuleId": "Default_Action", "terminatingRuleType": "REGULAR", "action": "ALLOW",
  "terminatingRuleMatchDetails": [], "httpSourceName": "ALB", "httpSourceId": "111122223333-app/example-public-alb/50dc6c495c0c9188",
  "ruleGroupList": [{ "ruleGroupId": "AWS#AWSManagedRulesCommonRuleSet", "terminatingRule": null, "nonTerminatingMatchingRules": [{ "ruleId": "CrossSiteScripting_BODY", "action": "COUNT", "overriddenAction": "BLOCK", "ruleMatchDetails": [] }], "excludedRules": null }],
  "rateBasedRuleList": [], "nonTerminatingMatchingRules": [], "requestHeadersInserted": null, "responseCodeSent": null,
  "httpRequest": { "clientIp": "198.51.100.23", "country": "DE", "headers": [{ "name": "Host", "value": "support.example.com" }], "uri": "/tickets", "args": "", "httpVersion": "HTTP/1.1", "httpMethod": "POST", "requestId": "1-65f6e1e5-18b57ff33c10e5c016b508c5" },
  "labels": [{ "name": "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body" }]
}
```

Rate-based rule in Count (the client stays under no block), and ATP on a login:

```json
{
  "timestamp": 1773739010012, "formatVersion": 1,
  "webaclId": "arn:aws:wafv2:eu-west-1:111122223333:regional/webacl/example-edge-acl/1a2b3c4d-1111-4222-8333-444455556666",
  "terminatingRuleId": "Default_Action", "terminatingRuleType": "REGULAR", "action": "ALLOW",
  "terminatingRuleMatchDetails": [], "httpSourceName": "ALB", "httpSourceId": "111122223333-app/example-public-alb/50dc6c495c0c9188",
  "ruleGroupList": [],
  "rateBasedRuleList": [{ "rateBasedRuleId": "api-rate-per-ip", "rateBasedRuleName": "api-rate-per-ip", "limitKey": "IP", "limitValue": "203.0.113.90", "maxRateAllowed": 300, "evaluationWindowSec": "300" }],
  "nonTerminatingMatchingRules": [{ "ruleId": "api-rate-per-ip", "action": "COUNT", "ruleMatchDetails": [] }], "requestHeadersInserted": null, "responseCodeSent": null,
  "httpRequest": { "clientIp": "203.0.113.90", "country": "RO", "headers": [{ "name": "Host", "value": "api.example.com" }], "uri": "/api/v2/customers/48244/statements", "args": "", "httpVersion": "HTTP/1.1", "httpMethod": "GET", "requestId": "1-65f6e252-17ac754c2ed9f0620e0f2a0c" }
}
```

```json
{
  "timestamp": 1773739120455, "formatVersion": 1,
  "webaclId": "arn:aws:wafv2:eu-west-1:111122223333:regional/webacl/example-edge-acl/1a2b3c4d-1111-4222-8333-444455556666",
  "terminatingRuleId": "AWS-AWSManagedRulesATPRuleSet", "terminatingRuleType": "MANAGED_RULE_GROUP", "action": "BLOCK",
  "terminatingRuleMatchDetails": [], "httpSourceName": "ALB", "httpSourceId": "111122223333-app/example-public-alb/50dc6c495c0c9188",
  "ruleGroupList": [{ "ruleGroupId": "AWS#AWSManagedRulesATPRuleSet", "terminatingRule": { "ruleId": "VolumetricIpHigh", "action": "BLOCK", "ruleMatchDetails": null }, "nonTerminatingMatchingRules": [], "excludedRules": null }],
  "rateBasedRuleList": [], "nonTerminatingMatchingRules": [], "requestHeadersInserted": null, "responseCodeSent": null,
  "httpRequest": { "clientIp": "203.0.113.61", "country": "BG", "headers": [{ "name": "Host", "value": "portal.example.com" }], "uri": "/account/login", "args": "", "httpVersion": "HTTP/1.1", "httpMethod": "POST", "requestId": "1-65f6e2c0-3d1b0c9a5e7f4a22b1c0d9e8" },
  "labels": [{ "name": "awswaf:managed:aws:atp:aggregate:volumetric:ip:high" }, { "name": "awswaf:managed:aws:atp:VolumetricIpHigh" }],
  "ja3Fingerprint": "e7d705a3286e19ea42f587b344ee6865"
}
```

## 5. Investigation notes

- A block is a request that failed. The question is what the same `clientIp` did next: the first `ALLOW` after a run of blocks is the row that matters.
- `action: ALLOW` with a matching `COUNT` rule means the WAF saw it and let it through. Go to the web server log for the status and the size.
- Rotating addresses from one tool usually share `ja3Fingerprint`.
- `args` is the query string. A POST's body is not in the record: only the rule name speaks for it.

## 6. Common mistakes and fields that do not exist

- `waf.attack.type`, `waf.attack.score`, `bot.score`, `url.query`, `http.request.body`, `action_result`: none of these exist in a web ACL log (the draft field list in the platform's memory was ECS-style, not AWS's).
- No `httpResponseCode` on the record. `responseCodeSent` is only the custom response of a block.
- The EC2 metadata rule is `EC2MetaDataSSRF_*`, in the core rule set.
- Rule-level labels use mixed case that differs from the rule name (`CrossSiteScripting_Body` for rule `CrossSiteScripting_BODY`).
