# AWS VPC Flow Logs — log schema card

VPC Flow Logs are **text-native**: each record is a single line of space-separated fields.
Per the folder rule, show the raw line **and** a flat JSON object whose keys are the exact documented field
names. Do **not** invent nested ECS structures (`source.ip`, `network.bytes`) or a Wazuh envelope.

## 1. Official sources

- Flow log records (default v2 order, every available field with its version, types, allowed values):
  https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
- Record examples (accept/reject, NODATA/SKIPDATA, ICMP, IPv6, TCP flags, NAT/TGW, service name/path/direction):
  https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html
- File format, delivery interval, S3 path/file-name templates:
  https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-path.html
- Field order/realism cross-checked against elastic/integrations `packages/aws/data_stream/vpcflow` raw test inputs.

## 2. Native format & delivery

- **Record** = one space-separated line; fields appear in the order chosen (default = all v2 fields in doc order).
  Any missing/not-applicable field is literally `-`.
- **Default (v2) field order** (14 fields):
  `version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status`
- **Destinations:** CloudWatch Logs (each record is one log event), Amazon S3 (gzipped text, or Parquet),
  or Kinesis Data Firehose. Delivery to S3 ≈ every 10 min; to CloudWatch ≈ every 5 min (Nitro instances
  aggregate every 1 min regardless of the configured interval).
- **Aggregation interval:** default up to 10 min (configurable to 1 min). One record = one 5-tuple flow
  aggregated over that window.
- **S3 object path** (default):
  `<bucket>/AWSLogs/<account_id>/vpcflowlogs/<region>/<YYYY>/<MM>/<DD>/<account_id>_vpcflowlogs_<region>_<flow_log_id>_<YYYYMMDD>T<HHmm>Z_<hash>.log.gz`
- **We standardise on:** the raw line first, then a flat JSON `{field-name: value}` using the vendor's own
  hyphenated field names, with `-` represented as JSON `null`.

## 3. Core field reference

`start`/`end` are **Unix seconds** (not millis). `-` = not applicable/not computed. All text when stored as
plain text; Parquet types shown by AWS are int/string.

| Field | Ver | Meaning / values |
|---|---|---|
| `version` | 2 | Flow log version (2 for default; highest among chosen fields otherwise). |
| `account-id` | 2 | Owner of the source ENI (or `unknown` for some AWS-created ENIs). |
| `interface-id` | 2 | ENI id, e.g. `eni-1235b8ca123456789`. `-` for a regional NAT gateway flow. |
| `srcaddr` | 2 | Source IP (for egress, the ENI private/IPv6 addr). See `pkt-srcaddr`. |
| `dstaddr` | 2 | Destination IP (for ingress, the ENI addr). See `pkt-dstaddr`. |
| `srcport` | 2 | Source port. |
| `dstport` | 2 | Destination port. |
| `protocol` | 2 | IANA protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6). |
| `packets` | 2 | Packets in the flow. |
| `bytes` | 2 | Bytes in the flow. |
| `start` | 2 | Unix seconds, first packet in the window. |
| `end` | 2 | Unix seconds, last packet in the window. |
| `action` | 2 | `ACCEPT` \| `REJECT`. |
| `log-status` | 2 | `OK` \| `NODATA` (no traffic in window) \| `SKIPDATA` (records skipped). |
| `vpc-id` | 3 | `vpc-...`. `-` for regional NAT gateway. |
| `subnet-id` | 3 | `subnet-...`. |
| `instance-id` | 3 | `i-...`; `-` for requester-managed ENIs (e.g. NAT gateway). |
| `tcp-flags` | 3 | Bitmask: FIN=1, SYN=2, RST=4, SYN-ACK=18; 0 if none; `-` if invalid. OR-ed over the window (e.g. 3 = SYN+FIN, 19 = SYN-ACK+FIN). |
| `type` | 3 | `IPv4` \| `IPv6` \| `EFA`. |
| `pkt-srcaddr` | 3 | Packet-level original source (differs from `srcaddr` behind NAT/intermediary). |
| `pkt-dstaddr` | 3 | Packet-level original destination. |
| `region` | 4 | e.g. `us-east-1`. |
| `az-id` | 4 | AZ id, e.g. `use1-az2`; `-` for sublocation traffic. |
| `sublocation-type` | 4 | `wavelength` \| `outpost` \| `localzone`; `-` otherwise. |
| `sublocation-id` | 4 | Sublocation id; `-` otherwise. |
| `pkt-src-aws-service` | 5 | AWS service name if source is AWS IP range (e.g. `S3`, `EC2`, `DYNAMODB`, `AMAZON`, `CLOUDFRONT`, `ROUTE53`…); `-` otherwise. |
| `pkt-dst-aws-service` | 5 | Same, for destination. |
| `flow-direction` | 5 | `ingress` \| `egress` (w.r.t. the capturing ENI). |
| `traffic-path` | 5 | Egress path: 1=same VPC/AWS ENI, 2=IGW/gateway endpoint, 3=VGW, 4=intra-region peering, 5=inter-region peering, 6=Local/Wavelength Zone, 7=gateway VPC endpoint, 8=internet gateway; `-` if N/A (always `-` for ingress). |
| `ecs-*` | 7 | ECS task/cluster/container context (needs ecs permissions); `-` if not from an ECS task. |
| `reject-reason` | 8 | `BPA` (VPC Block Public Access) \| `EC` (encryption controls); `-` otherwise. |
| `resource-id` | 9 | Regional NAT gateway id `nat-...`; `-` otherwise. |
| `encryption-status` | 10 | 0=not encrypted, 1=nitro-encrypted, 2=application-encrypted, 3=both; `-` if N/A. |
| `interface-type` | 11 | `nat_gateway` \| `network_load_balancer` \| `regional_nat_gateway` \| `transit_gateway` \| `vpc_endpoint`; `-`. |
| `instance-tag`, `interface-tag`, `asg-tag` (+ `-2`) | 11 | Tag values (percent-encoded). |
| `next-hop-*` | 11 | Next-hop ENI/subnet/az/vpc/type. |

---

## 4. Realistic samples

All use the **default v2 format** unless noted. These extend the attack narrative: the compromised
`ec2-ci-runner` instance (`10.0.3.47`, ENI `eni-0a1b2c3d4e5f60718`) in account `123456789012`.

### V1 — Accepted outbound HTTPS to the exfil IP (data leaving to 203.0.113.77)
Raw:
```
2 123456789012 eni-0a1b2c3d4e5f60718 10.0.3.47 203.0.113.77 49512 443 6 8421 48217940 1790648520 1790648578 ACCEPT OK
```
Flat JSON:
```json
{
  "version": "2",
  "account-id": "123456789012",
  "interface-id": "eni-0a1b2c3d4e5f60718",
  "srcaddr": "10.0.3.47",
  "dstaddr": "203.0.113.77",
  "srcport": 49512,
  "dstport": 443,
  "protocol": 6,
  "packets": 8421,
  "bytes": 48217940,
  "start": 1790648520,
  "end": 1790648578,
  "action": "ACCEPT",
  "log-status": "OK"
}
```

### V2 — Rejected inbound SSH brute-force (REJECT from a scanner)
Raw:
```
2 123456789012 eni-0a1b2c3d4e5f60718 198.51.100.23 10.0.3.47 51044 22 6 1 40 1790644800 1790644860 REJECT OK
```
Flat JSON:
```json
{
  "version": "2",
  "account-id": "123456789012",
  "interface-id": "eni-0a1b2c3d4e5f60718",
  "srcaddr": "198.51.100.23",
  "dstaddr": "10.0.3.47",
  "srcport": 51044,
  "dstport": 22,
  "protocol": 6,
  "packets": 1,
  "bytes": 40,
  "start": 1790644800,
  "end": 1790644860,
  "action": "REJECT",
  "log-status": "OK"
}
```

### V3 — Crypto-mining pool connection (outbound to mining port 3333)
Raw:
```
2 123456789012 eni-0a1b2c3d4e5f60718 10.0.3.47 192.0.2.155 44210 3333 6 15230 912400 1790650000 1790650060 ACCEPT OK
```
Flat JSON:
```json
{
  "version": "2",
  "account-id": "123456789012",
  "interface-id": "eni-0a1b2c3d4e5f60718",
  "srcaddr": "10.0.3.47",
  "dstaddr": "192.0.2.155",
  "srcport": 44210,
  "dstport": 3333,
  "protocol": 6,
  "packets": 15230,
  "bytes": 912400,
  "start": 1790650000,
  "end": 1790650060,
  "action": "ACCEPT",
  "log-status": "OK"
}
```

### V4 — NODATA (no traffic on the ENI during the window)
Raw:
```
2 123456789012 eni-0a1b2c3d4e5f60718 - - - - - - - 1790651000 1790651060 - NODATA
```
Flat JSON:
```json
{
  "version": "2",
  "account-id": "123456789012",
  "interface-id": "eni-0a1b2c3d4e5f60718",
  "srcaddr": null,
  "dstaddr": null,
  "srcport": null,
  "dstport": null,
  "protocol": null,
  "packets": null,
  "bytes": null,
  "start": 1790651000,
  "end": 1790651060,
  "action": null,
  "log-status": "NODATA"
}
```

### V5 — Custom (v5) format: service name, traffic-path, flow-direction (egress to S3 via IGW)
Custom field order:
```
version srcaddr dstaddr srcport dstport protocol start end type packets bytes account-id vpc-id subnet-id instance-id interface-id region az-id action tcp-flags pkt-srcaddr pkt-dstaddr pkt-src-aws-service pkt-dst-aws-service traffic-path flow-direction log-status
```
Raw (two records: ingress response from S3, then egress request to S3):
```
5 52.217.66.12 10.0.3.47 443 51330 6 1790652000 1790652057 IPv4 14 15044 123456789012 vpc-0def67890 subnet-0abc12345 i-02468ace13579bdf0 eni-0a1b2c3d4e5f60718 us-east-1 use1-az2 ACCEPT 19 52.217.66.12 10.0.3.47 S3 - - ingress OK
5 10.0.3.47 52.217.66.12 51330 443 6 1790652000 1790652057 IPv4 7 471 123456789012 vpc-0def67890 subnet-0abc12345 i-02468ace13579bdf0 eni-0a1b2c3d4e5f60718 us-east-1 use1-az2 ACCEPT 3 10.0.3.47 52.217.66.12 - S3 8 egress OK
```
Flat JSON (egress record):
```json
{
  "version": "5",
  "srcaddr": "10.0.3.47",
  "dstaddr": "52.217.66.12",
  "srcport": 51330,
  "dstport": 443,
  "protocol": 6,
  "start": 1790652000,
  "end": 1790652057,
  "type": "IPv4",
  "packets": 7,
  "bytes": 471,
  "account-id": "123456789012",
  "vpc-id": "vpc-0def67890",
  "subnet-id": "subnet-0abc12345",
  "instance-id": "i-02468ace13579bdf0",
  "interface-id": "eni-0a1b2c3d4e5f60718",
  "region": "us-east-1",
  "az-id": "use1-az2",
  "action": "ACCEPT",
  "tcp-flags": 3,
  "pkt-srcaddr": "10.0.3.47",
  "pkt-dstaddr": "52.217.66.12",
  "pkt-src-aws-service": null,
  "pkt-dst-aws-service": "S3",
  "traffic-path": 8,
  "flow-direction": "egress",
  "log-status": "OK"
}
```

### V6 — NAT gateway intermediary (srcaddr ≠ pkt-srcaddr): instance → NAT → internet
Custom order: `instance-id interface-id srcaddr dstaddr pkt-srcaddr pkt-dstaddr`. The NAT gateway ENI is
requester-managed, so `instance-id` = `-`.
Raw (traffic from instance to the NAT ENI, then NAT ENI out to the internet):
```
- eni-0naabbccddeeff001 10.0.3.47 10.0.0.220 10.0.3.47 203.0.113.77
- eni-0naabbccddeeff001 10.0.0.220 203.0.113.77 10.0.0.220 203.0.113.77
```
Flat JSON (first line):
```json
{
  "instance-id": null,
  "interface-id": "eni-0naabbccddeeff001",
  "srcaddr": "10.0.3.47",
  "dstaddr": "10.0.0.220",
  "pkt-srcaddr": "10.0.3.47",
  "pkt-dstaddr": "203.0.113.77"
}
```

---

## 5. Investigation notes

- **Pivots:** `interface-id`/`instance-id` tie a flow to a host; `srcaddr`+`dstaddr`+`dstport`+`protocol`
  identify the conversation; `bytes`/`packets` size it (exfil = large outbound `bytes`); `start`/`end`
  bound it in time (Unix seconds — convert before comparing to CloudTrail ISO timestamps).
- **ACCEPT ≠ benign.** Flow logs record what the SG/NACL allowed, not intent. A huge ACCEPT egress on 443 to
  a foreign IP is the network footprint of the S3/GetObject exfil; a REJECT inbound burst on 22/3389 is
  brute-force recon that never got in.
- **`srcaddr` vs `pkt-srcaddr`:** behind a NAT gateway / intermediary ENI they differ. Use `pkt-srcaddr` /
  `pkt-dstaddr` to find the *real* endpoint; `srcaddr`/`dstaddr` show the intermediary.
- **`tcp-flags`** reveals direction and scans: lone SYN (2) with no SYN-ACK (18) back = unanswered connection
  attempts (port scan / blocked); OR-ed values like 3 (SYN+FIN) or 19 (SYN-ACK+FIN) = short-lived connections.
- **`log-status`:** `NODATA` means the ENI was idle (not an outage); `SKIPDATA` means some flows were dropped
  internally — a visibility gap, not evidence of no traffic.
- **Correlate with GuardDuty:** EC2 findings sourced from VPC flow logs (`Recon:EC2/Portscan`,
  `UnauthorizedAccess:EC2/SSHBruteForce`, `CryptoCurrency:EC2/BitcoinTool.B`, `Backdoor:EC2/DenialOfService.*`,
  `Impact:EC2/PortSweep`) are derived from exactly these records; the finding's instance/IP/ports map back here.
- **`pkt-dst-aws-service`/`traffic-path`** distinguish traffic to AWS services vs the open internet
  (traffic-path 2/8 = via internet/IGW), which helps tell legitimate S3/DynamoDB access from C2.

## 6. Common mistakes / non-existent fields

- **Do not** reorder fields arbitrarily; the default record is exactly the 14 v2 fields in the order above.
  A custom format can reorder/subset, but then the field list must be stated (as in V5/V6).
- `-` is the only "missing" token in the raw line (represented as `null` in the flat JSON). Don't emit empty
  strings or `0` where AWS emits `-` (e.g. ports/bytes on a NODATA record).
- `start`/`end` are **Unix seconds**, not milliseconds and not ISO strings.
- `protocol` is the **IANA number** (6/17/1/58), not `"TCP"`/`"UDP"`.
- `action` is `ACCEPT`/`REJECT` only (uppercase). `log-status` is `OK`/`NODATA`/`SKIPDATA` only.
  `flow-direction` is lowercase `ingress`/`egress`.
- `tcp-flags` is a numeric bitmask, not a flag name. It can be `-` when invalid; don't force 0.
- Don't add fields the format doesn't include (e.g. no `vpc-id`/`region`/`pkt-srcaddr` in a pure v2 record).
  Conversely, if you show v3+ fields, bump `version` to the highest version among the chosen fields.
- Regional NAT gateway flows put `-` in `interface-id`/`instance-id`/`subnet-id` and the id in `resource-id`;
  zonal NAT gateway flows put the id in `interface-id` with `instance-id` = `-`. Don't fill these with a host id.
- **Do not** rename to ECS (`source.ip`, `destination.port`, `network.bytes`) or wrap in a Wazuh envelope.
  Keep the hyphenated AWS field names.
