# Zscaler Internet Access (ZIA) — NSS Web log, JSON feed

Category: Secure Web Gateway / web proxy. Vendor: Zscaler. Native format: NSS feed — a customer-defined output template filled with Zscaler variables; we use the **Zscaler-published JSON feed format** (JSON-native once the template is fixed).
Platform representation: `{"sourcetype":"zscalernss-web","event":{...}}` exactly as the template emits it (all values are strings).

---

## 1. Official sources

| Source | What it confirmed |
|---|---|
| https://help.zscaler.com/zia/nss-feed-output-format-web-logs | Authoritative list of web-log variables (`%s{url}`, `%s{eurl}`, `%s{ehost}`, `%s{cip}`, `%s{cintip}`, `%s{cpubip}`, `%s{login}`, `%s{urlcat}`, `%s{urlsupercat}`, `%s{urlclass}`, `%s{malwarecat}`, `%s{malwareclass}`, `%s{threatname}`, `%d{riskscore}`, `%s{appname}`, `%s{appclass}`, `%s{dlpeng}`, `%s{dlpdict}`, `%d{dlpidentifier}`, `%s{bamd5}`, `%d{reqsize}`, `%d{respsize}`, `%d{totalsize}`, `%d{ctime}`, `%d{stime}`, ...). Page is JS-rendered; variables cross-checked in the two sources below. |
| Zscaler & Splunk Deployment Guide (help.zscaler.com/downloads/zscaler-technology-partners/operations/zscaler-and-splunk-deployment-guide/Zscaler-Splunk-Deployment-Guide-FINAL.pdf), "Web feed" section | **The exact JSON feed template we standardise on**: keys `datetime, reason, event_id, protocol, action, transactionsize, responsesize, requestsize, urlcategory, serverip, clienttranstime, requestmethod, refererURL, useragent, product ("NSS"), location, ClientIP, status, user, url, vendor ("Zscaler"), hostname, clientpublicIP, threatcategory, threatname, filetype, appname, pagerisk, department, urlsupercategory, appclass, dlpengine, urlclass, threatclass, dlpdictionaries, fileclass, bwthrottle, servertranstime, contenttype, ssldecrypted, unscannabletype, md5, deviceowner, devicehostname`, and the variable behind each. Also the tab-separated `key=value` variant of the same names. |
| https://github.com/elastic/integrations/blob/main/packages/zscaler_zia/docs/README.md and `data_stream/web/_dev/test/pipeline/test-web.log` | Zscaler's newer "v11" template (different key names: `cltip`, `cltpubip`, `login`, `urlsubcat`, `urlsupercat`, `respcode`, `rulelabel`, ...) — shows that key names are template-defined. Also value styles: `action` `Allowed`/`Blocked`, `ssldecrypted` `Yes`/`No`, `bwthrottle` `Yes`/`No`. |
| https://help.zscaler.us/zia/release-upgrade-summary-2024 | URL category `AI and ML Applications` renamed to `Generative AI and ML Applications` (Information Technology super-category); `Newly Registered and Observed Domains` category exists. |

## 2. Native format and delivery

- NSS (Nanolog Streaming Service) VM or Cloud NSS streams logs to a SIEM (TCP syslog, or HTTPS for Cloud NSS e.g. Splunk HEC). Feed **Output Type** can be CSV, tab-separated, Splunk CIM, QRadar LEEF, JSON, or Custom. The administrator pastes a template; Zscaler replaces each `%s{var}` / `%d{var}`.
- Keys are therefore **whatever the template says**. We fix the template to the Zscaler-published Splunk JSON web feed (sourcetype `zscalernss-web`). Every value is quoted in that template, so every value is a JSON string.
- `datetime` = `%d{yy}-%02d{mth}-%02d{dd} %02d{hh}:%02d{mm}:%02d{ss}` rendered in the feed's configured timezone (default GMT) -> `"2026-10-01 05:02:11"` (4-digit year rendering of `%d{yy}` UNVERIFIED).
- `url` (`%s{eurl}`) is the URL **without scheme** (`chatgpt.com/backend-api/files`). `e`-prefixed variables are escaped with the feed escape characters.
- Known template quirk: the guide maps `clientpublicIP` to `%s{cintip}` (client *internal* IP variable); the public-IP variable is `%s{cpubip}`. We keep the guide's key name and populate it with the client's public egress IP (as the key name says) — flagged here so nobody "fixes" the key.

## 3. Core field reference (key -> Zscaler variable)

| Key | Variable | Meaning | Values / notes |
|---|---|---|---|
| `datetime` | time parts | Transaction time | `2026-10-01 05:02:11` |
| `reason` | `reason` | Policy reason text | `Allowed`, `Not allowed to browse this category`; malware/DLP block texts vary (e.g. `Virus/Malware detected`, `Blocked by DLP`) — exact strings UNVERIFIED |
| `event_id` | `recordid` | Unique record ID | numeric string |
| `protocol` | `proto` | Protocol | `HTTP`, `HTTPS`, `SSL`, `FTP`, `TUNNEL` |
| `action` | `action` | Policy action | `Allowed`, `Blocked` (also `Caution`/`Isolated` in some policies, UNVERIFIED) |
| `transactionsize` / `requestsize` / `responsesize` | `totalsize` / `reqsize` / `respsize` | Bytes total / client->server (upload) / server->client (download) | |
| `urlcategory` | `urlcat` | URL category | `Generative AI and ML Applications`, `Newly Registered and Observed Domains`, `Web Search`, `Corporate Marketing`, `File Host` / `Online and Cloud Storage` (last two names UNVERIFIED) |
| `urlsupercategory` | `urlsupercat` | Super-category | `Information Technology`, `Miscellaneous`, `Business and Economy`, `Internet Communication`, `Security` |
| `urlclass` | `urlclass` | URL class | `Business Use`, `General Surfing`, `Productivity Loss`, `Bandwidth Loss`, `Legal Liability`, `Privacy Risk`, `Security Risk`, `Advanced Security Risk` |
| `serverip` | `sip` | Destination server IP | |
| `clienttranstime` / `servertranstime` | `ctime` / `stime` | Client-side / server-side transaction time (ms) | |
| `requestmethod` | `reqmethod` | HTTP method | `GET`, `POST`, `PUT`, `CONNECT` |
| `refererURL` | `ereferer` | Referer | `None` when absent |
| `useragent` | `eua` | User-Agent | |
| `product` / `vendor` | literals | Constants | `NSS` / `Zscaler` |
| `location` | `elocation` | ZIA location (office / `Road Warrior`) | |
| `ClientIP` | `cip` | Client IP as seen by ZIA | |
| `clientpublicIP` | see quirk above | Client public egress IP | |
| `status` | `respcode` | HTTP response code | `200`, `403` |
| `user` | `elogin` | User login (UPN) | |
| `url` | `eurl` | URL without scheme | |
| `hostname` | `ehost` | Host header | |
| `threatcategory` | `malwarecat` | Malware category | `None`, `Trojan`, `Virus`, `Adware`, `Spyware`, `Phishing`, `Ransomware` (list UNVERIFIED) |
| `threatname` | `threatname` | Threat/signature name | `None` when clean |
| `threatclass` | `malwareclass` | Threat class | `None`, `Virus`, `Advanced Security`, `Behavioral Analysis` (UNVERIFIED) |
| `filetype` / `fileclass` | `filetype` / `fileclass` | File type / class | `None` when no file |
| `appname` / `appclass` | `appname` / `appclass` | Cloud app / app class | `ChatGPT`, `WeTransfer`; `General Browsing`, `File Sharing`, `AI & ML Applications` (class names UNVERIFIED) |
| `pagerisk` | `riskscore` | Page risk index 0–100 | |
| `department` | `edepartment` | User's department | |
| `dlpengine` / `dlpdictionaries` | `dlpeng` / `dlpdict` | DLP engine / dictionaries hit | `None` when no hit |
| `bwthrottle` | `bwthrottle` | Bandwidth throttled | `Yes` / `No` |
| `contenttype` | `contenttype` | Content-Type | |
| `ssldecrypted` | `ssldecrypted` | TLS inspected | `Yes` / `No` |
| `unscannabletype` | `unscannabletype` | Why content could not be scanned | `None`, `Encrypted File`, `Undetectable File` |
| `md5` | `bamd5` | MD5 of the file (sandbox/AV) | `None` when no file |
| `deviceowner` / `devicehostname` | same | Client Connector device owner / hostname | |

## 4. Realistic samples

### 4.1 Malware download blocked (Trojan executable from a lure site)
```json
{"sourcetype":"zscalernss-web","event":{"datetime":"2026-10-01 06:12:44","reason":"Virus/Malware detected","event_id":"7392018475561029634","protocol":"HTTPS","action":"Blocked","transactionsize":"1843399","responsesize":"1842211","requestsize":"1188","urlcategory":"Miscellaneous or Unknown","serverip":"192.0.2.91","clienttranstime":"412","requestmethod":"GET","refererURL":"https://docs-invoice-share.top/view?id=INV-0931","useragent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36","product":"NSS","location":"Road Warrior","ClientIP":"203.0.113.24","status":"403","user":"dana.levi@nexacorp.co.il","url":"docs-invoice-share.top/download/Invoice_Sept2026.exe","vendor":"Zscaler","hostname":"docs-invoice-share.top","clientpublicIP":"203.0.113.24","threatcategory":"Trojan","threatname":"Win32.Trojan.Agenttesla","filetype":"Windows Executables","appname":"General Browsing","pagerisk":"88","department":"Finance","urlsupercategory":"Miscellaneous","appclass":"General Browsing","dlpengine":"None","urlclass":"Security Risk","threatclass":"Virus","dlpdictionaries":"None","fileclass":"Executable","bwthrottle":"No","servertranstime":"287","contenttype":"application/octet-stream","ssldecrypted":"Yes","unscannabletype":"None","md5":"4b1f9e2a7c0d38e5a6f1b2c3d4e5f607","deviceowner":"dana.levi","devicehostname":"NXC-LT-0412"}}
```
(`reason` text, `filetype`/`fileclass` labels and `threatname` style are UNVERIFIED as exact Zscaler strings.)

### 4.2 Newly registered domain allowed (credential-phishing page impersonating corporate SSO)
```json
{"sourcetype":"zscalernss-web","event":{"datetime":"2026-10-01 06:31:09","reason":"Allowed","event_id":"7392018475561033120","protocol":"HTTPS","action":"Allowed","transactionsize":"48211","responsesize":"46105","requestsize":"2106","urlcategory":"Newly Registered and Observed Domains","serverip":"198.51.100.14","clienttranstime":"96","requestmethod":"POST","refererURL":"https://login-nexacorp-sso.online/auth/","useragent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36","product":"NSS","location":"Road Warrior","ClientIP":"203.0.113.24","status":"200","user":"dana.levi@nexacorp.co.il","url":"login-nexacorp-sso.online/auth/submit.php","vendor":"Zscaler","hostname":"login-nexacorp-sso.online","clientpublicIP":"203.0.113.24","threatcategory":"None","threatname":"None","filetype":"None","appname":"General Browsing","pagerisk":"64","department":"Finance","urlsupercategory":"Miscellaneous","appclass":"General Browsing","dlpengine":"None","urlclass":"Security Risk","threatclass":"None","dlpdictionaries":"None","fileclass":"None","bwthrottle":"No","servertranstime":"71","contenttype":"text/html","ssldecrypted":"Yes","unscannabletype":"None","md5":"None","deviceowner":"dana.levi","devicehostname":"NXC-LT-0412"}}
```

### 4.3 Large upload to a file-sharing service (exfiltration, 2.3 GB request body)
```json
{"sourcetype":"zscalernss-web","event":{"datetime":"2026-10-01 22:47:31","reason":"Allowed","event_id":"7392018475561102877","protocol":"HTTPS","action":"Allowed","transactionsize":"2471094921","responsesize":"1840","requestsize":"2471093081","urlcategory":"File Host","serverip":"192.0.2.177","clienttranstime":"812440","requestmethod":"POST","refererURL":"https://wetransfer.com/","useragent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36","product":"NSS","location":"Road Warrior","ClientIP":"192.0.2.140","status":"200","user":"r.mizrahi@nexacorp.co.il","url":"storm-eu.wetransfer.com/upload/v2/chunk","vendor":"Zscaler","hostname":"storm-eu.wetransfer.com","clientpublicIP":"192.0.2.140","threatcategory":"None","threatname":"None","filetype":"ZIP Files","appname":"WeTransfer","pagerisk":"12","department":"Sales","urlsupercategory":"Internet Communication","appclass":"File Sharing","dlpengine":"None","urlclass":"Bandwidth Loss","threatclass":"None","dlpdictionaries":"None","fileclass":"Archive","bwthrottle":"No","servertranstime":"810201","contenttype":"application/octet-stream","ssldecrypted":"Yes","unscannabletype":"Encrypted File","md5":"None","deviceowner":"r.mizrahi","devicehostname":"NXC-LT-0377"}}
```
(`urlcategory` "File Host", `filetype` "ZIP Files", `fileclass` "Archive" exact labels UNVERIFIED. Note `unscannabletype=Encrypted File` — a password-protected archive, which DLP cannot inspect.)

### 4.4 Document upload to ChatGPT (allowed, no DLP match)
```json
{"sourcetype":"zscalernss-web","event":{"datetime":"2026-10-01 07:58:02","reason":"Allowed","event_id":"7392018475561049915","protocol":"HTTPS","action":"Allowed","transactionsize":"4219844","responsesize":"2210","requestsize":"4217634","urlcategory":"Generative AI and ML Applications","serverip":"198.51.100.120","clienttranstime":"3311","requestmethod":"POST","refererURL":"https://chatgpt.com/","useragent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36","product":"NSS","location":"TLV-HQ","ClientIP":"10.20.31.77","status":"200","user":"oren.katz@nexacorp.co.il","url":"chatgpt.com/backend-api/files","vendor":"Zscaler","hostname":"chatgpt.com","clientpublicIP":"203.0.113.10","threatcategory":"None","threatname":"None","filetype":"Microsoft Excel","appname":"ChatGPT","pagerisk":"5","department":"IT","urlsupercategory":"Information Technology","appclass":"AI & ML Applications","dlpengine":"None","urlclass":"Business Use","threatclass":"None","dlpdictionaries":"None","fileclass":"Document","bwthrottle":"No","servertranstime":"2984","contenttype":"multipart/form-data","ssldecrypted":"Yes","unscannabletype":"None","md5":"None","deviceowner":"okatz","devicehostname":"NXC-WS-1188"}}
```

### 4.5 Upload to ChatGPT blocked by DLP (credit-card numbers in pasted file)
```json
{"sourcetype":"zscalernss-web","event":{"datetime":"2026-10-01 08:14:26","reason":"Blocked by DLP","event_id":"7392018475561052240","protocol":"HTTPS","action":"Blocked","transactionsize":"913477","responsesize":"1622","requestsize":"911855","urlcategory":"Generative AI and ML Applications","serverip":"198.51.100.120","clienttranstime":"640","requestmethod":"POST","refererURL":"https://chatgpt.com/","useragent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36","product":"NSS","location":"TLV-HQ","ClientIP":"10.20.31.52","status":"403","user":"maya.peretz@nexacorp.co.il","url":"chatgpt.com/backend-api/files","vendor":"Zscaler","hostname":"chatgpt.com","clientpublicIP":"203.0.113.10","threatcategory":"None","threatname":"None","filetype":"CSV Files","appname":"ChatGPT","pagerisk":"5","department":"Billing","urlsupercategory":"Information Technology","appclass":"AI & ML Applications","dlpengine":"PCI","urlclass":"Business Use","threatclass":"None","dlpdictionaries":"Credit Cards","fileclass":"Document","bwthrottle":"No","servertranstime":"0","contenttype":"multipart/form-data","ssldecrypted":"Yes","unscannabletype":"None","md5":"None","deviceowner":"mperetz","devicehostname":"NXC-WS-1042"}}
```
(`reason` "Blocked by DLP" exact wording UNVERIFIED.)

## 5. Investigation notes

- **Who:** `user`, `department`, `devicehostname`, `deviceowner`. **From where:** `ClientIP` (internal IP at an office location; for Road Warrior/Client Connector it is the device's egress IP), `clientpublicIP`, `location`.
- **Malware delivery:** `action=Blocked` + `threatname`/`threatcategory`; pivot `md5` to EDR (CrowdStrike `MD5HashData`, Defender `MD5`) and to Sysmon `Hashes` to check whether the file reached disk by another route. Check `refererURL` for the lure page and search other users hitting the same `hostname`.
- **Phishing:** `urlcategory=Newly Registered and Observed Domains` + `requestmethod=POST` + a lookalike `hostname` = likely credential submission -> check IdP sign-ins for the user right after.
- **Exfiltration:** sort by `requestsize` (upload), not `transactionsize`. Large POST/PUT to `appclass=File Sharing` outside business hours, or `unscannabletype=Encrypted File`. Correlate with the VPN/ZTNA session (`clientpublicIP`) and EDR file-archive events (7z/rar creation).
- **GenAI data leakage:** `urlcategory=Generative AI and ML Applications` / `appname=ChatGPT` with POST to `/backend-api/files` or large `requestsize`; `dlpengine`/`dlpdictionaries` show what sensitive data was detected.
- **Firewall correlation:** ZIA is the egress point — the perimeter firewall only sees the GRE/IPsec tunnel or Client Connector traffic to Zscaler, so URL-level detail exists only here. `serverip` can be matched to EDR network events (Sysmon 3 `DestinationIp`) on the endpoint.

## 6. Common mistakes / fields that do NOT exist

- Key names are template-specific: don't mix this template (`ClientIP`, `urlcategory`, `threatcategory`, `pagerisk`) with the v11 template (`cltip`, `urlsubcat`, `malwarecategory`, `riskscore`) or raw variable names (`cip`, `urlcat`) in one log.
- No `src_ip`, `dest_ip`, `bytes_in`, `bytes_out`, `http_method`, `category`, `signature` — those are Splunk CIM aliases created at search time, not feed fields.
- `url` has no `http://` / `https://` prefix; `refererURL` does keep its scheme.
- `requestsize` is upload (client->server), `responsesize` is download; `transactionsize` = both.
- All values are strings in this template (`"403"`, `"88"`), and "empty" is the literal `None` for most text fields.
- ZIA web logs are not ZPA (private-app) logs — no `ConnectionID`, `AppGroup`, `Connector`.
- No Wazuh `data.*` or Elastic `zscaler_zia.web.*` envelope.
