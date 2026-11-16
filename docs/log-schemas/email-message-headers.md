# Internet message headers (RFC 5322) as Exchange Online / EOP stamps them

Category: Email security · Vendor: IETF standard + Microsoft (Exchange Online Protection, Defender for Office 365) · Card version: 2026-11-15
Registry: header fields are admitted for `Microsoft Defender for Office 365` under the existing `email.headers.<Header-Name>` prefix (the shape the graded rooms already use). A lab that shows the header block itself shows text lines, not keys.

Companion card: [email-defender-o365](email-defender-o365.md) (the Advanced Hunting tables that summarise the same message).

## 1. Official sources

| Source | What it confirmed |
|---|---|
| Microsoft, "Anti-spam message headers": https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo (checked 2026-11-15) | `Authentication-Results` syntax and values: `spf=<pass (IP address)\|fail (IP address)\|softfail (reason)\|neutral\|none\|temperror\|permerror> smtp.mailfrom=<domain>`; `dkim=<pass\|fail (reason)\|none> header.d=<domain>`; `dmarc=<pass\|fail\|bestguesspass\|none> action=<…> header.from=<domain>`; `compauth=<pass\|fail\|softpass\|none> reason=<3 digits>`. Examples `spf=pass (sender IP is 192.168.0.1) smtp.mailfrom=contoso.com`, `dkim=pass (signature was verified)`, `dkim=fail (body hash did not verify)`. `action` values include `permerror`, `temperror`, `oreject`, `pct.quarantine`, `pct.reject` (and `none` in the examples). Compauth reason codes (000, 001, 002, 010, 1xx incl. 100-116 and 130, 2xx incl. 201/202, 3xx, 4xx, 501/502, 6xx/601, 7xx, 9xx/905). `X-Forefront-Antispam-Report` fields `ARC`, `CAT` (`AMP`, `BIMP`, `BULK`, `DIMP`, `FTBP`, `GIMP`, `HPHSH`/`HPHISH`, `HSPM`, `INTOS`, `MALW`, `OSPM`, `PHSH`, `SAP`, `SPM`, `SPOOF`, `UIMP`), `CIP`, `CTRY`, `DIR` (`INB`/`OUT`/`INT`), `H`, `IPV` (`CAL`, `NLI`), `LANG`, `PTR`, `SCL`, `SFTY` (9.19, 9.20, 9.25), `SFV` (`BLK`, `NSPM`, `SFE`, `SKA`, `SKB`, `SKI`, `SKN`, `SKQ`, `SKS`, `SPM`), `SRV:BULK`. `X-Microsoft-Antispam` `BCL`. |
| RFC 5322 §3.6 (originator, identification, trace fields): https://www.rfc-editor.org/rfc/rfc5322 and RFC 5321 §4.4 (trace information): https://www.rfc-editor.org/rfc/rfc5321 | `From`, `Sender`, `Reply-To`, `To`, `Cc`, `Subject`, `Date`, `Message-ID`, `In-Reply-To`, `References`; each relay **prepends** a `Received:` line (`from … by … with … id … for …; date`), so the bottom line is the oldest; `Return-Path` is added at final delivery from the envelope `MAIL FROM`. |
| Microsoft, `Get-QuarantineMessage`: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-quarantinemessage (checked 2026-11-15) | Quarantine reasons (`-QuarantineTypes`): `Bulk`, `DataLossPrevention`, `FileTypeBlock`, `HighConfPhish`, `Malware`, `Phish`, `Spam`, `SPOMalware`, `TransportRule`. Policy types: `AntiMalwarePolicy`, `AntiPhishPolicy`, `DataLossPreventionRule`, `ExchangeTransportRule`, `HostedContentFilterPolicy`, `SafeAttachmentPolicy`. Release status values `Approved`, `Denied`, `Error`, `NotReleased`, `PreparingToRelease`, `Released`, `Requested`. Default window 16 days, maximum 30. |

## 2. Native format and delivery

Plain text at the top of the message, one `Name: value` per field, long values folded onto lines starting with whitespace. Where an analyst sees it: Outlook File > Properties > Internet headers (or "View message details"), Defender Explorer > email entity > View header, the `.eml` from a quarantine download. Microsoft's Message Header Analyzer parses it.

Order matters. Every server that accepts the message **adds a `Received:` at the top**, so the block is read **bottom up**: lowest `Received` = earliest hop. Lines below the first `Received` your own service wrote are the sender's claims.

## 3. Core field reference

| Header | Written by | Meaning / trust |
|---|---|---|
| `Received: from <helo> (<rDNS> [<ip>]) by <host> with <protocol> id <id> for <rcpt>; <date>` | each receiving server | The IP in brackets/parentheses is what **that** server saw on the TCP connection: trustworthy only for lines your servers wrote. `with ESMTPSA` = an authenticated client submitted it (a mailbox login). The HELO name is whatever the client claimed |
| `Received: … by <X>.mail.protection.outlook.com (<ip>) with Microsoft SMTP Server (version=TLS1_3, cipher=…) id 15.20.… via Frontend Transport; <date>` | EOP front end | The **border hop**: the `from` IP here is the connecting server (`SenderIPv4` in `EmailEvents`, `CIP:` in `X-Forefront-Antispam-Report`) |
| `Received: from <A>.prod.outlook.com (…) by <B>.prod.outlook.com … with HTTPS` / `with Microsoft SMTP Server` | Exchange Online internal | Hops inside Microsoft's cloud after the border: not investigation evidence |
| `Authentication-Results:` | the receiving service (EOP) | SPF, DKIM, DMARC, compauth verdicts as described in §1 |
| `Authentication-Results-Original:` | EOP when an earlier hop's result is preserved | (seen in hybrid / ARC flows; layout UNVERIFIED) |
| `Return-Path:` | final delivery, from `MAIL FROM` (P1, envelope) | What SPF checks (`smtp.mailfrom`); where bounces go |
| `From:` | the sender's client | P2 address the user sees; what DMARC aligns to (`header.from`) |
| `Reply-To:` | the sender's client | Where answers go; a different domain from `From` is a BEC sign |
| `Message-ID:` | the sending software | Unique id; the domain part is often an internal server name (`@HS-EX01.hollins.local`, `@…prod.outlook.com`): a weak signal only |
| `X-Originating-IP:` | some webmail / submission servers | Client IP that submitted the message; often absent or removed by transport rules (UNVERIFIED for current Exchange Online and Exchange Server builds) |
| `X-Forefront-Antispam-Report:` | EOP | `CIP`, `CTRY`, `H`, `PTR`, `SFV`, `CAT`, `SCL`, `DIR`, `SFTY`, `IPV` |
| `X-Microsoft-Antispam:` | EOP | `BCL:<0-9>` |
| `X-MS-Exchange-Organization-SCL`, `X-MS-Exchange-Organization-AuthAs` | Exchange transport | Spam confidence; `AuthAs` `Anonymous` / `Internal` / `Partner` (meaning of each value UNVERIFIED) |

Compauth reason quick table: `000` explicit fail (DMARC fail with p=quarantine/reject) · `001` implicit fail · `100` SPF or DKIM passed and aligned · `101` DKIM signed by the From domain · `102` SPF passed and aligned · `108` DKIM broken by a legitimate earlier hop · `130` trusted ARC sealer overrode DMARC fail · `2xx` softpass (`201`, `202` PTR alignment) · `601` self-to-self spoof of an accepted domain · `905` complex routing, DMARC not enforced.

## 4. Samples

Supplier message, read bottom up (documentation addresses):

```text
Received: from DB9PR04MB8412.eurprd04.prod.outlook.com (2001:db8:10a6:2c1::9) by AS8PR04MB7765.eurprd04.prod.outlook.com with HTTPS; Tue, 3 Nov 2026 09:14:23 +0000
Received: from DU2PEPF00028D0A.eurprd03.prod.outlook.com (2001:db8:10a6:28::4) by DB9PR04MB8412.eurprd04.prod.outlook.com (2001:db8:10a6:2c1::9) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8114.20; Tue, 3 Nov 2026 09:14:22 +0000
Received: from smtp.fenwick-scaffold.example (198.51.100.25) by DU2PEPF00028D0A.mail.protection.outlook.com (10.167.242.10) with Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8114.14 via Frontend Transport; Tue, 3 Nov 2026 09:14:21 +0000
Received: from [10.8.0.14] (unknown [203.0.113.58]) by smtp.fenwick-scaffold.example (Postfix) with ESMTPSA id 4XkT2m0R1Hz9 for <accounts@rivermead.example>; Tue, 3 Nov 2026 09:14:14 +0000 (GMT)
Authentication-Results: spf=pass (sender IP is 198.51.100.25) smtp.mailfrom=fenwick-scaffold.example; dkim=pass (signature was verified) header.d=fenwick-scaffold.example;dmarc=pass action=none header.from=fenwick-scaffold.example;compauth=pass reason=100
Return-Path: statements@fenwick-scaffold.example
From: Fenwick Accounts <accounts@fenwick-scaffold.example>
```

Spoof of a bank's own domain through a bulk relay:

```text
Authentication-Results: spf=pass (sender IP is 198.51.100.61) smtp.mailfrom=mailpush.example; dkim=none (message not signed) header.d=none;dmarc=fail action=quarantine header.from=northwind-bank.example;compauth=fail reason=000
X-Forefront-Antispam-Report: CIP:198.51.100.61;CTRY:NL;LANG:en;SCL:5;SRV:;IPV:NLI;SFV:SPM;H:relay3.mailpush.example;PTR:relay3.mailpush.example;CAT:SPOOF;SFTY:;DIR:INB;
```

The same message as the graded rooms index it (flat `email.headers.*` keys under `Microsoft Defender for Office 365`):

```json
{
  "email.headers.From": "Northwind Bank Security <security@northwind-bank.example>",
  "email.headers.Return-Path": "<bounce@mailpush.example>",
  "email.headers.Authentication-Results": "spf=pass (sender IP is 198.51.100.61) smtp.mailfrom=mailpush.example; dkim=none (message not signed) header.d=none;dmarc=fail action=quarantine header.from=northwind-bank.example;compauth=fail reason=000"
}
```

## 5. Investigation notes

- Find the border hop first (`… by …mail.protection.outlook.com … via Frontend Transport`): its `from` IP is the last server you can trust, and it equals `SenderIPv4` in `EmailEvents`.
- Everything below the border is the sender's account of events: a bottom `Received` dated hours earlier, or naming a bank server, proves nothing.
- `with ESMTPSA` below the border: someone logged in to a mailbox on the sender's server and submitted the message. The bracketed client IP is the lead to hand to the sender's admin.
- DMARC passes when **either** SPF or DKIM passes **and** its domain aligns with `header.from`. SPF pass for another domain (`smtp.mailfrom=mailpush.example`) does not help `northwind-bank.example`.
- A look-alike domain passes everything: authentication proves who owns the domain, not who the sender pretends to be.
- A compromised real mailbox also passes everything; compare with an older message from the same sender (originating host, `Reply-To`, client IP).
- `spf=temperror` is a DNS failure, `permerror` a broken record (for example more than 10 DNS lookups): neither is proof of spoofing.

## 6. Common mistakes

- Reading `Received` top down, or calling the top line "where it came from".
- Writing `Authentication-Results` with `spf=fail (sender IP is …)` for a softfail, or `dmarc=reject`: DMARC results are `pass`, `fail`, `bestguesspass`, `none`; the policy outcome is in `action=`.
- `compauth=pass reason=000` (000 is a fail code) or `compauth=softpass reason=100` (1xx are pass codes).
- Missing semicolons: Microsoft writes `…header.d=<domain>;dmarc=…` with no space before `dmarc` and `…;compauth=…`.
- Treating `Message-ID` domain mismatch as proof of forgery.
- `X-Originating-IP` on every message: many services never add it or strip it.
- Using `EmailEvents` to read `Reply-To` or `X-Originating-IP`: the table has neither; they live only in the headers.

## 7. UNVERIFIED

- The exact `Received:` wording EOP writes (`with Microsoft SMTP Server (version=…, cipher=…) id 15.20.… via Frontend Transport`) is taken from real messages, not from a Microsoft specification; server names and build ids vary.
- `X-Originating-IP` behaviour in current Exchange Online and Exchange Server 2019 webmail.
- `X-MS-Exchange-Organization-AuthAs` value meanings and `Authentication-Results-Original` layout.
