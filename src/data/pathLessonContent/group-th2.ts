import type { AuthoredPathLesson } from "./types";

/** Authored Learning Path content -- group "th2". Keys: "<pathSlug>--<lessonSlug>". */
export const lessons_th2: Record<string, AuthoredPathLesson> = {
  "threat-hunter--entity-baselining": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What Normal Looks Like: Entity-Centric Hunting",
        "body": "In threat hunting, an **entity** is anything your SIEM (Security Information and Event Management platform) can track as a first-class subject over time: a user account, a host or device, an IP address, a process, or a service principal. Entity-centric hunting means you stop asking \"did anything bad happen anywhere?\" and start asking \"is *this specific entity* behaving differently than it usually does?\"\n\n### The night-shift guard analogy\n\nA night-shift security guard doesn't carry a photo of every possible burglar. Instead, they know the building's rhythms: Bob from accounting never badges in before 7 AM, the loading dock door never opens after 9 PM, and the server room is empty on weekends. When one of those rhythms breaks — Bob badges in at 3 AM — the guard doesn't need a rulebook entry for \"3 AM badge-in is malicious.\" They just need to know what's normal *for Bob*. That personalized sense of normal is a **baseline**.\n\n### Baselines vs. static thresholds\n\nMost detections you have written or will write in this path — including the Sigma rules covered later in this module — are **static-threshold** or **signature-based**: they fire when a specific pattern occurs, regardless of who or what triggered it (a known-bad command line, a specific registry key, a listed malicious IP). Baselining is different: it compares an entity's *current* behavior only to *its own historical* behavior. A login from Country X at 2 AM might be completely normal for a night-shift administrator and wildly anomalous for a 9-to-5 payroll clerk — the exact same raw event, two different verdicts, because the baseline differs per entity.\n\n### Why hunters specifically need this\n\nSignature-based rules catch known-bad patterns. Baselining catches \"quietly weird\" activity that has no signature at all — a hallmark of insider threats, low-and-slow data exfiltration, and living-off-the-land techniques that reuse completely legitimate binaries and therefore never trip a blacklist. This lesson builds baselines using **KQL** (Kusto Query Language), the query language behind Microsoft Sentinel and Azure Data Explorer, which you have already used for joins and aggregations earlier in this module. Here you will extend that foundation with percentile-based statistics to turn \"what happened\" into \"what's abnormal for this entity.\"",
        "keyPoints": [
          "An entity is any first-class subject a SIEM tracks over time: user, host, IP, process, or service principal.",
          "A baseline compares an entity's current behavior to its own history, not to a fixed rule for everyone.",
          "Static-threshold/signature detection catches known-bad patterns; baselining catches unsigned, 'quietly weird' activity.",
          "Insider threats and low-and-slow exfiltration are classic cases signatures miss but baselines can catch."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Picking the Entity and the Metric",
        "body": "Before writing a single line of KQL, a hunter makes two decisions: **which entity type** to baseline, and **which metric** on that entity actually carries signal. Get this wrong and you either drown in noise or miss the behavior you were hunting for.\n\n### Matching entity, metric, and data source\n\n| Entity | Useful metric | Typical data source |\n|---|---|---|\n| User (identity) | sign-ins per hour, distinct countries/day, distinct apps used | `SigninLogs` |\n| Host (device) | process-creation count/hour, distinct parent-child process pairs | `DeviceProcessEvents` |\n| Service account | Kerberos ticket requests/hour, distinct target services | `SecurityEvent` (Event ID 4768/4769) |\n| Application/service principal | OAuth token grants/day, distinct scopes requested | `SigninLogs` (non-interactive sign-ins) |\n\n### Choosing a metric that carries signal\n\nA good baselining metric has **enough natural stability** that a real deviation stands out, but **enough natural variance** that you're not just re-detecting \"it's Monday.\" Sign-in *count* per hour is usually stable for an office worker; sign-in *count* for a batch-processing service account might swing wildly for entirely legitimate reasons (a nightly job that runs 500 times in one hour). In that case, a cardinality metric — like *distinct countries the account signed in from* — is often more stable and more meaningful than a raw count.\n\n### Choosing the time window\n\nThe bucket size you pick shapes what you can see. Hourly bins suit interactive human behavior (login timing, working hours). Daily bins suit slower phenomena like data-volume creep. KQL's `bin()` function rounds a timestamp down to the nearest bucket boundary, which is what lets `summarize` group activity into consistent time windows:\n\n```kql\nSigninLogs\n| where TimeGenerated > ago(30d)\n| extend Hour = bin(TimeGenerated, 1h)\n| summarize SignInCount = count() by UserPrincipalName, Hour\n```\n\nThis produces one row per user per hour — the raw material every baseline in this lesson is built from. Get the entity, metric, and bucket size right here, and the statistics in the next three pages become almost mechanical.",
        "codeExample": "SigninLogs\n| where TimeGenerated > ago(30d)\n| extend Hour = bin(TimeGenerated, 1h)\n| summarize SignInCount = count() by UserPrincipalName, Hour",
        "keyPoints": [
          "Pick the entity type first (user, host, service account), then a metric that matches its natural behavior pattern.",
          "Cardinality metrics (distinct countries, distinct apps) are often more stable than raw counts for bursty/automated entities.",
          "bin() rounds timestamps to a fixed interval so summarize can group activity into consistent buckets.",
          "Bucket size shapes what you can detect: hourly for human interactive behavior, daily for slow volume creep."
        ]
      },
      {
        "pageNumber": 3,
        "title": "The percentile() and percentiles() Functions",
        "body": "Once you have per-entity, per-bucket activity counts, the next step is describing what \"normal\" looks like statistically. KQL's `percentile()` and `percentiles()` aggregation functions are the core tools for this.\n\n### Syntax\n\n`percentile(expr, N)` returns an estimate of the value at the Nth **nearest-rank percentile** of `expr` within each group defined by `summarize ... by`. `percentiles(expr, N1, N2, ...)` computes several percentiles in one pass — more efficient than calling `percentile()` repeatedly, and it returns them as separate columns. A related function, `percentiles_array()`, returns the requested percentiles packed into a single dynamic (array) column instead of multiple columns.\n\n### Why percentile beats mean + standard deviation here\n\nHuman behavior data is usually **skewed**, not symmetric. Most employees log in during a tight 9-to-5 window; a handful of power users or on-call engineers log in at all hours and drag a simple average upward. A mean-and-standard-deviation baseline gets distorted by those outliers before you even start looking for anomalies. Percentiles are far more robust to that skew: the 95th percentile of \"hourly sign-ins\" tells you the value that 95% of a user's normal hours fall below, regardless of how extreme the remaining 5% are.\n\n### Worked example: building a per-user baseline\n\n```kql\nSigninLogs\n| where TimeGenerated > ago(30d)\n| extend Hour = bin(TimeGenerated, 1h)\n| summarize SignInCount = count() by UserPrincipalName, Hour\n| summarize\n    p50 = percentile(SignInCount, 50),\n    p95 = percentile(SignInCount, 95),\n    p99 = percentile(SignInCount, 99)\n  by UserPrincipalName\n```\n\nThis produces one row per user with three columns: the typical hour (p50), the \"busy but still normal\" hour (p95), and the near-ceiling hour (p99) over the past 30 days. A user whose current hourly count blows past their own p99 is doing something they have essentially never done before — a far stronger signal than comparing them to a single hard-coded number that applies to everyone in the tenant.",
        "codeExample": "SigninLogs\n| where TimeGenerated > ago(30d)\n| extend Hour = bin(TimeGenerated, 1h)\n| summarize SignInCount = count() by UserPrincipalName, Hour\n| summarize\n    p50 = percentile(SignInCount, 50),\n    p95 = percentile(SignInCount, 95),\n    p99 = percentile(SignInCount, 99)\n  by UserPrincipalName",
        "keyPoints": [
          "percentile(expr, N) returns the Nth nearest-rank percentile of a value within each summarize group.",
          "percentiles(expr, N1, N2, ...) computes several percentiles in one pass; percentiles_array() packs them into one column.",
          "Percentiles resist the skew that a handful of high-activity outliers cause in a mean/standard-deviation baseline.",
          "A per-user p50/p95/p99 table is the reusable baseline that later comparisons are measured against."
        ]
      },
      {
        "pageNumber": 4,
        "title": "From Percentiles to a Reusable Baseline Table",
        "body": "A one-off percentile query is useful for a single investigation, but a hunting program wants a **standing baseline** it can compare fresh activity against on a recurring basis. Two more KQL building blocks make that practical.\n\n### arg_max(): the latest row per entity\n\n`arg_max(Column, *)` returns, for each group, the entire row that has the maximum value of `Column` — commonly used to grab the *most recent* baseline computation per entity when a baseline is recalculated on a schedule and old versions pile up in a results table:\n\n```kql\nBaselineResults\n| summarize arg_max(ComputedOn, *) by UserPrincipalName\n```\n\nThis keeps exactly one row per user: the newest baseline, discarding stale ones automatically as new computations land.\n\n### dcount() and dcountif(): cardinality-based baselines\n\nNot every useful baseline is a count of events — sometimes the signal is in **how many distinct values** an entity touches. `dcount(expr)` estimates the number of distinct values of `expr` per group; `dcountif(expr, predicate)` restricts that count to rows matching a condition first.\n\n```kql\nSigninLogs\n| where TimeGenerated > ago(30d)\n| summarize\n    DistinctCountries = dcount(tostring(LocationDetails.countryOrRegion)),\n    DistinctFailedCountries = dcountif(tostring(LocationDetails.countryOrRegion), ResultType != \"0\")\n  by UserPrincipalName\n```\n\nA user whose 30-day baseline shows `DistinctCountries = 1` (they only ever sign in from one country) is a far more sensitive population than a globally-traveling sales rep whose baseline is `DistinctCountries = 6`. Applying the *same* fixed threshold (\"alert on 2+ countries\") to both users would either miss the anomaly for the frequent traveler or flag the stable user's second country as a false positive at a totally different severity than it deserves — which is exactly the blind spot per-entity baselining is built to fix.\n\n### Putting the two together\n\nA mature baseline table typically stores, per entity: the percentile thresholds from the previous page, a cardinality baseline like the one above, and the timestamp it was computed — with `arg_max` ensuring downstream queries always join against the freshest version.",
        "codeExample": "SigninLogs\n| where TimeGenerated > ago(30d)\n| summarize\n    DistinctCountries = dcount(tostring(LocationDetails.countryOrRegion)),\n    DistinctFailedCountries = dcountif(tostring(LocationDetails.countryOrRegion), ResultType != \"0\")\n  by UserPrincipalName",
        "keyPoints": [
          "arg_max(Column, *) keeps only the most recent row per entity when a baseline is recomputed on a schedule.",
          "dcount() estimates distinct values per group; dcountif() restricts that count to rows matching a condition.",
          "Cardinality baselines (distinct countries, distinct apps) often reveal risk that a raw activity count hides.",
          "A fixed threshold applied to every entity ignores the fact that 'normal cardinality' varies enormously by role."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Joining Current Activity Against the Baseline",
        "body": "A baseline sitting alone in a table doesn't detect anything — it becomes useful only when fresh activity is compared against it. This is where the `join` operator, already covered earlier in this module, does real hunting work.\n\n### The pattern: two summaries, one join\n\nThe comparison always has the same shape: summarize the **recent window** (for example, the last 24 hours) exactly the way you summarized the baseline window, then `join` the two result sets on the entity key, and compute a deviation.\n\n```kql\nlet Baseline =\n    SigninLogs\n    | where TimeGenerated between (ago(37d) .. ago(7d))\n    | extend Hour = bin(TimeGenerated, 1h)\n    | summarize SignInCount = count() by UserPrincipalName, Hour\n    | summarize p95 = percentile(SignInCount, 95) by UserPrincipalName;\nlet Recent =\n    SigninLogs\n    | where TimeGenerated > ago(24h)\n    | extend Hour = bin(TimeGenerated, 1h)\n    | summarize CurrentCount = count() by UserPrincipalName, Hour;\nRecent\n| join kind=inner Baseline on UserPrincipalName\n| where CurrentCount > (p95 * 2)\n| project UserPrincipalName, Hour, CurrentCount, p95, DeviationRatio = CurrentCount * 1.0 / p95\n| order by DeviationRatio desc\n```\n\n### Reading the query\n\nThe `let` statements build two independent tables in memory: a 30-day baseline window that deliberately ends 7 days before \"now\" (so the most recent week's activity — which might itself be the thing under investigation — never contaminates the baseline it is compared against), and a 24-hour recent window. The `join kind=inner` keeps only users present in both tables, and the `where` clause flags any hour where current activity is more than double the user's own 95th-percentile hour.\n\n### Why the gap between baseline and recent windows matters\n\nIf a user has been quietly escalating their activity for the past two weeks, including those two weeks inside the \"baseline\" would teach the query that the escalation *is* normal — the classic trap of baseline poisoning. Leaving a buffer between the two windows, or explicitly excluding days already under investigation, keeps the comparison honest.",
        "codeExample": "let Baseline =\n    SigninLogs\n    | where TimeGenerated between (ago(37d) .. ago(7d))\n    | extend Hour = bin(TimeGenerated, 1h)\n    | summarize SignInCount = count() by UserPrincipalName, Hour\n    | summarize p95 = percentile(SignInCount, 95) by UserPrincipalName;\nlet Recent =\n    SigninLogs\n    | where TimeGenerated > ago(24h)\n    | extend Hour = bin(TimeGenerated, 1h)\n    | summarize CurrentCount = count() by UserPrincipalName, Hour;\nRecent\n| join kind=inner Baseline on UserPrincipalName\n| where CurrentCount > (p95 * 2)\n| project UserPrincipalName, Hour, CurrentCount, p95, DeviationRatio = CurrentCount * 1.0 / p95\n| order by DeviationRatio desc",
        "keyPoints": [
          "Comparing current activity to a baseline is a summarize-join-summarize pattern using the same entity key on both sides.",
          "join kind=inner keeps only entities present in both the recent window and the baseline window.",
          "Leave a gap between the baseline window and 'now' so recent, possibly-anomalous activity can't poison its own baseline.",
          "A deviation ratio (current / baseline threshold) is easier to triage and rank than a raw pass/fail flag."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Tuning: False Positives and Baseline Drift",
        "body": "A baseline is a snapshot of history, and history changes for reasons that have nothing to do with compromise. A hunting program that doesn't account for this drowns in false positives within weeks.\n\n### Common legitimate causes of baseline breaks\n\n- **Role changes**: a user promoted to admin, or moved to a new team, legitimately starts touching new systems and hours.\n- **New accounts**: a brand-new employee has no real history yet — their first \"normal\" week will look anomalous against an empty or tiny baseline.\n- **Seasonal business cycles**: finance teams spike activity at month-end and quarter-end closes; retail spikes around peak shopping periods.\n- **Infrastructure and org changes**: mergers, tenant migrations, or a new SSO (single sign-on) provider can shift where and how sign-ins originate for an entire population at once.\n- **Daylight saving time and travel**: an hour-bucketed baseline can misread a one-hour clock shift as an activity-timing anomaly twice a year.\n\n### Practical mitigations\n\n| Problem | Mitigation |\n|---|---|\n| New accounts with no history | Apply a grace period (e.g., 14 days) before baseline-driven detections fire for that entity |\n| Baseline goes stale after a role change | Use a rolling window (e.g., trailing 30 days) so old behavior ages out automatically |\n| One-off legitimate spikes (month-end) | Allow a documented exception window rather than permanently loosening the whole rule |\n| Org-wide shifts (M&A, new IdP) | Rebaseline the affected population explicitly rather than waiting for the rolling window to catch up |\n\n### The discipline of documenting exceptions\n\nEvery baseline exception should be written down: which entity, why it's excluded, for how long, and who approved it. An undocumented exception is indistinguishable from a detection gap six months later when nobody remembers why a given account was carved out — and that gap is exactly where a real intrusion likes to hide. A rolling window (recomputing the baseline continuously over a trailing period, as used throughout this lesson with `ago(30d)`) handles ordinary drift automatically; documented exceptions handle the deliberate, known-cause spikes that a rolling window alone can't distinguish from an attack.",
        "keyPoints": [
          "Role changes, new accounts, seasonal cycles, and infrastructure changes all legitimately break baselines.",
          "A rolling (trailing) baseline window ages out old behavior automatically as time moves forward.",
          "New accounts need a grace period before baseline detections apply to them at full sensitivity.",
          "Every manual baseline exception should be documented with entity, reason, duration, and approver."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Analyst Workflow: From Deviation to Verdict",
        "body": "A baseline breach is a **lead**, not a conclusion. The KQL in this lesson tells you an entity did something statistically unusual; it does not tell you whether that's a compromised account or a legitimate business change. Converting a deviation into a verdict is an analyst workflow, not a query.\n\n### The questions a hunter asks at the breach\n\n- Is there a business explanation? (a new project, a announced role change, a scheduled migration)\n- Does the deviation correlate with anything else? (a new device, a new IP range, a password reset just before the spike, a helpdesk ticket)\n- Is the deviation isolated to one metric, or does it show up across several independent baselines for the same entity? (a single metric breach is weaker evidence than three unrelated metrics breaking at once)\n- Can the activity be reproduced or explained by the account owner directly?\n\n### From lead to documented outcome\n\nEvery lead a hunter opens should end in one of a small set of documented verdicts: **true positive** (the deviation reflects real malicious or policy-violating activity), **false positive** (the deviation is an artifact of the detection logic itself — a bad query, a bad baseline window), **benign** (the deviation is real but has a legitimate, verified explanation), or **undetermined** (insufficient evidence either way, tracked for follow-up). Recording which one applies — and why — is what turns a one-off KQL result into an auditable hunting program instead of a pile of unresolved alerts.\n\n### Workflow diagram\n\nThe following flow captures how a single baseline breach moves through triage to a recorded verdict:",
        "codeExample": "flowchart TD\n    A[Baseline breach detected] --> B{Business explanation exists?}\n    B -- Yes, verified --> C[Verdict: Benign]\n    B -- No --> D[Corroborate: other data sources]\n    D --> E{Other independent signals also breach?}\n    E -- Yes --> F[Open hunt lead / hypothesis]\n    E -- No --> G[Verdict: Undetermined - monitor]\n    F --> H[Pivot: entity -> host -> process -> hash]\n    H --> I{Malicious activity confirmed?}\n    I -- Yes --> J[Verdict: True positive]\n    I -- No, query/baseline flawed --> K[Verdict: False positive - tune baseline]",
        "keyPoints": [
          "A statistical deviation is a lead, not proof — it must be corroborated before a verdict is assigned.",
          "Multiple independent baseline breaches on the same entity are stronger evidence than a single metric breaking.",
          "Standard verdicts (true positive, false positive, benign, undetermined) turn hunt leads into auditable outcomes.",
          "Pivoting from entity to host to process to hash is how a corroborated lead becomes a confirmed finding."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked Case Study: The Quiet Finance Analyst",
        "body": "Bringing every piece of this lesson together against a single scenario shows how the parts fit into one hunt.\n\n### The setup\n\nAt the fictional company **NexaCorp**, a finance analyst's account has a 30-day baseline (computed with the exact percentile and cardinality queries from earlier in this lesson) showing `DistinctCountries = 1` and an hourly sign-in `p95` of 3. One Tuesday, the same account signs in from three different countries within a six-hour window, and the OAuth refresh token used for the third sign-in was originally issued during the first session — a pattern consistent with **token replay** rather than three independent legitimate logins. This maps to MITRE ATT&CK **T1078.004 (Valid Accounts: Cloud Accounts)**, which ATT&CK associates with the Initial Access, Persistence, Privilege Escalation, and Defense Evasion tactics — because a stolen cloud credential or token can be reused to achieve any of them without ever touching a traditional malware sample.\n\n### The chain, end to end\n\n```kql\nlet Baseline =\n    SigninLogs\n    | where TimeGenerated between (ago(37d) .. ago(7d))\n    | summarize DistinctCountries = dcount(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName;\nlet RecentActivity =\n    SigninLogs\n    | where TimeGenerated > ago(24h)\n    | where UserPrincipalName == \"j.rivera@nexacorp.example\"\n    | project TimeGenerated, UserPrincipalName, IPAddress,\n              Country = tostring(LocationDetails.countryOrRegion), AppDisplayName, ResultType;\nRecentActivity\n| join kind=inner Baseline on UserPrincipalName\n| summarize TodayDistinctCountries = dcount(Country), Baseline = any(DistinctCountries) by UserPrincipalName\n| where TodayDistinctCountries > Baseline\n```\n\n### Why the baseline mattered here\n\nA static rule of \"alert on any sign-in from a new country\" would have fired for this account exactly as often as for a globally-traveling sales rep — either drowning the SOC in noise for travelers, or (if tuned down to avoid that noise) missing this analyst entirely. Because the baseline was per-entity, three countries in six hours was measured against *this specific account's* near-zero cardinality history, producing a high-confidence lead instead of a coin-flip. The analyst pivots next: check the device ID and IP ranges behind each sign-in, check whether a phishing-style consent grant or a leaked token preceded the spike, and only then record the verdict.",
        "codeExample": "let Baseline =\n    SigninLogs\n    | where TimeGenerated between (ago(37d) .. ago(7d))\n    | summarize DistinctCountries = dcount(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName;\nlet RecentActivity =\n    SigninLogs\n    | where TimeGenerated > ago(24h)\n    | where UserPrincipalName == \"j.rivera@nexacorp.example\"\n    | project TimeGenerated, UserPrincipalName, IPAddress,\n              Country = tostring(LocationDetails.countryOrRegion), AppDisplayName, ResultType;\nRecentActivity\n| join kind=inner Baseline on UserPrincipalName\n| summarize TodayDistinctCountries = dcount(Country), Baseline = any(DistinctCountries) by UserPrincipalName\n| where TodayDistinctCountries > Baseline",
        "keyPoints": [
          "T1078.004 (Valid Accounts: Cloud Accounts) covers stolen or reused cloud credentials and tokens.",
          "ATT&CK maps T1078.004 to Initial Access, Persistence, Privilege Escalation, and Defense Evasion tactics.",
          "A per-entity cardinality baseline turns 'three countries in six hours' into a high-confidence lead for a low-travel account.",
          "The same raw event would be low-signal noise for a naturally high-cardinality entity like a frequent traveler."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A hunter wants to baseline a service account that runs a nightly batch job hundreds of times in a single hour, purely for legitimate reasons. Why would a raw sign-in count metric be a poor baseline choice here, compared to a cardinality metric like distinct countries?",
        "options": [
          {
            "label": "Bursty automated entities produce widely varying raw counts, so a legitimate spike looks like an anomaly, while distinct-country cardinality tends to stay stable",
            "value": "a"
          },
          {
            "label": "KQL's count() aggregation only accepts interactive human sign-in rows and errors out on any service or application identity",
            "value": "b"
          },
          {
            "label": "Cardinality functions such as dcount() always execute faster than count() in Kusto, regardless of table size or data shape",
            "value": "c"
          },
          {
            "label": "SignInCount is a reserved field name that cannot be applied to service principal or application identity telemetry",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The lesson explains that raw counts on bursty/automated entities have high natural variance, so a legitimate spike is indistinguishable from an anomaly, whereas a cardinality metric like distinct countries usually stays stable and carries clearer signal for that entity type. The other options misstate KQL capabilities."
      },
      {
        "question": "Why does the lesson recommend percentile() over a mean-and-standard-deviation baseline for human sign-in behavior?",
        "options": [
          {
            "label": "percentile() resists the skew that a few high-activity outliers, like power users or on-call staff, introduce into a plain average",
            "value": "b"
          },
          {
            "label": "Standard deviation cannot be calculated at all inside the Kusto Query Language, on any numeric column",
            "value": "a"
          },
          {
            "label": "percentile() always needs far fewer rows of input data than computing an average over the same column",
            "value": "c"
          },
          {
            "label": "Mean and standard deviation functions only accept string-typed fields, never numeric sign-in counts",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "Human sign-in data is typically skewed, and a small number of outliers can drag a mean far from what's typical; percentiles describe the distribution without being distorted the same way. KQL fully supports standard deviation via avg()/stdev(); the claim that it can't be calculated is false, as are the other distractors."
      },
      {
        "question": "In the join-based comparison pattern from this lesson, why is a gap deliberately left between the end of the baseline window and the start of the recent window (e.g., baseline ending 7 days ago instead of 'now')?",
        "options": [
          {
            "label": "So recent, possibly-anomalous activity can't be absorbed into the baseline and teach the query that the anomaly is normal",
            "value": "c"
          },
          {
            "label": "Because the KQL join operator fails outright whenever two time windows overlap even slightly",
            "value": "a"
          },
          {
            "label": "To reduce the total number of columns that the summarize operator is allowed to return",
            "value": "b"
          },
          {
            "label": "Because the ago() function cannot accept two different duration values within one query",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The lesson calls this out directly: including very recent (possibly compromised) activity in the baseline window would poison the baseline, hiding the very anomaly the hunt is looking for. join does not require non-overlapping windows, and ago() can be called with any number of different durations in one query."
      },
      {
        "question": "A hunter's baseline-driven detection starts flagging an employee heavily every day for two weeks after that employee is promoted to a new role with broader system access. What is the most appropriate response described in the lesson?",
        "options": [
          {
            "label": "Treat it as expected drift from the role change, and rebaseline the account or log a documented, time-bound exception instead of loosening the rule globally",
            "value": "d"
          },
          {
            "label": "Disable baseline-driven hunting across the entire organization until the flagging eventually stops on its own",
            "value": "a"
          },
          {
            "label": "Assume without any further corroboration that the account is compromised and disable it immediately",
            "value": "b"
          },
          {
            "label": "Permanently remove the sign-in count metric from every future baseline computed company-wide",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "The lesson lists role changes as a common, legitimate cause of baseline drift and recommends rebaselining the affected entity or logging a documented exception — not disabling detection broadly, jumping straight to containment without corroboration, or discarding a useful metric entirely."
      },
      {
        "question": "In the worked case study, why does the baseline make the finding of 'three countries in six hours' a high-confidence lead for this specific finance analyst, when a fixed company-wide rule would not have worked as well?",
        "options": [
          {
            "label": "The account's own history showed near-zero country cardinality, so the jump is unusual for this account, while a fixed rule would treat a frequent traveler identically",
            "value": "a"
          },
          {
            "label": "MITRE ATT&CK formally requires every Valid Accounts detection to be built on a per-entity baseline query",
            "value": "b"
          },
          {
            "label": "A fixed, company-wide rule is technically incapable of querying the SigninLogs table at all in Sentinel",
            "value": "c"
          },
          {
            "label": "OAuth refresh tokens are only ever visible inside per-entity baseline queries, never in any static detection rule",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The case study explains that a static, one-size-fits-all rule produces either noise for travelers or missed detections for low-travel accounts, while a per-entity baseline measures the deviation against that specific account's own history. ATT&CK does not mandate any particular detection method, and SigninLogs/OAuth tokens are equally queryable by static rules."
      }
    ]
  },
  "threat-hunter--time-series-analysis": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why Hunters Think in Time Series",
        "body": "A **time series** is simply an ordered sequence of values indexed by time — a metric measured again and again at regular intervals. The previous lesson's percentile baselines looked at single-point snapshots (this hour's count vs. a 30-day p95). Time series analysis instead studies the **shape** of an entity's behavior across many consecutive points: is it rising, falling, cyclical, or does it have a sudden break in its pattern?\n\n### The heart monitor analogy\n\nA hospital heart monitor doesn't just check \"is the heart rate above 200 bpm?\" A trained nurse watches the *shape* of the waveform — a sudden departure from this specific patient's own steady rhythm is what actually triggers concern, even if the raw number never crosses a fixed threshold. A patient's baseline resting rate might be 55 bpm or 95 bpm; what matters is a break from *their* pattern, not a break from an arbitrary number that applies to every patient.\n\n### Single-point thresholds vs. sequence-aware detection\n\nA single-point check (this lesson's predecessor: \"is this hour's count above p95?\") can catch a sudden spike but is blind to slower, cumulative changes — a value creeping up 5% a day for three weeks never crosses any single-point threshold, yet the cumulative drift over that time is exactly the kind of behavior that matters for **beaconing** malware maintaining regular command-and-control (C2) check-ins, or slow-drip data exfiltration designed specifically to stay under any one-shot alert.\n\n### The KQL time-series toolchain\n\nKQL has a native time-series engine built around three functions used together in sequence: `make-series` (turns raw event rows into an evenly-spaced numeric series per entity), `series_decompose()` (splits that series into seasonal, trend, and residual components), and `series_decompose_anomalies()` / `series_decompose_forecast()` (use that decomposition to flag outliers or project future values). The rest of this lesson builds up that pipeline one function at a time, then applies it to two concrete hunting scenarios.",
        "codeExample": "flowchart LR\n    A[Raw event rows] --> B[make-series: evenly-spaced numeric array per entity]\n    B --> C[series_decompose: seasonal + trend + residual + baseline]\n    C --> D[series_decompose_anomalies: flag outlier points]\n    C --> E[series_decompose_forecast: extrapolate future values]",
        "keyPoints": [
          "A time series is an ordered sequence of measurements at regular time intervals for a single entity or metric.",
          "Time series analysis studies the shape of behavior (trend, cycle, sudden break) across many points, not one snapshot.",
          "Single-point thresholds miss slow, cumulative drift — exactly the pattern behind beaconing C2 and slow-drip exfiltration.",
          "KQL's native pipeline is make-series -> series_decompose() -> series_decompose_anomalies()/series_decompose_forecast()."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Building a Series with make-series",
        "body": "Everything in this lesson depends on first turning raw, irregularly-timed event rows into an evenly-spaced numeric array — that conversion is what the `make-series` operator does.\n\n### Syntax\n\n```\nTableName\n| make-series <agg>=<function>(<column>) on <TimeColumn> from <start> to <end> step <interval> by <dimension>\n```\n\n`from`/`to`/`step` define the exact time grid the series will be built on, and `by` splits the result into one series per distinct value of the dimension (per host, per user, per source IP). A key behavior to know: buckets in the requested range with no matching rows are **filled with zero by default** rather than dropped — which matters, because a gap silently disappearing from your data would make a real lull in activity invisible to every downstream function.\n\n### Worked example: process-creation volume per host\n\n```kql\nlet min_t = ago(14d);\nlet max_t = now();\nlet dt = 2h;\nDeviceProcessEvents\n| make-series ProcessCount = count() on Timestamp from min_t to max_t step dt by DeviceName\n```\n\nThis produces one row per `DeviceName`, with two array-valued columns: one holding the sequence of timestamps (every 2 hours from 14 days ago to now) and one holding the matching process-creation counts — the exact input shape every function on the following pages expects.\n\n### Choosing the step size\n\nThe step size is the same tradeoff seen in entity baselining's bucket size, but now it also controls how many points feed the decomposition: too coarse (a 1-day step) can smooth away short-lived beaconing behavior; too fine (a 1-minute step) generates a huge, noisy array and can make legitimate seasonality (like an hourly cron job) statistically indistinguishable from noise. A 1–2 hour step is a common starting point for endpoint and identity telemetry, adjusted per data source volume.",
        "codeExample": "let min_t = ago(14d);\nlet max_t = now();\nlet dt = 2h;\nDeviceProcessEvents\n| make-series ProcessCount = count() on Timestamp from min_t to max_t step dt by DeviceName",
        "keyPoints": [
          "make-series converts raw event rows into an evenly-spaced numeric array per entity, defined by from/to/step/by.",
          "Buckets with no matching events are filled with zero by default rather than silently dropped.",
          "The output is array-valued columns (one timestamp array, one value array) per distinct value of the 'by' dimension.",
          "Step size trades off smoothing short-lived patterns away vs. generating noisy, hard-to-decompose series."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Decomposing the Series: series_decompose()",
        "body": "A raw series — even a clean one from `make-series` — mixes together several different signals at once: a repeating daily or weekly pattern, a slow overall drift, and random noise. `series_decompose()` separates those signals so each can be examined on its own.\n\n### What it returns\n\n`series_decompose()` decomposes a series into four components, most commonly extracted together using tuple assignment:\n\n```kql\n| extend (baseline, seasonal, trend, residual) = series_decompose(ProcessCount)\n```\n\n- **seasonal** — the repeating pattern the algorithm automatically detects (e.g., a daily cycle of office-hours activity).\n- **trend** — the slow-moving underlying direction once the seasonal pattern is removed (e.g., a gradual week-over-week rise).\n- **residual** — whatever is left after removing both seasonal and trend; this is where genuine anomalies live, because it should look like structureless noise if the model fits well.\n- **baseline** — seasonal + trend added back together, i.e. \"what this series is expected to look like\" at each point, ignoring noise.\n\n### Worked example\n\n```kql\nlet min_t = ago(14d);\nlet max_t = now();\nlet dt = 2h;\nDeviceProcessEvents\n| make-series ProcessCount = count() on Timestamp from min_t to max_t step dt by DeviceName\n| where DeviceName == \"nexacorp-fin-ws07.nexacorp.example\"\n| extend (baseline, seasonal, trend, residual) = series_decompose(ProcessCount)\n| render timechart with(title=\"Process creation decomposition\", ysplit=panels)\n```\n\n### Why decomposition matters for hunting\n\nWithout decomposition, a host that always spikes at 9 AM every workday would look \"anomalous\" to a naive threshold every single morning — a textbook source of alert fatigue. By isolating that 9 AM spike into the **seasonal** component, the **residual** component is left clean enough that a genuine anomaly (a process burst at 3 AM that has no seasonal explanation) actually stands out instead of being buried under recurring, entirely normal daily noise.",
        "codeExample": "let min_t = ago(14d);\nlet max_t = now();\nlet dt = 2h;\nDeviceProcessEvents\n| make-series ProcessCount = count() on Timestamp from min_t to max_t step dt by DeviceName\n| where DeviceName == \"nexacorp-fin-ws07.nexacorp.example\"\n| extend (baseline, seasonal, trend, residual) = series_decompose(ProcessCount)\n| render timechart with(title=\"Process creation decomposition\", ysplit=panels)",
        "keyPoints": [
          "series_decompose() splits a series into seasonal, trend, residual, and baseline (seasonal+trend) components.",
          "The seasonal component isolates recurring, expected patterns like daily office-hours cycles.",
          "The residual component should look like structureless noise; real anomalies stand out there once seasonality is removed.",
          "Decomposition prevents recurring, entirely normal patterns from repeatedly triggering naive threshold alerts."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Finding Anomalies: series_decompose_anomalies()",
        "body": "Once a series is decomposed, the natural next question is: which points in the residual are statistically unusual? `series_decompose_anomalies()` answers that directly, without requiring a separate manual step.\n\n### How it works\n\n`series_decompose_anomalies()` internally calls `series_decompose()` to build the same seasonal/trend/residual model from the previous page, then runs `series_outliers()` on the residual component. `series_outliers()` scores each residual point using **Tukey's fence test**, a classic statistical outlier method based on the interquartile range. Scores above 1.5 or below -1.5 indicate a **mild** anomaly (rise or decline respectively); scores above 3.0 or below -3.0 indicate a **strong** anomaly.\n\n### Syntax and worked example\n\n```kql\nlet min_t = ago(14d);\nlet max_t = now();\nlet dt = 2h;\nDeviceProcessEvents\n| make-series ProcessCount = count() on Timestamp from min_t to max_t step dt by DeviceName\n| where DeviceName == \"nexacorp-fin-ws07.nexacorp.example\"\n| extend (anomalies, score, baseline) = series_decompose_anomalies(ProcessCount, 1.5, -1, \"linefit\")\n| render anomalychart with(anomalycolumns=anomalies, title=\"Process creation anomalies\")\n```\n\nThe parameters after the series column are, in order: the anomaly **threshold** (1.5 here, meaning \"flag mild anomalies and above\"), the **seasonality** period (`-1` requests automatic detection rather than a fixed period), and the **trend** model to use (`\"linefit\"` fits a straight-line trend). The function returns three arrays: `anomalies` (a flag per point, positive for a rise, negative for a decline, zero otherwise), `score` (the underlying Tukey's fence score), and `baseline` (the expected value at each point).\n\n### Reading the score, not just the flag\n\nA hunter should look at the `score` array, not only the binary `anomalies` flag: a point scoring 1.6 is a candidate worth a quick glance during routine review, while a point scoring 4.2 warrants immediate triage. Treating every flagged point identically throws away exactly the prioritization information the score was computed to provide.",
        "codeExample": "let min_t = ago(14d);\nlet max_t = now();\nlet dt = 2h;\nDeviceProcessEvents\n| make-series ProcessCount = count() on Timestamp from min_t to max_t step dt by DeviceName\n| where DeviceName == \"nexacorp-fin-ws07.nexacorp.example\"\n| extend (anomalies, score, baseline) = series_decompose_anomalies(ProcessCount, 1.5, -1, \"linefit\")\n| render anomalychart with(anomalycolumns=anomalies, title=\"Process creation anomalies\")",
        "keyPoints": [
          "series_decompose_anomalies() builds the decomposition model, then scores residual points with series_outliers().",
          "Scoring uses Tukey's fence test: |score| above 1.5 is a mild anomaly, above 3.0 is a strong anomaly.",
          "Function parameters (in order) are threshold, seasonality (-1 for auto-detect), and trend model (e.g. linefit).",
          "Use the numeric score to prioritize triage, not just the binary anomalies flag."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Forecasting and Sliding Windows: series_decompose_forecast()",
        "body": "Anomaly detection looks backward at points that already happened. `series_decompose_forecast()` looks forward: it extrapolates the seasonal and trend components into the future to predict what an entity's normal activity *should* look like, which is useful both for capacity planning and for setting expectations before an anomaly even occurs.\n\n### Syntax and worked example\n\n```kql\nlet min_t = ago(14d);\nlet max_t = now();\nlet dt = 2h;\nlet horizon = 3d;\nDeviceProcessEvents\n| make-series ProcessCount = count() on Timestamp from min_t to max_t+horizon step dt by DeviceName\n| where DeviceName == \"nexacorp-fin-ws07.nexacorp.example\"\n| extend forecast = series_decompose_forecast(ProcessCount, toint(horizon / dt))\n| render timechart with(title=\"3-day process creation forecast\")\n```\n\nThe second argument to `series_decompose_forecast()` is the number of future points to predict, calculated here as the forecast horizon divided by the step size (`toint(horizon / dt)`) — the same pattern used in Microsoft's own Kusto documentation for this function.\n\n### The sliding window concept\n\nA **sliding window** means the entire `make-series` computation is re-run on a moving lookback period — for example, always \"the trailing 14 days\" — refreshed on a schedule (hourly, or on every new batch of ingested events) rather than computed once against a fixed historical range. This is what lets a hunting program catch emerging drift continuously: as each new bucket of data arrives, the oldest bucket ages out of the window, the decomposition recomputes, and a change that was too small to flag yesterday can cross the anomaly threshold today as more of the drift accumulates inside the window.\n\n### Why this matters for slow-moving threats\n\nA fixed one-time baseline computed on January data and never refreshed will eventually be comparing October's activity to a nine-month-old snapshot of \"normal\" — by then, almost anything looks either anomalous or, worse, an attacker's slow escalation has become the new normal without ever being flagged. A sliding window keeps the comparison point recent enough to still be meaningful, while still requiring a real, sustained deviation (not just one noisy bucket) to cross the threshold.",
        "codeExample": "let min_t = ago(14d);\nlet max_t = now();\nlet dt = 2h;\nlet horizon = 3d;\nDeviceProcessEvents\n| make-series ProcessCount = count() on Timestamp from min_t to max_t+horizon step dt by DeviceName\n| where DeviceName == \"nexacorp-fin-ws07.nexacorp.example\"\n| extend forecast = series_decompose_forecast(ProcessCount, toint(horizon / dt))\n| render timechart with(title=\"3-day process creation forecast\")",
        "keyPoints": [
          "series_decompose_forecast() extrapolates the seasonal and trend components to predict future values.",
          "Its second argument is the number of future points to generate, typically horizon divided by step size.",
          "A sliding window recomputes make-series on a moving lookback period, refreshed on a schedule.",
          "Sliding windows let slow, accumulating drift eventually cross the anomaly threshold instead of being permanently hidden."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Reading the Chart Like an Analyst",
        "body": "KQL's time-series functions are built to pair with `render`, and reading those rendered charts correctly is as much a skill as writing the query.\n\n### The render statements\n\n`render timechart with(ysplit=panels)` after a `series_decompose()` extend draws the original series alongside separate panels for its seasonal, trend, and residual components — useful for understanding *why* the model produced the numbers it did. `render anomalychart with(anomalycolumns=anomalies)` after `series_decompose_anomalies()` overlays the flagged anomalous points directly on top of the original series as distinct markers, which is the faster view for day-to-day triage once you already trust the model.\n\n### Recognizing a decomposition artifact vs. a real anomaly\n\nNot every flagged point is a genuine finding. A one-time company holiday, an unannounced maintenance window, or a single missing hour of log ingestion can all produce a residual spike that the algorithm has no way to know is explainable. Before escalating a flagged anomaly, an analyst should check: does the timing line up with a known change-management event, a holiday calendar, or a monitoring outage? If so, this is very likely a **decomposition artifact**, not a threat — but it should still be logged as a false positive against a specific known cause, the same discipline covered in the baseline-tuning lesson.\n\n### Minimum data and seasonality detection failures\n\n`series_decompose()` needs enough historical points to reliably detect a repeating pattern; `series_periods_detect()` runs under the hood to find that period automatically when seasonality is set to `-1`. With too few periods of history (for example, only three days of data for a weekly cycle), automatic seasonality detection can fail to find the real pattern, and the decomposition falls back to treating normal weekly variation as trend or residual — which inflates false positives. As a rule of thumb, request at least several full cycles of the expected period (multiple weeks of history for a weekly pattern) before trusting automatic seasonality detection on a new series.",
        "keyPoints": [
          "render timechart with ysplit=panels shows the full decomposition; render anomalychart overlays flagged points for triage.",
          "Known events (holidays, maintenance windows, ingestion outages) can produce artifacts that look like anomalies but aren't.",
          "Automatic seasonality detection (seasonality=-1) needs several full cycles of history to reliably find the real pattern.",
          "Too little history causes decomposition to misattribute normal cyclical variation to trend or residual, inflating false positives."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Hunting Applications: Beaconing and Slow Exfiltration",
        "body": "Time-series decomposition is not an academic exercise — it directly targets two classic patterns that fixed-threshold rules struggle with.\n\n### Detecting C2 beaconing through periodicity\n\nMalware maintaining command-and-control (C2) communication often \"beacons\" — sends small outbound connections back to an attacker's infrastructure at a near-fixed interval to check for new instructions. This maps to MITRE ATT&CK **T1071 (Application Layer Protocol)**, under the Command and Control tactic, since the beacon typically rides over a legitimate-looking protocol like HTTPS or DNS specifically to blend in with normal traffic.\n\nBeaconing's defining trait is *regularity*: a legitimate user's outbound web traffic is bursty and irregular, while a beacon fires every N seconds or minutes with only small jitter. Running `series_decompose()` on per-host outbound-connection-count series and inspecting whether `series_periods_detect()` finds a strong, short period (minutes, not the expected daily/weekly business cycle) is a direct way to surface this pattern — a host beaconing every 300 seconds shows up as a tight, short-period seasonal component that has no legitimate business-hours explanation.\n\n### Detecting slow-drip exfiltration through trend\n\nWhere beaconing shows up in the **seasonal** component, gradual data exfiltration shows up in the **trend** component. An attacker moving data out slowly — deliberately staying under any single-hour volume threshold — produces a steadily rising trend line in outbound byte volume per user or host that a one-shot threshold check would never catch, because no individual hour looks extreme on its own. This maps to MITRE ATT&CK **T1041 (Exfiltration Over C2 Channel)**, under the Exfiltration tactic, when the stolen data rides the same channel as the attacker's C2 traffic — the same connection a beaconing detection might already be watching.\n\n### Combining both signals\n\nA host showing both a short-period seasonal beacon *and* a rising trend in the volume of those same connections is a materially stronger lead than either signal alone — exactly the kind of corroboration the previous lesson's analyst workflow calls for before opening a hunt hypothesis.",
        "keyPoints": [
          "T1071 (Application Layer Protocol) covers C2 traffic riding over legitimate-looking protocols like HTTPS or DNS, under the Command and Control tactic.",
          "Beaconing shows up as a tight, short-period seasonal component with little business-hours explanation.",
          "T1041 (Exfiltration Over C2 Channel) covers data theft over an existing C2 channel, under the Exfiltration tactic.",
          "Slow-drip exfiltration shows up as a rising trend component that no single-hour threshold would ever flag alone."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Limitations and Combining With Entity Baselines",
        "body": "Time-series decomposition is a powerful tool, but it is not a universal replacement for the percentile-based entity baselining covered earlier in this module — each approach has a domain where it works best.\n\n### When decomposition struggles\n\nDecomposition assumes there is enough regular, periodic structure in the data for `series_periods_detect()` to find a real seasonal pattern. That assumption breaks down for **sparse or irregular entities**: a service account that authenticates once a week at an unpredictable time, or a rarely-used administrative host, simply doesn't generate a dense enough series for seasonal/trend/residual decomposition to be meaningful. Forcing decomposition onto a mostly-empty series tends to produce noisy, low-confidence results — exactly the entities where the simpler percentile-based approach from the earlier lesson is the better tool, because it makes no assumption about periodicity at all.\n\n### A practical division of labor\n\n| Entity behavior pattern | Better-suited technique |\n|---|---|\n| Dense, regularly active (daily logins, hourly process activity) | Time-series decomposition (this lesson) |\n| Sparse, irregular activity (rare admin accounts, occasional batch jobs) | Percentile-based baselining (previous lesson) |\n| Need to detect a *sudden* single-point spike | Either — percentile p95/p99 comparison is simpler and sufficient |\n| Need to detect a *slow, cumulative* drift | Time-series trend component specifically |\n\n### Corroborating across both techniques\n\nThe strongest hunting leads combine independent signals: a time-series anomaly score flagging a host's connection pattern, corroborated by that same host's process-creation count also breaching its percentile baseline, is far more convincing than either alone — precisely the \"do multiple independent signals agree?\" question from the analyst workflow covered earlier in this module.\n\n### Where this leads next\n\nOnce a hunt using either technique confirms a real, repeatable pattern — not a one-off, but something you'd want to catch automatically every time it recurs — the next step is turning that finding into a standing detection. The following lessons in this module show how to express that pattern portably as a **Sigma rule**, so it survives beyond one hunter's personal KQL query and can run against any SIEM the organization uses.",
        "keyPoints": [
          "Time-series decomposition needs enough regular, periodic activity to find a meaningful seasonal pattern.",
          "Sparse or irregular entities are better served by the percentile-based baselining from the previous lesson.",
          "Time-series trend components are specifically suited to catching slow, cumulative drift that single-point checks miss.",
          "A confirmed, repeatable hunt finding should be turned into a portable Sigma rule, covered in the next lessons."
        ]
      }
    ],
    "quiz": [
      {
        "question": "Why can a single-point threshold check (comparing this hour's count to a fixed p95) fail to catch a slow-drip data exfiltration campaign that grows outbound volume by 5% each day for three weeks?",
        "options": [
          {
            "label": "No individual hour's value crosses the fixed threshold on its own, even though the cumulative trend across the full three weeks is highly abnormal",
            "value": "b"
          },
          {
            "label": "The where operator in KQL is fundamentally unable to filter on any numeric column comparison at all",
            "value": "a"
          },
          {
            "label": "The percentile() aggregation function can only ever be recomputed once per full calendar month",
            "value": "c"
          },
          {
            "label": "Outbound byte volume is simply not a field that appears in any Microsoft security telemetry table",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson explains that gradual, cumulative drift never produces a single extreme point, so a one-shot threshold comparison never fires — the trend component of a time-series decomposition is specifically designed to catch this instead. The other options misstate basic KQL capabilities."
      },
      {
        "question": "In a make-series query with from/to/step, what happens to a time bucket in that range that has zero matching source events?",
        "options": [
          {
            "label": "It is filled with a value of zero by default rather than being dropped from the resulting series",
            "value": "c"
          },
          {
            "label": "It is automatically dropped from the array, shrinking the series length for that entity",
            "value": "a"
          },
          {
            "label": "The entire query fails with an error because every bucket must contain at least one row",
            "value": "b"
          },
          {
            "label": "It is filled with the average of all other buckets in the series",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The lesson states that make-series fills empty buckets with zero by default, preserving an evenly-spaced series — which matters because a silently dropped bucket would make a real lull in activity invisible to later decomposition and anomaly functions."
      },
      {
        "question": "After running series_decompose_anomalies(), an analyst sees two flagged points: one with a score of 1.6 and one with a score of 4.1. Per Tukey's fence test as described in the lesson, how should these be triaged differently?",
        "options": [
          {
            "label": "The 4.1 score is a strong anomaly warranting immediate triage, while the 1.6 score is only a mild anomaly worth a routine glance",
            "value": "d"
          },
          {
            "label": "Both scores mean exactly the same thing operationally, since anything above 1.5 is treated identically",
            "value": "a"
          },
          {
            "label": "The 1.6 score is more severe because lower positive scores indicate a closer match to malicious C2 timing",
            "value": "b"
          },
          {
            "label": "Scores have no defined severity bands in KQL and must be interpreted purely by the analyst's intuition",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "The lesson defines |score| above 1.5 as a mild anomaly and above 3.0 as a strong anomaly, and explicitly recommends using the numeric score for prioritization rather than treating every flagged point the same way."
      },
      {
        "question": "A host shows a tight, short seasonal period of exactly every 300 seconds in its outbound-connection-count time series, with no correlation to business hours. Which MITRE ATT&CK technique and tactic does this pattern most directly suggest, per the lesson?",
        "options": [
          {
            "label": "T1071 Application Layer Protocol, under the Command and Control tactic — consistent with C2 beaconing",
            "value": "a"
          },
          {
            "label": "T1078.004 Valid Accounts: Cloud Accounts, under the Initial Access tactic — consistent with credential theft",
            "value": "b"
          },
          {
            "label": "T1041 Exfiltration Over C2 Channel, under the Exfiltration tactic — consistent with slow data theft",
            "value": "c"
          },
          {
            "label": "T1059.001 PowerShell, under the Execution tactic — consistent with scripted command execution",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The lesson ties a tight, short, non-business-hours seasonal period directly to beaconing behavior, mapped to T1071 under Command and Control. T1041 (exfiltration) is instead associated with a rising trend in volume, not a short seasonal period, and the other two techniques are unrelated to periodic network beaconing."
      },
      {
        "question": "A rarely-used administrative service account authenticates once every week or two at unpredictable times. Why does the lesson recommend percentile-based baselining over time-series decomposition for an entity like this?",
        "options": [
          {
            "label": "Decomposition needs dense, periodic activity to find a real seasonal pattern, and sparse irregular entities don't provide that, so results are noisy",
            "value": "b"
          },
          {
            "label": "The series_decompose() function is only able to accept entities that have an even total number of recorded events",
            "value": "a"
          },
          {
            "label": "Percentile-based baselining always requires typing fewer total KQL operators than any decomposition query would need",
            "value": "c"
          },
          {
            "label": "Time-series decomposition functions are architecturally restricted to host entities and cannot run against service accounts",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson explicitly states that decomposition assumes enough regular structure to find a real period, and that sparse/irregular entities are better served by percentile baselining, which makes no assumption about periodicity. The other options are fabricated technical constraints."
      }
    ]
  },
  "threat-hunter--sigma-syntax-basics": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "What Sigma Is, and Why Hunters Write Rules In It",
        "body": "Every hunt in the previous lessons of this module ended the same way once it confirmed a real pattern: someone had to write that pattern down as a repeatable query. The problem is that \"repeatable query\" means something different in every environment — Splunk speaks SPL (Search Processing Language), Microsoft Sentinel speaks KQL, Elastic speaks its own set of query languages. A query written for one SIEM (Security Information and Event Management platform) is often useless in another without a full rewrite.\n\n### The shipping-container analogy\n\nBefore standardized shipping containers existed, cargo had to be manually loaded and unloaded differently for every ship, train, and truck it touched — enormously wasteful. A standard container shape let the same box move across every mode of transport unchanged. **Sigma**, introduced in 2017, is that standard container for detection logic: a vendor-neutral, human-readable YAML (a structured, indentation-based text format) way of describing a log-based behavioral pattern, written once and convertible into any SIEM's native query language by a separate conversion tool (covered in the next lesson).\n\n### Why this matters specifically for hunters\n\nA hunt hypothesis validated with the KQL from earlier lessons lives, by default, in one hunter's query history on one SIEM. Writing it as a Sigma rule instead turns it into a **portable, shareable artifact**: any team running any SIEM can adopt it directly, and the community-maintained SigmaHQ repository holds thousands of such rules, each mapped to a specific MITRE ATT&CK technique, that a hunting program can both draw hypotheses from and contribute back to.\n\n### What this lesson covers\n\nThis lesson walks through Sigma's rule anatomy field by field: what's required, what's optional, how the `logsource` section scopes a rule to the right kind of telemetry, how the `detection` section expresses the actual matching logic, the field modifiers that make that logic precise, and the common mistakes that make an otherwise well-intentioned rule too broad or too narrow.",
        "codeExample": "flowchart TD\n    A[One Sigma rule, written once] --> B[Splunk SPL]\n    A --> C[Microsoft Sentinel KQL]\n    A --> D[Elastic Lucene / EQL / ES|QL]\n    B --> E[Deployed detection, no rewrite needed]\n    C --> E\n    D --> E",
        "keyPoints": [
          "Sigma is a vendor-neutral, human-readable YAML format for describing log-based behavioral detection patterns.",
          "A single Sigma rule can be converted into any SIEM's native query language (SPL, KQL, Elastic query languages).",
          "Writing a hunt finding as Sigma turns it from a personal query into a portable, shareable, ATT&CK-mapped artifact.",
          "The community-maintained SigmaHQ repository holds thousands of rules mapped to specific ATT&CK techniques."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Rule Anatomy: Required and Optional Fields",
        "body": "A Sigma rule is a single YAML document with a defined set of top-level fields. Understanding which are required and which are optional-but-conventional is the first step to reading or writing any rule correctly.\n\n### Required fields\n\nOnly three top-level fields are strictly required: **title** (a brief description, conventionally kept short), **logsource** (which telemetry this rule applies to — covered on the next page), and **detection** (the actual search logic and its condition). A YAML document missing any of these three will fail validation.\n\n### Commonly used optional fields\n\n| Field | Purpose |\n|---|---|\n| `id` | A UUID uniquely identifying the rule, useful for tracking it across conversions and updates |\n| `status` | Rule maturity: one of `stable`, `test`, `experimental`, `deprecated`, `unsupported` |\n| `description` | A longer explanation of what the rule detects and why |\n| `author` | Who wrote the rule |\n| `date` / `modified` | Creation and last-modified dates, in `YYYY-MM-DD` format |\n| `references` | Source citations (a blog post, an advisory, an ATT&CK page) |\n| `tags` | Categorization labels, including ATT&CK technique mappings (covered later in this lesson) |\n| `falsepositives` | Known legitimate activity that can trigger the rule |\n| `level` | Severity: one of `informational`, `low`, `medium`, `high`, `critical` |\n| `fields` | A list of fields considered especially relevant for triage once the rule fires |\n\n### A minimal skeleton\n\n```yaml\ntitle: Example Minimal Rule\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\\\whoami.exe'\n  condition: selection\nlevel: low\n```\n\nThis is a complete, valid Sigma rule — nothing more than the three required fields plus a couple of good-practice optional ones. Every rule built through the rest of this lesson simply adds more precision to this same basic shape.",
        "codeExample": "title: Example Minimal Rule\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    Image|endswith: '\\\\whoami.exe'\n  condition: selection\nlevel: low",
        "keyPoints": [
          "Only title, logsource, and detection are strictly required in a Sigma rule.",
          "status has five defined values: stable, test, experimental, deprecated, unsupported.",
          "level has five defined severity values: informational, low, medium, high, critical.",
          "tags, references, and falsepositives are optional but strongly conventional for a usable, maintainable rule."
        ]
      },
      {
        "pageNumber": 3,
        "title": "The logsource Section: Scoping a Rule to the Right Telemetry",
        "body": "Before a rule can express any matching logic, it has to declare what kind of telemetry it applies to. That is the entire job of the `logsource` section.\n\n### The three sub-fields\n\nSigma splits a log source description into three distinct, independently optional sub-fields:\n\n- **category** — a general class of telemetry, such as `process_creation`, `network_connection`, or `file_event`, independent of any specific vendor.\n- **product** — a specific product or platform generating the logs, such as `windows`, `linux`, or `aws`.\n- **service** — a specific service running within a product, such as `sysmon`, `kerberos`, or `defender`.\n\nA rule can combine these however precisely it needs to. `category: process_creation` alone matches any process-creation telemetry regardless of platform; adding `product: windows` narrows it to Windows process creation specifically; using `service` instead narrows to one specific logging service within that product.\n\n### Why this scoping matters downstream\n\nThe `logsource` section does not, by itself, change field names or telemetry format — that translation work happens in the conversion **pipelines** covered in the next lesson. What `logsource` does is tell a conversion pipeline *which* field-mapping and query-target rules to apply. A rule scoped to `category: process_creation, product: windows` can be converted against a Sysmon-based pipeline (targeting Event ID 1 and its `Image`/`CommandLine`/`ParentImage` fields) or a native Windows Security auditing pipeline (targeting Event ID 4688 and its own field names) — the same YAML, two different underlying data sources, because the pipeline decides the mapping.\n\n### Worked example\n\n```yaml\nlogsource:\n  category: process_creation\n  product: windows\n```\n\nThis is the logsource used by the worked rule built across the remaining pages of this lesson: a Windows process-creation detection, deliberately left at the category+product level (rather than pinning to a specific `service: sysmon`) so it stays convertible against multiple Windows telemetry pipelines without being rewritten.",
        "codeExample": "logsource:\n  category: process_creation\n  product: windows",
        "keyPoints": [
          "logsource has three sub-fields: category (general telemetry class), product (platform), and service (a specific service).",
          "category: process_creation, product: windows, and service: sysmon can each be used alone or combined for precision.",
          "logsource does not translate field names itself — it tells a conversion pipeline which mapping rules apply.",
          "The same logsource can be converted against multiple underlying data sources (e.g., Sysmon vs. native Windows auditing)."
        ]
      },
      {
        "pageNumber": 4,
        "title": "The detection Section: Selections, Keywords, and Conditions",
        "body": "The `detection` section is where a Sigma rule actually expresses matching logic. It always has two parts: one or more named **search identifiers**, and a mandatory **condition** that combines them.\n\n### Search identifiers: selections and keywords\n\nA **selection** (the identifier can be named anything — `selection`, `selection_img`, `filter_admin` are all just labels) is typically written as a YAML map of field names to values. Multiple fields inside one map are combined with **AND**; multiple values under one field are combined with **OR**:\n\n```yaml\ndetection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n    CommandLine|contains:\n      - '-enc'\n      - '-EncodedCommand'\n  condition: selection\n```\n\nHere, a matching event must have `Image` ending in `powershell.exe` **AND** `CommandLine` containing *either* `-enc` **OR** `-EncodedCommand`. A **keyword** list, by contrast, searches the entire raw event for any of the listed strings rather than matching against a specific field — useful when a log format doesn't cleanly parse into fields.\n\n### The condition field: combining search identifiers\n\n`condition` is mandatory and uses `and`, `or`, and `not` to combine named search identifiers, plus two shorthand patterns for groups of similarly-named identifiers: `1 of selection*` (at least one identifier whose name starts with `selection` must match) and `all of selection*` (every one of them must match). A common pattern separates a broad match from a narrowing exclusion:\n\n```yaml\ncondition: selection and not filter\n```\n\n### Why separate identifiers instead of one giant selection\n\nSplitting logic into multiple named identifiers — one for \"this is the right kind of process,\" one for \"this looks suspicious,\" one for \"but exclude this known-legitimate case\" — keeps a rule readable and lets a filter be updated independently of the core detection logic as false positives are discovered, without touching the part of the rule that defines what's actually being hunted for.",
        "codeExample": "detection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n    CommandLine|contains:\n      - '-enc'\n      - '-EncodedCommand'\n  condition: selection",
        "keyPoints": [
          "A selection map combines multiple fields with AND, and multiple values under one field with OR.",
          "A keyword list searches the whole raw event rather than a specific field.",
          "condition combines named identifiers with and/or/not, plus shorthands like '1 of selection*' and 'all of selection*'.",
          "Splitting logic into separate named identifiers (selection + filter) keeps rules readable and easy to tune."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Field Modifiers: Precision Matching Beyond Exact Values",
        "body": "A bare `field: value` pair in a selection requires an exact match. Real-world detection almost always needs more flexibility than that — which is what **field modifiers** provide, appended to a field name after a pipe character.\n\n### The modifiers used most often in hunting rules\n\n| Modifier | Effect |\n|---|---|\n| `contains` | Value must appear anywhere in the field (adds wildcards around it) |\n| `startswith` / `endswith` | Value must appear at the beginning / end of the field |\n| `re` | Value is treated as a regular expression |\n| `cidr` | Value is matched as an IPv4 or IPv6 network range |\n| `base64offset` | Matches the value even if it's embedded inside a base64-encoded string, accounting for the byte-offset shifts encoding introduces |\n| `windash` | Matches a value across dash-like character variants (`-`, `/`, en dash, em dash) that Windows command lines can accept interchangeably |\n| `all` | Changes a list of values under one field from OR logic to AND logic (every value must be present) |\n| `exists` | Checks only whether a field is present, ignoring its value |\n\n### Building the worked rule: catching an obfuscated PowerShell encoded command\n\nAttackers frequently launch PowerShell with a base64-encoded command to avoid exposing readable strings in the command line, and often vary the dash style of the flag itself to dodge naive string matches:\n\n```yaml\ntitle: Suspicious PowerShell Execution via Encoded Command\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection_img:\n    Image|endswith: '\\\\powershell.exe'\n  selection_flag:\n    CommandLine|windash|contains:\n      - '-enc'\n      - '-EncodedCommand'\n  selection_encoded:\n    CommandLine|base64offset|contains:\n      - 'Net.WebClient'\n      - 'DownloadString'\n      - 'IEX'\n  condition: selection_img and selection_flag and selection_encoded\nfalsepositives:\n  - Legitimate administrative scripts that pass base64-encoded commands; verify the author and decoded content\nlevel: high\ntags:\n  - attack.execution\n  - attack.t1059.001\n```\n\n### Reading the modifier chaining order\n\nNotice `windash|contains` and `base64offset|contains`, in that order: value-transforming modifiers (`windash`, `base64offset`) come first, and the wildcard-adding match modifier (`contains`) comes last, so the wildcards are applied to the already-transformed value rather than being transformed themselves.",
        "codeExample": "title: Suspicious PowerShell Execution via Encoded Command\nstatus: experimental\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection_img:\n    Image|endswith: '\\\\powershell.exe'\n  selection_flag:\n    CommandLine|windash|contains:\n      - '-enc'\n      - '-EncodedCommand'\n  selection_encoded:\n    CommandLine|base64offset|contains:\n      - 'Net.WebClient'\n      - 'DownloadString'\n      - 'IEX'\n  condition: selection_img and selection_flag and selection_encoded\nfalsepositives:\n  - Legitimate administrative scripts that pass base64-encoded commands; verify the author and decoded content\nlevel: high\ntags:\n  - attack.execution\n  - attack.t1059.001",
        "keyPoints": [
          "Field modifiers (field|modifier: value) extend matching beyond exact equality: contains, startswith, endswith, re, cidr, and more.",
          "base64offset|contains matches a value even when it's embedded inside a base64-encoded string.",
          "windash|contains matches a flag across dash-like character variants Windows accepts interchangeably.",
          "Value-transforming modifiers (windash, base64offset) are chained before the wildcard-adding match modifier (contains)."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Tagging with MITRE ATT&CK: The tags Convention",
        "body": "The worked rule from the previous page ended with two `tags` entries: `attack.execution` and `attack.t1059.001`. This is the community-standard convention for linking a Sigma rule to the MITRE ATT&CK framework, and it's what lets a rule collection be rolled up into technique-coverage reporting.\n\n### The tag format\n\nATT&CK tags in Sigma follow a consistent lowercase, dot-separated format: `attack.` followed by either a **tactic name** (lowercase, e.g. `attack.execution`, `attack.persistence`, `attack.command-and-control`) or a **technique ID** (lowercase, e.g. `attack.t1059.001` for the sub-technique, or `attack.t1059` for the parent technique with no sub-technique specified). A well-tagged rule typically includes both: the tactic it maps to, and the specific technique or sub-technique ID.\n\n### Why both a tactic tag and a technique tag\n\nA tactic tag (`attack.execution`) answers \"what stage of an intrusion is this?\" A technique tag (`attack.t1059.001`) answers \"what specific method?\" Rule-management tooling and ATT&CK Navigator heatmaps consume the technique tags to compute coverage per technique across an entire rule set — a rule missing its technique tag is invisible to that kind of coverage analysis even if the detection logic itself works perfectly.\n\n### T1059.001 in context\n\nThe worked rule's tag, `attack.t1059.001`, refers to the **PowerShell** sub-technique of **T1059 (Command and Scripting Interpreter)**, under the Execution tactic — accurately describing what the rule detects: use of the PowerShell interpreter (specifically, an obfuscated invocation of it) to execute attacker-supplied commands. Tagging accurately matters beyond bookkeeping: a rule tagged with the wrong technique will make a coverage gap look filled when it isn't, and a real gap can go unnoticed for exactly that reason — a topic covered from the coverage-analysis side elsewhere in this path, and from the testing side in a later lesson in this module.",
        "keyPoints": [
          "ATT&CK tags follow the format attack.<tactic-name> or attack.t<technique-id>, both lowercase and dot-separated.",
          "A well-tagged rule typically includes both a tactic tag and a technique (or sub-technique) tag.",
          "Coverage tooling and ATT&CK Navigator heatmaps rely on technique tags to compute per-technique detection coverage.",
          "attack.t1059.001 refers to the PowerShell sub-technique of T1059 (Command and Scripting Interpreter), under Execution."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Common Pitfalls That Make a Rule Too Broad or Too Narrow",
        "body": "Syntactically valid Sigma rules can still be operationally bad rules — either firing constantly on legitimate activity or silently missing the exact behavior they were meant to catch. A few mistakes account for most of these problems.\n\n### Pitfall 1: combining wildcard modifiers with encoding modifiers in the wrong order\n\nAs shown on an earlier page, `base64offset` and `windash` must come **before** `contains`/`startswith`/`endswith` in a modifier chain, never after. Putting a wildcard-adding modifier before an encoding modifier would cause the wildcard characters themselves to be base64-encoded or dash-transformed along with the real value — corrupting the match target entirely rather than just failing loudly.\n\n### Pitfall 2: an over-broad selection with no filter\n\nA selection matching only `Image|endswith: '\\\\powershell.exe'` with no further narrowing will match *every* PowerShell launch on every host — completely swamping a SOC with noise, since PowerShell itself is a completely legitimate, heavily-used administrative tool. Every one of the worked rule's three separate selection identifiers exists specifically to narrow a broad starting point (any PowerShell process) down to a specific suspicious pattern (an encoded command containing a download-cradle indicator).\n\n### Pitfall 3: assuming a command-line flag can only be spelled one way\n\nPowerShell accepts abbreviated, case-insensitive parameter names — `-EncodedCommand`, `-enc`, `-e`, and other partial forms are all functionally equivalent to PowerShell itself, but Sigma's field matching is a literal string match, not an interpreter-aware parser. A rule chasing only the two spellings shown earlier can still be evaded by an attacker using a different valid abbreviation. Some EDR (Endpoint Detection and Response) platforms surface a separately decoded/normalized version of an obfuscated command line as its own field — worth checking your specific vendor's schema for before assuming the raw `CommandLine` field already contains everything relevant.\n\n### Pitfall 4: missing or inaccurate falsepositives\n\nSkipping the `falsepositives` field doesn't make a rule generate fewer false positives — it just means the next analyst who inherits the rule has no documented starting point for tuning it when noise inevitably shows up, and has to rediscover the same known caveats from scratch.",
        "keyPoints": [
          "Encoding/transform modifiers (base64offset, windash) must be chained before wildcard modifiers (contains, startswith, endswith), not after.",
          "A selection with no narrowing filter on a common legitimate tool (like PowerShell) will generate overwhelming noise.",
          "Sigma matches literal strings, not interpreter semantics — command-line flag abbreviations can evade a rule that only checks specific spellings.",
          "Skipping falsepositives doesn't reduce noise; it just removes the documented starting point for the next analyst who tunes the rule."
        ]
      }
    ],
    "quiz": [
      {
        "question": "Which three fields are the only strictly required top-level fields in a valid Sigma rule?",
        "options": [
          {
            "label": "title, logsource, and detection",
            "value": "c"
          },
          {
            "label": "title, author, and level",
            "value": "a"
          },
          {
            "label": "id, status, and tags",
            "value": "b"
          },
          {
            "label": "description, references, and falsepositives",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The lesson states that only title, logsource, and detection are strictly required; everything else (id, status, author, level, tags, references, falsepositives, description) is optional though conventional for a well-documented rule."
      },
      {
        "question": "A rule's logsource is set to category: process_creation, product: windows, with no service specified. What does this actually control, per the lesson?",
        "options": [
          {
            "label": "It tells a downstream pipeline which field-mapping and query-target rules to apply; field-name translation happens in the pipeline, not here",
            "value": "d"
          },
          {
            "label": "It directly renames every field inside the detection section to match Sysmon's schema automatically at parse time",
            "value": "a"
          },
          {
            "label": "It permanently restricts the rule so it can only ever be converted for a Splunk target, never any other backend",
            "value": "b"
          },
          {
            "label": "It has no effect on conversion unless a service sub-field is also explicitly specified alongside category and product",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "The lesson explicitly distinguishes logsource (which scopes the rule and informs pipeline selection) from the actual field-mapping work, which happens in conversion pipelines covered in the next lesson. logsource alone doesn't rename fields or lock the rule to one specific backend."
      },
      {
        "question": "In the worked rule's detection section, why does the condition use 'selection_img and selection_flag and selection_encoded' with three separate named identifiers instead of one combined selection block?",
        "options": [
          {
            "label": "Separating the image, flag, and encoded-content checks keeps the rule readable and lets any one part be tuned independently later",
            "value": "a"
          },
          {
            "label": "The Sigma specification requires every rule to define at least three separate selection identifiers by name",
            "value": "b"
          },
          {
            "label": "A single selection block is limited to exactly one field-modifier combination under the Sigma specification",
            "value": "c"
          },
          {
            "label": "Splitting logic into multiple identifiers is purely stylistic, with no effect on validation or conversion output",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The lesson explains that splitting logic into separate named identifiers keeps a rule readable and tunable piece by piece, using this exact rule as the example. There is no rule requiring exactly three identifiers, and a single selection block can absolutely contain multiple modified fields."
      },
      {
        "question": "Why is the modifier order CommandLine|windash|contains correct, while CommandLine|contains|windash would be a mistake, according to the lesson?",
        "options": [
          {
            "label": "Value-transforming modifiers like windash must be applied before the wildcard-adding contains modifier, so the wildcards aren't themselves transformed",
            "value": "b"
          },
          {
            "label": "Sigma alphabetizes modifiers automatically, so contains must always come after windash regardless of intent",
            "value": "a"
          },
          {
            "label": "windash only works when it is the very last modifier in any chain, with no exceptions",
            "value": "c"
          },
          {
            "label": "contains and windash cannot be combined on the same field under any circumstances",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson explains that encoding/transform modifiers like windash and base64offset must come before wildcard-adding modifiers like contains, so that the wildcards apply to the already-transformed value rather than being corrupted by the transform themselves. The other options invent rules that don't exist in the specification."
      },
      {
        "question": "The lesson notes that PowerShell accepts abbreviated flags like -enc, -e, or -EncodedCommand interchangeably. Why is this a meaningful limitation for a Sigma rule that only checks for the exact strings '-enc' and '-EncodedCommand'?",
        "options": [
          {
            "label": "Sigma performs literal string matching, not interpreter-aware parsing, so an attacker using a different valid abbreviation of the same flag can evade the rule entirely",
            "value": "c"
          },
          {
            "label": "PowerShell itself will refuse to execute any command using an abbreviated flag, making the concern purely theoretical",
            "value": "a"
          },
          {
            "label": "Sigma automatically expands all known PowerShell flag abbreviations before matching, so this is already handled",
            "value": "b"
          },
          {
            "label": "The base64offset modifier resolves this problem completely on its own without any additional logic",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The lesson states plainly that Sigma matches literal strings, not interpreter semantics, so a rule chasing only specific spellings can be evaded by a different valid abbreviation — a real, practical gap, not a theoretical one, and not something base64offset (which targets encoding, not flag spelling) resolves by itself."
      }
    ]
  },
  "threat-hunter--backend-conversion": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "One Rule, Many Query Languages",
        "body": "The previous lesson built a complete Sigma rule expressing \"flag PowerShell launched with an obfuscated, base64-encoded download-cradle command.\" That YAML file, on its own, cannot run anywhere — no SIEM executes Sigma directly. It has to be **converted** into that SIEM's native query language first: SPL (Search Processing Language) for Splunk, KQL for Microsoft Sentinel and Microsoft Defender, or one of several query languages for Elastic.\n\n### pySigma: the conversion engine\n\n**pySigma** is the Python library that performs this translation, and it is the direct successor to Sigma's original converter, `sigmac` (now deprecated). pySigma parses a Sigma rule into an internal representation, then hands that representation to a **backend** — a separate package, one per target query language — which renders it into that language's actual syntax. **sigma-cli** is the command-line tool built on top of pySigma that most hunters and detection engineers interact with day to day; it is what the rest of this lesson uses.\n\n### The three pieces that fit together\n\n- **pySigma core** — parses Sigma YAML and represents its logic (selections, conditions, modifiers) in a structure backends can consume.\n- **A backend** — one Python package per target query language (Splunk, Microsoft 365 Defender/Kusto, Elasticsearch, and others), responsible for rendering that internal representation into real query syntax.\n- **A pipeline** — a preset that tells the backend how to map generic Sigma fields (like `Image` or `CommandLine`) onto the actual field names used by a specific log source or product, covered in detail on the next page.\n\n### Why hunters specifically care about this layer\n\nA hunt hypothesis proven with the KQL from earlier in this module, then formalized as Sigma in the previous lesson, only becomes genuinely useful to an entire organization once it can be deployed to whatever SIEM that organization actually runs — and contributed back to a shared detection library instead of staying trapped in one hunter's personal rule collection. Backend conversion is the step that makes that portability real rather than theoretical.",
        "keyPoints": [
          "A Sigma rule cannot run directly on any SIEM; it must be converted into that SIEM's native query language first.",
          "pySigma is the Python library that performs this conversion; sigma-cli is the command-line tool built on top of it.",
          "pySigma core parses Sigma rules; a backend renders that parsed logic into a specific target query language.",
          "A pipeline maps generic Sigma field names onto the real field names of a specific log source or product."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Anatomy of a Backend: Fields, Pipelines, and Output Formats",
        "body": "Understanding what a backend and a pipeline each actually do — and why they're separate concepts — makes the CLI commands on the rest of this lesson's pages far less mysterious.\n\n### What a backend is responsible for\n\nA backend's job is purely **syntactic**: given a parsed Sigma condition (an AND/OR/NOT tree of field-value comparisons), render it as valid query syntax for one target — Splunk's `field=value` search syntax, KQL's `| where` pipeline syntax, or Elastic's Lucene/EQL/ES|QL syntax. A backend also typically supports multiple **output formats** for the same target — for example, the Splunk backend can render a plain ad-hoc search, or a `savedsearches.conf`-formatted saved search ready to drop into a Splunk app.\n\n### What a pipeline is responsible for\n\nA pipeline's job is **semantic field mapping and logsource-to-table translation**. The same generic Sigma field `CommandLine` might need to become `CommandLine` verbatim against one Sysmon-based data source, or a completely different field name against a native Windows Security auditing source, or a nested field path against a cloud-native EDR schema. The pipeline supplies that mapping so the exact same Sigma rule can target different underlying log sources without being rewritten — this is also where `logsource: category/product/service` from the previous lesson gets resolved into an actual table or index name.\n\n### Matching backend packages to targets\n\n| Backend package | Target flag (-t) | Typical pipeline |\n|---|---|---|\n| pySigma-backend-splunk | `splunk` | `splunk_windows` |\n| pySigma-backend-microsoft365defender | `microsoft365defender` | `sysmon` |\n| pySigma-backend-elasticsearch | `lucene`, `eql`, `esql` | `ecs_windows` |\n\n### The mental model going forward\n\nEvery conversion command in this lesson follows the same shape: pick a **target** (which backend/query-language to render into), pick a **pipeline** (which field mapping to apply), and run `sigma convert` against one or more rule files. Everything else is a variation on that pattern.",
        "keyPoints": [
          "A backend's job is purely syntactic: rendering parsed detection logic into a specific target query language.",
          "A pipeline's job is field mapping and logsource-to-table translation, letting one rule target different log sources.",
          "Backends often support multiple output formats for the same target (e.g., a plain search vs. a savedsearches.conf entry).",
          "Every conversion follows the same pattern: choose a target, choose a pipeline, run sigma convert."
        ]
      },
      {
        "pageNumber": 3,
        "title": "Installing the Toolchain",
        "body": "Before converting anything, the CLI tool and the specific backend packages needed for your organization's SIEM stack have to be installed.\n\n### Installing sigma-cli\n\n```bash\npip3 install sigma-cli\n```\n\nThis installs the `sigma` command itself, along with pySigma core, but no backends yet — backends are separate, installable plugins so that a hunter targeting only Splunk doesn't need to pull in Elastic-specific dependencies they'll never use.\n\n### Installing backend plugins\n\nsigma-cli manages backend plugins through its own `plugin` subcommand:\n\n```bash\nsigma plugin install splunk\nsigma plugin install microsoft365defender\nsigma plugin install elasticsearch\n```\n\nEach of these installs the corresponding pySigma backend package (`pySigma-backend-splunk`, `pySigma-backend-microsoft365defender`, `pySigma-backend-elasticsearch`) and registers its available targets and pipelines with the CLI.\n\n### Discovering what's available\n\n```bash\nsigma plugin list\n```\n\nlists every backend plugin sigma-cli knows how to install, which is the fastest way to check whether a specific SIEM already has community backend support before writing a custom one. The same subcommand family also handles removal and upgrades (`sigma plugin uninstall <name>`), which matters because backend packages version independently of sigma-cli itself — a backend can add support for a new pipeline or fix a field-mapping bug well after the core CLI was last updated, so periodically checking for newer backend versions is worth building into a team's regular maintenance routine rather than treating installation as a one-time setup step.\n\n### A realistic starting toolchain\n\nA hunting team supporting both a Splunk deployment and a Microsoft Sentinel deployment — a common situation after a merger or a multi-tool SOC build-out — would typically run all of the commands above once, then have both `splunk` and `microsoft365defender` available as conversion targets for every Sigma rule in their repository going forward, without needing to maintain two separate rule sets. Adding a third target later, if the organization brings on an Elastic-based deployment, requires only one additional `sigma plugin install elasticsearch` command — the existing rule repository does not need to be touched at all, since the rules themselves never encoded any assumption about which backend would eventually consume them.",
        "codeExample": "pip3 install sigma-cli\nsigma plugin install splunk\nsigma plugin install microsoft365defender\nsigma plugin install elasticsearch\nsigma plugin list",
        "keyPoints": [
          "pip3 install sigma-cli installs the sigma command and pySigma core, but no backends by default.",
          "sigma plugin install <name> installs a specific backend package and registers its targets/pipelines.",
          "sigma plugin list shows every backend plugin available for installation.",
          "One rule repository can support multiple SIEM targets simultaneously by installing multiple backend plugins."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Converting to Splunk SPL",
        "body": "With the Splunk backend installed, converting the encoded-PowerShell rule from the previous lesson into SPL (Search Processing Language) is a single command.\n\n### The conversion command\n\n```bash\nsigma convert -t splunk -p splunk_windows encoded_powershell.yml\n```\n\n`-t splunk` selects the Splunk backend as the conversion target; `-p splunk_windows` selects the pipeline that maps generic Windows process-creation fields onto the field names used in a typical Windows-log Splunk deployment.\n\n### What the resulting search looks like\n\nA backend renders the rule's AND/OR condition tree into Splunk's native search syntax. For the three-identifier rule from the previous lesson, the result is representative of:\n\n```spl\nindex=* sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1\nImage=\"*\\\\powershell.exe\"\n(CommandLine=\"*-enc*\" OR CommandLine=\"*-EncodedCommand*\" OR CommandLine=\"*/enc*\" OR CommandLine=\"*/EncodedCommand*\")\n(CommandLine=\"*Net.WebClient*\" OR CommandLine=\"*DownloadString*\" OR CommandLine=\"*IEX*\")\n```\n\nEach Sigma selection becomes one grouped clause; the AND between `selection_img`, `selection_flag`, and `selection_encoded` in the rule's condition becomes implicit AND between clauses in SPL, and the OR lists inside each selection become explicit `OR` groups.\n\n### Alternative output formats\n\n`-O format=savedsearches` renders the same logic as a `savedsearches.conf` stanza, ready to drop directly into a Splunk app as a scheduled saved search rather than a one-off ad-hoc query. `-O format=data_model` instead renders an accelerated `tstats` query against Splunk's Common Information Model data model — typically far faster at scale than searching raw events directly, at the cost of depending on that data model being properly populated and accelerated first.\n\n### The point of showing the raw output\n\nA hunter doesn't need to memorize SPL syntax to write good Sigma rules — but reading the converted output at least once, and confirming it matches the intended logic, is an essential sanity check before trusting any converted rule in production, a theme this lesson returns to on its closing pages.",
        "codeExample": "sigma convert -t splunk -p splunk_windows encoded_powershell.yml\n\n# with -O format=savedsearches, the same logic is rendered as a\n# savedsearches.conf stanza instead of a one-off ad-hoc search",
        "keyPoints": [
          "sigma convert -t splunk -p splunk_windows <file> converts a Sigma rule to Splunk SPL.",
          "Each Sigma selection becomes a grouped SPL clause; the rule's AND/OR condition structure carries over directly.",
          "-O format=savedsearches renders a savedsearches.conf stanza instead of an ad-hoc search.",
          "-O format=data_model renders an accelerated tstats query against Splunk's Common Information Model."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Converting to Microsoft Sentinel / KQL",
        "body": "The same Sigma rule converts to KQL for Microsoft's security stack through a different backend and target — no changes to the rule's YAML are needed.\n\n### The conversion command\n\n```bash\nsigma convert -t microsoft365defender -p sysmon encoded_powershell.yml\n```\n\n`-t microsoft365defender` targets Microsoft Defender's advanced hunting KQL dialect (queried against `Device*` tables like `DeviceProcessEvents`); `-p sysmon` selects the pipeline mapping generic Sigma process-creation fields onto Sysmon-sourced field names.\n\n### What the resulting query looks like\n\n```kql\nDeviceProcessEvents\n| where FolderPath has \"powershell.exe\"\n| where ProcessCommandLine has_any (\"-enc\", \"-EncodedCommand\", \"/enc\", \"/EncodedCommand\")\n| where ProcessCommandLine has_any (\"Net.WebClient\", \"DownloadString\", \"IEX\")\n```\n\n`FolderPath` and `ProcessCommandLine` are real fields in the `DeviceProcessEvents` advanced hunting table; `has_any` is KQL's operator for \"contains at least one of this list,\" a direct rendering of the OR groups inside each Sigma selection.\n\n### Two related but distinct Microsoft-targeting backends\n\n`pySigma-backend-microsoft365defender` (published by SigmaHQ) targets Microsoft Defender's advanced hunting queries specifically. A separate community backend, `pySigma-backend-kusto`, targets a broader set of Kusto-based destinations, including Microsoft Sentinel's **ASIM** (Advanced Security Information Model) normalized schema — useful when an organization wants detections written against Sentinel's vendor-agnostic normalized tables rather than the Defender-specific `Device*` tables directly.\n\n### Why the pipeline choice changes the output table, not just field names\n\nChoosing `-p sysmon` here is what routes the query toward `DeviceProcessEvents` in the first place — a different pipeline built for, say, native Windows Security auditing telemetry ingested into Sentinel's `SecurityEvent` table would route the exact same Sigma rule to query `SecurityEvent` instead, using Event ID 4688 semantics. The rule's intent stays identical; the pipeline decides where and how that intent gets executed.",
        "codeExample": "sigma convert -t microsoft365defender -p sysmon encoded_powershell.yml\n\n# representative KQL output against DeviceProcessEvents:\nDeviceProcessEvents\n| where FolderPath has \"powershell.exe\"\n| where ProcessCommandLine has_any (\"-enc\", \"-EncodedCommand\", \"/enc\", \"/EncodedCommand\")\n| where ProcessCommandLine has_any (\"Net.WebClient\", \"DownloadString\", \"IEX\")",
        "keyPoints": [
          "sigma convert -t microsoft365defender -p sysmon <file> converts a rule to KQL against Defender's DeviceProcessEvents table.",
          "has_any in KQL is the direct equivalent of an OR group inside a Sigma selection.",
          "pySigma-backend-microsoft365defender targets Defender advanced hunting; pySigma-backend-kusto also supports Sentinel's ASIM schema.",
          "The chosen pipeline determines which underlying table/schema the query targets, not just which field names are used."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Converting to Elastic: Lucene, EQL, and ES|QL",
        "body": "Elastic's security stack supports several distinct query languages, and the Elasticsearch backend exposes each as a separate conversion target rather than a single unified one.\n\n### The three main targets\n\n- **lucene** — Elastic's classic simple query-string syntax (`field:value`-style queries). The least expressive of the three; no native support for multi-event sequences.\n- **eql** (Event Query Language) — a purpose-built query language for security use cases, including native support for **sequences** of related events (useful for expressing a multi-step attack chain as a single query, beyond what any single Sigma rule alone typically expresses).\n- **esql** (ES|QL) — a newer, pipe-based query language (syntactically similar in spirit to KQL's own piped structure), which also supports **correlations** across data sources.\n\n### Conversion command and pipeline\n\n```bash\nsigma convert -t lucene -p ecs_windows encoded_powershell.yml\n```\n\n`ecs_windows` maps generic Sigma fields onto **ECS** (Elastic Common Schema) field names — Elastic's own cross-log-source normalized naming convention, comparable in purpose to Microsoft's ASIM. Under this mapping, `Image` becomes `process.executable` and `CommandLine` becomes `process.command_line`, both real, documented ECS field names.\n\n### Representative Lucene output\n\n```\nprocess.executable:*powershell.exe AND\n(process.command_line:*-enc* OR process.command_line:*-EncodedCommand*) AND\n(process.command_line:*Net.WebClient* OR process.command_line:*DownloadString* OR process.command_line:*IEX*)\n```\n\n### Choosing among the three targets\n\nFor a single-event detection like the encoded-PowerShell rule, all three targets can express the same logic adequately, and `lucene` is the simplest to read and debug. `eql` becomes the better choice once a detection needs to express an actual sequence (process A spawns process B, which then makes a network connection) rather than a single event's fields. `esql`'s correlation support is aimed at newer, more complex detection patterns that span multiple indices or data sources in one query — a capability still being actively built out across the Sigma-to-Elastic conversion ecosystem.",
        "codeExample": "sigma convert -t lucene -p ecs_windows encoded_powershell.yml\n\n# representative Lucene output using ECS field names:\nprocess.executable:*powershell.exe AND\n(process.command_line:*-enc* OR process.command_line:*-EncodedCommand*) AND\n(process.command_line:*Net.WebClient* OR process.command_line:*DownloadString* OR process.command_line:*IEX*)",
        "keyPoints": [
          "The Elasticsearch backend exposes three main targets: lucene (simple), eql (native sequences), and esql (pipe-based, with correlation support).",
          "The ecs_windows pipeline maps Sigma fields onto Elastic Common Schema names like process.executable and process.command_line.",
          "eql is the better choice once a detection needs to express a sequence of related events rather than one event's fields.",
          "All three Elastic targets can adequately express a single-event detection like the worked encoded-PowerShell rule."
        ]
      },
      {
        "pageNumber": 7,
        "title": "Validating the Output Before You Trust It",
        "body": "A syntactically valid conversion is not automatically a correct one. Before deploying any converted query to production alerting, a few checks catch the most common ways a conversion can silently go wrong.\n\n### Validate the rule itself first\n\n`sigma check` runs before conversion and validates a rule's structure, condition logic, and general best practices — catching typos and malformed logic cheaply, before ever generating a query in a target language:\n\n```bash\nsigma check encoded_powershell.yml\n```\n\n### Sanity-check the converted output manually\n\nConfirm the field names in the converted query actually exist in your environment's real schema — a pipeline mismatch (for example, applying a Sysmon-oriented pipeline against an environment that only ingests native Windows Security auditing events) can leave fields silently unmapped, either causing a conversion error or, worse, producing a query that runs without error but never matches real data because it's querying a field or table that's empty in your environment.\n\n### Common conversion pitfalls\n\n- **Pipeline/data-source mismatch**: choosing a pipeline built for one log source (Sysmon) when the target environment actually ingests a different one (native Windows auditing, or a cloud-native EDR agent).\n- **Wildcard escaping differences**: each target language escapes special characters differently; a value containing a literal character that's also a wildcard/metacharacter in the target syntax needs to be escaped correctly by the backend, which is worth spot-checking on any regex-heavy (`re` modifier) rule.\n- **Value-substitution modifiers needing pipeline support**: the `expand` modifier from the previous lesson relies entirely on the chosen pipeline knowing how to fill in the substituted value's actual contents for your environment; without that pipeline support, the substitution silently fails or errors.\n- **Regex flavor mismatches**: Sigma's `re` modifier doesn't guarantee identical regex behavior across every target's native regex engine; a pattern that works in one backend's output may need adjustment in another.\n\n### The rule this leads to\n\nManual review catches obvious mismatches, but the only way to be confident a converted query still fires on genuinely malicious activity — and doesn't fire on obviously benign activity — is to actually run it against real or synthetic test data, which is exactly what the next lesson in this module covers.",
        "codeExample": "sigma check encoded_powershell.yml",
        "keyPoints": [
          "sigma check validates a rule's structure and condition logic before any conversion is attempted.",
          "A pipeline/data-source mismatch can leave fields silently unmapped, producing a query that runs but never matches anything.",
          "Wildcard escaping and regex flavor can differ subtly between target query languages.",
          "The expand modifier depends entirely on pipeline support for the specific substituted value used."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Analyst Workflow: One Repo, Every SIEM",
        "body": "Putting backend conversion into a repeatable workflow is what turns \"we occasionally convert a rule by hand\" into a hunting program with a real, maintainable detection library.\n\n### The typical shape of the workflow\n\nA hunting or detection team maintains its Sigma rules in a version-controlled repository — either its own private repo, or as contributions mirrored against the public, community-maintained **SigmaHQ** repository referenced in the previous lesson. A continuous integration (CI) pipeline then runs automatically on every change: lint every rule with `sigma check`, convert each rule to every target the organization's actual SIEM stack requires, and commit or deploy the resulting queries as saved searches, analytics rules, or detection rules in each target platform.\n\n### Why this benefits a hunter specifically\n\nA hunt hypothesis validated with the KQL techniques from earlier lessons in this module, written up as Sigma in the previous lesson, now ships automatically to every SIEM the organization runs — Splunk, Sentinel, Elastic, or all three — without the hunter manually rewriting the query language by hand for each one, and without that hunt's finding staying trapped in one person's personal query history where it disappears the day they change teams.\n\n### The full pipeline, visualized\n\n```\nflowchart TD\n    A[Sigma rule committed to git] --> B[sigma check: lint and validate]\n    B --> C{Which targets does the org run?}\n    C -->|Splunk| D[sigma convert -t splunk]\n    C -->|Sentinel| E[sigma convert -t microsoft365defender]\n    C -->|Elastic| F[sigma convert -t lucene / eql / esql]\n    D --> G[Deploy as saved search]\n    E --> H[Deploy as analytics rule]\n    F --> I[Deploy as detection rule]\n```\n\n### What comes next in this module\n\nA rule that converts cleanly and looks correct on manual review has still only been reviewed, not tested. The final lesson in this module builds the missing piece: generating real or synthetic telemetry to run converted rules against, so that \"this rule detects the technique\" becomes a verified fact rather than an assumption.",
        "codeExample": "flowchart TD\n    A[Sigma rule committed to git] --> B[sigma check: lint and validate]\n    B --> C{Which targets does the org run?}\n    C -->|Splunk| D[sigma convert -t splunk]\n    C -->|Sentinel| E[sigma convert -t microsoft365defender]\n    C -->|Elastic| F[sigma convert -t lucene / eql / esql]\n    D --> G[Deploy as saved search]\n    E --> H[Deploy as analytics rule]\n    F --> I[Deploy as detection rule]",
        "keyPoints": [
          "A mature detection workflow keeps Sigma rules in version control, with CI running sigma check and sigma convert automatically.",
          "The SigmaHQ community repository is a real, contributable destination for sharing rules beyond one organization.",
          "One committed Sigma rule can ship as a saved search, analytics rule, and detection rule across every SIEM the org runs.",
          "Conversion and manual review reduce risk but don't replace actually testing a converted rule against real or synthetic data."
        ]
      }
    ],
    "quiz": [
      {
        "question": "What is the key difference in responsibility between a pySigma backend and a pySigma pipeline?",
        "options": [
          {
            "label": "A backend renders parsed logic into a target query language's syntax; a pipeline maps generic field names onto a specific log source's real fields",
            "value": "d"
          },
          {
            "label": "A backend can only ever target Splunk, while a pipeline is reserved exclusively for Microsoft Sentinel conversions",
            "value": "a"
          },
          {
            "label": "A pipeline first converts the rule's YAML into JSON, and a backend then converts that JSON into final query text",
            "value": "b"
          },
          {
            "label": "There is no meaningful difference between the two; both terms describe the exact same component inside pySigma",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "The lesson defines a backend as purely syntactic (rendering the parsed logic into a target language) and a pipeline as responsible for semantic field mapping and logsource-to-table translation, letting one rule target different underlying log sources."
      },
      {
        "question": "A hunting team runs sigma convert -t microsoft365defender -p sysmon on a rule, but the resulting query fields don't match anything in their environment because they actually ingest native Windows Security auditing events, not Sysmon. What does the lesson call this kind of problem?",
        "options": [
          {
            "label": "A pipeline/data-source mismatch, where the chosen pipeline doesn't correspond to what the environment actually ingests",
            "value": "a"
          },
          {
            "label": "A syntax error that sigma convert should have refused to run in the first place",
            "value": "b"
          },
          {
            "label": "An unfixable limitation of the microsoft365defender backend that has no workaround",
            "value": "c"
          },
          {
            "label": "Evidence that the original Sigma rule itself was written with invalid YAML",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The lesson lists pipeline/data-source mismatch as a specific, named common conversion pitfall, distinct from a YAML syntax error — the conversion can succeed syntactically while still producing a query that queries the wrong fields for the real environment."
      },
      {
        "question": "Why might a detection team choose the eql target over lucene when converting a Sigma-based detection for Elastic, per the lesson?",
        "options": [
          {
            "label": "EQL has native support for sequences of related events, useful once a detection needs a multi-step pattern rather than one event's fields",
            "value": "b"
          },
          {
            "label": "The lucene target is fundamentally incompatible with the ecs_windows pipeline under any circumstances whatsoever",
            "value": "a"
          },
          {
            "label": "The Sigma specification mandates the eql target for every single rule that declares a process_creation logsource",
            "value": "c"
          },
          {
            "label": "Lucene query syntax is structurally unable to express OR logic between values, unlike EQL's query syntax",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson specifically calls out EQL's native sequence support as the reason to prefer it once a detection needs to express a multi-step event chain, while noting lucene is adequate (and simplest) for single-event detections like the worked example. The other options are fabricated constraints."
      },
      {
        "question": "Before deploying a converted query to production alerting, the lesson recommends running sigma check. What does that command actually validate?",
        "options": [
          {
            "label": "The rule's structure, condition logic, and best-practice conventions, before any conversion is attempted",
            "value": "c"
          },
          {
            "label": "Whether the converted SPL or KQL output will return zero false positives once deployed",
            "value": "a"
          },
          {
            "label": "Whether the target SIEM currently has enough storage capacity to run the query",
            "value": "b"
          },
          {
            "label": "Whether every analyst on the team has reviewed and approved the rule",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The lesson describes sigma check as validating rule structure and logic before conversion — a cheap, early check, not a guarantee about false-positive rates, infrastructure capacity, or team approval, none of which the tool can assess."
      },
      {
        "question": "In the full CI pipeline diagram from this lesson, what happens immediately after a Sigma rule is committed to git and before any target-specific conversion runs?",
        "options": [
          {
            "label": "sigma check lints and validates the rule",
            "value": "d"
          },
          {
            "label": "The rule is immediately deployed as a saved search in Splunk with no further steps",
            "value": "a"
          },
          {
            "label": "The rule is automatically rewritten in EQL regardless of which SIEM the organization runs",
            "value": "b"
          },
          {
            "label": "The rule's falsepositives field is deleted to reduce noise",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "The pipeline diagram in the lesson shows sigma check running right after a commit, before branching out to per-target sigma convert steps for whichever SIEMs the organization actually runs. The other options either skip validation entirely or invent steps not shown in the workflow."
      }
    ]
  },
  "threat-hunter--sigma-test-data": {
    "pages": [
      {
        "pageNumber": 1,
        "title": "Why 'It Converts Cleanly' Isn't 'It Works'",
        "body": "The previous lesson ended with a converted Sigma rule that looked syntactically correct across three different SIEM targets. That is necessary, but it is not sufficient. A query can be perfectly valid syntax and still fail in either of two costly ways: it might never actually match the real malicious activity it was written for (a **false negative**), or it might match a huge amount of unrelated, entirely legitimate activity (a **false positive**).\n\n### Validation vs. testing: two different questions\n\n`sigma check`, covered in the previous lesson, answers \"does this rule text parse correctly, with valid structure and sound condition logic?\" That is **validation**. It says nothing about whether the rule's logic actually corresponds to real attacker behavior, or whether it's specific enough to avoid drowning a SOC in noise. Answering *that* question requires **testing**: running the converted query against real or realistic log data and confirming it behaves as intended — firing on the malicious sample, staying silent on the benign one.\n\n### Why this matters more, not less, once conversion is automated\n\nThe CI (continuous integration) pipeline from the previous lesson makes it trivially easy to push a rule change and have it automatically reconverted and redeployed across every SIEM target. That speed is valuable, but it also means a subtly broken rule change can reach production in minutes instead of days if nothing in the pipeline actually verifies detection behavior — which is exactly the gap this lesson closes.\n\n### What this lesson covers\n\nThis lesson walks through where realistic test data comes from, the positive/negative fixture pattern used to structure that data, how validation and testing fit together as sequential CI stages, tools purpose-built for generating and capturing test telemetry, and how individual rule tests roll up into an organization-wide view of detection coverage gaps.",
        "codeExample": "flowchart LR\n    A[sigma check: validation] --> B{Parses correctly?}\n    B -- No --> C[Fix and re-validate]\n    B -- Yes --> D[sigma convert]\n    D --> E[Execute against positive and negative fixtures]\n    E --> F{Detects the right things, only the right things?}\n    F -- No --> G[Testing: tune the rule]\n    F -- Yes --> H[Proven, deployable detection]",
        "keyPoints": [
          "A syntactically valid, cleanly converted query can still be a false negative (misses real attacks) or false positive (fires on benign activity).",
          "Validation (sigma check) confirms a rule parses correctly; testing confirms it actually detects the right things and only the right things.",
          "Automated CI conversion makes speed easy but raises the stakes of not testing detection behavior before deployment.",
          "This lesson connects individual rule testing to organization-wide detection coverage gap analysis."
        ]
      },
      {
        "pageNumber": 2,
        "title": "Where Test Data Comes From",
        "body": "Testing a converted detection rule requires telemetry that looks like what a real attack — and a real benign look-alike — would actually produce. Four sources cover most practical needs, each with different tradeoffs.\n\n### Atomic Red Team\n\n**Atomic Red Team**, maintained by Red Canary, is an open-source library of small, executable \"atomic tests,\" each mapped directly to a specific MITRE ATT&CK technique or sub-technique ID. Run through the companion `Invoke-AtomicTest` PowerShell cmdlet, an atomic test actually *executes* a miniature version of the technique on a real or disposable host — for the PowerShell encoded-command rule from earlier in this module, an atomic test under T1059.001 genuinely launches an obfuscated PowerShell command and lets your real endpoint logging capture whatever telemetry your actual environment produces.\n\n### MITRE CALDERA\n\n**CALDERA** is an automated adversary emulation platform, also from MITRE, that runs chained \"abilities\" across one or more deployed agents as part of a larger \"operation\" — better suited than a single atomic test when the goal is validating detection across a **multi-step, multi-host** attack chain rather than one isolated technique.\n\n### Splunk's attack_data repository\n\n`splunk/attack_data` on GitHub is a public, community-curated collection of already-captured log datasets, organized by ATT&CK technique ID — usable directly as test fixtures without needing to execute anything yourself, at the cost of the data being captured in someone else's environment rather than yours.\n\n### Manually crafted fixtures\n\nHand-written log lines matching your exact schema remain valuable for edge cases none of the above naturally produce, and for guaranteed-clean \"negative\" baselines built to look deliberately close to — but distinct from — the malicious pattern, which is exactly the next page's topic.",
        "keyPoints": [
          "Atomic Red Team provides small, ATT&CK-mapped tests run via Invoke-AtomicTest that genuinely execute a technique and capture real telemetry.",
          "MITRE CALDERA automates multi-step, multi-host adversary emulation operations, not single isolated techniques.",
          "splunk/attack_data is a public, curated repository of already-captured datasets organized by ATT&CK technique ID.",
          "Manually crafted fixtures cover edge cases and guaranteed-clean negative baselines the other sources don't naturally produce."
        ]
      },
      {
        "pageNumber": 3,
        "title": "The Positive/Negative Fixture Pattern",
        "body": "A single test sample only tells you a rule *can* fire — it says nothing about whether the rule fires *only* when it should. The community convention for closing that gap is the **positive/negative fixture pair**: for every technique a rule targets, keep one fixture that should trigger the rule and one close look-alike that deliberately should not.\n\n### The naming convention\n\nA common, self-documenting convention names fixtures directly after the technique and the expected outcome: `t1059_001_positive.json` sitting alongside `t1059_001_negative.json` in a shared `fixtures/` directory — readable at a glance, without opening either file, by anyone who later needs to understand what the test set covers.\n\n### A concrete pair for the encoded-PowerShell rule\n\n```json\n// t1059_001_positive.json — SHOULD trigger the rule\n{\n  \"EventID\": 1,\n  \"Image\": \"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\n  \"CommandLine\": \"powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=\",\n  \"ParentImage\": \"C:\\\\Windows\\\\System32\\\\cmd.exe\"\n}\n\n// t1059_001_negative.json — should NOT trigger the rule\n{\n  \"EventID\": 1,\n  \"Image\": \"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\n  \"CommandLine\": \"powershell.exe -EncodedCommand JABuAG8AdABoAGkAbgBnAF8AcwB1AHMAcABpAGMAaQBvAHUAcwA=\",\n  \"ParentImage\": \"C:\\\\Windows\\\\System32\\\\TaskScheduler.exe\"\n}\n```\n\nBoth fixtures pass a `-EncodedCommand` flag — that alone should not be enough to trigger a well-written rule. The positive fixture's base64 payload decodes to a `Net.WebClient` download-cradle string, matching `selection_encoded` from the rule built in the previous lesson; the negative fixture's payload decodes to unrelated text, so `selection_encoded` never matches and the overall `condition: selection_img and selection_flag and selection_encoded` correctly stays false.\n\n### Why the negative fixture matters as much as the positive one\n\nA rule that only ever gets tested against positive fixtures can pass every test while still being catastrophically over-broad — the negative fixture is what specifically proves the rule *isn't* just \"any PowerShell with an encoded command,\" a distinction the SOC's alert volume depends on.",
        "codeExample": "// t1059_001_positive.json -- SHOULD trigger the rule\n{\n  \"EventID\": 1,\n  \"Image\": \"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\n  \"CommandLine\": \"powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=\",\n  \"ParentImage\": \"C:\\\\Windows\\\\System32\\\\cmd.exe\"\n}\n\n// t1059_001_negative.json -- should NOT trigger the rule\n{\n  \"EventID\": 1,\n  \"Image\": \"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\n  \"CommandLine\": \"powershell.exe -EncodedCommand JABuAG8AdABoAGkAbgBnAF8AcwB1AHMAcABpAGMAaQBvAHUAcwA=\",\n  \"ParentImage\": \"C:\\\\Windows\\\\System32\\\\TaskScheduler.exe\"\n}",
        "keyPoints": [
          "A positive fixture should trigger a rule; a paired negative fixture, a close look-alike, deliberately should not.",
          "A self-documenting naming convention (e.g., t1059_001_positive.json / t1059_001_negative.json) makes a fixture set readable at a glance.",
          "Negative fixtures specifically prove a rule isn't over-broad, not just that it can fire at all.",
          "Both fixtures in a pair should share as many superficial traits as possible, differing only in the specific detail the rule is meant to catch."
        ]
      },
      {
        "pageNumber": 4,
        "title": "Validating Before You Test: sigma check as Stage One",
        "body": "Testing against real or synthetic data is comparatively expensive — it requires fixtures, a place to run the converted query, and time to review results. Validation is cheap. A well-ordered pipeline always runs the cheap check first.\n\n### The two-stage order, and why it's in this order\n\n```bash\nsigma check encoded_powershell.yml\nsigma convert -t splunk -p splunk_windows encoded_powershell.yml\n```\n\n`sigma check` catches structural problems — a typo in a field-modifier name, a condition referencing a selection identifier that doesn't exist, an invalid `level` value — in milliseconds, before any conversion or fixture-based testing is attempted. There is no value in spending time running a broken rule against test fixtures when a five-second structural check would have caught the same problem for free.\n\n### What happens after validation passes\n\nOnce `sigma check` passes and `sigma convert` produces a query, that query still needs to be executed against the fixtures from the previous page and its results inspected: does it return the positive fixture? Does it correctly exclude the negative fixture? This execution step depends on where the fixtures live — loaded into a disposable test index in the target SIEM, or replayed through a local instance for faster iteration — which the next page addresses directly.\n\n### Treating this as a mandatory gate, not an optional nicety\n\nA CI pipeline that runs `sigma check` and `sigma convert` but stops there — as the previous lesson's pipeline diagram did — has validated that the rule is well-formed and converts cleanly, but has not yet proven it detects anything real. Extending that same pipeline with a fixture-execution stage, and failing the build when a positive fixture doesn't fire or a negative fixture does, is what turns \"the rule looks right\" into \"the rule is proven to work\" before it ever reaches production alerting.",
        "codeExample": "sigma check encoded_powershell.yml\nsigma convert -t splunk -p splunk_windows encoded_powershell.yml",
        "keyPoints": [
          "sigma check is cheap and fast; running it before conversion and testing avoids wasting effort on a structurally broken rule.",
          "Validation confirms a rule is well-formed; it does not confirm the rule actually detects the intended behavior.",
          "The full sequence is: validate, convert, then execute against fixtures and inspect the results.",
          "A CI pipeline that stops at conversion without fixture testing has not proven the rule actually works."
        ]
      },
      {
        "pageNumber": 5,
        "title": "Building a Minimal CI Pipeline",
        "body": "Extending the conversion pipeline from the previous lesson with an actual testing stage follows a consistent conceptual shape, regardless of which specific CI platform (GitHub Actions, GitLab CI, or another) an organization uses.\n\n### The five conceptual stages\n\n1. **Lint** — run `sigma check` against every changed rule; fail fast on structural problems.\n2. **Convert** — run `sigma convert` for every target the organization's SIEM stack requires.\n3. **Load fixtures** — ingest the positive/negative fixture pairs into a disposable or test-scoped backend: a local Splunk or Elastic test container, or a Sentinel workspace populated with test data specifically for this purpose.\n4. **Execute** — run each converted query against the loaded fixtures.\n5. **Assert** — confirm every positive fixture's identifier appears in the results and every negative fixture's identifier does not; fail the build immediately if either check fails.\n\n### Why \"disposable or test-scoped\" matters\n\nRunning rule tests against a production SIEM index risks either polluting real data with synthetic test events or, worse, having a test fixture accidentally trigger a real production alert routed to an on-call analyst. Isolating test execution to a disposable environment (spun up fresh for each test run and torn down afterward) or a clearly test-scoped index/table keeps synthetic fixtures from ever being mistaken for genuine telemetry.\n\n### Visualizing the extended pipeline\n\n```\nflowchart TD\n    A[Rule change pushed to git] --> B[sigma check: lint]\n    B --> C[sigma convert: per target]\n    C --> D[Load positive/negative fixtures into test backend]\n    D --> E[Execute converted query against fixtures]\n    E --> F{Positive fires and negative doesn't?}\n    F -->|Yes| G[Build passes: deploy to production]\n    F -->|No| H[Build fails: block deployment]\n```\n\nThis is a direct extension of the conversion-only pipeline from the previous lesson — the new stages (D through F) are what turn a rule that merely converts cleanly into one that is actually proven, on every single change, to detect what it claims to detect.",
        "codeExample": "flowchart TD\n    A[Rule change pushed to git] --> B[sigma check: lint]\n    B --> C[sigma convert: per target]\n    C --> D[Load positive/negative fixtures into test backend]\n    D --> E[Execute converted query against fixtures]\n    E --> F{Positive fires and negative doesn't?}\n    F -->|Yes| G[Build passes: deploy to production]\n    F -->|No| H[Build fails: block deployment]",
        "keyPoints": [
          "A testing pipeline extends conversion with three more stages: load fixtures, execute the query, and assert on the results.",
          "Fixture-based tests should run against a disposable or clearly test-scoped backend, never production indexes.",
          "The build should fail automatically if a positive fixture doesn't fire or a negative fixture incorrectly does.",
          "This pipeline is a direct extension of the conversion-only pipeline from the previous lesson, not a separate system."
        ]
      },
      {
        "pageNumber": 6,
        "title": "Attack Range and Lab-Based Telemetry Capture",
        "body": "Hand-written fixtures and community datasets cover a lot of ground, but sometimes the most trustworthy test data comes from actually running an attack technique in a controlled lab and capturing whatever your real logging pipeline produces.\n\n### Splunk Attack Range\n\n**Attack Range** is Splunk's open-source project that provisions a small, instrumented lab environment — Splunk itself, one or more Windows/Linux hosts, and optionally supporting tools like Zeek or a Kali attacker box — using Terraform and Ansible, then runs an execution engine (commonly Atomic Red Team) against that lab to generate genuine attack telemetry captured directly into Splunk. Because the environment is disposable (built for the test, then torn down), it sits in an unusual middle ground: fully synthetic in the sense that nothing in it is a real production asset, but fully realistic in the sense that the attack execution and the resulting logs are genuine, not hand-crafted.\n\n### Three sources, three tradeoffs\n\n| Source | Realism | Cost/effort | Matches your exact environment? |\n|---|---|---|---|\n| Hand-crafted fixtures | Depends entirely on the author's accuracy | Lowest | Only if written carefully against your real schema |\n| Community data (splunk/attack_data) | High — genuinely captured | Low (already exists) | Only as closely as their environment resembles yours |\n| Lab-captured (Attack Range / CALDERA) | Highest — real execution, real logging | Highest (infrastructure, time) | As closely as the lab is configured to mirror production |\n\n### Choosing where to invest testing effort\n\nCheap, hand-crafted fixtures are the right default for the bulk of day-to-day rule testing, including most of the positive/negative pairs from earlier in this lesson. Lab-captured telemetry from Attack Range or CALDERA earns its higher cost for a smaller set of high-value rules — ones covering a technique your organization considers especially critical, or ones where you specifically need to confirm behavior against your exact log source version and configuration rather than an approximation of it.",
        "keyPoints": [
          "Splunk Attack Range provisions a disposable, instrumented lab and runs real attack execution (often via Atomic Red Team) into Splunk.",
          "Lab-captured telemetry sits between fully synthetic and production data: disposable infrastructure, but genuine attack execution and logging.",
          "Hand-crafted, community, and lab-captured test data each trade off realism, cost, and how closely they match your real environment.",
          "Higher-cost lab-based testing is best reserved for especially critical techniques rather than every rule by default."
        ]
      },
      {
        "pageNumber": 7,
        "title": "From Individual Rule Tests to Coverage Gap Analysis",
        "body": "Testing one rule at a time answers \"does this specific detection work?\" A hunting and detection program eventually needs the broader answer: across the *entire* MITRE ATT&CK matrix, which techniques have real, tested detection coverage, and which have none at all?\n\n### DeTT&CT\n\n**DeTT&CT** (Detect Tactics, Techniques & Combat Threats), an open-source framework originally created by Rabobank's Cyber Defence Center, is purpose-built for this. It scores **data source quality** (how good is your actual visibility into a given kind of telemetry) and **detection coverage** (how many techniques have a real, working detection) per ATT&CK technique, and it can export that scoring directly as an **ATT&CK Navigator** layer file — a color-coded heatmap over the full ATT&CK matrix showing exactly where coverage is strong, partial, or absent.\n\n### Why testing (this lesson) feeds directly into coverage scoring\n\nA Sigma rule tagged `attack.t1059.001` (from the syntax-basics lesson) that has never actually been executed against a positive/negative fixture pair is, from a coverage-scoring perspective, a claim, not a fact. Once that rule has passing fixture tests in the pipeline from earlier in this lesson, the tag becomes something a tool like DeTT&CT can credit with real confidence — the testing discipline from this lesson is what makes a coverage heatmap trustworthy rather than aspirational.\n\n### Closing the loop across this entire module\n\nThis module's arc has been: build a hunt hypothesis and validate it with KQL (entity baselining, time series analysis), formalize a confirmed finding as a portable Sigma rule (syntax basics), ship that rule to every SIEM the organization runs (backend conversion), and now prove — with real fixtures, not just a clean conversion — that the shipped rule actually detects what it claims to. A technique that makes it through all four stages is a technique a coverage heatmap can honestly mark as covered; a technique still missing any of those stages is exactly the kind of coverage gap the earlier hunt-methodology lessons in this path teach hunters to go looking for next.",
        "keyPoints": [
          "DeTT&CT scores data source quality and detection coverage per ATT&CK technique and exports ATT&CK Navigator heatmap layers.",
          "An untested rule's ATT&CK tag is a claim; a fixture-tested rule's tag is a verified fact a coverage tool can trust.",
          "Coverage gap analysis operates at the level of the whole ATT&CK matrix, not one rule at a time.",
          "This module's full arc is: hypothesize and validate with KQL, formalize as Sigma, convert to every SIEM, then test with real fixtures."
        ]
      },
      {
        "pageNumber": 8,
        "title": "Worked Example: Testing the EncodedCommand Rule End to End",
        "body": "Bringing every piece of this lesson together against the rule built across this module shows the full loop from execution to a verified, deployable detection.\n\n### Step 1: generate real telemetry with Atomic Red Team\n\n```powershell\nInvoke-AtomicTest T1059.001 -TestNumbers 1\n```\n\nRun on a disposable lab host, this executes a real (contained, non-destructive) PowerShell atomic test under technique T1059.001, and the host's own Sysmon Event ID 1 logging captures whatever telemetry the actual execution produces — no hand-crafted assumption about what a \"real\" encoded command line looks like.\n\n### Step 2: capture and confirm the positive fixture\n\nThe captured Sysmon event is exported and saved as `t1059_001_positive.json`, following the naming convention from earlier in this lesson — now backed by genuine execution rather than a manually typed guess.\n\n### Step 3: convert the Sigma rule\n\n```bash\nsigma check encoded_powershell.yml\nsigma convert -t splunk -p splunk_windows encoded_powershell.yml\n```\n\n### Step 4: execute against both fixtures\n\nThe converted SPL runs against the captured positive fixture and the hand-crafted negative fixture (a legitimate scheduled-task PowerShell invocation, also using `-EncodedCommand`, but decoding to unrelated text) from earlier in this lesson. The positive fixture appears in the results; the negative fixture does not.\n\n### Step 5: commit the proof alongside the rule\n\nThe rule, both fixtures, and the passing CI run are committed together to the detection repository — so six months from now, the *evidence* that this rule works travels with the rule itself, rather than living only in one hunter's memory of having tested it once.\n\n### Closing the loop\n\nThis is the complete path from a KQL-validated hunt hypothesis at the start of this module to a Sigma rule that is portable across every SIEM the organization runs, and now provably — not just plausibly — detects the technique it was written for.",
        "codeExample": "# Step 1 -- generate real telemetry\nInvoke-AtomicTest T1059.001 -TestNumbers 1\n\n# Step 3 -- validate then convert\nsigma check encoded_powershell.yml\nsigma convert -t splunk -p splunk_windows encoded_powershell.yml",
        "keyPoints": [
          "Invoke-AtomicTest T1059.001 -TestNumbers 1 runs a real, contained atomic test for a specific technique on a lab host.",
          "A captured positive fixture from real execution is stronger evidence than a hand-typed guess at what the telemetry looks like.",
          "The full loop runs sigma check, then sigma convert, then executes the converted query against both fixtures.",
          "Committing the rule alongside its passing fixtures and CI run preserves proof that the rule works, not just a claim that it does."
        ]
      }
    ],
    "quiz": [
      {
        "question": "A converted Sigma rule passes sigma check with no errors. Per this lesson, what does that alone tell you about whether the rule actually detects the intended attack technique?",
        "options": [
          {
            "label": "Nothing definitive — it only validates structure and logic, not whether the rule matches real attacks or avoids matching benign activity",
            "value": "a"
          },
          {
            "label": "It fully guarantees the rule will never produce a single false positive once it reaches production alerting",
            "value": "b"
          },
          {
            "label": "It fully guarantees the rule will detect every possible variant of the technique it was written to target",
            "value": "c"
          },
          {
            "label": "It means the rule has already been executed successfully against real captured attack telemetry",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The lesson explicitly distinguishes validation (sigma check, which confirms structure and logic) from testing (running the rule against real or synthetic data), and states that passing validation says nothing about actual detection accuracy in either direction."
      },
      {
        "question": "Why does the lesson emphasize pairing every positive fixture with a negative fixture, rather than only testing rules against fixtures that should trigger them?",
        "options": [
          {
            "label": "A negative fixture proves the rule isn't over-broad, since a rule tested only against positives could pass while still matching unrelated benign activity",
            "value": "b"
          },
          {
            "label": "The Sigma file format technically requires exactly two fixture files to exist before a rule is considered valid",
            "value": "a"
          },
          {
            "label": "Negative fixtures always execute measurably faster than positive fixtures inside any continuous integration pipeline",
            "value": "c"
          },
          {
            "label": "A positive fixture on its own cannot technically be loaded into any SIEM's disposable test index or table",
            "value": "d"
          }
        ],
        "answer": "b",
        "explanation": "The lesson states directly that a rule tested only against positive fixtures could still be catastrophically over-broad, and that the negative fixture is what specifically proves the rule discriminates correctly, not just that it can fire at all."
      },
      {
        "question": "In the recommended pipeline order, why does sigma check run before sigma convert and before any fixture-based execution?",
        "options": [
          {
            "label": "Structural validation is fast and cheap, so catching a malformed rule there avoids wasting effort converting and testing something that was broken from the start",
            "value": "c"
          },
          {
            "label": "sigma convert cannot technically run at all until fixtures have already been loaded into a test backend",
            "value": "a"
          },
          {
            "label": "Fixture-based execution always modifies the original rule file, so it must run after validation to avoid corrupting it",
            "value": "b"
          },
          {
            "label": "sigma check and sigma convert are actually the same underlying command with different names",
            "value": "d"
          }
        ],
        "answer": "c",
        "explanation": "The lesson explains this ordering is about cost: validation is cheap and fast, so running it first avoids spending conversion and fixture-testing effort on a rule that a five-second structural check would have already caught as broken."
      },
      {
        "question": "What distinguishes Splunk Attack Range's test telemetry from both hand-crafted fixtures and the community splunk/attack_data repository, according to the lesson?",
        "options": [
          {
            "label": "It provisions a disposable lab and runs real attack execution into it, so the resulting telemetry is genuine even though the infrastructure is temporary",
            "value": "d"
          },
          {
            "label": "It only produces fully synthetic, hand-typed log lines and never executes any real attack technique at all",
            "value": "a"
          },
          {
            "label": "It requires no infrastructure whatsoever and runs its entire simulation inside the sigma-cli tool itself",
            "value": "b"
          },
          {
            "label": "It and the splunk/attack_data repository are actually the exact same project published under two different names",
            "value": "c"
          }
        ],
        "answer": "d",
        "explanation": "The lesson describes Attack Range as sitting in a middle ground: the lab infrastructure is disposable, but the attack execution and resulting telemetry are genuine, unlike hand-crafted fixtures (fully synthetic) or attack_data (pre-captured in someone else's environment, not run fresh by you)."
      },
      {
        "question": "How does DeTT&CT's coverage scoring depend on the fixture-testing discipline covered in this lesson, as the lesson describes it?",
        "options": [
          {
            "label": "An untested ATT&CK-tagged rule is only a claim of coverage; passing fixture tests turn that tag into something a coverage tool can credit with real confidence",
            "value": "a"
          },
          {
            "label": "DeTT&CT requires every single Sigma rule to be fully rewritten in the EQL target before it can be scored",
            "value": "b"
          },
          {
            "label": "DeTT&CT is only capable of scoring ATT&CK techniques that have zero associated Sigma rules written for them",
            "value": "c"
          },
          {
            "label": "Fixture testing and coverage scoring are unrelated activities carried out by completely separate teams",
            "value": "d"
          }
        ],
        "answer": "a",
        "explanation": "The lesson states this connection directly: an untested rule's ATT&CK tag is a claim, while a fixture-tested rule's tag is a verified fact — making the testing discipline from this lesson what turns a DeTT&CT coverage heatmap from aspirational into trustworthy."
      }
    ]
  }
};
