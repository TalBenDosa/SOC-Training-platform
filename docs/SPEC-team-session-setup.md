# אפיון: הקמת אימון צוותי — בחירת התקפות ובחירת מקורות מידע (Data Sources)

**סטטוס:** טיוטה לאישור · **תאריך:** 2026-10-01 · **בעלים:** Tal · **מבוסס על מיפוי הקוד הקיים (main `df50ad5`)**

---

## 1. המטרה

שמי שמפעיל את האימון (אדמין המכללה / מדריך) יוכל לבנות אימון **שתואם לסביבה האמיתית של המתרגלים**:

1. **לבחור עד 4 סוגי התקפות** לאימון — או להשאיר "רנדומלי".
2. **לבחור לכל סוג מקור מידע את הספק (Vendor)** שיש בארגון — EDR (CrowdStrike / Defender / SentinelOne / Sophos), חומת אש (FortiGate / Check Point / Palo Alto / Cisco), דואר ושיתוף (Microsoft 365 / Google Workspace), זהויות (Entra ID / Okta / AD מקומי) וכו'.
3. **כל לוג באימון — התקפות, רעשי רקע, הזרקות, תיקי ServiceNow וקונסולת ה-EDR — יופיע בפורמט האמיתי של הספק שנבחר**, בלי שום שדה של ספק אחר.

**עיקרון-על:** ספק לא תואם הוא לא רק "לא ריאליסטי" — הוא **רמז**. אם כל לוגי הרקע הם Defender ורק ההתקפה היא CrowdStrike, המתרגל מזהה את ההתקפה לפי הפורמט ולא לפי התוכן. לכן הכלל: **ספק אחד לכל קטגוריה, בכל לוג באימון.** (זה הלקח של תיקון L-03 שכבר קיים ל-EDR.)

---

## 2. המצב היום (מה מיפיתי בקוד)

### 2.1 תהליך יצירת אימון
| שלב | היום | קובץ |
|---|---|---|
| בונה האימון | בוחרים **חברה** (5 חברות), **רמת קושי**, ו**Storyline אחד** (או רנדומלי), ומזמינים משתתפים לתפקידים | `src/app/(app)/team/page.tsx` |
| יצירה | נשמר `company_id`, `difficulty`, `scenario_id`, `format` | `src/app/api/team/sessions/route.ts` |
| התחלה | `buildTeamTimeline(company, difficulty, seed, scenario_id, load)` בונה את כל הפיד ונשמר ב-`session_injects` | `src/app/api/team/sessions/[id]/start/route.ts` |
| כמות התקפות | נקבעת אוטומטית לפי קושי וגודל צוות: **1–3 Storylines** + **0–7 התקפות בודדות** מהמאגר | `src/lib/team/load.ts` |

- יש עמודת `team_sessions.config jsonb` **ריקה ולא בשימוש** — מוסתרת כבר ממשתתפים שאינם צוות. מתאימה בדיוק לשמירת ההגדרות החדשות.
- רק Storyline **אחד** ניתן לבחירה; השני והשלישי תמיד רנדומליים.

### 2.2 ה"סביבה" היום = חברה עם ספקים קבועים
| חברה | EDR | חומת אש | דואר | זהויות | ענן | VPN / Proxy |
|---|---|---|---|---|---|---|
| NexaCorp (פיננסים) | Defender for Endpoint | Palo Alto | Microsoft 365 | Entra ID + AD | Azure | GlobalProtect |
| RocketStack (SaaS) | CrowdStrike | FortiGate | **Google Workspace** | Okta | AWS | Cloudflare Access |
| MedCore (בית חולים) | SentinelOne | **Check Point** | Microsoft 365 | AD + Entra hybrid | Azure | AnyConnect |
| GlobalLogis (לוגיסטיקה) | Sophos | Cisco Firepower | Microsoft 365 | AD | AWS | AnyConnect |
| QuantumBank (בנק) | CrowdStrike | Palo Alto | Microsoft 365 | Okta + CyberArk | AWS GovCloud | Zscaler |

כלומר: אי אפשר היום "NexaCorp עם CrowdStrike ו-FortiGate" — הספקים מגיעים ב"חבילה" עם החברה.

### 2.3 כיסוי הספקים בלוגים (ספירה בפועל)
**87 Storylines** (23 בסיס · 28 בינוני · 36 מתקדם), **57 מהם מוצמדים לחברה מסוימת**. סה"כ 753 לוגי התקפה.

| קטגוריה | איך ההתקפות כתובות היום | מה קיים לספקים אחרים |
|---|---|---|
| **EDR** (165 לוגים) | ~150 ב-CrowdStrike, ~11 ב-Defender | **יש המרה אוטומטית** (L-03) ל-Defender / SentinelOne / Sophos — אבל **מינימלית**: מוחקת שדות זרים ומוסיפה 2–5 שדות של הספק. יש Emitters מלאים ל-CrowdStrike, Defender, SentinelOne (`src/lib/sim/emitters`). Sophos — אין Emitter. |
| **חומת אש** (70) | ~60 Palo Alto, ~9 FortiGate | **אין המרה ב-Storylines.** יש מיפוי ל-4 ספקים רק בלוגי התמיכה של ההזרקות (`firewallRaw` ב-`buildTimeline.ts`). יש Emitters ל-FortiGate, Check Point, Palo Alto. Check Point ו-Cisco מופיעים רק במאגר הרעש של MedCore / GlobalLogis. |
| **דואר / שיתוף** | 86 Microsoft 365 / Entra · **17 Google Workspace** (3 Storylines) | **אין המרה** M365 ↔ Google. |
| **אבטחת דואר** | 14 Defender for Office 365 · 2 Proofpoint | — |
| **זהויות** | 62 Windows/AD · 41 Okta · Entra בתוך M365 | **אין המרה** Entra ↔ Okta. |
| **ענן** | 83 AWS · 17 Azure | GCP — אין בכלל. |
| **Proxy** | 35 Zscaler | Palo Alto URL במאגר הרעש. |
| **רעש רקע** | מאגר משותף (415 לוגים) מוטה Microsoft/Palo Alto + מאגר לכל חברה בספקים שלה | — |

**קונסולת ה-EDR** (`/edr`) בנויה בסגנון CrowdStrike Falcon (עץ תהליכים, RTR). השמות והמונחים לא משתנים לפי ספק.

**אין "סוג התקפה" כשדה** — ל-Storyline יש רק `id`, `title`, `complexity`, `companies`. צריך להוסיף טקסונומיה.

### 2.4 המסקנה
- **בחירת עד 4 התקפות** — שינוי בינוני: התשתית קיימת (Storyline נבחר + `load.stories`), חסרים טקסונומיה, UI, ותמיכה ב-4 במקום 3.
- **בחירת ספקים** — זה הלב הגדול: צריך **שכבת התאמת ספקים (Vendor Adapters)** לכל קטגוריה, ובסיס רעש שמומר גם הוא. EDR כבר באמצע הדרך; חומת אש קרובה (יש Emitters); דואר וזהויות הם העבודה הכבדה.

---

## 3. חוויית המשתמש החדשה — אשף הקמת אימון

הבונה הקיים הופך לאשף של 5 שלבים. כל שלב שומר טיוטה; אפשר לחזור אחורה.

### שלב 1 — הסביבה (מי הארגון)
- **ארגון בסיס**: בוחרים אחת מ-5 החברות (התעשייה, המשתמשים, השרתים, הדומיין) — **בנפרד** מהספקים.
  - הסיבה להפריד: זהות הארגון (שמות משתמשים, שרתים, תעשייה) והספקים הם שני דברים שונים. "בית חולים עם CrowdStrike" הוא שילוב לגיטימי.
- **פרופיל סביבה שמור** (מומלץ): המכללה שומרת את הסטאק האמיתי שלה פעם אחת ("הסביבה שלנו"), והוא נטען אוטומטית בכל אימון.

### שלב 2 — מקורות המידע (Data Sources)
טבלה אחת, שורה לכל קטגוריה, בחירת ספק בכל שורה:

| קטגוריה | אפשרויות |
|---|---|
| EDR | CrowdStrike Falcon · Microsoft Defender for Endpoint · SentinelOne · Sophos Intercept X |
| חומת אש / NGFW | Palo Alto · Fortinet FortiGate · Check Point · Cisco Firepower |
| דואר ושיתוף | Microsoft 365 · Google Workspace |
| אבטחת דואר | Defender for Office 365 · Proofpoint *(שלב 3)* |
| ספק זהויות (IdP) | Microsoft Entra ID · Okta |
| Active Directory מקומי | יש / אין |
| ענן | AWS · Azure · אין *(GCP — שלב 3)* |
| VPN | GlobalProtect · Cisco AnyConnect · FortiGate SSL-VPN · Zscaler ZPA · Cloudflare Access |
| Proxy / SWG | Zscaler · Palo Alto URL Filtering · אין |
| DNS | Windows DNS · Infoblox |

**ליד כל אפשרות — תג כיסוי** (מחושב אוטומטית, לא ידני):
- ✅ **מלא** — כל ההתקפות והרעש קיימים או מומרים בפורמט מלא.
- ◐ **חלקי** — חלק מסוגי ההתקפות לא זמינים בבחירה הזאת (מוצג כמה ולמה).
- 🔒 **בקרוב** — עדיין לא נתמך (אפור, לא ניתן לבחירה).

**ברירת מחדל**: הסטאק של ארגון הבסיס (כמו היום) — כך שמי שלא משנה כלום מקבל בדיוק את ההתנהגות הנוכחית.

### שלב 3 — ההתקפות
- **מצב "רנדומלי"** (ברירת מחדל): כמו היום — המערכת בוחרת לפי קושי וגודל צוות.
- **מצב "אני בוחר"**: עד **4** סוגי התקפות מתוך קטלוג מקובץ (ראו סעיף 5).
  - כל כרטיס מציג: שם, תיאור קצר, **מקורות המידע שהוא צריך** ("דורש: EDR, AD, חומת אש"), ורמות הקושי שבהן הוא זמין.
  - סוג שלא ניתן לבנות עם הסטאק שנבחר — **אפור עם הסבר** ("Kerberoasting דורש Active Directory מקומי").
  - **מתקדם (אופציונלי):** בחירת Storyline מסוים בתוך סוג (כמו הבחירה היחידה שקיימת היום).
  - אפשר לערבב: 2 סוגים נבחרים + "השלם רנדומלית".
- **אזהרת עומס**: 4 התקפות עם 2 משתתפים → "עומס גבוה לצוות בגודל הזה — מומלץ עד 2". (אזהרה, לא חסימה.)
- **ההתקפות הבודדות מהמאגר** (Pool attacks) נשארות אוטומטיות לפי הקושי, ומסוננות גם הן לפי הסטאק.

### שלב 4 — קושי וקצב
רמת קושי (קיים) · משך משמרת · הזרקות הנהלה/Help Desk פעילות או לא · עוצמת רעש (רגיל / גבוה).

### שלב 5 — צוות וסיכום
הזמנת משתתפים ותפקידים (קיים) + **כרטיס סיכום**: הסביבה, הסטאק, ההתקפות (שם הסוג בלבד — המשתתפים לא רואים), הקושי. כפתור "צור אימון".

**מה המשתתפים רואים:** בלובי — רק את הסטאק ("הסביבה שלכם: CrowdStrike · FortiGate · Microsoft 365 · Okta"), כמו תדריך משמרת אמיתי. **לא** את סוגי ההתקפות.

---

## 4. מודל הנתונים

### 4.1 `team_sessions.config` (העמודה הקיימת)
```json
{
  "version": 1,
  "environment": {
    "base_company": "medcore",
    "stack": {
      "edr": "crowdstrike", "firewall": "fortigate", "collab": "m365",
      "email_security": "defender_o365", "idp": "entra", "onprem_ad": true,
      "cloud": "azure", "vpn": "anyconnect", "proxy": "none", "dns": "infoblox"
    }
  },
  "attacks": {
    "mode": "choose",
    "picks": [
      { "type": "phishing_delivery" },
      { "type": "ad_attacks", "story_id": "kerberoasting" },
      { "type": "ransomware" }
    ],
    "fill_random": false
  },
  "pacing": { "injects": true, "noise": "normal" }
}
```
- `company_id` ו-`scenario_id` נשארים (תאימות לאחור). אימון ישן בלי `config` → ההתנהגות של היום.
- `config` כבר מוסתר ממשתתפים שאינם צוות (`redact` ב-GET) — סוגי ההתקפות לא דולפים.
- **ה-seed + ה-config** קובעים את האימון באופן דטרמיניסטי (לדוח ולשחזור).

### 4.2 טבלה חדשה `org_environment_profiles`
`id · org_id · name · stack jsonb · base_company · is_default · created_by · updated_at` — RLS: קריאה לצוות המכללה, כתיבה ל-org_admin. "הסביבה שלנו" של כל מכללה.

### 4.3 ולידציה בשרת (`POST /api/team/sessions`)
- כל ספק מתוך רשימה סגורה; קטגוריה עם 🔒 → 400.
- עד 4 picks; כל `type` מהקטלוג; כל `story_id` חייב להיות זמין לשילוב (חברה × קושי × סטאק) — כמו `resolveTeamStory` היום.
- אם אין אף Storyline שמתאים לסוג שנבחר בסטאק הזה → 400 עם הסבר ברור.

---

## 5. קטלוג סוגי ההתקפות (טקסונומיה)

שדה חדש `type` לכל Storyline (מיפוי חד-פעמי של 87 הקיימים; בדיקה אוטומטית שאין Storyline בלי סוג):

| סוג (type) | דוגמאות מהקיים | בערך |
|---|---|---|
| `phishing_delivery` — פישינג והפצת נוזקה | phishing-malware, malicious-macro, iso-container, ai-svg-invoice, gws-phish-attachment | 8 |
| `commodity_malware` — נוזקה נפוצה | usb-malware, cracked-software, trojanized-keylogger, clickfix, clipboard-clipper, fake-browser-update, seo-poisoned | 10 |
| `ransomware` — כופרה וסחיטה | ransomware, esxi-ransomware, exfil-first-extortion, medcore-chain-a | 4 |
| `credential_attacks` — ניחוש/ריסוס סיסמאות | bruteforce-single, okta-password-burst, nexacorp-chain-d, quantumbank-chain-d | 5 |
| `account_takeover` — השתלטות על חשבון וגניבת Session | impossible-travel, aitm-token-theft, infostealer-session-theft, mfa-fatigue, helpdesk-mfa-reset | 8 |
| `bec` — הונאת דוא"ל עסקית | bec, nexacorp-chain-b, oauth-consent | 4 |
| `ad_attacks` — תקיפות Active Directory | dcsync, kerberoasting, asrep-roasting, ntlm-relay, rogue-admin | 5 |
| `insider_threat` — איום פנימי וגניבת מידע | insider, nexacorp-chain-c, medcore-chain-b, globallogis-chain-c | 5 |
| `cloud_compromise` — פריצה לענן | cryptomining, rocketstack-chain-a/c/d, k8s-pod-escape | 7 |
| `web_edge_exploit` — ניצול אפליקציה/רכיב קצה | webshell-rce, edge-vpn-cve-exploit, ai-agentic-intrusion | 3 |
| `supply_chain` — שרשרת אספקה ו-CI/CD | supply-chain, rocketstack-chain-b, rs-cicd-pipeline, rs-terraform | 4 |
| `c2_evasion` — תקשורת שליטה והתחמקות | dns-tunneling, lolbins, scheduled-task-persistence | 3 |
| `ai_misuse` — שימוש לרעה ב-AI | 12 ה-Storylines של AI | 12 |
| `financial_fraud` — הונאה פיננסית | qb-swift-wire-fraud, qb-cyberark-mule-payout, qb-fraud-monitoring | 4 |

הבחירה: לכל סוג שנבחר — Storyline אחד, רנדומלי מתוך הזמינים (קושי × סטאק × ארגון בסיס), שונה מהאחרים. **4 סוגים = עד 4 תקריות במקביל** (היום התקרה 3) — מוסיפים רצועת מיקום רביעית בציר הזמן.

---

## 6. הלב הטכני: שכבת התאמת ספקים (Vendor Adapters)

### 6.1 הגישה
לא כותבים כל התקפה מחדש לכל ספק (87 × 4 × 4 × 2… = בלתי אפשרי). במקום זה, לכל קטגוריה:

```
לוג מקורי (בפורמט שבו נכתב)
   → parse: חילוץ "אירוע קנוני" (מה קרה: תהליך, חיבור, התחברות, פעולת מייל…)
   → render: Emitter של הספק שנבחר (src/lib/sim/emitters/*)
   → לוג בפורמט הספק, עם אותם ערכים (משתמש, מחשב, IP, Hash, זמן)
```

- **הערכים זהים, רק הפורמט משתנה** — המתרגל צריך לצטט את ה-raw בדו"ח, אז ה-IP / Hash / שם משתמש חייבים להישאר.
- הכלל "**לא ממציאים**": אם לפעולה אין מקבילה אמיתית אצל הספק (למשל פעולת Exchange שאין לה מקבילה ב-Gmail) — **ה-Storyline לא מוצע בסטאק הזה** (תג ◐), במקום לזייף לוג.

### 6.2 לפי קטגוריה

| קטגוריה | מה קיים | מה צריך |
|---|---|---|
| **EDR** | המרה מינימלית ל-4 ספקים (`reshapeEdrRaw`) + Emitters ל-CrowdStrike/Defender/SentinelOne | (1) לשדרג את ההמרה לפורמט **מלא** דרך ה-Emitters (process / network / file / dns / detection / registry). (2) Emitter ל-Sophos. (3) **"עור" לקונסולת ה-EDR** לפי ספק: מונחים (RTR ↔ Live Response ↔ RemoteOps), שמות שדות בעץ התהליכים, לוגו/צבעים. |
| **חומת אש** | Emitters ל-FortiGate / Check Point / Palo Alto; מיפוי 4 ספקים ללוגי תמיכה (`firewallRaw`) | Parser מ-Palo Alto/FortiGate לאירוע קנוני (src, dst, ports, action, app, url, category, bytes, rule, threat) + Emitter ל-Cisco Firepower. הכללת `firewallRaw` לכל לוגי ה-Storylines והרעש. |
| **דואר ושיתוף** | 86 לוגי M365, 17 Google | **טבלת מקבילות** M365 ↔ Google Workspace: התחברות, קבלת מייל, כלל העברה, גישה לתיבה, הורדה/שיתוף קובץ (SharePoint/OneDrive ↔ Drive), אפליקציית OAuth. Emitter ל-Google Workspace (Admin/Login/Drive/Gmail logs). פעולות בלי מקבילה → סימון ה-Storyline כ"דורש M365". |
| **זהויות** | Emitters ל-Entra ול-Okta | Parser ⇄ בין Entra sign-in/audit ל-Okta System Log (התחברות, כשל, MFA push, שינוי מדיניות, הוספת מכשיר). **AD מקומי** הוא תוספת (Windows Security 4624/4768/4769…) — Storyline שדורש AD לא מוצע בסטאק בלי AD. |
| **ענן** | AWS (CloudTrail/GuardDuty), מעט Azure | בשלב 1–2: Storyline ענן מוצע רק אם יש את הענן שהוא נכתב עליו. המרת AWS ↔ Azure — שלב 3 (פעולות לא חד-חד-ערכיות). |
| **VPN / Proxy / DNS** | GlobalProtect, AnyConnect, FortiGate VPN, Zscaler, Infoblox, Windows DNS | Parser + Emitter לכל אחד (לוגים פשוטים יחסית). |

### 6.3 עקביות בכל האימון
1. **ספק אחד לכל קטגוריה** בכל לוג: Storylines, התקפות מהמאגר, רעש, לוגי תמיכה להזרקות, רשומות ServiceNow.
2. **שמות מוצרים בטקסט** (תיאור, כותרת התראה) מוחלפים לספק שנבחר — הכללה של `EDR_PRODUCT_NAMES` לכל הקטגוריות.
3. **רעש הרקע** נבנה מהמאגר של ארגון הבסיס **ומומר** לסטאק — אחרת הספק עצמו הופך לרמז (סעיף 1).
4. **מקורות שלא קיימים בסטאק לא מופיעים** — בלי ענן, אין CloudTrail; בלי Proxy, אין Zscaler.
5. **ה-SIEM שמציג** — כל הלוגים מוצגים במעטפת אחידה (כמו היום). מעטפת לפי SIEM (Sentinel / Splunk / Elastic) — שלב 3, החלטה פתוחה.

### 6.4 בחירת Storyline לפי יכולות
לכל Storyline מחשבים אוטומטית **רשימת דרישות** מתוך הלוגים שלו (קטגוריה + פעולה), למשל: `edr`, `windows_ad`, `m365_mailbox_rule`, `aws`. ה-Storyline זמין לסטאק אם **כל** לוג בו (א) מקטגוריה שקיימת בסטאק ו-(ב) ניתן להמרה לספק שנבחר. זה מחליף את כלל "התאמת המקורות" (`sourceFitRatio`) של היום, וזה גם מה שמזין את תגי הכיסוי באשף.

---

## 7. בדיקות ושערי איכות

1. **ולידטור נאמנות לספק** (חדש) — לכל לוג באימון: אין שדה של ספק אחר; כל שדות הליבה של הספק קיימים (לפי קבצי ייחוס השדות: CrowdStrike, Defender, SentinelOne, FortiGate, Check Point, Palo Alto, Entra, Okta, Google Workspace).
2. **מטריצת שילובים** — טסט שבונה ציר זמן לכל צירוף מרכזי (ספק × קטגוריה) ובודק: עקביות ספק, אפס שדות זרים, אותם ערכי ראיה לפני ואחרי ההמרה, כמות התקפות = מה שנבחר.
3. **דטרמיניזם** — אותו seed + config → אותו אימון (חשוב לדוח ולשחזור).
4. **אין דליפת תשובות** — `check:client-answers` ובדיקת `TEAM_ANSWER_FIELDS` ממשיכים לעבור; סוגי ההתקפות לא נשלחים למשתתפים.
5. **ניקוד ודוח** — הדוח והניקוד הצוותי (0087) עובדים זהה בכל סטאק.
6. **תאימות לאחור** — אימון בלי `config` מייצר בדיוק את מה שהוא מייצר היום (Snapshot).

---

## 8. שלבי ביצוע

### שלב 1 — בחירת התקפות + EDR וחומת אש (הכי הרבה ערך, סיכון נמוך)
- טקסונומיית `type` ל-87 ה-Storylines + טסט כיסוי.
- אשף: שלבים 1, 3, 5 + שורות EDR וחומת אש בשלב 2 (שאר הקטגוריות לפי ארגון הבסיס).
- `config` בשרת + ולידציה; עד 4 תקריות (רצועה רביעית ב-`buildTeamTimeline`, `load.stories` = מספר הנבחרים).
- EDR: המרה מלאה דרך Emitters (כולל Sophos) + עור לקונסולה.
- חומת אש: Parser + Emitters ל-4 הספקים, על Storylines + רעש + לוגי תמיכה.
- ולידטור נאמנות + מטריצת שילובים ל-EDR × חומת אש.
- **קבלה:** אדמין בונה "MedCore + CrowdStrike + FortiGate + Kerberoasting + Ransomware" — כל לוג EDR בפורמט CrowdStrike, כל לוג חומת אש בפורמט FortiGate, 2 תקריות בדיוק, אין שדה זר אחד.

### שלב 2 — דואר וזהויות + פרופילי סביבה
- Adapters ל-M365 ↔ Google Workspace ול-Entra ↔ Okta, AD כן/לא.
- חישוב דרישות לכל Storyline + תגי כיסוי באשף.
- `org_environment_profiles` + "הסביבה שלנו" כברירת מחדל במכללה.
- VPN / Proxy / DNS.
- **קבלה:** אימון BEC בסביבת Google Workspace + Okta — כל לוגי הדואר בפורמט Google, ההתחברויות ב-Okta; Storyline שדורש Exchange לא מוצע (◐ עם הסבר).

### שלב 3 — הרחבות
GCP ו-Azure מלא · אבטחת דואר (Proofpoint / Mimecast) · מעטפת לפי SIEM · ספקים נוספים (Cortex XDR, Carbon Black, Netskope) · אותה בחירה גם בדשבורד היחידני.

---

## 9. החלטות שצריכות אישור

| # | שאלה | המלצה |
|---|---|---|
| 1 | ספקים לבחירה חופשית או רק "חבילות" מוכנות? | **בחירה חופשית** לכל קטגוריה + חבילות מוכנות (5 החברות) כנקודת התחלה. |
| 2 | להפריד בין זהות הארגון (משתמשים/שרתים/תעשייה) לספקים? | **כן** — "בית חולים עם CrowdStrike" צריך להיות אפשרי. |
| 3 | מה קורה כשסוג התקפה לא זמין בסטאק? | **אפור עם הסבר**, לא מזייפים לוג. |
| 4 | 4 התקפות עם צוות קטן — לחסום או להזהיר? | **להזהיר** בלבד. |
| 5 | המשתתפים רואים את הסטאק בלובי? | **כן** (כמו תדריך משמרת), אבל **לא** את סוגי ההתקפות. |
| 6 | מעטפת לפי SIEM (Sentinel / Splunk / Elastic)? | לדחות לשלב 3. |
| 7 | גם בדשבורד היחידני? | אחרי שהאימון הצוותי יציב (שלב 3). |

---

## 10. סיכונים

| סיכון | התמודדות |
|---|---|
| התפוצצות שילובים (ספקים × התקפות) | אירוע קנוני + Emitters + מטריצת טסטים אוטומטית, לא כתיבה ידנית לכל שילוב. |
| המרה שמאבדת ראיה (IP / Hash / משתמש) | טסט "אותם ערכי ראיה לפני ואחרי"; הדוח מצטט את ה-raw. |
| פעולות בלי מקבילה אמיתית בין ספקים | Storyline לא מוצע בסטאק (◐) — אין לוגים מומצאים. |
| רעש רקע שלא תואם לספק = רמז | גם הרעש עובר את אותה המרה; ולידטור עקביות על כל האימון. |
| רגרסיה באימונים קיימים | אימון בלי `config` = ההתנהגות של היום (Snapshot). |
