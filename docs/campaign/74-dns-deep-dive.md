# תסריט חדר 74: DNS Internals, Tunneling & Abuse

**שם המבצע:** Operation Deep Query
**רמה:** מתקדם
**העולם:** Cinderhill Observatory (מצפה כוכבים ואתר מחקר בדוי): רכס אחד, קו דק אחד במורד ההר, וסקר שמיים שנמצא באמברגו עוד שנים עשר יום.
**המנטור:** Oskar Bello, Network Forensics Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
האתר סוגר כמעט כל תעבורה יוצאת. דלת אחת נשארת פתוחה, כי בלי שמות שום דבר לא עובד. הלילה הקו של ה-resolver עמוס יותר ממה שהטלסקופים מסבירים, ו-Oskar רוצה לדעת מי ממשיך לשאול שאלות. התשובה מתגלה בשמות עצמם: תחנת עיבוד נתונים מוציאה לוחות סקר דרך שאילתות, החסימה מעירה מחשב שני שמתחיל לנחש דומיינים, אחד הדומיינים החיים מסתובב בין כתובות, ו-sinkhole מגלה מחשב שלישי. בסוף המשמרת נשארת התראה אחרונה אחת.

## המכניקה הייחודית של החדר
- **Read the Query:** הקלטת רשת (`pcap`) של חבילות DNS. סוגי הרשומות וקודי התשובה מספרים את סיפור הלילה: הליכה מלאה במורד העץ, CNAME עד הסוף, TTL שיורד ב-cache, MX ו-SPF, NXDOMAIN מול SERVFAIL, רשומת NULL שמקבלת תשובה, ו-DoT על פורט 853.
- **Three Dials:** מעבדת `tune` עם שלושה חוגים: אורך שאילתה, אנטרופיה ונפח. לכל חוג יש שכן תמים אחר (CDN, טלמטריה של ספקים, שמות קריאים ארוכים), סף גבוה מדי מעוור למנהרת hex, ומנהרה איטית עוברת מתחת לסף, וזה חלק מהשיעור.

## העולם התלת-ממדי
אי קמפוס (`facility`) של המצפה: חמישה מבנים לפי התחנות. עיר ה-Hub נושאת את שם האתר.

## סדר המשימות
r1, o1, r2 | r3, q1, r6, la1, qf1 | r4, q2, la2, q3, f1 | r5, m1 | ac1

(סדר חדש. בחדר המקורי כל הקריאות מרוכזות בהתחלה. r6 לפני la1 כי la1 קורא שדות של Sysmon Event 22, q3 אחרי la2 כי הוא שואל על אותה תחנה, qf1 אחרי la1 כי הוא נשען עליו.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Resolution Path | r1, o1, r2 | **Follow One Lookup, Hop by Hop** (pathway), **Logged at the Resolver, or Lost?** (sort), **Read the Query** (pcap), **What the Wire Still Shows** (simulate) |
| 2 | Inside the Tunnel | r3, q1, r6, la1, qf1 | **Anatomy of a Tunnel Query** (anatomy), **Count the Names** (worksheet), **Three Dials: Length, Entropy, Volume** (tune), **Anatomy of Sysmon Event 22** (anatomy), **From Packet to Process** (trace), **Order of Operations: A Web Shell** (sequence), **Read a Rule Line by Line** (inspect) |
| 3 | Generated Names | r4, q2, la2, q3, f1 | **Generated or Provisioned?** (rush), **Score the Burst** (worksheet) |
| 4 | Flux and Sinkholes | r5, m1 | **Flux, Balance or Sinkhole?** (reactor), **Who Knocked on the Sinkhole?** (queue) |
| 5 (בוס) | Port 443 | ac1 | **True, Benign or False?** (defuse), ואז ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- שאלת הביניים של r1 (של מי הלוג שמחזיק את ההליכה): ההערות של **Follow One Lookup** מראות שרק ה-resolver הולך במורד העץ, על מחשב נייד ו-plates.skyportal.example. המעבדה לא שואלת על לוגים, ובמעבדה אין "דומיין חדש ב-.com".
- o1 (סדר שמונה שלבים): אותו רעיון, אבל כמפה של קפיצות עם שמות שרתים. ההערות מלמדות cache ב-resolver וגם ב-stub, בלי ניסוח השלבים הנבחנים.
- q1 ושאלת הביניים של r3 (יחס ייחודיים לכלל): **Count the Names** מחשב את היחס על 600 שאילתות ו-594 ייחודיים, לא 200, 498 או 6. קוד NOERROR בשדה rcode_name ושדה TTLs ב-**Anatomy of a Tunnel Query** מלמדים למה NXDOMAIN ו-cache לא מתארים מנהרה, ושדה proto מלמד למה התעבורה לא מוכיחה דבר.
- la1 שאלה 1: **Anatomy of a Tunnel Query** ו-**Three Dials** על NULL ו-base32 תחת pm.plate-mirror.example, לא TXT ו-hex תחת הדומיין הנבחן. QueryStatus 0 נלמד ב-**Anatomy of Sysmon Event 22**. ההבדל מ-DGA נראה ב-rcode: מנהרה חייבת להצליח.
- la1 שאלה 2: שדה Image ושדה User ב-**Anatomy of Sysmon Event 22** על fitsview.exe תקין, ו-Read the Query מלמד ש-TXT שגרתי בשרת דואר ולא בתחנת עבודה. בלי PowerShell.
- la1 שאלה 3: **Order of Operations: A Web Shell** מלמד את סדר הפעולות על אירוע אחר לגמרי, web shell ב-ch-web02 מהאביב שעבר, בלי מנהרה, בלי כלי סנכרון או allowlist, ובלי צמד של reimage וסגירה.
- qf1: **Read a Rule Line by Line** מציג חוק על טבלת Zeek עם NULL, חלון 20m, סף 400 ויחס 0.6. כולם מחוץ לטווחי התשובות. שורה שנזרקה מלמדת את מלכודת ה-80 ושורה שנייה את חילוק המספרים השלמים.
- שאלת הביניים של r6 (אין Event 22): **From Packet to Process** על NULL מ-platesync.exe, לא TXT. הסיכום של האנטומיה מזכיר את העיוורון כנתון.
- q3: **From Packet to Process** מראה ש-Zeek ו-DHCP נעצרים בכתובת ובמכונה, על מנהרה ולא על פרץ NXDOMAIN.
- q2 ושאלת הביניים של r4: **Generated or Provisioned?** עם קלפים ו-qvztkpl.example. לא 300 דומיינים, לא 96%, לא cloudfront עם אותו שם.
- la2 שאלה 1: **Score the Burst** על ch-dome-ctl2 עם 180 שמות ו-171 כישלונות ב-12 דקות, לא 340 ו-318 ב-8 דקות.
- la2 שאלה 2: התקרה log2(length) נלמדת על 16 ו-4 תווים, לא על 8 תווים ולא על kqxpzr4t.
- la2 שאלה 3: ב-**Score the Burst**, השאלה על השמות שלא נכשלו מלמדת למה הם רשימת ה-pivot, והשאלה על ה-sinkhole מסבירה רק שאין מה לצפות בשם שלא נרשם. הבידוד נלמד ב-**Order of Operations: A Web Shell**.
- f1: **Score the Burst** מחשב 180 פחות 171, והתשובה הנבחנת היא חשבון אחר על נתוני la2.
- m1: כל זוג נלמד בנפרד: NXDOMAIN ב-Generated or Provisioned?, TXT ב-Anatomy of a Tunnel Query, TTL קצר ב-Flux, Balance or Sinkhole?, sinkhole ב-Who Knocked on the Sinkhole?, יחס ב-Count the Names, ו-DoH ב-What the Wire Still Shows.
- ac1: האות המכריע נלמד במעבדה משלו, **True, Benign or False?**: DoT על מחשב לינוקס (benign), חוק שירה על נקודת קצה של האתר (false) ושתי פריצות אמיתיות (true). אין דפדפן, אין מחשב מפתחים ואין 1.1.1.1. העובדה הכללית על דפדפנים ועל דפוס התעבורה של DoH מופיעה בתרחיש DoH של **What the Wire Still Shows**, שלא שואל שאלה.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "One Door Open" | כניסה | תחנה 1 |
| Chapter 2: "Nineteen Minutes" | אחרי Inside the Tunnel | תחנה 3 |
| Chapter 3: "Someone Knocked" | אחרי Flux and Sinkholes | תחנה 5 |
| Finale: "First Light" | אחרי Port 443 | החדר הבא |
