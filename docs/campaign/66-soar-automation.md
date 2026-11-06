# תסריט חדר 66: SOAR and Security Automation

**שם המבצע:** Operation Autopilot
**רמה:** בינוני
**העולם:** Cobalt Ridge Logistics (חברת הובלה בקירור בדויה): 640 עובדים, ארבעה דיפואים, צי שלא עוצר, וצוות SOC של ארבעה אנליסטים.
**המנטור:** Freya Dlamini, SOAR Engineer. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שני ב-07:12 Playbook של דיווחי פישינג השבית את חשבון המנכ"ל, 48 דקות לפני חתימת החוזה הגדול בתולדות החברה. פגיעה ישנה אחת מפיד מוניטין ובדיקה אחת שנכשלה עשו את זה, ואף אדם לא ראה. הדירקטוריון רוצה לכבות את הבוט, וארבעת האנליסטים אומרים שבלעדיו הם טובעים. ל-Freya Dlamini יש עד יום שישי להראות מה מותר לרוץ לבד.

## המכניקה הייחודית של החדר
- **Trust the Automation?:** שני חלקים. **Run Phish Report on Real Cases** (`simulate`): הלומד מריץ את ה-Playbook החדש על ארבעה תיקים אמיתיים, כולל התיק של יום שני, וכל בדיקה עוברת או נכשלת וקובעת מה ה-Playbook עושה. **The Trust Dial** (`tune`): שני חוגים, סף ביטחון ותקרת Blast Radius, קובעים מה רץ בלי אדם. קשוח מדי והאנליסטים טובעים, רופף מדי והבוט משבית שוב את המנכ"ל.
- **Bad Lookup, Live Run** (`defuse`): ארבע ריצות של הגרסה הישנה, כל אחת שניות לפני פעולה על מידע שאסור להאמין לו. השיעור: כל פעולה יורשת את הבדיקה החלשה ביותר שמתחתיה.

## העולם התלת-ממדי
אי קמפוס (`facility`) של החברה: ארבעה מבנים לפי התחנות. עיר ה-Hub נושאת את שם החברה.

## סדר המשימות
r1, q1, r2, q2, o1 | r3, q3, m1 | la1, la2, r4 | ac1, flag1

זה סדר חדש: בחדר כל הקריאות מופיעות קודם, ו-la2 ו-ac1 צריכים את r3 ואת r4 לפניהם.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Playbook | r1, q1, r2, q2, o1 | **Detector, Sprinkler or Analyst?** (sort), **Three Words in the Name** (match), **Put a Playbook in Running Order** (sequence), **Reads, Changes, Records or Sorts?** (sort), **Which Lookup Answers It?** (match) |
| 2 | The Gate | r3, q3, m1 | **One Action for Each Move** (duel), **Where Does the Line Go?** (sort), **Run Phish Report on Real Cases** (simulate) |
| 3 | The Dial | la1, la2, r4 | **Anatomy of a Raw Failed-Logon Alert** (anatomy), **Already There, or Needs a Lookup?** (sort), **Who Is Behind the Account?** (inspect), **Two Logon Myths** (inspect), **Anatomy of an Enriched Case** (anatomy), **Read the Run Log** (evidence), **Bad Lookup, Live Run** (defuse), **The Trust Dial** (tune), **Close, Escalate or Queue?** (sort), **Did the Bot Earn Its Keep?** (worksheet) |
| 4 (בוס) | Trust the Automation? | ac1, flag1 | **Three Kinds of Alert That Fired** (sort), **Read the Enrichment, Not the Recommendation** (queue), **Which Record Explains Why?** (trace) |

**הפרדה מהשאלות הנבחנות:**
- שאלת הביניים של r1 (Orchestration): נלמד ב-Three Words in the Name, על זרימה של שער דואר, דיירקטורי ותור תיקים, לא SIEM, VirusTotal, AD ו-ServiceNow. Correlation מוצג כמשימה של ה-SIEM.
- q1 (היחס בין SIEM ל-SOAR): נלמד ב-Detector, Sprinkler or Analyst? על משימות של Cobalt Ridge. ההסברים אומרים ש-SOAR לא מחליף את ה-SIEM ושאין לו מה להריץ בלי התראה.
- q2 (שם הקטגוריה): נלמד ב-Reads, Changes, Records or Sorts?, על hash, גיל דומיין ומחלקה, לא על הצירוף של q2. כותרת המעבדה לא נושאת את התשובה.
- o1 (סדר ה-Playbook): נלמד ב-Put a Playbook in Running Order על Playbook של זיהוי נוזקה ב-EDR, לא על דיווח פישינג.
- שאלת הביניים של r3 (טוקן גנוב): נלמד במהלך m4 של ה-duel: עוגייה מ-infostealer אחרי החלפת סיסמה, לא אחרי השבתת חשבון.
- q3 (למה שער אישור): נלמד ב-Where Does the Line Go? (הניסוח של Blast Radius בפרומפט והפריטים של ציוד ייצור) וב-Run Phish Report on Real Cases, על פעולות של Cobalt Ridge ובלי ניסוח האפשרות הנכונה.
- m1 (פעולות ותיאורן): isolate, disable ו-block ב-One Action for Each Move, כל קלף בניסוח אחר מהתשובה. Enrichment ו-Case management ב-Reads, Changes, Records or Sorts?. שער האישור ב-Where Does the Line Go?.
- la1.1 (מה חסר באירוע הגולמי): נלמד ב-Anatomy of a Raw Failed-Logon Alert וב-Already There, or Needs a Lookup?, על חשבון מושבת של עובד שעזב דרך Remote Desktop ‏(SubStatus 0xC0000072), לא סיסמה שגויה על חשבון שירות. 0xC000006A מופיע רק כנתון בשורה.
- la1.2 (חשבון שירות): נלמד ב-Who Is Behind the Account? על svc-routeplan, בניסוח אחר מהתשובה: תהליך מספק את האישור, ולכן טעות אנוש לא מסבירה את הכשלים. ה-lockout וה-MFA ב-Two Logon Myths, על תקלת מדפסות ולא על עדיפות של חשבון שירות. 4625 לכל סוג חשבון נלמד באנטומיה. בלי svc-backup.
- la2.1 (איזה שדה מזיז את ההכרעה): נלמד ב-Anatomy of an Enriched Case: חשבון משתמש רגיל, תג bulletproof-hosting, ציון 4/91, פורטוגל, טווח 10.40.2.0/24. לא TOR, לא 9/89, לא הולנד ולא 10.10.5.0/24.
- la2.2 (למה השער נשאר): נלמד באותה מעבדה, על החבילה block_ip_and_isolate_server ועל pending, וב-Read the Run Log.
- ac1 (benign true positive, סימן מכריע): נלמד ב-Three Kinds of Alert That Fired וב-Read the Enrichment, Not the Recommendation. כל הדוגמאות הן HTTP 401 מול API ולא 4625, עם קצב קבוע מול פרצים, מוניטין, בעלים ושינוי. הסיבה התמימה היא מעבר של ה-API ל-token issuer חדש, לא החלפת סיסמה או מפתח. שני מקרי הקצה: קצב קבוע בלי הסבר, וספק מוכר עם התנהגות חדשה אחרי הצלחה, שניהם להסלמה.
- flag1 (איזה כרטיס מסביר למה): נלמד ב-Which Record Explains Why?, על שער חיישנים ו-MQTT: רשומה שאומרת מי מול רשומה שאומרת למה. הסיבה היא הגירת מאגר משתמשים, לא החלפת סיסמה, בלי CHG-30117 ובלי VEND-2291.
- התוכן של r4 (מדדים, auto-triage, over-automation): נלמד ב-Did the Bot Earn Its Keep?, Close, Escalate or Queue?, Bad Lookup, Live Run ו-The Trust Dial.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "07:12" | כניסה: יום שני, החוזה, החשבון שננעל, ו-Freya Dlamini מול הדירקטוריון | תחנה 1 |
| Chapter 2: "What Ran" | אחרי The Playbook: מה הריצה עשתה, והשאלה מי נתן לה רשות | תחנה 2 |
| Chapter 3: "Until Friday" | אחרי The Gate: התור של ארבעת האנליסטים גדל, והדירקטוריון מחכה למספרים | תחנה 3 |
| Finale: "Trust" | אחרי הבוס: יום שישי, הבוט חוזר לעבודה עם קו ברור | החדר הבא |
