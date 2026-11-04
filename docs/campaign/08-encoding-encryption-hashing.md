# תסריט חדר 8: Encoding, Encryption & Hashing

**שם המבצע:** Operation Cipher Room
**רמה:** מתחילים
**העולם:** Arclight Insurance (חברה בדויה), שולחן העבודה של האנליסט.
**המנטור:** Tomas Reyes, Senior Analyst. Mei Tanaka (Tier 2) מופיעה בשאלה האחרונה.

## סיפור הרקע
שלוש מילים מופיעות כמעט בכל כרטיס: encoded, encrypted ו-hashed. מי שמבלבל ביניהן טועה בהערכת החומרה של ממצא. ל-Tomas יש שולחן עבודה בדיוק בשביל זה: מפענח, מכבש hash והקלטת TLS. לומדים מה כל אחת מהשלוש יכולה להסתיר ומה לא, ומפעילים אותן בעצמכם.

**כל ערכי ה-hash וההצפנה במעבדות אמיתיים.** הם חושבו בפועל ולא הומצאו, כך שמי שיריץ את אותן פקודות במחשב שלו יקבל בדיוק את אותו פלט.

## העולם התלת-ממדי: Cipher Lab
שלוש מכונות על בסיסים עגולים:
- **מקודד:** קוביית זכוכית שבה Hello הופך ל-SGVsbG8= וחוזר בחזרה.
- **כספת הצפנה:** כספת עם חוגה ומפתח.
- **מכבש hash:** מכבש שהופך כל דבר לאסימון באורך קבוע, בלי דרך חזרה.

מאחוריהן קיר טביעות אצבע הקסדצימליות, ואחת מהן אדומה (התאמה). מלפנים מנהרת TLS בין לקוח לשרת, ותג ה-SNI קריא מחוץ למנהרה.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Three Jobs | r1 | **Which Operation?**: מיון מצבים אמיתיים לקידוד, הצפנה או hash |
| 2 | The Decoder Bench | r2, f1, q1, ac1 | **The Decoder Bench** (bash): base64 -d לכתובת URL, xxd -r -p ל-hex, פענוח URL של הזרקת SQL, ופענוח blob של PowerShell עם iconv מ-UTF-16LE (החרגה של Defender). **Spot the Encoding** |
| 3 | The Hash Press | r3, r4, q2 | **The Hash Press** (bash): sha256sum, md5sum ו-sha1sum על מחרוזת תשלום, אפקט המפולת (100 מול 900), ואורך קבוע גם לדיסק של 4GB. **Property to Superpower** (התאמה) |
| 4 | Hashes on Shift | r5, o1, la1, r6, m1 | **Verify the Download**: איזו מראה תואמת ל-hash של הספק. **Who Shares a Password?**: טבלה בלי salt מול טבלה עם salt. תרגול **Anatomy of a File Event** לפני la1. **Hash Check Results**: תור של ידוע רע, לא ידוע וידוע טוב (NSRL) |
| 5 (בוס) | Inside the Tunnel | r7, r8, q3 | **One Key or Two?**, **Build a TLS Session**, ו-**The Beacon You Can't Decrypt**: הקלטת TLS שממנה קוראים את ה-SNI, קצב של 60 שניות, גודל זהה של 517 בתים, והוכחה שהנתיב לא נראה |

**הפרדה מהשאלות הנבחנות:**
- המפענח לא משתמש במחרוזת של הדגל ולא ב-blob של המשימה המתוזמנת (f1, ac1).
- אפקט המפולת מוצג על מחרוזת תשלום ולא על invoice.pdf (q2).
- תור בדיקות ה-hash נמצא אחרי ההתראה הנבחנת.
- רשומת התרגול לא עוסקת בשינוי שם של קובץ (la1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Three Words" | כניסה | תחנה 1 |
| Chapter 2: "Not a Secret" | אחרי The Decoder Bench | תחנה 3 |
| Chapter 3: "One Byte, New Hash" | אחרי The Hash Press | תחנה 4 |
| Finale: "Read It Without Breaking It" | אחרי הבוס | החדר הבא: Timestamps and Timelines |
