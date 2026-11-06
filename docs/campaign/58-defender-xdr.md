# תסריט חדר 58: Microsoft Defender XDR

**שם המבצע:** Operation Last Word
**רמה:** בינוני
**העולם:** Fenwick & Ash Publishers (הוצאת ספרים בדויה): 180 עובדים, tenant אחד, ותשעה ימים עד שהספר השמור ביותר בבניין יוצא לחנויות.
**המנטור:** Nkechi Holloway, SOC Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
The Last Word הוא ספר הזיכרונות של שר לשעבר, ועיתון כבר הציע כסף על עותק מוקדם. הבוקר פורטל אחד נדלק עם התראות מהדואר, מהלפטופ ומהדיירקטורי, ו-Nkechi צריכה לדעת אם אלה תשע בעיות או בעיה אחת.

## המכניקה הייחודית של החדר
- **One Queue, One Story:** פורטל בסגנון Defender עם תור תקריות, גרף תקיפה שמנגנים עם Play, ואישור או דחייה של פעולות ממתינות לפי הראיות. מחיקת הודעות אמיתיות של בית הדפוס, רק כי סומנו Suspicious, עולה בחיים.
- **The Query Ladder:** מעבדה חדשה (`hunt`). הלומד בונה שאילתת KQL שורה אחרי שורה, והתוצאות מחושבות באמת מהשורות, כך ששורה שגויה מראה מה היא באמת מחזירה.

## העולם התלת-ממדי
אי קמפוס (`facility`) של ההוצאה: ארבעה מבנים לפי התחנות. עיר ה-Hub נושאת את שם החברה.

## סדר המשימות
r1, q1, q3 | r2, la1, f1 | r3, q2, q4 | ac1

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Incident | r1, q1, q3 | **Who Saw It?** (duel), **One Queue, One Story** (portal) |
| 2 | The Timeline | r2, la1, f1 | **Hide or Break?** (rush), **Anatomy of a Remote Process** (anatomy), **Which Sign-In Was Relayed?** (deduce), **Which App Gets Revoked?** (worksheet) |
| 3 | The Hunt | r3, q2, q4 | **The Query Ladder** (hunt), **Triage the Hits** (intercept) |
| 4 (בוס) | Last Word | ac1 | ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- התקרית במעבדה: 9 התראות ו-2 מכשירים, לא 12 ו-4 ‏(q3).
- מכשיר בלי סוכן מריץ LDAP, לא בקשות Kerberos ‏(q1).
- Live Response מריץ פקודה, לא אוסף קובץ (שאלת הביניים של r1).
- האנטומיה היא PsExec בלי ‎-s על ידי אדמין מזוהה, בלי SRV-FILE01, svc-backup או SYSTEM ‏(la1, f1).
- ה-join הוא בין טבלת תהליכים לטבלת קבצים על certutil, לא תהליכים ורשת ‏(q2) ולא PowerShell מקודד ‏(q4).
- ההתחברות המתווכת מסתיימת בכלל דואר נכנס, וגיליון ה-consent עוסק באפליקציית יומן שקוראת קבצים, לא באפליקציית דואר אחרי התחברות מסוכנת ‏(ac1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Nine Days" | כניסה | תחנה 1 |
| Chapter 2: "Nine Alerts" | אחרי The Incident | תחנה 2 |
| Chapter 3: "Before the Alert" | אחרי The Timeline | תחנה 3 |
| Finale: "The Last Word" | אחרי הבוס | החדר הבא |
