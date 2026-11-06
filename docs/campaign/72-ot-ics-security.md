# תסריט חדר 72: OT/ICS Security for SOC Analysts

**שם המבצע:** Operation Long Game
**רמה:** בינוני
**העולם:** Fellside Water and Power (חברת מים וחשמל קטנה ובדויה): מאגר אחד, מתקן טיהור אחד, תחנת הידרו קטנה, ו-23,000 בתים שתלויים בהם.
**המנטור:** Tariq Lindholm, OT Security Engineer. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום ראשון ב-03:12 שער הכניסה של תחנת ההידרו זז לבד, בלי אף אחד ליד הלוח, ומפעיל הלילה החזיר אותו ידנית. ה-IT הארגוני רוצה לבודד עד הצהריים כל מחשב במפעל. Tariq רוצה לדעת קודם מה כל מחשב כזה מחזיק בחיים. אחר כך מתברר שהתוקף יושב ברשת כבר תשעה שבועות. המקרה הנבחן הוא התיק של השכנים, Meridian Valley, ו-Tariq משתמש בו כמבחן.

## המכניקה הייחודית של החדר
- **Safety Before Containment:** ההרגל מה-IT (לבודד את המחשב) יכול לעצור תהליך פיזי. **Cut Ahead of the Spread** (`outbreak`) מלמד לחתוך לפני ההתפשטות במקום הצר ברשת, והשיעור שלו מראה שהמשחק סופר מחשבים והמפעל סופר תוצאות. מיד אחריו **Approve the Cut, or Stop It** (`intercept`): בקשות חיתוך מגיעות תחת לחץ זמן, והלומד שוקל כל אחת מול בטיחות וזמינות.
- **Down the Purdue Levels:** ‏`pathway` על רמות Purdue מהשולחן הארגוני עד השער הפיזי, דרך ה-Industrial DMZ.
- **Read the Write:** ‏`pcap` של Modbus אמיתי: סריקה, קריאה, כתיבה בקוד פונקציה 6, הבתים עצמם, וה-HMI שרואה את הערך החדש.

## העולם התלת-ממדי
אי קמפוס (`facility`) של Fellside: חמישה מבנים לפי התחנות, seed משלו. עיר ה-Hub נושאת את שם החברה.

## סדר המשימות
r0, r1, r2, q1, m1 | r3, r4, q2 | r5, la1, ac1 | r6, r7, q3 | q4, f1

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Plant Floor | r0, r1, r2, q1, m1 | **What Would Wake the Plant?** (sort), **Why the Plant Looks Out of Date** (inspect), **Who Does What on the Floor** (match), **Down the Purdue Levels** (pathway), **What the Sensor Hears** (worksheet), **What Stops a Command?** (sort), **Name the Way In** (reactor) |
| 2 | The Case Files | r3, r4, q2 | **The Case Files** (lineup), **Message, Value or Effect?** (sort) |
| 3 | The Write | r5, la1, ac1 | **Anatomy of a Modbus Record** (anatomy), **Read the Write** (pcap), **Who Moved the Gate?** (deduce) |
| 4 | Safe Containment | r6, r7, q3 | **How Do You Watch a Controller?** (simulate), **Reading a Modbus Alert Rule** (inspect), **Find the Holes in the Boundary** (hotspot), **Cut Ahead of the Spread** (outbreak), **Approve the Cut, or Stop It** (intercept) |
| 5 (בוס) | The Long Game | q4, f1 | **Nine Weeks, Two Stages** (sequence), ואז ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- **q1 (פורט Modbus ומה חסר בו):** השורה ב-What the Sensor Hears מציגה 502/TCP כנתון בלבד ולא שואלת עליו. What Stops a Command? מלמד שהבקר מציית לכל שולח, על לפטופ במתג הבקרה ובקשות שגויות, בלי לשאול מהו הפורט.
- **m1 (פרוטוקול מול פורט ושימוש):** הטבלה ב-What the Sensor Hears מציגה את ארבעת הפרוטוקולים כשורות נתונים. השאלות שם הן איזה פרוטוקול לא תואם למלאי ואיזו שורה היא שיחת הנדסה, לא התאמה.
- **q2 (T0886, ואז T0855 ב-TA0106):** Name the Way In מלמד T0886 על RDP מתוך IT. Message, Value or Effect? מפריד T1692.001 (לשעבר T0855) מ-T0836 ומ-T0831 על אירועי DNP3 ו-S7 ב-Fellside, ולא על תחנת המשנה באוקראינה. התיק של Industroyer ב-The Case Files לא נותן לו מזהי טכניקה.
- **la1 שאלה 1 (השדה שמראה כתיבה):** Anatomy of a Modbus Record הוא רשומת קריאה, RESPONSE של FC 3 מ-FS-HMI-01. הוא מסביר למה ערכים, כתובת ו-REQUEST לא מעידים על כיוון. Read the Write מראה FC 6 לערך 550 ברגיסטר 40108 (כתובת 107), לא FC 16 ל-40020.
- **la1 שאלה 2 (המקור החשוד):** Who Moved the Gate? מלמד מקור מחוץ לבלוק ההנדסה, בלי היסטוריה, על FS-COMM-07 בכתובת 192.168.44.87, לא 10.50.12.77. האנטומיה מסבירה למה פורט זמני, משך קצר וכתובת פרטית לא אומרים כלום.
- **ac1 (פרץ כתיבות מתחנת ההנדסה):** ב-Who Moved the Gate? FS-ENG-01 הוא כמעט-חשוד: תחנה נכונה, טיקט וחלון תחזוקה, ולכן שגרה גם אם יש הרבה כתיבות, ונסגר כ-Benign True Positive ולא כ-False Positive. ה-burst, ה-plc-dose-04 ו-MAINT-2026-0819 לא מופיעים.
- **q3 (התגובה הנכונה):** Approve the Cut, or Stop It מלמד חיתוך במקור, בדיקת רגיסטרים על ידי מהנדסי תהליך, איסור אתחול, איסור חסימת 502 בכל האתר, ו-How Do You Watch a Controller? מלמד שחיישן פסיבי לא יכול לאפס שיחה. הדוגמה היא FS-COMM-07 וטורבינה ב-80% עומס, לא plc-dose-03 ומקור ב-VLAN ארגוני.
- **q4 (השרשרת המלאה והסיבה):** Nine Weeks, Two Stages מסדר שמונה שלבים של חדירה אחרת ב-Fellside, עם השלב הראשון ב-IT, שני ה-T0886, ההבדל מ-T0883, והחיישן שרואה הכול. הסיבה (Modbus/TCP לא שואל מי שלח) מופיעה בהערת הכתיבה ובתרגול What Stops a Command?.
- **f1 (T0855):** המזהה הישן מופיע כנתון, בתווית "formerly T0855" של T1692.001, בדלי של Message, Value or Effect?, בהסבר של Who Moved the Gate? ובהערה של השרשרת. אף תרגול לא שואל מהו המזהה.
- **שאלות הביניים:** r0 (למה AIC) ב-What Would Wake the Plant?. r1 (רמה של תחנת הנדסה) ב-Down the Purdue Levels על FS-ENG-01. r2 (T0886 בשני טקטיקות) ב-Name the Way In. r3 (TRITON ו-SIS) כנתון בתיק של The Case Files, בלי שאלה עליו. r4 ב-Message, Value or Effect?. r5 (קודי פונקציה) באנטומיה וב-pcap. r6 (למה אין סוכן, SPAN ו-TAP) ב-How Do You Watch a Controller?. r7 (חסימת 502) ב-Approve the Cut, or Stop It.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "03:12" | כניסה | תחנה 1 |
| Chapter 2: "Nobody at the Panel" | אחרי The Case Files | תחנה 3 |
| Chapter 3: "Isolate Everything" | אחרי Safe Containment | תחנה 5 |
| Finale: "The Long Game" | אחרי The Long Game | החדר הבא |
