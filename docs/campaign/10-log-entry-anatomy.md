# תסריט חדר 10: Anatomy of a Log Entry

**שם המבצע:** Operation Dissection
**רמה:** מתחילים
**העולם:** Halvard Energy (חברה בדויה) עם 200 מוצרים שכל אחד מהם כותב לוג בדרך משלו.
**המנטור:** Felix Adeyemi, Detection Engineer. Sara Lind (תשתיות) מופיעה בהכרעה.

## סיפור הרקע
אף אחד לא זוכר בעל פה את הפורמט של כל מוצר. אנליסטים לומדים לקרוא את מה שמעולם לא ראו. Felix מניח לוג גולמי על השולחן ונותן לך אזמל: חמש שאלות (מתי, מי, איפה, מה וכמה בטוח), ואחריהן השאלה מה חסר.

## העולם התלת-ממדי: Dissection Table
שורת לוג גולמית מרחפת מעל שולחן, חתוכה לחמישה מקטעים. חמש עדשות צבעוניות (WHEN, WHO, WHERE, WHAT, HOW SURE) יורדות על המקטעים שלהן. מאחור עומדים מונוליתים לפורמטים: SYSLOG, KEY=VALUE, ‏JSON עם קופסאות מקוננות, ו-CSV/W3C. מימין, משפך נרמול: srcip, ‏id.orig_h, ‏cIP ו-ClientIP נופלים לתוך source.ip. בסוף השורה יש מקטע ריק ואדום, NOT LOGGED.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Five Questions | r1 | **Five Questions, Three Logs**: שלוש שורות משלושה מוצרים, ומכל אחת שולפים את התשובה הנדרשת |
| 2 | Syslog and Key=Value | r2, q1, r3, q2 | **Slice the Text**: ‏grep, ‏awk, ‏uniq -c על auth.log, מעקב אחרי ניחוש שהצליח, ופענוח הקוד <38>. **Key=Value at Scale**: ‏grep -o srcip על לוגים של FortiGate וזיהוי הכיוון |
| 3 | Nested JSON | r4, m1 | **Query JSON with jq**: אירוע 4720 ב-JSON. מזהה האירוע, מי נוצר, מי יצר, והנתיב המלא בנקודות |
| 4 | Columns and Headers | r5, o1 | **Read It by the Header**: ‏IIS עם סדר עמודות לא סטנדרטי. **No Header at All**: שורת CSV של PAN-OS בלי כותרת, שנקראת לפי טבלת סדר השדות של היצרן |
| 5 | Names and Opinions | r6, q3, r7, ac1 | **One Fact, Five Names** (התאמה). **Severity Is an Opinion**: תור של ארבע התראות שבו ההקשר גובר על דירוג החומרה. אחר כך ההכרעה על התראת ה-IPS |
| 6 (בוס) | What Isn't There | r8, la1, f1 | **Silence or Gap?**: מעקב מלוג תחנת העבודה, דרך השתיקה ב-SIEM, ועד ל-forwarder של DC02 שנעצר. תרגול **Anatomy of a Zeek HTTP Record**, ואחריו רשומת ה-conn.log הנבחנת והדגל |

**הפרדה מהשאלות הנבחנות:**
- שולחן ה-syslog משתמש במארח ובחשבון אחרים מאלה של q1.
- מעבדת key=value סופרת מקורות ולא שואלת על שדה התוצאה (q2).
- בתור החומרה אין התראת IPS מחלון סריקה (ac1).
- התרגול הוא http.log של Zeek ולא ה-conn.log הנבחן (la1, f1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Two Hundred Formats" | כניסה | תחנה 1 |
| Chapter 2: "Paths and Columns" | אחרי Nested JSON | תחנה 4 |
| Chapter 3: "Names and Opinions" | אחרי Names and Opinions | תחנה 6 |
| Finale: "What Isn't There" | אחרי הבוס | החדר הבא: Identity Basics |
