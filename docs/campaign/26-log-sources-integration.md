# תסריט חדר 26: Log Sources & SIEM Integration

**שם המבצע:** Operation Intake
**רמה:** בינוני
**העולם:** Vantage Telecom (חברת תקשורת בדויה): ‏340 מקורות לוג, חמש דרכי תעבורה, שלוש סכמות, ו-SIEM אחד שיודע רק מה שמגיע אליו.
**המנטור:** Owen Fischer, מהנדס חיבור מקורות ל-SIEM.

## סיפור הרקע
Owen מחבר כל מקור חדש ל-SIEM. לוג שלא מגיע, מגיע כגוש טקסט אחד או מגיע עם שעון שגוי הוא נקודה עיוורת, גם אם יש מעליה דשבורד יפה. כאן עוקבים אחרי לוג מהמכשיר שכתב אותו ועד השדה שמחפשים עליו.

## העולם התלת-ממדי: Intake
- שישה מקורות שולחים חבילות בצינורות משלושה סוגים: קו מנוקד (UDP), קו מלא (TCP) וצינור מוגן (TLS). כולם מגיעים אל COLLECTOR.
- הצינור של מקור אחד (APP) כבוי, עד שתחנה 2 נפתרת.
- גוש אפור נכנס לגלגל PARSER ויוצא כשבבי שדות צבעוניים.
- השבבים נופלים דרך משפך source.ip אל כספת SIEM.
- כרטיס CEF נדלק בסוף.

## סדר המשימות
r1 | r2, q3 | r3, q1, q2, q4 | la1, flag1

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Where Logs Come From | r1 | **How Does It Travel?**: ‏UDP 514, ‏TLS 6514, ‏WEF, סוכן ו-API |
| 2 | The Silent Source | r2, q3 | **Why Did It Go Quiet?**: ‏rsyslog על TLS. השירות רץ, אבל תעודת ה-CA פגה ב-30 באוקטובר |
| 3 | Parse and Normalise | r3, q1, q2, q4 | **Five Names, One Schema**: ‏srcip, ‏IpAddress, ‏sourceIPAddress ו-client.ipAddress אל source.ip, ותבנית grok |
| 4 (בוס) | Read the Wire Format | la1, flag1 | תרגול **Anatomy of a LEEF Event** (מפריד ^) לפני ה-CEF הנבחן |

**הפרדה מהשאלות הנבחנות:**
- מיון התעבורה לא מציג CEF שנוחת כגוש (q1).
- המקור השקט הוא rsyslog ב-Linux, ולא Winlogbeat ב-Windows (q3).
- דף הנרמול ממפה שדות, ולא שואל למה נרמול חשוב (q2) או איך לשמור זמן (q4).
- התרגול הוא LEEF, ולא שורת ה-CEF של PAN-OS (la1, flag1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Only What Reaches It" | כניסה | תחנה 1 |
| Chapter 2: "Running Isn't Arriving" | אחרי Where Logs Come From | תחנה 2 |
| Chapter 3: "One Name for One Fact" | אחרי The Silent Source | תחנה 3 |
| Finale: "Header, Then Extension" | אחרי הבוס | החדר הבא: Email Security |
