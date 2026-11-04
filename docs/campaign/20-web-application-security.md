# תסריט חדר 20: Web Application Security

**שם המבצע:** Operation Request Line
**רמה:** מתחילים
**העולם:** Fernhill Outdoor (חנות ציוד שטח בדויה), עם חנות מקוונת אחת ו-40,000 הזמנות בחודש.
**המנטור:** Kai Morgan, מהנדס אבטחת אפליקציות.

## סיפור הרקע
כל תקיפת web היא מישהו שמכניס משהו לא צפוי לתוך בקשה. Kai רוצה שתראה בקשה כזו מקרוב לפני שתחקור אחת. בחדר:
- שולחים בקשות ידנית.
- משנים את מה שהדפדפן "מרשה".
- רואים SQL injection עובר משגיאות להצלחה.
- בודקים אילו הגנות באמת פועלות.

## העולם התלת-ממדי: Request Line
- חלון דפדפן משמאל שולח חבילות בקשה לאורך מסילה זוהרת. המסילה עוברת דרך צינור TLS, שער WAF, שרת WEB ו-APP, ועד תוף DATABASE.
- החבילה נפרשת לחלקיה: METHOD, ‏PATH, ‏QUERY, ‏HEADERS, ‏COOKIE ו-BODY.
- חבילה מזויפת (price=0.01) עוברת באדום.
- סמני תקיפה נוחתים על השכבה שכל סוג פוגע בה: SQLi, ‏XSS, ‏TRAVERSAL ו-CMD INJ.
- שער ה-WAF מהבהב כשהחבילה האדומה עוברת דרכו.
- לשונית זדונית (win-a-prize) שולחת בקשה שאוספת את העוגייה של הקורבן בדרך.

## סדר המשימות
ללא שינוי: r1 | r2, q1 | r3, m1, la1 | r4, q2, la2, ac1 | r5, q3, o1

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Anatomy of a Request | r1 | **Read a Request by Hand**: ‏curl -v, קריאה של כל שורת > ו-<, ו-404 |
| 2 | Trust Nothing | r2, q1 | **Change What You 'Can't'**: שדה price מוסתר ו-dropdown של כמות, שנשלחים ב-curl POST. השרת מקבל 500 כיריים ב-5 ליש"ט |
| 3 | Where Attacks Land | r3, m1, la1 | **Errors, Then Success**: מרשת 500 אל ORDER BY, ועד UNION שמחזיר 2.9MB |
| 4 | The WAF's View | r4, q2, la2, ac1 | **Can the WAF See It?**: מה יש לו לזהות ומה לא (credential stuffing, קופון, עוגייה גנובה) |
| 5 (בוס) | Forged Requests | r5, q3, o1 | **Are the Defences On?**: ‏SameSite ו-tokens של CSRF בשלושה דפים |

**הפרדה מהשאלות הנבחנות:**
- מעבדות ה-curl לא מציגות לוג IIS (q1).
- דף ה-SQLi הוא נקודת חיפוש, ולא ה-traversal ב-/download.aspx (la1). הוא גם לא מתאים סוגי תקיפה לסימנים (m1).
- מיון ה-WAF לא כולל IDOR (q2), ‏X-Forwarded-For (la2) או גרש בשם משפחה (ac1).
- דף ה-CSRF בודק הגנות, ולא מזהה בקשה מזויפת (q3) או מסדר את חיי הבקשה (o1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Every Attack Is a Request" | כניסה | תחנה 1 |
| Chapter 2: "The Lock Is Drawn on the Door" | אחרי Trust Nothing | תחנה 3 |
| Chapter 3: "Errors, Then Success" | אחרי Where Attacks Land | תחנה 4 |
| Finale: "The Browser's Own Trust" | אחרי הבוס | החדר הבא: Commodity Initial Access |
