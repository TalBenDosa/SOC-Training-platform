# תסריט חדר 40: SentinelOne

**שם המבצע:** Operation Rollback
**רמה:** בינוני
**העולם:** Saltmarsh Brewing Co. (מבשלת בירה בדויה): שלוש מבשלות, ‏60 פאבים, ומתכונים שמתחרה ניסה לגנוב באביב שעבר.
**המנטורית:** Ingrid Solberg, ראש אבטחת תחנות קצה.

## סיפור הרקע
בכל מחשב ושרת של Saltmarsh רץ agent של SentinelOne Singularity. ביום שני בבוקר הקונסולה נדלקה בסגול ובאדום על פני כל צוות הכספים. Ingrid רוצה שתקרא את ה-Threat Center לפני שאתה נוגע בכפתור, כי כל כפתור שם עושה משהו אמיתי.

## המכניקה הייחודית של החדר
**קריאת פס הסטטוס של ה-Threat Center:** ‏Threat Status, ‏AI Confidence, ‏Analyst Verdict ו-Incident Status, כמו במוצר האמיתי. הלומד פותח כל שדה ומחליט מה עוד מחכה לאדם.

## העולם התלת-ממדי: Rollback
- חוט Storyline סגול שיוצא ממחשב נייד בכספים ועובר דרך חרוזי אירועים.
- לוח Threat Center מעל נקודת ההתחלה.
- ארונות השרתים של המבשלה, עם מסוף Remote Shell.
- ערימת קבצים שעוברת מאדום לנקי כשחוגת ה-Rollback מסתובבת לאחור.
- מגן שסוגר את הסיפור.

## סדר המשימות
r1, q4 | r2, q1 | r3, q2, q3 | la1, flag1 | q5 (במקור שלוש הקריאות היו לפני כל השאלות)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Threat Center | r1, q4 | **Read the Threat Center**: שש חלקים של מסך האיום |
| 2 | Remote Shell | r2, q1 | **Remote Shell: the Brewery Server**: ‏top, ‏systemctl ו-cryptominer שחוזר בגלל Restart=always |
| 3 | Ransomware | r3, q2, q3 | שאלות |
| 4 | Monday 09:14 | la1, flag1 | הזיהוי הנבחן |
| 5 (בוס) | The Rollout | q5 | מצב Detect מול Protect |

**הפרדה מהשאלות הנבחנות:**
- ה-Threat Center לא מסביר איך Static AI שופט קובץ (q4) ולא מציע rollback.
- ה-Remote Shell הוא ציד persistence ב-Linux, ולא בידוד מחשב (q1).
- שום תרגול לא קורא את זיהוי ה-LockBit ‏(la1, ‏flag1), שינויי שמות המוניים ואנטרופיה (q2), ציד ב-Deep Visibility ‏(q3) או Detect מול Protect ‏(q5).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Purple Monday" | כניסה | תחנה 1 |
| Chapter 2: "Mitigated Is Not Finished" | אחרי The Threat Center | תחנה 2 |
| Chapter 3: "Restart=always" | אחרי Remote Shell | תחנה 3 |
| Finale: "Rewind" | אחרי הבוס | החדר הבא |
