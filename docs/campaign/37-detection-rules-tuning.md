# תסריט חדר 37: Detection Rules & Tuning

**שם המבצע:** Operation Signal to Noise
**רמה:** בינוני
**העולם:** Glasshouse Media (שירות סטרימינג בדוי): 9 מיליון מנויים, כספת של סדרות שעוד לא שודרו, ו-SOC של שישה אנשים.
**המנטורית:** Ilse Brandt, מהנדסת זיהוי (Detection Engineer).

## סיפור הרקע
ברבעון שעבר ה-SOC קיבל 41,000 התראות. שתיים מהן היו אמיתיות, ואחת מהשתיים נסגרה כרעש, כי האנליסט ראה את אותו חוק יורה 300 פעמים באותו שבוע. Ilse כותבת ומכווננת את החוקים. היא רוצה שכל חוק יצדיק את מקומו: לוגיקה ברורה, פורמט נייד, ורעש שנמדד.

## העולם התלת-ממדי: Signal to Noise
- נהר רחב של חלקיקי אירועים אפורים, ואות אדום אחד ביניהם.
- שלושה שערי לוגיקה (THRESHOLD, ‏CORRELATION, ‏ANOMALY).
- מגילת rule.yml.
- מחיצות כיוונון שיורדות לנהר ומדללות את האפור.
- עדשת שיפוט, ומשואה שעולה כשרק האות נשאר.

## סדר המשימות
r1, q2 | r2, q3 | r3, q1 | la1, q4 | q5, flag1 (במקור שלוש הקריאות היו לפני כל השאלות. כל שאלה עברה אל התחנה של הנושא שלה)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Logic Types | r1, q2 | **What Kind of Logic?**: שישה חוקים ושלושה סוגי לוגיקה (בלי sequence) |
| 2 | Read the Sigma | r2, q3 | **Anatomy of a Sigma Rule**: חוק Linux של cron מ-/tmp: ‏logsource, ‏selection, ‏filter, ‏condition, ‏level ו-tags |
| 3 | Tune the Noise | r3, q1 | **The Noisy Rule**: ‏GH-022 ירה 120 פעמים, אחת מהן אמיתית: precision מתחת ל-1% ודפוס ה-on-call |
| 4 | Real or Benign? | la1, q4 | ההתראה הנבחנת ומדד הכיסוי |
| 5 (בוס) | Earn Its Place | q5, flag1 | spray מול guessing, ומונח הכיוונון |

**הפרדה מהשאלות הנבחנות:**
- מיון הלוגיקה בלי דלי sequence ובלי דוגמה של כישלונות שאחריהם הצלחה (q2).
- ה-anatomy לא מסבירה למה הפורמט ניטרלי לספקים (q3), והוא חוק Linux ולא spray.
- גיליון הכיוונון הוא חוק RDP מחוץ לשעות, ולא password spray ‏(q1). הוא גם לא מזכיר את המונח "exception list" ‏(flag1) ולא מודד recall ‏(q4).
- שום תרגול לא שופט את ההורדה של WSUS ‏(la1) ולא תת-טכניקת spray ‏(q5).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "41,000 Alerts, Two Real" | כניסה | תחנה 1 |
| Chapter 2: "Write It Once" | אחרי Read the Sigma | תחנה 3 |
| Chapter 3: "One in 120" | אחרי Tune the Noise | תחנה 4 |
| Finale: "Earn Its Place" | אחרי הבוס | החדר הבא: Microsoft 365 Security |
