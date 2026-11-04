# תסריט חדר 36: Microsoft Sentinel Fundamentals

**שם המבצע:** Operation Clear Sky
**רמה:** בינוני
**העולם:** Ashgrove Pharmacy (רשת בתי מרקחת בדויה): 310 סניפים, מערכת מרשמים שאסור לה ליפול, והכול כבר יושב ב-Microsoft 365 וב-Azure.
**המנטור:** Malik Haddad, ארכיטקט Sentinel.

## סיפור הרקע
בחודש שעבר Ashgrove העבירה את ה-SIEM שלה ל-Microsoft Sentinel. הלוגים זורמים, אבל רוב הצוות עדיין לא יודע לקרוא אותם. Malik תכנן את ה-workspace. הלילה נפתח Incident 4412 על d.okafor. הוא רוצה אנליסטים שיודעים איזו טבלה לפתוח, כותבים את השאילתה בעצמם ומבדילים בין incident לרעש.

## העולם התלת-ממדי: Clear Sky
- כדור workspace שקוף מעל שורה של עמודי טבלאות (‏SigninLogs, ‏SecurityEvent, ‏OfficeActivity, ‏CommonSecLog, ‏Syslog).
- זרמי connectors שעולים מהקרקע אל הכדור.
- קרן KQL שיורדת על עמוד ומצטמצמת.
- שלושה רסיסי התראה שמתאחדים למשושה של Incident 4412.
- כרטיס שורה גולמית שמסתובב אל המצלמה.

## סדר המשימות
r1 | r2, q1 | r3 | la1, flag1 | q2, q3, queryfill-1, ac1 (זהה למקור. התחנות פשוט מקבצות אותו)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Workspace and Tables | r1 | **Which Table?**: שישה אירועים וחמש טבלאות |
| 2 | Speak KQL | r2, q1 | **Build the Query**: ‏SigninLogs צעד אחר צעד (‏where, ‏summarize dcount, ‏project), עד כניסה מ-NG ב-23:41 |
| 3 | Rules to Incidents | r3 | **Open the Incident**: ‏Incident 4412: שלוש התראות משלושה חוקים, ישות אחת ו-playbook שביטל sessions |
| 4 | Inside the Event | la1, flag1 | **Anatomy of a SigninLogs Row**: ‏ResultType, ‏IPAddress, כניסה בלי MFA ו-Conditional Access שלא חל |
| 5 (בוס) | Write It, Call It | q2, q3, queryfill-1, ac1 | בחירת סוג חוק, דירוג, כתיבת KQL והכרעה |

**הפרדה מהשאלות הנבחנות:**
- מיון הטבלאות לא כולל כניסת Windows ‏(la1).
- קונסולת ה-KQL שואלת על SigninLogs, ולא סופרת 4625 או מדרגת כישלונות התחברות (q1, ‏q3, ‏queryfill-1).
- גיליון ה-incident לא בוחר סוג חוק (q2).
- ה-anatomy היא שורת SigninLogs, ולא 4625 או העמודות SubStatus, ‏LogonType ו-IpAddress ‏(la1, ‏flag1).
- שום תרגול לא מכריע על spray ‏(ac1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Logs Are Flowing" | כניסה | תחנה 1 |
| Chapter 2: "Four Countries in a Week" | אחרי Speak KQL | תחנה 3 |
| Chapter 3: "Incident 4412" | אחרי Rules to Incidents | תחנה 4 |
| Finale: "Query, Build, Decide" | אחרי הבוס | החדר הבא: Detection Rules & Tuning |
