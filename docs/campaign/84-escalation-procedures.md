# תסריט חדר 84: Escalation Procedures

**שם המבצע:** Operation Chain of Command
**רמה:** בינוני
**העולם:** Ashdown Rail Freight (חברת הובלת מטענים ברכבת, בדויה): רכבות מכולות בלילה, שלושה טרמינלים (Thornley Gate, Kestrel Yard ועוד אחד), ואנליסט אחד על דסק ה-SOC מ-22:00 עד 06:00.
**המנטור:** Renata Volkova, SOC Shift Lead. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
הרכבת הראשונה יוצאת מ-Thornley Gate ב-04:40, וכל מה שהיא נושאת תוכנן על שרת אחד, ASH-PLAN-02. ל-Renata, שעל ה-pager של ה-on-call הלילה, יש כלל אחד: הקפצה לחינם עולה שינה, והקפצה שהתעכבה עולה שעה, ושתיהן לא בחינם. הלילה הלומד לבד על הדסק. בתור מצטברות התראות, הקפצה אחת של Renata כבר בוזבזה על בדיקת רישיון תמימה, וב-02:52 מגיע הדבר האמיתי: חשבון קבלן גנוב עשה dump לזיכרון של LSASS על שרת התכנון. למחרת בבוקר מתברר שגם רשימת הלקוחות הועתקה, והשאלה עוברת למי עוד צריך לדעת.

## המכניקה הייחודית של החדר
- **Wake Them or Wait?:** מעבדת `queue` של שש התראות לילה. לכל התראה ארבע דרכי יציאה: לסגור עם הערה, להמשיך ב-playbook, לשלוח לתור של Tier 2 של הבוקר, או להעיר את ה-on-call. המחיר אמיתי לשני הכיוונים: שדות `on_call.pages_tonight` ו-`day_shift_in` מראים כמה עולה כל בחירה, ה-Severity של החוק מטעה בכוונה (Critical תמים, Medium אמיתי), וגם ההקפצה שהתבררה כתמימה הייתה נכונה לפי מה שהיה ידוע באותו רגע.
- **Wake Renata With a Usable Message:** מעבדת `chat` אמיתית (`memory: true`) עם ה-on-call lead. הלומד מקליד הסלמה שאפשר לפעול לפיה חצי ישנים: מה קרה, מי ואיפה, מה ההשפעה, מה כבר נעשה, ומה צריך. Renata שואלת על החלק החסר, כך שגם לומד שעונה חלק אחרי חלק מגיע לניצחון. הכללים בטוחים לשלילה (`said()`), ולכן "this can't wait until 06:00" עובר ו-"this can wait until 06:00" לא.
- **Set the Night Pager:** מעבדת `tune` שקובעת את חוק ה-pager לפי מספר ה-triggers ומגבלת הזמן של ה-playbook, על שנים עשר לילות אמיתיים מהרבעון.

## העולם התלת-ממדי
אי קמפוס (`facility`, Campus) של Ashdown Rail Freight עם Hub בשם Ashdown Rail Freight וארבעה מבנים לפי התחנות.

## סדר המשימות
esc-read-1, esc-q1 | esc-read-2, esc-q2 | esc-read-3, esc-q3, esc-log-1 | esc-ac1

(הסדר הוחלף: בחדר המקורי כל הקריאות באות קודם, ולכן הוא לא מתחלק לתחנות. esc-q1 יושבת אחרי קריאה 1, כי שם כתוב ש-Tier 1 סוגר false positives ברורים עם תיעוד ועובד לפי playbooks. בחדר אין משימת flag, ולכן אין מספור "Log Analysis N" לבדוק.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Page | esc-read-1, esc-q1 | **Read the On-Call Card** (anatomy), **Which Desk Does It Land On?** (sort), **Finish a Case at Your Own Desk** (sequence) |
| 2 | The Call | esc-read-2, esc-q2 | **Set the Night Pager** (tune), **Wake Them or Wait?** (queue), **Wake Renata With a Usable Message** (chat) |
| 3 | The Handover | esc-read-3, esc-q3, esc-log-1 | **Who Gets Called Next?** (duel), **What's Wrong With This Contact Sheet?** (hotspot), **After the Page** (match), **Read an Escalation Record Field by Field** (anatomy), **How Long Did Each Page Sit?** (worksheet) |
| 4 (בוס) | Night Verdict | esc-ac1 | **Finished, or Only Half Done?** (reactor), ואז ההחלטה הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של קריאה 1 (מי מאשר בידוד):** עובדת זיכרון, ולכן היא מופיעה רק כשורה עם התווית שלה ב-Read the On-Call Card, בשדה `tier2.authority`. שום מעבדה לא שואלת אותה. ה-sort לא כולל פריט של בידוד.
- **esc-q1 (דפוס מוכר, לתעד ולסגור):** נלמד ב-Finish a Case at Your Own Desk ובפריימר שלו. במעבדה gateways של טלמטריה בקרונות בזמן החלפת צוות, ובדוגמת הפריימר גיבוי של חברת מחסנים, לא התחברות כושלת ולא VPN. אף אפשרות לא מנוסחת.
- **שאלת הביניים של קריאה 2 (קודם ה-playbook):** נלמד בהתראות `encoded` ו-`signin` ב-Wake Them or Wait?, ובשורה "Not triggers" בפריימר של Set the Night Pager. המקרים הם PowerShell מקודד במשרד החצר וחיבור קבלן מחוץ למשמרת.
- **esc-q2 (bridge):** עובדת זיכרון, ולכן היא מופיעה רק בדרך אגב: בתשובה של Renata בצ'אט נפתח escalation bridge על ההחלטה של Ashdown, והמעבדה לא שואלת מה לפתוח. המטרה `bridge` שואלת מי צריך להיות על הקו ומה כל אחד מחליט: Renata על הבידוד, ה-Duty Controller על ה-04:40, ובעל המערכת על העתקת התוכנית. אין כופר, אין 40 שרתים ואין ארבעה צוותים, ואף אפשרות של q2 לא מופיעה.
- **esc-q3 (להישאר זמין):** נלמד ב-After the Page ובפריימר שלו, על ארבעה רגעים מהלילה של Ashdown: לענות מההערות, לקשר התראה חדשה, ללמוד מ-Tier 2, ולהשאיר הערות בסוף המשמרת. במעבדה אין טלפון ללקוח ואין שאלה על השמטת ממצאים לא ודאיים.
- **esc-log-1, שאלה 1 (ההסלמה מאוחרת):** נלמד בשדה `escalation.timestamp` וב-`actions_taken_by_tier1` ב-Read an Escalation Record, וב-How Long Did Each Page Sit?. הרשומה במעבדה נשלחה 8 דקות אחרי האישור, והפערים בטבלה הם 8, 53, 7, 82 ו-8 דקות, לא 09:17 עד 09:45. אין Maze ואין 12 מארחים.
- **esc-log-1, שאלה 2 (ה-DC עוד לא נפגע):** הרעיון נלמד בשדה `escalation.analyst_notes`, על gateway לרשת האיתות, ASH-GW-SIG, לא על domain controller. העובדה ש-domain controller עונה על התחברויות בכל הדומיין מופיעה כנתון בפריימר של Set the Night Pager, ברשימת המערכות הרגישות.
- **esc-ac1 (להסלים עכשיו):** האות המכריע, טיפול חלקי הוא לא טיפול, נלמד במעבדה משלו, Finished, or Only Half Done?. המקרים הם חשבונות, כללי דואר וסשנים מרוחקים, לא EDR שמבודד מארחים ולא כופר. המשמרת הבאה מתחילה ב-06:00 ולא ב-07:00. Wake Them or Wait? מלמד את שאר ההחלטה: הקפצה קודמת באותו לילה לא משנה את ההחלטה הבאה.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "One Analyst, One Pager" | כניסה | תחנה 1 |
| Chapter 2: "The Queue at Midnight" | אחרי The Page | תחנה 2 |
| Chapter 3: "The Morning After" | אחרי The Call | תחנה 3 |
| Finale: "Chain of Command" | אחרי Night Verdict | החדר הבא |
