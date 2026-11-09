# תסריט חדר 53: ESXi & Virtualization Security

**שם המבצע:** Operation Bare Metal
**רמה:** מתקדם
**העולם:** Skerry Line (חברת מעבורות בדויה): 11 מעבורות, 30 איים, וחדר קר אחד על המזח שבו הזמנות, מניפסטים וסידור צוותים רצים כמכונות וירטואליות על שישה שרתים פיזיים.
**המנטור:** Callum Okafor, מהנדס וירטואליזציה.

## סיפור הרקע
לכל מחשב ולכל מכונה וירטואלית ב-Skerry יש חיישן EDR. לשישה השרתים שמתחתיהם אין, ולא יכול להיות. האזהרה של Callum לכל אנליסט חדש: השכבה שמחזיקה הכול היא השכבה היחידה שהכלים שלך לא רואים.

## המכניקה הייחודית של החדר
**Walk the Alarm Back:** קונסולה בסגנון vSphere Client, סקין חדש של `portal`: עץ inventory משמאל, לשוניות Summary, Monitor, Permissions, טבלאות Tasks ו-Events ופרטים למטה. הלומד מתחיל מאזעקה על host והולך אחורה ברשומות: האירוע במארח, ה-task ב-vCenter, ההרשאה, אירוע ההענקה, והכניסה שממנה הכול התחיל.

## העולם התלת-ממדי: Bare Metal
- חתך של כל המחסנית: לוח datastore, שלושה hosts, מכונות זכוכית עם נורת חיישן ירוקה.
- vCenter תלוי מעל, והרשאה זורמת ממנו מטה.
- דלת (מנעול) על host נפתחת לקונסולה.
- המכונות נכבות בזו אחר זו, ונורות החיישן כבות איתן, בזמן שהמנעולים על קובצי הדיסק נפתחים.
- מגן "OWN LOGS" שקורא את המחסנית מבחוץ.

## סדר המשימות
r1, r2, q1 | r3, r4, la1, f1 | r5, q2, la2, ac1 | r6, r7, q3 | r8, q4, m1, o1

(q2 זז אחרי r5 כי הוא מזכיר esx.audit.ssh.enabled. f1 זז מיד אחרי la1 כי הוא קורא את אותו לוג.)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Hypervisor | r1, r2, q1 | **Walk the Stack** (pathway), **Who Sees It?** (rush) |
| 2 | The Grant | r3, r4, la1, f1 | **Smallest to Biggest** (sort), **Who Could Have Stopped It?** (deduce), **One vCenter Event** (inspect) |
| 3 | The Host's Own Log | r5, q2, la2, ac1 | **Walk the Alarm Back** (portal, vSphere) |
| 4 | The Power-Off Loop | r6, r7, q3 | **Spot What Isn't Maintenance** (spotdiff), **Can It Write?** (simulate), **Tune the Power-Off Rule** (tune) |
| 5 (בוס) | Before the Damage | r8, q4, m1, o1 | **Where Does It Go?** (sort) |

**הפרדה מהשאלות הנבחנות:**
- שום ערך מהרשומות של MedCore: אין svc-backup, ‏esx-prod-07, ‏vcsa-04, ‏10.60.9.14, ‏j.marchetti, ‏CHG-77410.
- ההרשאה במעבדה על cluster ולא על תיקיית השורש, ואין moref ‏(f1).
- אין פסק דין על שינוי מתוכנן ‏(ac1).
- ה-sort של r8 לא משתמש ב-VPN, ב-EDR offline או בהענקה בשורש ‏(q4 ו-checkpoint של r8).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "The Cold Room" | כניסה | תחנה 1 |
| Chapter 2: "Green Across the Board" | אחרי The Hypervisor | תחנה 2 |
| Chapter 3: "03:12" | אחרי The Grant | תחנה 3 |
| Chapter 4: "One by One" | אחרי The Host's Own Log | תחנה 4 |
| Finale: "Bare Metal" | אחרי הבוס | החדר הבא |
