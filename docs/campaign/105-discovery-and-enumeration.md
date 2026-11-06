# תסריט חדר 105: Discovery & Enumeration in the Logs

**שם המבצע:** Operation Mapmaker
**רמה:** בינוני (ה-primers פתוחים)
**העולם:** Selkirk Timber Cooperative (קואופרטיב עצים בדוי): 62 בעלי קרקע חברים, מנסרה אחת, מגרש בולי עץ אחד, והצעה לרישיון כריתה ל-20 שנה שצריכה להיות מוגשת ביום שני.
**המנטור:** Bahar Nkemelu, Detection Analyst. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום חמישי ב-09:12 חשבון של מודד עצים הקליד whoami במחשב של תחנת השקילה. שום התראה לא נדלקה, ובצדק: אף אחד לא מתריע על whoami אחד. אבל Bahar חושדים שמישהו משרטט מפה של הקואופרטיב, שאלה תמימה אחת בכל פעם, ושבסוף המפה נמצאת תיקיית ההצעות Bids. הזמן שנותר הוא הזמן שבין להסתכל לבין לקחת.

## המכניקה הייחודית של החדר
- **One Command Is Nothing, Ten Are a Map:** גם אדמינים מריצים whoami ו-net group, ולכן פקודה אחת לא אומרת כלום. ב-`hunt` בשפת SPL הלומד בונה שורה אחרי שורה ערימה של פקודות Discovery לכל מארח, סשן וחלון של עשר דקות, על נתוני 4688 מקוריים, כשהתוצאות מחושבות באמת.
- **How Many Questions, How Fast?:** `tune` שבו שני חוגים קובעים כמה פקודות שונות בכמה זמן נחשבות למישהו שמסתובב ומסתכל. החוגים מתחילים על האמרה עצמה, עשר בעשר, והיא נכשלת.
- **Who Answers? ו-Looking or Taking?:** שני `rush`: מי עונה על השאלה, המחשב הזה או בקר התחום, ומתי הסתכלות הופכת ללקיחה.

## העולם התלת-ממדי
אולם קלפים (`facility`, פריסת hall, ליבה `matrix`) של שולחן הזיהוי בקואופרטיב: חמישה קלפים לפי התחנות.

## סדר המשימות
r0, r1, r2, q1 | r3, q2, r4, la1 | r5, q3, la2 | r6, o1, r7, q4 | ac1, m1, f1

סדר המשימות המקורי של החדר נשמר, אין צורך בסקריפט סידור מחדש.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Whoami | r0, r1, r2, q1 | **Name the Goal Before the Tool** (sort), **One Line Proves Nothing** (worksheet), **Three Questions on One Machine** (sort), **Anatomy of a 4798** (anatomy), **Normal Hum or Second Look?** (sort) |
| 2 | The Domain Question | r3, q2, r4, la1 | **Who Answers?** (rush), **Four Domain Queries, One Queue** (queue), **Exists, or What Runs There?** (sort), **Pull the Thread Both Ways** (trace) |
| 3 | The Cloud Census | r5, q3, la2 | **Three Questions for a Cloud** (reactor), **Read a Finding's Name** (inspect), **Anatomy of a CloudTrail Record** (anatomy), **Add Up the Burst** (worksheet) |
| 4 | Ten Are a Map | r6, o1, r7, q4 | **Looking or Taking?** (rush), **The Same Climb in the Cloud** (sequence), **One Command Is Nothing, Ten Are a Map** (hunt), **How Many Questions, How Fast?** (tune), **Narrow Enough to Keep?** (sort) |
| 5 (בוס) | The Finished Map | ac1, m1, f1 | **Correct Rule, Right Label** (queue) ואז ההחלטה הנבחנת |

**שילוב המשחקים הארקיידיים:** hunt + rush + tune.

**הפרדה מהשאלות הנבחנות (איפה נלמד כל רעיון ומה שונה):**
- **r1 checkpoint (למה Discovery קשה לזיהוי):** One Line Proves Nothing, השאלות על מספר הכלים שאינם של Windows ועל כלל whoami. הנתונים הם טבלת 4688 של Selkirk.
- **r2 checkpoint (`net localgroup administrators`) ו-q1 (whoami):** הקטגוריות של Three Questions on One Machine וה-primer. הפקודות במעבדה: `query user`, ‏`net user`, קבוצות Remote Desktop Users ו-Backup Operators. אין מיון של whoami, ולא של קבוצת Administrators; whoami מוצג רק בשורה של ה-primer.
- **la1 שאלה 1 (CallerProcessName):** Anatomy of a 4798 ו-Normal Hum or Second Look?. המקרה: 4798 עם PowerShell וכרטיס תמיכה, ולא 4799 על Administrators עם net.exe אחרי הקלקה על פישינג.
- **la1 שאלה 2 (קורלציה לציר הזמן):** Pull the Thread Both Ways, שמתחיל מ-4799 על Backup Operators ב-SLK-MILL-03 וחוזר להתחברות VPN חריגה. אין כאן פישינג.
- **r3 checkpoint (המקור הוא הסימן):** ה-primer של Four Domain Queries, One Queue והרשומות a1 ו-a3. הגבול בין מקומי לתחום: Who Answers?. המעבדה מלמדת ש-`Get-ADUser`, ‏`Get-ADGroup` ו-`Get-ADGroupMember` עובדים דרך ADWS בפורט TCP 9389, ו-LDAP נשאר עבור dsquery, ‏AdFind ו-SharpHound. הקריאה r3 אומרת אחרת, והפער מתועד.
- **q2 (שאילתה בודדת מול פרץ):** ההתראות a2 ו-a3 בתור. לולאת LDAP על 38 קבוצות ושאילתה אחת של מתכננת על הקבוצה שלה, ולא `net group "domain admins"` פעם אחת מול 200 פעם ולא עובד IT חדש.
- **r5 checkpoint ו-q3 (T1580 מול T1619, הממצא של GuardDuty והצעד הבא):** Three Questions for a Cloud ו-Read a Finding's Name. הממצא של q3 לא מוצג במעבדה: הוא נפתר ממבנה השם ומ-MaliciousIPCaller ב-Recon:IAMUser, לצד Discovery:S3/AnomalousBehavior. ה-T1619 נלמד על `ListObjectVersions` ועל `gcloud storage ls`, והרעיון "האם באו קריאות אחרי הרישום" נלמד על `storage.objects.get`, לא על GetObject אחרי ממצא של S3.
- **la2 ו-f1 (פרץ CloudTrail ו-IP לחקירה):** Anatomy of a CloudTrail Record ו-Add Up the Burst. התפקיד `survey-sync-role` על EC2, לא Lambda; 31 קריאות על 5 שירותים ב-11:32, לא 47 על 4 ב-02:06; הערך הוא 203.0.113.58.
- **o1 (שרשרת מ-Discovery ל-Collection):** The Same Climb in the Cloud, שרשרת של חמישה שלבים בענן במקום שישה על מארח. שני התחומים נלמדים ב-Looking or Taking?.
- **r7 checkpoint ו-q4 (allowlist):** Narrow Enough to Keep? והשורה של ה-lookup ב-hunt. שרת מלאי, סורק, CI וגיבוי, ולא חשבון ביקורת גישה מול לפטופ של שיווק.
- **ac1 (הבוס):** Correct Rule, Right Label, מעבדה נפרדת להבחנה בין benign true positive ל-false positive. המקרים הם סורק, Terraform והתאמת מחרוזת שגויה, ולא משימת ביקורת לילית של חשבון שירות על שרת ביקורת.
- **m1 (התאמה בין טכניקה לפקודה):** לא נשאל באף מעבדה. העובדות מופיעות ב-primers בדרך אגב, ליד התווית שלהן, והמעבדות ממיינות פקודות אחרות.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "One Word on a Yard PC" | כניסה | תחנה 1 |
| Chapter 2: "Sixty-Two Members" | אחרי The Domain Question | תחנה 3 |
| Chapter 3: "Monday's Deadline" | אחרי The Cloud Census | תחנה 4 |
| Finale: "The Finished Map" | אחרי The Finished Map | החדר הבא |

**הערות לסרטונים:** הסרטונים מספרים את סיפור הקואופרטיב, את Bahar ואת ההצעה שצריכה להיות מוגשת ביום שני. הם לא מראים פקודה, שדה, ערך IP, סף או שאילתה, ולא מסבירים איך קוראים לוג.
