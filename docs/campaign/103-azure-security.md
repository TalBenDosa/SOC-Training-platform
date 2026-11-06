# תסריט חדר 103: Azure IaaS Security for SOC Analysts

**שם המבצע:** Operation Subscription
**רמה:** בינוני (הפריימרים פתוחים)
**העולם:** Rowan Grid Energy (חברת חלוקת חשמל בדויה): מנוי Azure אחד מאחורי מפת ההפסקות שחצי מיליון בתים בודקים כשהחשמל נופל, וסופה עם שם שמגיעה ביום חמישי.
**המנטור:** Linnea Achebe, Azure Security Engineer. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שני בלילה Defender for Cloud מסמן סקריפט שרץ על vm-outagemap-02, ואף אחד בצוות לא התחבר למכונה. Linnea פותחים את הבוקר בשאלה אחת: מה יכול להגיע ל-VM הזה בלי להתחבר אליו בכלל? המעקב מוביל ל-sp-outagemap-deploy, זהות הפריסה של הקבלן Tern Build Services, שה-client secret שלה הודפס בלוג build. עם תפקיד Contributor אחד על קבוצת המשאבים, כתובת זרה מריצה קוד כ-root דרך ה-API של Azure, פותחת שלושה חוקי NSG ומשאירה crontab. אחרי שהסיפור בבית נבלם, NexaCorp, שמפיקה את החשבונות של לקוחות Rowan, חסרה אנליסט למשמרת הלילה, והלומד נשלח לשבת בדסק שלהם.

## המכניקה הייחודית של החדר
**A Role Is a Shell.** תפקיד על VM שווה ערך ל-shell על ה-VM. חדרים 55 ו-83 מכסים את Entra ואת מישור הניהול המשותף, וכאן נשארים על משאבי Azure.
- **From Contributor to the VM:** מעבדת `portal` על skin `azure`. הלומד עובד אחורה מההתראה: Activity log, טבלת `AzureActivity` עם `CallerIpAddress`, flow logs שמראים שלא נכנס שום חיבור, device events שמראים מה רץ, ורק אז IAM והגדרת התפקיד. `Actions: *` מכסה Run Command, ו-`NotActions` על `Microsoft.Authorization/*/Write` מסביר למה ניסיון הרשאה נכשל ב-02:38.
- **Which Operations Page Someone?:** מעבדת `tune` עם שני חוגים, דרגת רגישות והיסטוריית הקורא ב-30 הימים האחרונים. רגישות לבדה מעירה את התורן בגלל עבודת ה-patch הלילית, נדירות לבדה מעירה אותו בגלל תגיות של מהנדס חדש. רק צירוף אחד עובר את היעד, ואזעקת שווא אחת נשארת.

## העולם התלת-ממדי
אולם קלפים (`facility`, Hall) עם גלובוס מעל הכן: חמישה קלפים לפי התחנות. סצנה `facilitysubscription`, ערכת נושא `subscription`.

## סדר המשימות
r1, r2, q1 | r3, q2 | r4, r5, q3 | r8, la1, ac1, m1, r6 | la2, la-storage, f1, r7

**הסדר שונה.** הסדר המקורי: r1, r2, r3, r4, r5, q1, q2, q3, la1, la2, ac1, m1, r6, la-storage, f1, r7, r8. שלוש השאלות ישבו אחרי חמש קריאות ברצף, ושתי קריאות עם שאלות ביניים סגרו את החדר אחרי המשימה הקשה. עכשיו כל שאלה באה אחרי הקריאה שלה, r8 באה לפני שאלות הבלימה הראשונות, ו-la2 עברה לתחנת הבוס.

מה נשמר בכוונה:
- la1 לפני ac1, כי ב-fp_trap של ac1 כתוב "the earlier Key Vault event".
- ac1 לפני r6, כי r6 מפנה לתרגיל הזה ומסבירה אותו.
- la1 לפני la2 לפני la-storage, כי כל הקשר סופר דקות מהאירוע הקודם.
- f1 מיד אחרי la-storage ("the event above"), ו-r7 אחרי f1 ("the flag question above").

אין בחדר דגל או קריאה בנוסח "Log Analysis N", לכן אין מספור שעלול להישבר.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Tenant Map | r1, r2, q1 | **Read a Resource ID** (anatomy), **Does This Role Reach That?** (worksheet), **Which Log Holds It?** (sort), **Anatomy of an Activity Log Entry** (anatomy), **An Empty Log Proves Nothing** (worksheet) |
| 2 | Who Called? | r3, q2 | **Whose Token Is This?** (sort), **Follow the Client Secret** (trace) |
| 3 | The Overnight Script | r4, r5, q3 | **Reviewed Rules or Live Rules?** (spotdiff), **Three Containers, Three Settings** (inspect), **From Contributor to the VM** (portal), **One Identity's Unusual Monday** (worksheet) |
| 4 | Contain or Close | r8, la1, ac1, m1, r6 | **Close the Identity Down** (duel), **The Order of Work on vm-outagemap-02** (sequence), **Anatomy of a Vault Audit Record** (anatomy), **The Function App's Address List** (worksheet), **Right Rule, Right Verdict** (queue), **Five Questions, Five Fields** (match), **Which Operations Page Someone?** (tune) |
| 5 (בוס) | Twenty-Three Minutes | la2, la-storage, f1, r7 | **Decode the Tuple** (worksheet), **Did the Door Get Used?** (trace), **Anatomy of a SAS URL** (anatomy), **What Breaks If You Rotate key1?** (worksheet) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (מה גבול החיוב והגישה):** עובדת זיכרון. היא מופיעה כשורה עם תווית ב-Read a Resource ID, על נתיב של container באחסון, והמעבדה לא שואלת עליה.
- **q1 (למה קריאת סוד לא מופיעה ב-Activity Log):** נלמד ב-Which Log Holds It? וב-An Empty Log Proves Nothing על blobs, תורים ו-flows. אין במעבדות האלה Key Vault, וה-Entra מופיע רק על התחברות ועל הזמנת אורח. הפריימר מסביר control plane ו-data plane על שרת SQL.
- **שאלת הביניים של r3 (מה אומר xms_mirid):** נלמד ב-Whose Token Is This? על Logic App ו-function app. הפריימר אומר ש-`principalType` זהה לשתי הזהויות כעובדה כללית, כי q2 עצמה מניחה אותה.
- **q2 (ההבדל החקירתי בין app registration לזהות מנוהלת):** נלמד בהסברי המיון וב-Follow the Client Secret, שבו הסוד יוצא מלוג build ועובד מכתובת זרה. המילים של האפשרויות לא מופיעות.
- **שאלת הביניים של r4 (רמת Blob) ו-la-storage (רמת Container):** עובדות זיכרון. שלוש הרמות מופיעות ב-Three Containers, Three Settings כשורות לעיון בלבד, על קבצים של מפת ההפסקות, בלי שאלה ובלי דירוג. ההערות מתארות את ההגדרה ולא שופטות.
- **שאלת הביניים של r5 (איך Run Command עקף הכול):** נלמד ב-From Contributor to the VM. שם ה-VM משרת HTTPS, הסקריפט מוריד crontab, והראיה היא שאין flow נכנס מהכתובת. אין VM נעול, אין חשבון מקומי חדש ואין NSG שנותק.
- **q3 (פרץ קריאות):** נלמד ב-One Identity's Unusual Monday על משתמש אורח מול קו הבסיס שלו, דרך פעולות list שבאמת נרשמות. אין שם service principal, ואין מעבר על המסיחים.
- **שאלת הביניים של r8 (איפוס סיסמה לא עוצר סשן):** הרעיון נלמד ב-Close the Identity Down על עוגייה גנובה שממשיכה לעבוד אחרי החלפת אמצעי MFA. אין איפוס סיסמה בתרחיש, וקלף "Reset the password" נשאר קלף רזרבי.
- **la1, שאלה 1 (כתובת זרה לזהות מנוהלת):** נלמד במעבדה משלו, The Function App's Address List, על function app ופעולות `config/list`, בלי Key Vault.
- **la1, שאלה 2 (מה אומר SecretGet עם 200):** הקריאה נלמדת ב-Anatomy of a Vault Audit Record על `SecretSet` תמים של runbook. דוגמת הפריימר היא `GetBlob` מול `ListBlobs` באחסון, והלומד מעביר את הרעיון לבד.
- **la1, שאלה 3 (בלימה):** נלמד בפריימר של Close the Identity Down: חיתוך תפקידים, בדיקת המשאב, והחלפת מה שנקרא. לא מוזכרים חסימת IP, מחיקת כספת או מחזור החלפה חודשי.
- **ac1 (benign true positive):** נלמד ב-Right Rule, Right Verdict על Run Command והענקת תפקיד, ודוגמת הפריימר היא אזעקת תחנת משנה. אין שם listKeys, אין עבודת גיבוי.
- **m1 (מיפוי ל-AWS ו-GCP):** כל התאמה מופיעה פעם אחת בדרך אגב ולא נשאלת: subscription ו-resource group בהערות Read a Resource ID, Activity Log בפתיח האנטומיה שלו, זהות מנוהלת ו-service principal בהסברי המיון, NSG בפריימר של ה-spotdiff, Defender for Cloud בעמוד ההתראות בפורטל.
- **la2, שאלה 1 (קריאת החוק):** נלמד ב-Reviewed Rules or Live Rules? על SSH, 5432 ו-8080, בלי 3389.
- **la2, שאלה 2 (פענוח tuple):** נלמד ב-Decode the Tuple על tuples של SSH, HTTP, HTTPS ו-PostgreSQL. דוגמת הפריימר היא שאילתת DNS.
- **la2, שאלה 3 (האות המכריע של הבוס):** נלמד במעבדה משלו, Did the Door Get Used?, שעוקבת אחרי קורא אחד וכתובת אחת דרך שינוי, תעבורה וסשן, על SSH ב-Rowan. ההסבר מתאר את הקשר בין השכבות, ולא עובר על מסלולי ההסלמה השגויים.
- **f1 (שם חשבון האחסון):** השיטה נלמדת בסיכום של Read a Resource ID: נתיב שממשיך מתחת למשאב נקרא לפי תוויות ולא לפי מיקום מהסוף.
- **שאלת הביניים של r7 (מה מבטל SAS):** השיטה מופיעה כנתון בעמודה אחת ב-What Breaks If You Rotate key1?, והמעבדה לא שואלת עליה. המעבדה שואלת מי נפגע, ואיזה צרכן אפשר לבטל בנפרד. מחיקת container, Defender for Storage והחזרה ל-Private לא מוזכרים.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Nobody Signed In" | כניסה | תחנה 1 |
| Chapter 2: "Whose Key?" | אחרי The Tenant Map | תחנה 2 |
| Chapter 3: "One Analyst Short" | אחרי The Overnight Script | תחנה 4 |
| Finale: "Subscription" | אחרי Twenty-Three Minutes | החדר הבא |

**הערות לסרטונים:**
- Intro: חדר הבקרה של Rowan בתחזית הסופה, מפת ההפסקות על הקיר, וההתראה של הלילה. Linnea שואלים מי היה על המכונה והתשובה היא אף אחד. הסרטון נגמר לפני שנפתח לוג כלשהו.
- Chapter 2: הטלפון לקבלן והשתיקה בשיחה. הסרטון מראה שמישהו מחוץ לחברה מחזיק במשהו של Rowan, בלי לומר מה, ובלי שורת לוג ובלי שדה על המסך.
- Chapter 3: ערב יום שני, Rowan נושמים לרווחה, ואז שיחה מ-NexaCorp: חסר להם אנליסט ללילה. הלומד יוצא לדסק שלהם. הסרטון לא מראה איך בולמים ולא שום אירוע מהמשמרת.
- Finale: הסופה מגיעה ומפת ההפסקות נשארת למעלה. מבט קצר על מה שנשאר לסגור, בלי לפרט שיטה, ומעבר לחדר הבא.
