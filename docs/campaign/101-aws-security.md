# תסריט חדר 101: AWS Security for SOC Analysts

**שם המבצע:** Operation Root Account
**רמה:** בינוני (הפריימרים פתוחים)
**העולם:** Westmarch Biotech (חברת ביוטק בדויה): טיפול גני אחד, עשרה ימים עד ההגשה לרגולטור, וחשבון AWS אחד שמחזיק את כל ריצות הריצוף.
**המנטור:** Eun-ji Falk, Cloud Incident Responder. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום חמישי בבוקר מתברר ש-wm-seq-runs, באקט פרטי עם ריצות הריצוף, מעתיק את עצמו לחשבון שאף אחד ב-Westmarch לא מכיר. Eun-ji Falk מגיעים לשיחה ומתחילים מהרשומה. מסתבר שנתיב דיבוג בפונקציית ה-LIMS הדפיס את משתני הסביבה שלה לכל מי שביקש, ושם ישבו סשן של role ומפתח ארוך טווח של svc-qc-uploader. הפוליסי של ה-role הורחב במהלך מיגרציה ואף אחד לא החזיר אותו, ולכן הסשן הגנוב הספיק לכל מה שקרה באותו לילה. אף אחד לא נכנס כ-root, וזה בדיוק העניין: עם `s3:*` על `*` אף אחד לא היה צריך.

## המכניקה הייחודית של החדר
- **Reviewed Policy or Live Policy?:** מעבדת `spotdiff` על JSON של פוליסי IAM, שורה אחרי שורה: גרסה 3 שעברה ביקורת מול גרסה 4 שרצה עכשיו. ה-Condition עדיין שם, אבל הוא כבר לא מגביל כלום.
- **Follow the Session:** מעבדת `trace` שמתחילה בממצאי GuardDuty וממשיכה ב-CloudTrail, עד הסשן, הכתובת והזהות השנייה. כל הממצאים הם סוגים ש-AWS עדיין מייצרת, ונבדקו מול רשימת ה-retired.
- **Did They Leave a Way Back?:** מעבדת `hunt` ב-KQL של חמישה שלבים על `AWSCloudTrail`. הלומד עוקב אחרי ה-credential ולא אחרי כתובת אחת, משאיר רק קריאות שהצליחו ושינו מצב, ומוצא מה עדיין עומד אחרי שהסשן מת.
- **What's Still Open at 10:02** ו-**Did It Fire Right, and Was It Allowed?:** שתי מעבדות `defuse`. הראשונה סוגרת כל נתיב בשכבה שלו, והשנייה מפרידה בין שתי שאלות: האם החוק עבד, והאם הפעילות מאושרת.
- **הגבול של החדר:** חדר 83 מכסה את ה-control plane המשותף לכל העננים. כאן נשארים על השירותים של AWS עצמה: IAM, S3, CloudTrail, GuardDuty, IMDS.

## העולם התלת-ממדי
אולם קלפים (`facility`, Hall) בשם Root Hall, עם `core: "globe"` וחמישה קלפים לפי התחנות. סצנה `facilityrootaccount`, ערכת נושא `rootaccount`.

## סדר המשימות
r1, r2, q1 | r3, q3, r4, q2, m1 | la1, la2 | la-stoplogging, f1, r6 | r7, ac1, r5

**הסדר שונה.** הסדר המקורי: r1, r2, r3, r4, q1, q2, q3, la1, la2, ac1, m1, r5, la-stoplogging, f1, r6, r7. במקור יש ארבע קריאות ברצף, ו-ac1 בא לפני StopLogging למרות שהטקסט שלו אומר שהאירוע כבר נבלם. עכשיו כל שאלה יושבת ליד הקריאה שלה, ו-ac1 (פסיקה, 30 XP) עובר לתחנת הבוס, אחרי r7 ואחרי כל מה שהוא מפנה אליו. r5 נשאר אחרי ac1 כי Step 5 שלו אומר בגלוי את הפסיקה של ac1. r6 נשאר אחרי f1 ("the flag question above"), ו-f1 מיד אחרי האירוע שלו ("the event above"). la2 נשאר האירוע השני, כמו שכתוב ב-r3. אין בחדר דגל בנוסח "Log Analysis N".

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Bucket | r1, r2, q1 | **Which Record Answers the Question?** (sort), **Recorded by Default, or Only If Switched On?** (sort), **Read One CloudTrail Record** (anatomy) |
| 2 | The Policy | r3, q3, r4, q2, m1 | **Two Credentials, Two Lifetimes** (inspect), **Reviewed Policy or Live Policy?** (spotdiff), **Read One Bucket Statement** (anatomy), **Read the Finding Name** (match), **How a Metadata Request Becomes a Stolen Session** (sequence) |
| 3 | The Credentials | la1, la2 | **Set the Scope** (worksheet), **A Token Sent to the Wrong Person** (sequence), **Can You Take It Back?** (sort), **Follow the Session** (trace), **Read One Policy Version Call** (anatomy), **What's Still Open at 10:02** (defuse) |
| 4 | The Dark Trail | la-stoplogging, f1, r6 | **Read One Logging Change** (anatomy), **Which Camera Goes Dark?** (inspect), **Price the Fleet** (worksheet), **Who Would Have Caught It?** (match) |
| 5 (בוס) | Root Account | r7, ac1, r5 | **Read the Revoke Policy** (anatomy), **Did It Fire Right, and Was It Allowed?** (defuse), **Weigh the Call** (sort), **Did They Leave a Way Back?** (hunt) |

**הפרדה מהשאלות הנבחנות:**
- **שאלת הביניים של r1 (מאיזה מקור לומדים מי שינה bucket policy ומאיזו כתובת):** הפריימר של Which Record Answers the Question? מתאר מה כל מקור מתעד, והמיון נעשה על שאלות אחרות: השקת instance, יצירת משתמש, מחיקת snapshot. אף פריט לא עוסק בשינוי פוליסי של באקט.
- **q1 (מה נרשם כש-data events כבויים):** נלמד ב-Recorded by Default, על PutObject, DeleteObject, CopyObject ו-Invoke, עם דוגמת פריימר על פונקציית Lambda. GetObject לא מופיע במיון, והמעבדה לא דנה ב-server access logging או ב-Flow Logs כתחליף.
- **שאלת הביניים של r3 (למה סשן של role מסוכן פחות, אבל עדיין מסוכן):** עובדת זיכרון. היא מופיעה כשורה עם תווית ב-Two Credentials: מפתח ASIA עם שעת סיום מול מפתח AKIA בלי תאריך סיום. המעבדה לא שואלת אותה.
- **q3 (Condition שנעלם, Action ו-Resource זהים):** הרעיון נלמד ב-Reviewed Policy or Live Policy?, שם גם ה-Action וגם ה-Resource התרחבו, וה-Condition על Region לא נמחק אלא רוקן ל-`*`. אין במעבדה aws:SourceIp ואין שום פוליסי של דוחות. דוגמת הפריימר היא תור SQS עם aws:SecureTransport.
- **q2 (Principal '*' על s3:GetObject בלי Condition):** השדה נלמד ב-Read One Bucket Statement על s3:PutObject לתיקייה אחת, מאחורי Condition של VPC endpoint. הדוגמה בפריימר מציגה Principal של role ושל שירות. ההערות מתארות שדות ולא עוברות על המסיחים.
- **m1 (מיפוי שירותים):** הפריימר של Which Record Answers the Question? נותן את השירותים ואת שלושת המקורות, והפריימר של How a Metadata Request נותן את כתובת ה-IMDS. המעבדות לא שואלות את ההתאמה עצמה, ו-Read the Finding Name מתאים שמות של ממצאים, לא שירותים.
- **la1, שאלה 1 (למה סוג הזהות קובע את היקף הבדיקה):** נלמד ב-Set the Scope על svc-qc-uploader ועל נתיב דיבוג, עם דוגמת פריימר על כרטיס כניסה שאבד. אין שם GitHub, svc-deploy או שלושה ימים.
- **la1, שאלה 2 (האם ההורדה הצליחה):** errorCode נלמד ב-Read One CloudTrail Record על PutBucketReplication. על s3:GetObject מופיעה הערה אחת אגב קריאה ב-Read One Bucket Statement. אף הערה לא מזכירה את responseElements או מפרשת readOnly של קריאת קובץ.
- **la1, שאלה 3 (תוכנית בלימה):** הסדר נלמד ב-A Token Sent to the Wrong Person, על טוקן API של ספק שאינו AWS, שנשלח במייל לאדם הלא נכון: עוצרים, שומרים ראיות, מרחיבים את הבדיקה, מדווחים, ורק אז מסדרים. ההעברה ל-AWS נשארת ללומד. הפריימר של Can You Take It Back? נשאר עם נקודה אחת: להעדיף מהלך שאפשר לבטל. המיון עוסק בפקודות אחרות, בלי מפתח גישה.
- **שאלת הביניים של r7 (הפעולה הראשונה על מפתח שנפרץ):** update-access-key מופיע כהערה על השורה של המפתח ב-Two Credentials. הניגוד בין Inactive ל-delete-access-key נלמד בסיבוב משלו ב-What's Still Open at 10:02, על svc-qc-uploader, עם רצים שתלויים במפתח ונתוני last-used שהבדיקה צריכה. המפתח הנבחן, הזהות והכתובות אחרים. Can You Take It Back? לא כולל אף פקודת מפתח.
- **la2, שאלה 1 (מאיפה הגיעו ה-credentials):** נלמד ב-Follow the Session על סשן של Lambda ו-ResourceCredentialExfiltration.OutsideAWS, ועל שם הסשן בפריימר. העובדה ש-`i-` מסמן EC2 מופיעה כהערה ב-How a Metadata Request. אין ec2-webapp-role ואין Tor.
- **la2, שאלה 2 (מה עושה הגרסה החדשה):** נלמד ב-Read One Policy Version Call, על wm-ci-deploy-policy עם `setAsDefault: false` ו-v6, קריאה שלא שינתה הרשאות של אף אחד. הגרסה הנבחנת היא true ו-v7.
- **la2, שאלה 3 (מסלול ההסלמה):** נלמד בשלב השלישי של Follow the Session (זהות שנייה מאותה כתובת) וב-What's Still Open at 10:02, על מפתח, instance, סשן, כלל שכפול וגרסת פוליסי, לא בסדר של התשובה הנבחנת. המפתח נסגר בסיבוב משלו, על svc-qc-uploader. הסיבוב היחיד שקרוב למסיח הוא בידוד מול סיום של instance, על wm-lims-web, עובדה שמגיעה מ-r7.
- **la-stoplogging (מה StopLogging עושה):** נלמד ב-Which Camera Goes Dark? כשורה עם תווית, ליד DeleteTrail, PutEventSelectors ו-UpdateTrail. המעבדה לא שואלת, וההערה על StopLogging לא נוגעת באף מסיח. הרשומה ב-Read One Logging Change היא PutBucketLogging על באקט.
- **f1 (שם ה-trail):** המעבדה מראה איפה לקרוא: `requestParameters`, עם bucketName לדוגמה ו-name ל-trail. הערך הנבחן לא מופיע באף מעבדה.
- **ac1 (פסיקה על GetCallerIdentity):** האות המכריע נלמד במעבדה משלו, Did It Fire Right, and Was It Allowed?, על Terraform, על חוק שמתאים למילה בשם, על קריאת סוד ועל טיקט שמכסה באקט אחר. אין שם STS, Fargate, פייפליין יומי או חשבון שהיה בחקירה. דוגמת הפריימר היא חיישן דלת שמציג את שלוש התשובות זו לצד זו. GetCallerIdentity לא מופיע באף מעבדה.
- **שאלת הביניים של r5 (מה לבדוק קודם):** נלמד ב-Weigh the Call על PutUserPolicy, DeleteFlowLogs, ModifySnapshotAttribute ואחרות. DescribeInstances ו-AuthorizeSecurityGroupIngress לא מופיעים, ודוגמת הפריימר משווה שני שינויים ברוחב שונה, לא קריאה מול שינוי.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Ten Days" | כניסה | תחנה 1 |
| Chapter 2: "An Account Nobody Knows" | אחרי The Bucket | תחנה 2 |
| Chapter 3: "After Midnight" | אחרי The Credentials | תחנה 4 |
| Finale: "Root Account" | אחרי Root Account | החדר הבא |

**הערות לסרטונים:**
- Intro: Westmarch, ההגשה לרגולטור, וריצות הריצוף שמאחוריה. שיחת הבוקר של יום חמישי, ו-Eun-ji Falk נכנסים לחדר. הסרטון נגמר לפני שנפתחת רשומה כלשהי.
- Chapter 2: צוות המעבדה מגלה שעותקים של הריצות יוצאים החוצה. אף אחד לא יודע למי שייך החשבון בצד השני, והעבודה עוברת מ"מה קרה" ל"מי יכול היה לעשות את זה". בלי ערך מהרשומות ובלי שורת פוליסי על המסך.
- Chapter 3: המשרד בשעות הקטנות, ו-Eun-ji פותחים מסך אחד שהיה אמור להמשיך לדבר ופתאום שקט. הסרטון מראה את התחושה ולא את הרשומה.
- Finale: ההגשה יוצאת בזמן. שיחה שקטה בין Eun-ji לסמנכ"ל על השאלה מי באמת החזיק במפתחות, בלי שום פרט מהחיפוש האחרון. סיום בכרטיס NEXT MISSION לחדר הבא.
