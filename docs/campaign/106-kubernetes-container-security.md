# תסריט חדר 106: Kubernetes & Container Security

**שם המבצע:** Operation Container Break
**רמה:** מתקדם (כל ה-primers מקופלים, `fold: true`)
**העולם:** Northlight Streaming (חברה בדויה): שירות סטרימינג, קלאסטר Kubernetes אחד שנושא כל שידור, כל כתובית וכל פרסומת, והפרק האחרון של Glasswater עולה ביום שבת בלילה.
**המנטור:** Dae-jung Whitaker, Platform Security Engineer. (בטקסטים במעבדות אין לשון זכר או נקבה.)

## סיפור הרקע
ביום שישי ב-01:12 עולה על node בייצור Pod בשם subtitle-cache-warm, ואיש בצוות הפלטפורמה לא פרס אותו. ל-Dae-jung יש את ה-audit log, חיישן על ה-node ושאלה אחת: איך שירות העלאת כתוביות הגיע כל כך קרוב למכונה שמתחתיו? ככל שהלילה מתקדם מתברר שה-Pod הוא רק האמצע של הסיפור, ושהשרשרת לא נעצרת בגבול הקלאסטר.

## המכניקה הייחודית של החדר
- **From Pod to Node:** החתימה של החדר. `pathway` שבו הלומד הולך את המסלול של הפורץ: מ-Pod חשוף, דרך טוקן ה-ServiceAccount שמותקן בו ודרך RBAC, אל Pod עם גישה ל-host ואל ה-node. כל צעד שגוי מסביר מה באמת היה קורה: 403, Pod Security, או קונטיינר נוסף מאחורי אותם קירות.
- **Safe Spec, Dangerous Spec:** `spotdiff` של YAML אמיתי. מפרט Pod מאושר מ-Git מול העותק שרץ: hostPID, privileged ו-hostPath, ולצדם שינויים שלא מזיקים בכלל. הקו של hostPath שומר על אותו שם volume ואותו mountPath, ורק המקור משתנה.
- **The Change Queue:** `intercept` על עומסי עבודה (Deployment, DaemonSet, Job, CronJob) עם שדות audit אמיתיים. כל הבקשות הצליחו, וההבדל יושב בגוף הבקשה, בשולח ובמקור ה-image.

## העולם התלת-ממדי
אי קמפוס (`facility`) של Northlight Streaming: ארבעה מבנים לפי התחנות, אף מבנה לא מאחורי מבנה אחר ולא לפני ה-Hub. עיר ה-Hub נושאת את שם החברה.

## סדר המשימות
r1, r2, q1 | r3, q2, la2 | r4, m1 | la1, f1

הסדר שונה מהמקור (r1, r2, r3, r4, q1, q2, la1, la2, m1, f1), כי במקור ארבע קריאות ברצף, ו-q1 רחוק שתי קריאות ממה שהוא בודק. הקריאות r1 עד r4 שומרות על סדרן, אז ההפניות ל-"Reading 2" ול-"Reading 4" עדיין נכונות. la1 נשאר אחרי r4 כי ההסבר שלו מצטט את Reading 4. m1 צריך את r4 בגלל שירות המטא-דאטה. la2 עובר לפני la1, ואף טקסט לא מפנה אליהם במספר. הדגל f1 בא מיד אחרי la1, קשור אליו דרך `logTask: k8s-la1`, ולא כתוב בו "Log Analysis N".

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Cluster | r1, r2, q1 | **Four Words Under Every Container** (codebreak), **What Sits on One Node?** (worksheet), **Safe Spec, Dangerous Spec** (spotdiff), **Why a Node Agent Asks for Host Access** (inspect) |
| 2 | The Audit Trail | r3, q2, la2 | **From Pod to Node** (pathway), **What Did This Request Do?** (sort), **Whose Binding Is Too Big?** (worksheet), **The Change Queue** (intercept), **Anatomy of a Session Into a Pod** (anatomy), **Who Can Explain This?** (queue) |
| 3 | The Node | r4, m1 | **Follow It Off the Node** (trace), **One Incident or Separate Tickets?** (sort) |
| 4 (בוס) | Container Break | la1, f1 | **Split the Image Reference** (worksheet), **Four Questions for a Pod** (simulate) |

משחקי ארקייד בחדר: codebreak + intercept + pathway + spotdiff בלבד.

**הפרדה מהשאלות הנבחנות:**
- **r1 (שאלת ביניים, kubelet):** שאלת זיכרון טהורה. ה-kubelet מוצג כנקודה ב-primer של Four Words Under Every Container ולא נשאל: אין סיבוב codebreak עליו.
- **q1 (hostPID):** Safe Spec, Dangerous Spec. ההסבר מופיע רק אחרי לחיצה על השורה, כעובדה ולא כשאלה, על Pod של Northlight. הדוגמה ב-primer היא `runAsUser`, לא שדה מהשאלה, ואף שורה לא מתייחסת לאפשרויות השגויות.
- **r3 (שאלת ביניים, נתיב הטוקן):** שאלת זיכרון טהורה. הנתיב מופיע כנתון עם תווית בהערה של תחנת הטוקן ב-From Pod to Node ולא נשאל.
- **q2 (למה verb ו-resource לא מספיקים):** The Change Queue מלמד את הרעיון על patch ו-create של Deployment, DaemonSet, Job ו-CronJob, אף פעם לא create על pods. שני פריטים מאותו Deployment מראים את אותה כותרת עם גוף שונה. הדוגמה ב-primer היא איתור שדה בתוך CronJob, בלי השוואה בין בקשה תמימה לזדונית. What Did This Request Do? מלמד לקרוא את שדות ה-audit.
- **la2 שאלה 1 (משמעות exec):** Anatomy of a Session Into a Pod. זה kubectl cp עם tar אחר הצהריים, על ידי m.okoye, עם כרטיס, לא sh ולא התקנת חבילה. בלי d.abrams ובלי prod-checkout. הערות השדות מתארות מה השדה מראה ולא שופטות.
- **la2 שאלה 2 (הצעד הבא):** Who Can Explain This?. חמישה סשנים: port-forward, attach, ephemeral container ו-exec של עובד שעזב, בלי התקנת כלי. ה-primer מלמד איך בודקים כרטיס מול אירוע, על CHG-3902.
- **m1 (התאמה):** מפוזר בין המעבדות, בניסוח אחר מזה של השאלה: Safe Spec, Dangerous Spec ל-privileged, hostPID ו-hostPath, ה-primer של From Pod to Node ל-RoleBinding, ה-primer של Follow It Off the Node ל-IMDS.
- **la1 שאלה 1 (הצירוף וההקשר):** Four Questions for a Pod הוא המעבדה הייעודית לאות המכריע: השולח, הבעלים, הגישה ל-host וה-image. ארבעה Pods אחרים. ב-subtitle-cache-warm דווקא ה-image עובר, והשולח הוא ServiceAccount של אפליקציה ולא CI. The Change Queue מראה סנסור לגיטימי עם privileged ו-hostPID. בלי kube-system, בלי ci-deploy-token ובלי svc-monitoring-backup.
- **la1 שאלה 2 (חשיבות ה-registry):** Split the Image Reference ופריט i4 ב-The Change Queue. הניסוח שונה מההסבר הנבחן, והכתובת היא 198.51.100.23:8443.
- **la1 שאלה 3 (הצעד הבא על הזהות):** Whose Binding Is Too Big? ו-`kubectl auth can-i` ב-primer של From Pod to Node. החשבון הוא farm-controller, בקר של Jobs ולא CI, ו-subtitle-upload בעל Role ב-namespace אחד.
- **f1 (host:port):** Split the Image Reference מפרק הפניה אחרת, עם דוגמה ב-primer על `mirror.corp.example:5050`. לא נזכרים בו חומת אש, kube-system או הערך הנבחן.
- קטע ה-hop limit של IMDSv2 לא נבדק במשימה נבחנת. הוא נשאר נקודה אחת ב-primer של Follow It Off the Node, כי זה מה שקובע בפועל אם Pod מגיע למטא-דאטה.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Nobody Deployed It" | כניסה | תחנה 1 |
| Chapter 2: "It Can See the Whole Machine" | אחרי The Cluster | תחנה 2 |
| Chapter 3: "It Left the Building" | אחרי The Node | תחנה 4 |
| Finale: "Saturday Night" | אחרי Container Break | החדר הבא |

הערות לסרטונים:
- **Intro:** Northlight יומיים לפני הפרק האחרון של Glasswater, אולם הבקרה בלילה, ו-Dae-jung מול שורה אחת ברשימה שאיש לא מזהה. לא מראים YAML ולא שדה.
- **Chapter 2:** הצוות מבין שה-Pod הזר רואה יותר ממה שקונטיינר אמור לראות. השאלה עוברת מ-"מה זה" ל-"איך הוא הגיע לשם". לא מראים שדה, טוקן או לוג.
- **Chapter 3:** התראה מחשבון הענן בשעה שאיש לא עובד בה. מישהו מחוץ לחברה מחזיק במשהו ששייך ל-node, והקובץ הכי שמור בחברה בסכנה. לא מראים פקודה, כתובת או מסלול.
- **Finale:** ביום שבת בערב הפרק עולה בזמן, הדלתות שהיו פתוחות נסגרות, והתיק נסגר. סיפור בלבד, בלי פסיקה של המשימה הנבחנת.
