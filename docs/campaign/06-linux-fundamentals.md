# תסריט חדר 6: Linux Fundamentals for SOC Analysts

**שם המבצע:** Operation Root Cause
**רמה:** מתחילים
**העולם:** Brightwave Media (חברה בדויה), שרת הווב web-srv-02.
**המנטור:** Omar Haddad, Linux Incident Lead. Lucy Park (Compliance) מופיעה בשאלה.

## סיפור הרקע
השרת web-srv-02 רץ חם מאז 02:31. אין שולחן עבודה, אין אייקונים ואין עכבר, רק shell של root וסמן מהבהב. Omar נותן לך את המקלדת. כל מה שצריך נמצא במערכת הקבצים, למי שיודע איפה לחפש. החדר כולו הוא חקירה של שרת לינוקס פרוץ מתוך ה-shell שלו, הדוגמה שביקשת לחדר הלינוקס.

## העולם התלת-ממדי: Filesystem Tree
עץ הספריות של השרת, שגדל מ-/ בבסיס: /etc, /var, /tmp, /home, /proc, /root, /usr/bin ו-/dev/shm, ומעליהם shadow, sudoers.d, cron.d, log ו-.ssh. מאחור יורד גשם ירוק של תווי מסוף. התחנות מדליקות את העץ:
1. הענפים נדלקים.
2. שלישיות rwx מופיעות מעל הקבצים הרגישים.
3. שעון cron מופיע מעל cron.d, ומפתח פולש אדום מופיע על .ssh ונעלם.
4. קרן audit סורקת את כל העץ.

## סדר המשימות
סודר מחדש לפי נושא: r1 | r2, q1, q2 | r3, q3 | la1, flag1.

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | First Look | r1 | **First Look** (טרמינל bash): ps aux, ls -la /proc/4242/exe (בינארי שנמחק), ss -tulpn (פורט 31337), last (התחברות לילית מבחוץ). **Where Does It Belong?**: מיקומים תקינים מול חשודים |
| 2 | Who Can Do What | r2, q1, q2 | **Who Is Really Root?**: /etc/passwd (חשבון backup עם UID 0), sudoers.d/90-tmp (sudo בלי סיסמה ל-deploy), מצב מספרי של קובץ. **Permission Calculator**: המרה של מחרוזות הרשאה למספר, כולל SUID 4755 |
| 3 | Persistence Sweep | r3, q3 | **Sweep for Persistence**: crontab של deploy (curl ‏| bash כל 15 דקות), authorized_keys של root (המפתח kali@kali), היסטוריית apt (masscan) |
| 4 (בוס) | The Privilege Alarm | la1, flag1 | תרגול **Anatomy of an auditd Record**: useradd שהריץ deploy אחרי sudo, עם auid, uid ו-euid. אחריו ההתראה הנבחנת והדגל |

**הפרדה מהשאלות הנבחנות:**
- אין קובץ SUID ב-/tmp (q1).
- ההרשאות של /etc/shadow נשארות 640 (q2).
- ה-cron הוא crontab של משתמש ולא קובץ ב-/etc/cron.d (q3).
- החשבון www-data וה-UID שלו לא מוצגים בשום מקום (la1, flag).

## שינוי בממשק
הקונסולה עכשיו ברוחב מלא, והמשימות מתחתיה, כדי שפלט רחב כמו ps aux ייראה בשלמותו.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Running Hot Since 02:31" | כניסה | תחנה 1 |
| Chapter 2: "Two Ways to Root" | אחרי Who Can Do What | תחנה 3 |
| Chapter 3: "Every Door" | אחרי Persistence Sweep | תחנה 4 |
| Finale: "Root Cause" | אחרי הבוס | החדר הבא: Log Management |
