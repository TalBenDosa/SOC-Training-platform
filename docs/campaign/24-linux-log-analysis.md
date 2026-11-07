# תסריט חדר 24: Linux Log Analysis

**שם המבצע:** Operation Var Log
**רמה:** בינוני
**העולם:** Pinewood Hosting (חברת אחסון בדויה) עם 6,000 שרתי Linux שמריצים אתרים של אחרים. כל אחד מהם מקבל כמה מאות נקישות SSH בשעה.
**המנטור:** Arjun Mehta, איש תגובה לאירועים.

## סיפור הרקע
ב-Linux אין יומן אחד. ‏sshd, ‏sudo, ‏cron, הקרנל ו-auditd כותבים כל אחד למקום אחר, וחלקם לא כותבים טקסט בכלל. Arjun עונה לקריאות של שלוש בלילה, ויודע איזו מגירה של /var/log לפתוח לכל שאלה.

## העולם התלת-ממדי: /var/log
- ארון תיוק שהמגירות שלו נפתחות אחת אחרי השנייה: auth.log, ‏syslog, ‏audit.log, ‏nginx ו-wtmp.
- גביש של ה-journal הבינארי, וקרני שאילתה שולפות ממנו שורות: ‏-u cron, ‏-p err ו-_COMM=sudo.
- דלת SSH שנחיל נקישות אדומות פוגע בה, עד שאחת עוברת ומפתח (root@kali) נוצץ במנעול.
- שעון cron שהמחוג שלו מתקתק "כל חמש דקות" ויורה, ולידו סרט לוג עם חור אדום.

## סדר המשימות
r1, q1 | q2 | r2, la1, flag1 | r3, q3, q4 (השאלות q1 ו-q2 הוקדמו, והדגל עבר אל ה-log analysis שהוא מתייחס אליו)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Where Linux Writes | r1, q1 | **Which Drawer?**: שישה אירועים וחמשת הקבצים שבהם מוצאים אותם |
| 2 | Ask the Journal | q2 | תרגול **Query the Journal**: ‏-u cron -b, ‏-p err, ‏_COMM=sudo ו---list-boots |
| 3 | Knocks at the Door | r2, la1, flag1 | **Who Knocked, Who Got In**: ‏lastb -i מול last -i, ומפתח root@kali ב-authorized_keys |
| 4 (בוס) | What Stays Behind | r3, q3, q4 | **The Job That Keeps Coming Back**: ‏crontab -l -u www-data, הקובץ המוסתר .sysupd עם @reboot, ו-web shell ב-access.log של nginx |

**הפרדה מהשאלות הנבחנות:**
- המיון ממקם אירועים, ולא משווה בין auth.log ל-audit.log (q1).
- התרגול על ה-journal לא משתמש ב---since/--until עבור sshd (q2).
- קונסולת ה-SSH רצה על מארח אחר ו-IP אחר מ-198.51.100.45 (la1, flag1).
- קונסולת ה-cron לא קוראת auid/euid (q3).
- אף מעבדה לא מציגה פער ב-auth.log (q4).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "No Single Diary" | כניסה | תחנה 1 |
| Chapter 2: "Ask the Journal" | אחרי Where Linux Writes | תחנה 2 |
| Chapter 3: "The Key Under the Mat" | אחרי Ask the Journal | תחנה 3 |
| Finale: "@reboot" | אחרי הבוס | החדר הבא: SIEM Fundamentals |
