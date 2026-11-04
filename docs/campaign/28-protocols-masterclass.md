# תסריט חדר 28: Network Protocols Deep Dive

**שם המבצע:** Operation Deep Water
**רמה:** בינוני
**העולם:** Quayside Shipping (חברת ספנות בדויה): עגורני נמל, מערכות מכס ו-3,000 משתמשים, שכולם מדברים באותם פרוטוקולים בודדים.
**המנטור:** Lars Eriksen, ארכיטקט אבטחת רשת.

## סיפור הרקע
תוקפים לא ממציאים פרוטוקולים חדשים. הם מתחבאים בתוך TCP, ‏DNS, ‏HTTP ו-TLS, כי אלה תמיד מותרים. Lars רוצה שתהיה שוטף מספיק כדי לקרוא הקלטה, תעודה וטבלת ARP כמו שקוראים משפט.

## העולם התלת-ממדי: Deep Water
- ערימת זכוכית של שבע שכבות, שחבילה שוקעת דרכה.
- שני מארחים שמחליפים חיצי SYN, ‏SYN-ACK ו-ACK, וחץ UDP בודד שלא צריך תשובה.
- עץ DNS שנפתר עד עלה, ומנהרת TLS 1.3.
- שני מכשירים שטוענים לאותה כתובת MAC של ה-gateway, ואחד מהם אדום.
- beacon שפועם במרווחים קבועים בתוך צינור HTTP/DNS מותר.

## סדר המשימות
r1, r2 | r3, r4, q1 | r5, r6, r7 | r8, r9, q3 | r10, q2, la1, f1 (במקור כל הקריאות היו לפני כל השאלות. כל שאלה עברה אל התחנה של הנושא שלה)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Layers and Addresses | r1, r2 | **Subnet Maths**: ‏‎/20‎ ו-4,096 כתובות, כתובת אחת מחוץ לטווח, ‏169.254 ו-100.64 (CGNAT) |
| 2 | TCP and UDP | r3, r4, q1 | **Read the Conversation**: הקלטה עם DNS ב-UDP, ‏handshake, ‏Client Hello עם SNI ו-FIN |
| 3 | Names, Pages and Locks | r5, r6, r7 | **Interrogate the Stack**: ‏dig ‏(A ו-CNAME), ‏curl -sI ‏(302 ו-location) ו-openssl s_client (תעודה בת שלושה ימים) |
| 4 | The Plumbing | r8, r9, q3 | **Who Is the Gateway?**: ‏arp -a עם MAC כפול, ‏ipconfig /all עם DHCP ו-DNS זדוניים |
| 5 (בוס) | Hiding in Plain Sight | r10, q2, la1, f1 | תרגול **Anatomy of an HTTP Beacon** (‏Zeek http.log, כל 300 שניות ±15) לפני התראת ה-DNS הנבחנת |

**הפרדה מהשאלות הנבחנות:**
- ההקלטה מראה שיחה תקינה, ולא תגובות של סריקת SYN (q1).
- קונסולת ה-ARP לא עוסקת ב-SMB פנימי (q3).
- התרגול הוא beacon ב-HTTP, ולא labels ארוכים ב-base64 (q2). הוא גם לא רשומת Sysmon 22 או תת-הטכניקה של la1 (f1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Always Allowed" | כניסה | תחנה 1 |
| Chapter 2: "SYN, SYN-ACK, ACK" | אחרי Layers and Addresses | תחנה 2 |
| Chapter 3: "Two Devices, One MAC" | אחרי Names, Pages and Locks | תחנה 4 |
| Finale: "A Pipe Nobody Closes" | אחרי הבוס | החדר הבא: DLP Fundamentals |
