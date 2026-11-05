# תסריט חדר 48: Firewall Masterclass

**שם המבצע:** Operation Generations
**רמה:** בינוני
**העולם:** Greyfield University (אוניברסיטה בדויה): ‏31,000 סטודנטים, אשכול מחקר, מסד נתוני בחינות, ורשת קמפוס שגדלה בניין אחר בניין מאז 1991. בקצה הרשת חיים זה לצד זה ACL ישן של נתב, זוג חומות stateful ושני NGFW שנקנו בשנה שעברה.
**המנטור:** Gideon Achterberg, ארכיטקט אבטחת רשת.

## סיפור הרקע
Gideon מוציא לגמלאות את החומות הישנות הסמסטר. כדי לעשות את זה בבטחה, ה-SOC צריך לדעת מה כל דור של חומת אש רואה ומה הוא לא רואה. בסוף החדר מגיע מקרה C2 אמיתי, שבו חומה "חדשה" נתנה לתעבורה לעבור.

## המכניקה הייחודית של החדר
**מסוע "Which Wall Catches It?":** שבעה איומים נוסעים על מסוע לכיוון הקמפוס (Telnet מבחוץ, reset מזויף, ערוץ נתונים של FTP, ‏BitTorrent על פורט 80, כלל לפי משתמש, exploit בתוך HTTP). הלומד מנתב כל איום לדור הוותיק ביותר שיכול לעצור אותו לבד: PACKET FILTER, ‏STATEFUL או NGFW.

## העולם התלת-ממדי: Generations
- מסדרון של ארבעה דורות שזרם חבילות עובר דרכם: סורג פשוט (GEN 1 · ACL), ארון stateful עם טבלת conntrack, ארון NGFW עם שמות אפליקציות (bittorrent באדום), ומנעול TLS שנפתח.
- חבילה אדומה שנעצרת בכל מעבר בחומה אחרת.
- טבעות אזורים (DMZ, ‏INTERNAL, ‏RESTRICTED) ומשואה פועמת בסוף.

## סדר המשימות
r1, r2, q1 | r3, q2 | r4, r5 | r6, r7, r8, r9 | r10, q3, la1, f1 (במקור כל עשר הקריאות היו לפני השאלות)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The First Wall | r1, r2, q1 | **Forty Years of Walls**: סידור אבני הדרך לפי הסדר |
| 2 | The State Table | r3, q2 | **Read the State Table**: טרמינל conntrack על חומת Linux |
| 3 | Inside the Packet | r4, r5 | **Which Wall Catches It?** (מסוע) |
| 4 | Zones and Keys | r6, r7, r8, r9 | **Place the Campus**: התאמת מערכות לאזורים; **Read a Decryption Log**: אנטומיה של לוג decryption ב-PAN-OS |
| 5 (בוס) | The Beacon | r10, q3, la1, f1 | הלוג הנבחן |

**הפרדה מהשאלות הנבחנות:**
- אין תחביר ACL, ‏wildcards או כיוון פורטים (q1, ‏checkpoint של r2).
- פריטי ה-stateful לא עוסקים בתשובות נכנסות שלא התבקשו (q2).
- אין C2 מוצפן ואין certificate pinning ‏(checkpoints של r4 ו-r8).
- אין סדר חוקים או shadowing ‏(checkpoint של r6).
- אין חיפוש NAT, שדות בתים, תזמון beacon או סכומים (checkpoint של r10, ‏q3, ‏la1, ‏f1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION עם הפעולה הראשונה, ולא חושף את תשובות התרגול שאחריו)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Retire the Old Walls" | כניסה | תחנה 1 |
| Chapter 2: "A Wall With a Memory" | אחרי The First Wall | תחנה 2 |
| Chapter 3: "Port 80 Lies" | אחרי The State Table | תחנה 3 |
| Finale: "Defence in Depth" | אחרי הבוס | החדר הבא: AV vs EDR Masterclass |
