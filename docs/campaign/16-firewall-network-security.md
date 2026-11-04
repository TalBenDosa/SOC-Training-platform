# תסריט חדר 16: Firewall and Network Security

**שם המבצע:** Operation Zone Wall
**רמה:** מתחילים
**העולם:** Meridale Clinics (רשת מרפאות בדויה) עם 31 מרפאות ופורטל מטופלים אחד. הרשת בנויה באזורים, כמו בית חולים שבנוי במחלקות.
**המנטור:** Mateo Vidal, מהנדס אבטחת רשת.

## סיפור הרקע
כל חבילה שחוצה קו בין אזורים פוגשת חוק, וכל חוק משאיר לוג. Mateo רוצה אנליסט שיודע להגיד איזה חוק הופעל, איזה אזור החזיק, ואיזה "allow" לא היה צריך לקרות. כאן בודקים את החוקים, עוברים בין האזורים וקוראים את מה שעובר בקו.

## העולם התלת-ממדי: Zone Wall
משמאל האינטרנט. אחריו חומת firewall חיצונית, ופלטפורמת DMZ עם שרת web שמוגן במגן WAF. אחריה חומה פנימית, ובפנים איי VLAN מאחורי מחיצות זכוכית. חבילות טסות אל החומות: המורשות עוברות בירוק, והחסומות נהדפות באדום. קו העתק (SPAN) יוצא מהחומה החיצונית אל עין IDS. אי ה-IoT מאדים, והזכוכית מחזיקה. בסוף, גשוש סריקה מטאטא את החומה החיצונית בחיצי SYN שלא משלימים handshake.

## סדר המשימות
r1, q2 | r2 | q1, q3 | r3, la1, f1 (השאלה q2 על stateful עברה לתחנה של r1)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | Rules of the Door | r1, q2 | **Which Rule Fires?**: ‏show running security-policy ו-test security-policy-match על Palo Alto. ארבע חבילות: first match, ‏source שמשנה את החוק, ו-interzone-default |
| 2 | Zones and Sensors | r2 | **Which Zone?**: שיבוץ שבע מערכות לאזורים. **Anatomy of a WAF Block**: לוג של AWS WAF עם SQLi ב-query string |
| 3 | Hold the Line | q1, q3 | תרגול **Does the Wall Hold?**: מצלמה פרוצה ב-VLAN של ה-IoT מול מטריצת המדיניות |
| 4 (בוס) | Read the Wire | r3, la1, f1 | **Allowed Is Not Safe**: תור לוגים של הלילה (SMB יוצא, ‏2.1GB משרת ה-EHR). תרגול **Anatomy of a Suricata Alert** (‏alert.action blocked), ואחריו ההתראה הנבחנת והדגל |

**הפרדה מהשאלות הנבחנות:**
- ה-rulebase אינו הדוגמה של 10.0.1.50 מהקריאה, ולא מסביר stateful (q2).
- מעבדות האזורים וה-WAF לא מובילות פריצה מה-DMZ אל מסד הנתונים (q1).
- תרגול הסגמנטציה עוסק במצלמת IoT, ולא בתולעת SMB מתחנת עבודה (q3).
- התרגול על Suricata הוא probe של MSSQL שנחסם, ולא סריקת SYN של Nmap (la1).

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Every Packet Meets a Rule" | כניסה | תחנה 1 |
| Chapter 2: "First Match Wins" | אחרי Rules of the Door | תחנה 2 |
| Chapter 3: "The Wall Holds" | אחרי Hold the Line | תחנה 4 |
| Finale: "Allowed Is Not Safe" | אחרי הבוס | החדר הבא: Endpoint Security Fundamentals |
