# תסריט חדר 34: Active Directory Fundamentals

**שם המבצע:** Operation Keystone
**רמה:** בינוני
**העולם:** Rookwood County Council (מועצה מחוזית בדויה): בתי ספר, רווחה, משאיות אשפה ו-4,200 עובדים, וכולם נכנסים לדומיין אחד: ROOKWOOD.
**המנטור:** Femi Adeyemi, מהנדס אבטחת זהויות (Identity Security Engineer).

## סיפור הרקע
השנה נפגעו שתי מועצות שכנות. בשתיהן התוקפים הלכו ישר ל-Active Directory, וברגע שהשתלטו עליו השתלטו על הכול. Femi אחראי על הזהויות ב-Rookwood. כל תקיפה על AD משאירה עקבות על בקרי הדומיין, אם יודעים איזה אירוע לקרוא. הלילה RKW-DC02 התחיל לרשום דברים מוזרים.

## העולם התלת-ממדי: Keystone
- אבן מפתח (בקר הדומיין RKW-DC01) במרכז, וסביבה עצי דומיין: גרפים של צמתים, לא צמחים.
- כרטיס Kerberos שמסתובב בין CLIENT, ה-KDC ו-RKW-FS03.
- גחלים שעולות מצומת של חשבון שירות בזמן Kerberoast.
- כספת כתר עם krbtgt וטבעת מגן.
- קו relay אדום ממכשיר זר (10.44.6.120).

## סדר המשימות
r1, q1, q4 | r2, q2 | r3, q3, la1, flag1 | q5, q6, r4, q7 | r5, la2, flag2, ac1 (במקור שלוש הקריאות הראשונות היו לפני כל השאלות. q4 ו-flag1 עברו אל הנושא שלהם)

## התחנות
| # | תחנה | משימות | המשחקים |
|---|---|---|---|
| 1 | The Directory | r1, q1, q4 | **Map the Domain**: ‏Get-ADForest, בקרי דומיין, ‏OUs, ‏trusts ו-GPO שמקושר ל-Social Care |
| 2 | Kerberos Flow | r2, q2 | **Read the Wristbands**: ‏klist: ‏TGT של krbtgt, כרטיס cifs ל-RKW-FS03, עשר שעות תוקף |
| 3 | Kerberoast | r3, q3, la1, flag1 | **Night on the DC**: ‏4720, ‏4728 ל-Domain Admins ו-1102, וקבלן שנמצא ב-Account Operators |
| 4 | Crown Jewels | q5, q6, r4, q7 | **No Pre-Auth**: ‏Get-ADUser עם DoesNotRequirePreAuth, ושלושה חשבונות שאחד מהם מסוכן במיוחד |
| 5 (בוס) | Relay and Verdict | r5, la2, flag2, ac1 | **Names and Addresses**: שלוש התחברויות NTLM, ואחת שהשם והכתובת שלה לא מתאימים |

**הפרדה מהשאלות הנבחנות:**
- קונסולת הדומיין לא מציגה את סוגי הקבוצות (q4).
- ‏klist מציג כרטיסי AES תקינים, ולא אומר באיזה מפתח מוצפן כרטיס שירות (q2) או מה המשמעות של RC4 ‏(q3, ‏la1).
- קונסולת ה-DC עוסקת בחשבון חדש וביומן שנמחק, ולא ב-DCSync ‏(q5) או במפתח krbtgt ‏(q6).
- סריקת ה-pre-auth לא קוראת 4768 או PreAuthType ‏(q7).
- גיליון ההתחברויות הוא תת-רשת, משתמש וכתובות אחרים מ-la2 ומ-flag2.

## סרטונים (כל אחד מסתיים בכרטיס NEXT MISSION)
| סרטון | מתי | הפניה |
|---|---|---|
| Intro: "Own the Directory, Own Everything" | כניסה | תחנה 1 |
| Chapter 2: "The Wristband" | אחרי Kerberos Flow | תחנה 3 |
| Chapter 3: "01:47 on the DC" | אחרי Kerberoast | תחנה 4 |
| Finale: "Borrowed Logons" | אחרי הבוס | החדר הבא: Wazuh Fundamentals |
