# instructor — מדריך / בקר תרגיל (session owner) — חוות דעת

סשן `bec9df68-f32d-4dd7-bb17-f404e091fc11` · staging · nexacorp · v2 · התחלה 08:00:08Z · סיום 08:30:16Z (שעון משמרת 28:00)

## ציונים (1–5): ריאליזם מקצועי | חוויית משתמש | יציבות/תקינות | שיתוף פעולה | הוגנות הניקוד
**3 | 3 | 4 | 5 | 2**

- ריאליזם 3: שני הסיפורים המתוסרטים (fake browser update בסגנון SocGholish, ו-rogue admin / backdoor Domain Admin) בנויים טוב. אבל מיפוי הישויות בגרסת-הצוות שובר אותם (אירועי DC נרשמים על תחנת Finance, והנתיב ב-raw לא תואם לתיאור). בנוסף, "רעש" שהוא בפועל תקיפה אמיתית.
- חוויית משתמש 3: אין למדריך תצוגה חיה של מפתח התשובות מול מה שהצוות עושה. ה-composer של ה-inject לא מאפשר להגדיר תגובה צפויה.
- יציבות 4: מחזור-החיים (start / pause / resume / coverage-pause / auto-resume / end) עבד בלי אף שגיאה. מנגד, השרת לא מאמת payload בכלל.
- שיתוף פעולה 5: הצוות עבד כמו SOC אמיתי, עם SITREP, rebalance, bounce של כפילויות ו-re-containment.
- הוגנות 2: מפתח התשובות מזוהם, ולכן T1 שעשו עבודה מצוינת קיבלו 58–59.

## מה עשיתי במשמרת (ציר זמן קצר: seq + פעולה + למה)
| זמן (Z) | seq | פעולה | למה |
|---|---|---|---|
| 07:58–08:00 | — | קריאת InstructorPanel / InjectFeed / page.tsx / TeamReport / routes של start, end, pause, ו-computeReport / serverReport / buildTimeline / 0071 / 0072 | הכנה |
| 07:59:47 | #6 | כל 6 השחקנים ready (הלובי לקח פחות מ-2 דקות) | — |
| 08:00:04 | #7 | `start`: נזרעו 115 שורות, ~24 דק׳ | כולם מוכנים |
| 08:00:24 | #10 | תדריך משמרת ב-message.sent | ROE, חלוקת תפקידים |
| 08:00–08:07 | — | קריאת `injects` (מלא, דרך query read-only), והשוואה שוטפת של events מול המפתח | בקרה |
| 08:07:26 | #132 | inject ידני `announcement` (restart של ה-log forwarder PA-LF-02) | בדיקת inject. אצל השחקנים הופיע כ-`announcement`, ו-#134 המתוסרט (mgmt_pressure) הופיע כ-`update` ניטרלי ✓ |
| 08:10:09 | #197 | הודעה על pause | — |
| 08:10:12 | #199 | `pause` ידני | בדיקת בקרה |
| 08:10:~15 | — | probe: `act t1a note.added` נדחה: `REJECTED: action_not_allowed: note.added for role t1 in status paused` ✓. צ׳אט בזמן pause עבד (#203) ✓ | — |
| 08:11:05 | #205 | `resume` (paused_ms=53023) | — |
| 08:24:26 | #503 | הודעה על תרגיל coverage | — |
| 08:24:37 | — | `drop.txt ← t2` | סימולציית נשירה של T2 |
| 08:26:41 | #551 | **auto-pause coverage** ("No Tier-2 online right now.") | — |
| 08:27:16 | — | ריקון drop.txt | — |
| 08:28:01 | #554 | **auto_resume** | — |
| 08:29:1x | #576 | הודעת סיום | — |
| 08:30:16 | #604 | `end` | — |
| 08:30+ | — | `report instructor` וביקורת מול המפתח וה-events (סקריפט read-only) | — |

## מה עבד טוב
- **מחזור-החיים יציב לחלוטין:** 5 מעברים, 0 שגיאות. ה-pause עוצר את הפיד (אין feed.event בין 08:10:05 ל-08:11:05). פעולות נחסמות, הצ׳אט נשאר פתוח. ה-injects הממתינים מתוזמנים מחדש בהתחשב ב-pause (ה-false-lead יצא בשעון משמרת ≈10:59, תואם due=658s).
- **הסתרת סוג ה-inject** (0071): mgmt_pressure, false_lead ו-twist מגיעים לשחקנים כ-`update`. ל-inject ידני נוצרת שורה ב-`session_injects` עם `expected_action.kind`.
- **ה-AAR חושף את הסוג האמיתי אחרי הסיום.** שיוך SITREP ל-inject הוא אחד-לאחד. עבור mgmt_pressure (3/3 handled) הוא עבד נכון, כי ה-kind ממוזג בחזרה מ-session_injects.
- **תרחיש עשיר ומציאותי:** שתי אירועים חופפים (ב-t+170..823 וב-t+672..1261) יצרו עבודה מקבילה אמיתית. המנהל עשה priority, T2 עשה re-containment (seq 398, 421), ו-T3/TI תיקנו זה את זה (Tor ≠ attribution, #364/#382).

## תקלות / שגיאות מערכת (כל אחת: חומרה, שחזור מדויק, פלט שקיבלת)
1. **[גבוהה] `apply_session_action` לא מאמת payload לפי סוג הפעולה.** השרת בודק רק role ו-status (0071 שורות 137–166, 177–265). נשמרו בלוג:
   - `#146 escalation.requested {}`: ריק לגמרי, בלי event_id. T2 נאלץ לעשות bounce עם `"event_id":"undefined"` (#164).
   - `#21 alert.claimed {"event_id":"e0000deadbeef"}` ו-`#24 disposition.set` על id שלא קיים.
   - `#25 disposition.set {"verdict":"benign"}` בלי event_id.
   - `#23 verdict:"probably_fine"`: ערך שלא קיים ב-UI (T1Console.tsx:231).
   - `#319 ticket.answered` שני (t1b) על כרטיס 273 שכבר נענה (#299). ה-UI מסתיר את הכפתור (InjectFeed.tsx:149), אבל השרת מקבל.
   - **השפעה על הדוח:** `dispTotal` כולל את `e0000deadbeef` ו-`undefined` כ"benign נכון". ה-escalation הריק נספר ב-loop closure כ"dropped". ה-ticket הכפול זיכה גם את t1b ב-Help-desk=4.
2. **[בינונית] ה-replenisher ממחזר רשומות זהות.** אחרי שהטיימליין המתוסרט נגמר (t+1463s, 08:25:25) נוספו 30 שורות `at_time` (0072, replenish_feed). הן העתקים של רשומות benign עם אותו raw, אותו record_id ואותו ts (למשל `b_edr_07` ×4, `b_dcid_4757` ×4. בסך הכול 22 original_ids מוכפלים). הן מגיעות בפרצים של 2–3 שורות באותה מילישנייה (#523/#524/#525 ב-08:25:46.02x), ועם ts ישן (08:11, 08:18) אחרי ts של 08:24. אנליסט אמיתי מזהה את זה מיד כשכפול לוגים. בנוסף, ה-replenisher מסנן רק לפי `expected_verdict ∉ {tp, escalate}`, כך ששורות "atk" בלי verdict (סעיף תוכן 2) עלולות להיות ממוחזרות כהתראה שנייה.
3. **[בינונית] containment target נגזר אוטומטית ואי אפשר לערוך אותו** (T2Console.tsx:103, 231). ב-#378 הבקשה נשלחה עם `target:"WS-FIN-2847"` כי זה ה-hostname של אירוע ה-4728, והמנהל נאלץ לדחות containment נכון (#409). כלשון T2: "target field is auto-filled… cannot be edited". גם אין סוג containment לחשבון (disable account), רק "Isolate host".
4. **[נמוכה] ה-claim לא בלעדי:** claim שני דורס את הראשון בשקט (#341/#344, 5 שניות הפרש). התוצאה: escalation כפול על אותו אירוע (#351/#357, #239/#261), שפוגע גם ב-MTTR (ראו אימות, סעיף 5).
5. **[מידע, harness]** `status` של ה-harness ממשיך לספור את שעון המשמרת בזמן pause פעיל (10m7s → 10m29s תוך כדי pause), כי `paused_ms` מתעדכן רק ב-resume. זה לא באג בפלטפורמה.

## שגיאות מקצועיות בתוכן (לוג/שדה/ורדיקט/MITRE/תרחיש — עם feed id וציטוט השדה)
1. **[קריטית, מפתח תשובות] אירועי "control / baseline" מסומנים tp.** `buildTimeline.ts:118-122` נותן `expected_verdict: tp` לכל אירוע בסיפור, כולל אירועי בקרה. גם השדה `is_baseline` לא נבדק.
   - `e86ed725e9d99` (evt_ra_01_ticket): "New-hire onboarding request RITM0092416 was approved by HR Operations…" מוגדר בתרחיש המקורי כ-`// 1. CONTROL part 1 — an authorised onboarding request` (rogueAdminAccount.ts:64).
   - `e85eb32348d45` (evt_ra_02_baseline_create): `it_verify_result: confirmed`.
   - `eefe14bb6c523` (evt_fbu_01_site_visit): ההסבר של התרחיש עצמו אומר ש-fbu_01 הוא עובד אמיתי שקורא פרסום מקצועי אמיתי (fakeBrowserUpdate.ts:~210).
   - התוצאה: t1a (benign על ra_01) ו-t1b (benign על ra_02) נספרו כטועים, ומכנה ה-recall מנופח ל-18.
2. **[קריטית, מפתח תשובות] תקיפות אמיתיות בתוך מאגר ה-benign בלי verdict.** הן נספרות כ-benign, ו-escalation עליהן פוגע ב-precision:
   - `ee76d3093e336` b_email_replyto_mismatch: payroll-diversion phish. לשורה עצמה יש `mitre_technique: T1566`, Reply-To לכתובת gmail ו-Return-Path לדומיין lookalike.
   - `ee96d33b90e70` b_fwd_atk_01: `forward.tor_exit: true`, ה-it_verify_message אומר "escalate immediately", וה-fp_explanation של b_fwd_fp_01 מציג אותה במפורש כגרסת התקיפה.
   - `ef4f29cb6658b` b_copy_atk_01 (העתקת PII ל-USB, T1052.001) ו-`e1fa55d52f1b5` b_copy_atk_02 (azcopy של 14.2GB אחרי שעות העבודה, T1530). שתיהן תחת הכותרת "(attack event)" ב-benignEvents.ts:2448.
   - הפילטר ב-buildTimeline.ts:73 מוציא רק verdicts שהם tp או escalate. `undefined` עובר.
3. **[גבוהה] מיפוי מארחים שגוי בגרסת הצוות.** במקור: `host: dc.hostname` (DC01), `SRV-ADM-07`, `LAP-4471`. בפיד:
   - `efef2ac740d53` 4728 Domain Admins: `"winlog.computer_name": "WS-FIN-2847.nexacorp.com"`. 4728 לקבוצה גלובלית בדומיין נרשם על DC, לא על תחנת Finance.
   - אותו דבר ב-`e85eb32348d45` ו-`ef3f29b239296` (4720 "on WS-FIN-2847").
   - `e82eb2d7b3553`: "administrative server WS-ENG-2093". שרת עם תחילית WS-.
   - ההשלכה המעשית: containment על המארח הלא נכון (#378).
4. **[בינונית] אי-התאמה בין raw לתיאור** ב-`efae5da358c0c`: ב-raw `file.path: C:\Users\d.morgan\...`, אבל בשדה המנורמל `file.path: C:\Users\d.rosen\...` (הישות מהתרחיש המקורי לא הוחלפה). T3 זיהה את זה ב-#157.
5. **[בינונית] אותן ישויות ו-IPs חוזרים ברעש ויוצרים קורלציות שווא.**
   - r.williams, שחשבונו נפרץ ב-b_fwd_atk_01, מופיע גם ב-b_fail_02, b_vpn_05, b_dcid_4776 ו-b_wev_02. הצוות פירש את b_vpn_05 (VPN מלונדון) ככישלון containment ועשה re-containment (#398/#421). מבחינה מקצועית זו החלטה סבירה, אבל המפתח מסמן אותה כטעות.
   - ה-IP של Tor 185.220.101.45 חוזר ב-b_bf_04.
   - 10.10.20.61 (מקור סיפור C, WS-ENG-2208) חוזר ב-logon של rwilliams (#424), מה שהוביל ל"convergence A+C" שגוי (#448).
6. **[בינונית] סתירות ב-b_itv_02** (`ef8e5d70f7696`, p.wright → Domain Admins): ה-IT-verify מתאר את p.wright כ-CTO עם חלון CHG-00712 ב-05/10–05/11, בעוד שורה אחרת מציגה את p.wright כ-Legal Counsel, והמיילים מתוארכים לאמצע יוני (TI #169, T3 #175). ה-"confirmed" לא אמין.
7. **[בינונית] ה-twist (m1ea79a56a277) בלי טלמטריה תומכת:** "a host you already worked is now beaconing to a NEW C2 domain". אין שום שורת DNS או proxy שמגבה אותו (T3 #505: "swept every feed row since #330 – no DNS/pro…"). הוא נספר כ-handled במקרה (סעיף אימות 7).
8. **[נמוכה] תיאורים שעושים את הקורלציה בשביל האנליסט:** "Three minutes after it was created…" (`efef2ac740d53`), "same creator and same directory as the record written at 14:16" (`ef3f29b239296`), "Seventy-two seconds into the page view…" (`ef5e15528f8a8`). זה לא נראה כמו כותרת התראת SIEM, ומהווה רמז.
9. **[נמוכה]** `e86ed725e9d99` מקבל `event_type: policy_modification` לרשומת RITM של ServiceNow. זה סוג אירוע שגוי.
   - ערבוב שעונים: ts של הפיד הוא 2026-01-01, ה-raw מיוני, התיאורים ב-13:42 ו-22:47, וה-CHG ממאי.
   - `SubjectLogonId 0xB17C440` של סשן ה-RDP ב-WS-ENG-2093 מופיע ב-4720/4728 שנרשמו על מחשב אחר. LogonId הוא מקומי למכונה שרשמה אותו.
10. **[הערה]** ל-4728 ל-Domain Admins ניתן `T1098` / Persistence. זה סביר, אבל T1098.007 (Additional Local or Domain Groups) מדויק יותר.

## חיכוך בחוויית המשתמש (עם file:line מהקומפוננטה)
1. **אין למדריך תצוגת בקרה של מפתח התשובות מול ההתקדמות** (InstructorPanel.tsx:44-89). המדריך רואה פיד גולמי ואת הסוג האמיתי של ה-inject (InjectFeed.tsx:104-108), אבל לא:
   - אילו שורות הן תקיפה;
   - אילו מהן עברו escalation;
   - מה ה-inject המתוסרט הבא ומתי;
   - שעון משמרת.

   כדי לעשות את הבקרה נאלצתי לכתוב query read-only בנפרד. בכלי הזה אין לזה תחליף.
2. **ה-inject composer שולח רק `{kind, text}`** (InstructorPanel.tsx:41). אין שדות `expected_response` ו-`linked_objective`, אף שהשרת תומך בהם (0071:255-257). לכן כל curveball ידני שאינו announcement יופיע ב-AAR עם "Expected: —" ועם handled שנקבע לפי חלון בלבד. ב-report שלי: `"expected": ""`.
3. InstructorPanel.tsx:79: Reassign מציע רק t1, t2, t3 ו-mgr, בלי ti.
4. page.tsx:360: `confirm()` חוסם כשמסיימים את הסשן. לא ניתן לתת הודעת pause מותאמת. ההודעה קבועה: "Paused by the instructor." (page.tsx:439).
5. InjectFeed.tsx:151-152: לכרטיס help-desk יש שתי תשובות קנויות ("verified caller, no code shared" / "refused … escalated"), בלי טקסט חופשי. לכרטיס vishing, "Handle" עם "verified caller, no code shared" לא מתאים לעניין.
6. InstructorPanel.tsx:48-54: נקודות online בלבד, בלי גיל ה-heartbeat וספירה לאחור ל-coverage-pause. המדריך לא רואה שעומדת להתרחש השהיה.

## בקרת משחק ומחזור-חיים
| בדיקה | תוצאה | תזמון |
|---|---|---|
| לובי → start | כל 6 מוכנים ב-07:59:47. `start` ב-08:00:04, session.started ב-08:00:08 | ~2 דק׳ לובי, 0 תקלות |
| Pause ידני | `session.paused` reason=manual ב-08:10:12.168. `note.added` של t1a נדחה (action_not_allowed … status paused). הצ׳אט מותר. הפיד נעצר (#194 ב-08:10:05 היה האחרון עד אחרי ה-resume) | — |
| Resume ידני | `session.resumed` ב-08:11:05.188, paused_ms=53,023 | משך pause ≈53 שנ׳. ה-injects הבאים זזו בהתאם (false_lead ב-08:12:00 ≈ due 658s + 53s) ✓ |
| נשירת T2 | heartbeat אחרון של t2 ≈08:24:25 (seen=49s ב-08:25:14). drop.txt נכתב ב-08:24:37. באנר רך אמור להופיע ב-UI (page.tsx:765) | — |
| **Auto-pause coverage** | `session.paused` reason=coverage, detail "No Tier-2 online right now." ב-08:26:41.125 | **≈2:16 אחרי ה-heartbeat האחרון** (2:04 אחרי drop). בתוך יעד 2–3 דק׳ ✓ |
| חזרת T2 | drop.txt רוקן ב-08:27:16. heartbeat ראשון ≈08:27:45 | — |
| **Auto-resume** | `session.resumed` reason=auto_resume ב-08:28:01.436 | **45 שנ׳ אחרי הניקוי**, ~16 שנ׳ אחרי ה-heartbeat הראשון. בתוך יעד 30–90 שנ׳ ✓. השהיית coverage נמשכה 80 שנ׳ |
| End | `session.ended` ב-08:30:16 (#604), והדוח זמין מיד | — |

הערה: ה-replenisher התחיל למחזר benign כבר ב-08:25:25, לפני תרגיל ה-coverage, וזה הזמן שבו הטיימליין המתוסרט נגמר (ראו תקלה 2).

## אימות הדוח מול מפתח התשובות
מה הדוח מציג: attacks=18, detected=Yes, MTTD=530s, escalations=17, loop closure=80%, dispAcc (צוות)=84%, MTTR=554s, handoffLat=35s, MTTC=77s, injects 5/5.
1. **attacks=18 מנופח.** 3 מהם אירועי control/benign (ra_01, ra_02, fbu_01). 4 תקיפות אמיתיות ברעש לא נספרו (phish, TOR-forward, PII-USB, azcopy). המספר הנכון ≈ 15 בשני הסיפורים ועוד 4 תקריות רעש.
2. **MTTD=530s נכון אריתמטית ושגוי מושגית.** 530 = 08:08:58 (#173, fbu_03) פחות 08:00:08, כלומר נמדד מתחילת המשמרת (LEGEND ב-TeamReport). אבל:
   - אירוע התקיפה המתוסרט הראשון הופיע ב-t+170, והצעד הזדוני האמיתי הראשון (fbu_02) ב-t+245. המדד התעשייתי יוצא ≈285s.
   - הצוות עשה escalation ל-phish אמיתי כבר ב-t+116 (#36), שלא נספר.
   - ה-escalation של t1b ב-t+462 (#146) נשמר ריק בגלל חוסר הוולידציה, ולכן לא נספר.
3. **Attack recall (צוות)=4 (5/18=28%) לא הוגן.** הצוות העלה ל-escalation את שני הסיפורים המתוסרטים (fbu ב-#173, ra ב-#351), כלומר recall ברמת תקרית של 100%. המדד דורש escalation לכל אירוע בנפרד, כולל אירועי ה-control שאסור להעלות. זה גם מעניש T2 על dedupe מקצועי: bounce של #217 כ"duplicate".
4. **Escalation precision של t1a=0 (2/8=25%) לא הוגן.** 4 מתוך 6 ה-escalations ה"שגויים" הם תקיפות אמיתיות (ee76, ee96, ef4f, e1fa) שהמפתח מסמן benign. עם מפתח מתוקן: ~6/8. אצל t1b: precision 4 (≈44%).
5. **MTTR=554s: באג.** `escReqTs = new Map(...)` (computeReport.ts:68) שומר את ה-escalation האחרון לכל event_id. לאירוע e88ed758451ff היו שני escalations: #239 ב-t+756 ו-#261 (t1a) ב-t+804, **אחרי** ה-resolve (#259, t+797). ה-Δ יוצא שלילי והמקרה נזרק. מתוך 6 resolves נשארים 5, והחציון עולה מ-538 ל-554. אותו Map משמש גם ל-ackLatency ול-handoffLatS, עם אותו באג.
6. **Loop closure 80% (12/15):** המכנה כולל את ה-escalation הריק (`undefined`) ואת #217, שקיבל bounce כ-duplicate. bounce הוא לולאה סגורה, אבל הוא נספר כ"dropped". גם HandoffLadder (TeamReport.tsx:146) יסמן אותו "dropped — nobody acknowledged". בניכוי שני אלה: 12/13 = 92%.
7. **Curveballs 5/5:**
   - ה-twist קיבל handled בזכות `scope.confirmed` של T3 שלוש-עשרה שניות אחריו (08:17:58), שהיה חלק מעבודה על סיפור C ולא תגובה ל-twist. כל `escalation.requested` או `case.status_set` תוך 15 דק׳ היה עונה גם הוא (computeReport.ts:308). זה ניקוד מקרי.
   - false_lead לא נוקד, והצוות טיפל בו נכון (Mgr #236 "do NOT block or open an incident on volume alone"). אין קרדיט.
8. **Disposition accuracy:** מתוך 17 ה"טעויות" האחרונות של הצוות:
   - 4 הן תקיפות אמיתיות (המפתח שגוי).
   - 2 הן control שסומנו benign נכון (המפתח שגוי).
   - 8 הן `suspicious`. אפשרות UI לגיטימית (T1Console.tsx:231, וגם "low-confidence lead" בשורה 42) נספרת **תמיד** כשגויה, כי `isCorrectVerdict` מקבל רק true_positive / benign / false_positive (computeReport.ts:142).
   - t1a: 67% → 4, כשבפועל הדיוק ≳90%. t1b: 89% → 8.
   - ה-dispTotal של הצוות כולל שני ids פיקטיביים שנספרו "נכונים".
9. **Self-correction של t1b=8 נזקף על `probably_fine→benign`** (#23→#32 על b_dns_14), שינוי שם ולא תיקון. התיקון האמיתי שלו (fbu_01 מ-benign ל-suspicious, #151) לא נספר, כי suspicious "תמיד שגוי".
10. **Help-desk tickets:** היה רק כרטיס **אחד** במשמרת, והפס הוא `bandHigh(n,3,2,1)`, כך שהציון המקסימלי האפשרי הוא 4/12. t1a ענה נכון וקיבל 4 מתוך "כמה שאפשר". t1b קיבל 4 על תשובה כפולה.
11. **T3 "Final scope (confirmed)"=8 זו תקרה מבנית:** `scopeConfirmDims>=2 ? 8 : 4`, כך שאין דרך להגיע ל-12 (computeReport.ts, case "t3"). T3 אישר 5 hosts, 6 users ו-techniques, ובכל זאת קיבל 8.
12. **TI=100% על 2 מתוך 5 תאים**, שני תאים שבודקים רק שדות קיימים (actor+technique, next_expected). **contribution=100 לכולם** (רווי, חסר משמעות). **firstActionS** כולל הודעת צ׳אט (T2=14s).
13. **מה נכון ומדויק:** MTTC=77s (חציון של 4 executes), containmentReq=6, executed=4, contained=4 approvals, mgmt_pressure 3/3 עם שיוך אחד-לאחד, והתאים של T2 ושל המנהל. אלה משקפים נכון את מה שקרה.

**בשורה התחתונה:** הדוח מתגמל נכון את מי שעבד לפי ה-workflow (T2 100, Mgr 94, T3 80), אבל מעניש את שני ה-T1, שזיהו את **כל** התקיפות האמיתיות ואת שני הסיפורים. הסיבה היא מפתח מזוהם יחד עם מדדים ברמת-אירוע במקום ברמת-תקרית.

## הדוח שלי (Shift review) — האם הוגן? מה חסר/שגוי?
למדריך אין כרטיס, וזה נכון כי הוא לא נמדד. הוא רואה את כל הכרטיסים (`seesAll: true`), ויש לו CSV. חסר:
- תצוגת "answer key reveal" ברמת תקרית (אילו אירועים שייכים ל-inc:fbu:1 ול-inc:ra:1);
- כל תאי ה-n/a עם סיבה;
- אפשרות לדרוס ורדיקט של המפתח בזמן debrief (למשל לסמן b_fwd_atk_01 כתקיפה).

ה-inject הידני שלי מופיע ב-AAR כ-announcement FYI, וזה תקין.

## 3 המלצות מובילות
1. **לתקן את מפתח התשובות בזריעה (buildTimeline.ts:73, 118-122):**
   - לכבד `is_baseline` ואירועי CONTROL (verdict benign);
   - להוציא מהרעש כל שורה עם `mitre_technique` או `_atk_` בלי verdict, או לסמן אותה tp כ"תקרית רעש";
   - לתקן את מיפוי הישויות (DC נשאר DC, SRV נשאר SRV, ולהחליף את כל ה-raw, כולל `file.path`);
   - למנוע שימוש חוזר בישויות ו-IPs של הסיפור ברעש.
2. **לעבור למדדים ברמת תקרית ולתקן באגים בניקוד:**
   - recall ו-precision לפי incident_id;
   - MTTD מהאירוע הזדוני הראשון;
   - `suspicious` כ-lead חלקי ולא כטעות;
   - bounce נספר כלולאה סגורה;
   - `escReqTs` לפי ה-escalation **הראשון**;
   - Help-desk לפי שיעור הכרטיסים שנענו;
   - להסיר את תקרת ה-8 ב-T3 scope.
3. **וולידציית payload בשרת וכלי בקרה למדריך:**
   - ב-`apply_session_action`: לחייב event_id קיים ב-feed עבור claim, disposition ו-escalation, verdict מתוך enum, ו-ticket.answered אחד לכל כרטיס;
   - ב-InstructorPanel: לוח "מפתח מול צוות" חי (אילו attack rows עברו escalation, ה-inject הבא, שעון, גיל heartbeat);
   - שדות expected_response ו-objective ב-composer;
   - target עריך ו-containment לחשבון ב-T2Console;
   - replenisher שמייצר רשומות חדשות (record_id ו-ts חדשים) במקום העתקים.
