# מניפסט בנייה: הרחבה עיונית של תכנית הלימודים

מטרה: לכסות את כל פערי התוכן שזוהו באימות (CONTENT-VERIFICATION.md), ברמה אקדמית, בלי כפילויות. כל שיעור חדש כולל: תוכן עיוני (עכשיו) → מצגת → סרטון (שלבי הפקה נפרדים).

כלל אנטי-כפילות: כל שיעור למטה מציין מה הוא מלמד ומה הוא **לא** מלמד (כי כבר קיים). שיעור קיים לעולם לא נכתב מחדש.

מצב: ⬜ לא התחיל · 🟡 נכתב (staging) · 🟢 שולב ונבדק · 🎞️ מצגת · 📹 סרטון

---

## אצווה 1 — רשתות + Linux (יסודות, בטוח)
| # | slug | קורס | מכסה | לא מלמד (קיים) | מצב |
|---|---|---|---|---|---|
| 1 | network-types-topologies-and-devices | 01,03 | סוגי רשתות (PAN/LAN/CAN/MAN/WAN/WLAN/SAN), טופולוגיות, ציוד (hub/switch/router/AP/FW/LB) | OSI/TCPIP, IP-addressing, פרוטוקולים | 🟢 |
| 2 | linux-command-line-essentials | 02 | CLI, ניווט, פקודות, pipes/redirection, grep/awk/sed/find | הרשאות, משתמשים, FHS, לוגים | 🟢 |
| 3 | linux-bash-scripting-fundamentals | 02 | shebang, משתנים, תנאים, לולאות, פונקציות, סקריפט SOC מלא | פקודות בסיס, הרשאות | 🟢 |
| 4 | linux-networking-and-troubleshooting | 02 | ip/route/dig/ping/traceroute/ss/curl/tcpdump, מתודולוגיית אבחון | זיהוי reverse-shell, CLI בסיס | 🟢 |

## אצווה 2 — CCNA switching/routing
| # | slug | מכסה | מצב |
|---|---|---|---|
| 5 | switching-vlans-trunking-and-stp | VLAN, Trunk/802.1Q, VTP, STP/RSTP, EtherChannel | 🟢 |
| 6 | routing-fundamentals-static-and-inter-vlan | טבלת ניתוב, static, inter-VLAN, router-on-a-stick, SVI | 🟢 |
| 7 | dynamic-routing-ospf-eigrp-and-fhrp | OSPF, EIGRP, HSRP/VRRP/GLBP | 🟢 |
| 8 | cisco-ios-configuration-and-operations | IOS CLI, modes, show/running-config, SSH/SYSLOG/SNMP, Port-Security, ACLs, ניהול | 🟢 |

## אצווה 3 — CCNA wireless + automation
| # | slug | מכסה | מצב |
|---|---|---|---|
| 9 | wireless-networking-lap-and-wlc | WLAN, LAP/WLC, SSID, CAPWAP, WPA2/3, roaming | 🟢 |
| 10 | network-automation-apis-and-json | אוטומציה, REST/NETCONF/RESTCONF, JSON/YAML, Python/Ansible intro, IaC לרשת | 🟢 |

## אצווה 4 — AWS Practitioner (שירותים, לא רק אבטחה)
| # | slug | מכסה | לא מלמד (קיים) | מצב |
|---|---|---|---|---|
| 11 | aws-compute-ec2-and-scaling | EC2, AMI, instance types, EBS root, ELB, Auto Scaling | IAM/shared-responsibility (קיים) | 🟢 |
| 12 | aws-storage-s3-ebs-and-classes | S3 classes, EBS, EFS, Glacier, lifecycle | חשיפת S3 אבטחתית (קיים) | 🟢 |
| 13 | aws-databases-and-analytics | RDS, Aurora, DynamoDB, Redshift, Athena | | 🟢 |
| 14 | aws-serverless-and-containers | Lambda, API Gateway, ECS/Fargate, EKS, Lightsail | Lambda כ-privesc (קיים) | 🟢 |
| 15 | aws-networking-vpc-and-connectivity | VPC, subnets, route tables, IGW/NAT-GW, VPN, Direct Connect | Security Groups אבטחתי (קיים) | 🟢 |
| 16 | aws-iac-monitoring-and-billing | CloudFormation, CI/CD, CloudWatch, Cost/Budgets, Well-Architected | CloudTrail אבטחתי (קיים) | 🟢 |

## אצווה 5 — OSINT חקירתי (סיכון מסנן, לנסח כהגנתי/חקירתי-לגיטימי)
| # | slug | מכסה | מצב |
|---|---|---|---|
| 17 | osint-methodology-opsec-and-personas | מתודולוגיה, OPSEC, sock puppets, אתיקה/חוקיות | ⬜ |
| 18 | osint-advanced-search-and-dorking | אופרטורים, Google dorking, מנועים מיוחדים | ⬜ |
| 19 | osint-image-exif-and-geolocation | reverse image, EXIF, geolocation, chronolocation | ⬜ |
| 20 | osint-people-email-and-username | HIBP, breach data, Sherlock/holehe, people search | ⬜ |
| 21 | osint-social-media-investigation | טכניקות פר-פלטפורמה, archiving | ⬜ |
| 22 | osint-tools-frameworks-and-reporting | Maltego/SpiderFoot/Recon-ng, כתיבת דוח | ⬜ |
הערה: OSINT תשתיתי (WHOIS/passive-DNS/Shodan/Censys) כבר קיים (enrichment-tools) ולא ייכתב מחדש.

## אצווה 6 — SOC + נוזקות מעשי
| # | slug | מכסה | מצב |
|---|---|---|---|
| 23 | building-a-soc-home-lab | וירטואליזציה, Windows Server, DC, clients, networking למעבדה | ⬜ |
| 24 | log-ingestion-agents-and-collection | WinCollect/agents/forwarders, pipeline קליטה, parsing בסיס | ⬜ |
| 25 | risk-management-for-the-soc | assessment/treatment/appetite/register, מיפוי לבקרות | ⬜ |
| 26 | malware-analysis-lab-setup-and-safety | REMnux/FLARE-VM, snapshots, בידוד רשת, INetSim | ⬜ |
| 27 | malware-analysis-reporting-and-sysinternals | ערכת Sysinternals מסודרת, מבנה דוח ניתוח, IOCs | ⬜ |

## אצווה 7 — קצוות (AI יצרני; AD-trusts בסיכון מסנן)
| # | slug | מכסה | מצב |
|---|---|---|---|
| 28 | working-with-llms-and-prompt-engineering | שימוש יצרני ב-LLM, דפוסי prompt, RAG, הערכה | ⬜ |
| 29 | ad-domain-trusts-and-cross-forest (סיכון) | סוגי trust, SID-history/ExtraSids, trust attacks | ⬜ |

---

## שלבי הפקה אחרי התוכן
1. **מצגות:** נגזרות מהשיעורים דרך pipeline ה-decks (lesson-decks/build/gen-html.py). כלי הבנייה אינו ב-worktree הזה; צריך לאתר אותו בצ'קאאוט הראשי לפני ההרצה.
2. **סרטונים:** pipeline TTS+capture+העלאה ל-Supabase. נוגע באחסון פרודקשן, לכן לא יבוצע בלי אישור Tal.

## סיכוני מסנן בטיחות
שתי אצוות (OSINT חקירתי, AD-trusts) עלולות להיחסם ע"י מסנן הבטיחות (כפי שקרה עם התמדה ברג'יסטרי). ינוסחו כתוכן חקירתי/הגנתי לגיטימי; אם ייחסמו, אדווח ולא אעקוף.
