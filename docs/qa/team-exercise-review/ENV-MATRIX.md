choice | easy | medium | hard | distinct | platform noise rows (medium session) | native-rendered share
default (azure+linux, general) | 17 | 30 | 14 | 44 | azure:3 linux:12 | 86% of 148
no platforms | 16 | 28 | 11 | 39 | - | 85% of 149
+azure only (with default) | 17 | 30 | 14 | 44 | linux:10 azure:4 | 88% of 143
+aws only (with default) | 18 | 34 | 18 | 52 | aws:8 linux:8 azure:2 | 89% of 153
+k8s only (with default) | 17 | 30 | 14 | 44 | k8s:2 azure:3 linux:6 | 85% of 147
+linux only (with default) | 17 | 30 | 14 | 44 | azure:5 linux:6 | 87% of 141
+vmware only (with default) | 17 | 30 | 14 | 44 | linux:10 azure:4 | 88% of 145
+github only (with default) | 17 | 30 | 14 | 44 | azure:3 linux:6 | 86% of 141
+cyberark only (with default) | 17 | 30 | 14 | 44 | azure:2 linux:7 | 84% of 140
+ndr only (with default) | 17 | 30 | 16 | 46 | linux:11 azure:6 | 87% of 142
all platforms, general | 18 | 35 | 25 | 60 | aws:5 linux:7 azure:4 k8s:5 | 88% of 147
all platforms, general | 18 | 35 | 25 | 60 | linux:12 aws:7 azure:2 k8s:6 | 84% of 143
all platforms, healthcare | 18 | 38 | 26 | 64 | aws:3 linux:9 k8s:8 azure:2 | 83% of 155
all platforms, finance | 18 | 37 | 28 | 65 | azure:6 k8s:5 linux:8 aws:6 cyberark:1 | 85% of 144
all platforms, logistics | 18 | 37 | 25 | 62 | aws:4 k8s:6 linux:10 cyberark:1 azure:3 | 82% of 140
all platforms + edr=crowdstrike | 18 | 35 | 25 | 60 | k8s:6 azure:3 aws:4 linux:8 | 90% of 142
all platforms + edr=mde | 18 | 35 | 25 | 60 | k8s:5 aws:5 azure:4 linux:5 | 85% of 144
all platforms + edr=sentinelone | 18 | 35 | 25 | 60 | linux:9 azure:5 aws:4 k8s:6 cyberark:1 | 83% of 139
all platforms + edr=sophos | 18 | 35 | 25 | 60 | aws:4 k8s:6 linux:4 azure:4 cyberark:1 | 85% of 147
all platforms + firewall=paloalto | 18 | 35 | 25 | 60 | aws:4 k8s:7 linux:8 azure:1 | 93% of 138
all platforms + firewall=fortigate | 18 | 35 | 25 | 60 | linux:7 k8s:8 aws:5 azure:3 | 90% of 153
all platforms + firewall=checkpoint | 18 | 35 | 25 | 60 | linux:8 k8s:6 azure:1 aws:3 | 88% of 151
all platforms + firewall=cisco_ftd | 18 | 35 | 25 | 60 | k8s:5 aws:9 linux:7 azure:1 | 89% of 146
all platforms + firewall=cisco_asa | 16 | 32 | 23 | 55 | k8s:7 linux:8 aws:8 azure:2 cyberark:1 | 86% of 140
all platforms + vpn=globalprotect | 18 | 35 | 25 | 60 | linux:9 azure:2 k8s:4 aws:4 cyberark:1 | 87% of 151
all platforms + vpn=anyconnect | 18 | 35 | 25 | 60 | linux:7 azure:3 k8s:6 aws:3 cyberark:1 | 88% of 137
all platforms + vpn=fortigate_sslvpn | 18 | 35 | 26 | 61 | linux:9 azure:3 k8s:4 cyberark:1 aws:7 | 87% of 145
all platforms + vpn=zscaler_zpa | 18 | 35 | 25 | 60 | linux:9 aws:6 k8s:5 azure:2 | 83% of 145
all platforms + vpn=cloudflare_access | 18 | 35 | 25 | 60 | aws:10 azure:3 linux:12 k8s:7 | 88% of 139
all platforms + idp=entra | 18 | 35 | 25 | 60 | aws:4 k8s:6 azure:4 linux:5 | 75% of 151
all platforms + idp=okta | 18 | 34 | 23 | 57 | linux:6 k8s:6 azure:2 aws:5 | 87% of 149
all platforms + collab=m365 | 18 | 35 | 25 | 60 | azure:2 aws:6 k8s:7 linux:7 | 84% of 144
all platforms + collab=google_workspace | 16 | 27 | 20 | 47 | aws:8 linux:11 k8s:4 azure:1 | 83% of 148
all platforms + email_security=defender_o365 | 18 | 35 | 25 | 60 | linux:7 k8s:4 aws:10 azure:4 cyberark:1 | 88% of 139
all platforms + email_security=proofpoint | 15 | 30 | 24 | 54 | azure:2 linux:7 aws:5 cyberark:1 k8s:7 | 92% of 145
all platforms + dns=windows_dns | 18 | 35 | 25 | 60 | k8s:7 linux:9 aws:3 azure:2 | 83% of 143
all platforms + dns=infoblox | 18 | 35 | 24 | 59 | linux:7 aws:8 k8s:3 azure:1 | 88% of 146