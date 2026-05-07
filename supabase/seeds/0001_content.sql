-- Seed: starter learning paths, scenarios, and badges.
-- Run AFTER 0001_init.sql

-- ============== LEARNING PATHS ==============
insert into public.learning_paths (slug, title, description, difficulty, track, icon, estimated_hours, xp_reward) values
  ('soc-analyst',        'SOC Analyst Fundamentals', 'Triage, contain, escalate. The Tier-1 to Tier-2 backbone.', 'beginner',     'soc_analyst',        'graduation-cap', 18, 2500),
  ('threat-hunter',      'Threat Hunting',           'Hypothesize, query, find what your SIEM missed.',           'intermediate', 'threat_hunter',      'crosshair',      22, 3000),
  ('incident-responder', 'Incident Response',        'Contain, eradicate, recover. Lead the war room.',           'advanced',     'incident_responder', 'shield-alert',   26, 4000),
  ('detection-engineer', 'Detection Engineering',    'Author, validate, tune, and ship detections.',              'advanced',     'detection_engineer', 'shield-check',   24, 4000),
  ('purple-team',        'Purple Team',              'Emulate, detect, improve. Repeat.',                          'expert',       'purple_team',        'wrench',         28, 5000)
on conflict (slug) do nothing;

-- ============== SCENARIOS ==============
insert into public.scenarios (slug, title, summary, narrative_md, difficulty, threat_actor, attack_kind, mitre_tactics, mitre_techniques, industries, xp_reward, estimated_min) values
  (
    'phishing-to-cloud-exfil',
    'Phishing → Cloud Exfiltration',
    'A finance analyst opens a macro-laced invoice. Track the attacker through PowerShell, credential theft, and a 184MB S3 exfil.',
    '## Briefing\nA finance analyst received an invoice email that bypassed mail-flow rules with failed SPF/DKIM/DMARC. Twenty seconds after the user opened the attachment, an Office process spawned an obfuscated PowerShell command. Your job: piece together the full kill chain, scope blast radius, and recommend containment.',
    'intermediate', 'TA-COBALTSPIDER', 'phishing_to_exfil',
    array['TA0001','TA0002','TA0003','TA0005','TA0006','TA0011','TA0010'],
    array['T1566.001','T1059.001','T1547.001','T1218.011','T1027','T1003.001','T1071.001','T1078','T1567.002'],
    array['Finance','Tech','Healthcare'],
    400, 60
  ),
  (
    'bec-mailbox-rule',
    'Password Spray → BEC Mailbox Rule',
    'Spot the spray, the foreign sign-in, and the hidden inbox rule before the wire fraud lands.',
    '## Briefing\nOver a 12-minute window, 14 Finance/Exec accounts were probed by a single foreign IP. One succeeded. Six minutes later the user authenticated from the Netherlands and added a hidden inbox rule for wire/invoice keywords.',
    'beginner', 'TA-VOIDPELICAN', 'identity_bec',
    array['TA0001','TA0006','TA0009'],
    array['T1110.003','T1078','T1098.005'],
    array['Finance','Legal'],
    250, 35
  )
on conflict (slug) do nothing;

-- ============== BADGES ==============
insert into public.badges (slug, name, description, tier, xp_reward) values
  ('first-triage',         'First Triage',         'Triaged your first alert.',                                 'bronze',    50),
  ('kql-apprentice',       'KQL Apprentice',       'Wrote your first KQL hunt query.',                          'bronze',   100),
  ('mitre-cartographer',   'MITRE Cartographer',   'Mapped 25 alerts to ATT&CK techniques.',                   'silver',   250),
  ('lsass-hunter',         'LSASS Hunter',         'Identified an LSASS dump in a scenario.',                  'gold',     500),
  ('dns-tunnel-spotter',   'DNS Tunnel Spotter',   'Detected DNS tunneling C2 in a scenario.',                 'silver',   250),
  ('detection-engineer',   'Detection Engineer',   'Validated 5 Sigma detections.',                             'gold',     500),
  ('ir-lead',              'IR Lead',              'Closed an investigation with verdict + timeline.',          'gold',     500),
  ('purple-stripes',       'Purple Stripes',       'Completed a full purple-team scenario.',                    'platinum',1000),
  ('week-streak',          '7-Day Streak',         'Logged in 7 days in a row.',                                'bronze',   100),
  ('100k-events',          '100K Events Reviewed', 'Reviewed 100,000 telemetry events.',                       'platinum',1000)
on conflict (slug) do nothing;

-- ============== MODULES & LESSONS for SOC Analyst ==============
insert into public.modules (path_id, slug, title, description, sort_order, xp_reward)
select id, 'foundations', 'SOC Foundations', 'What a SOC actually does, and where you fit.', 1, 200
from public.learning_paths where slug = 'soc-analyst'
on conflict (path_id, slug) do nothing;

insert into public.modules (path_id, slug, title, description, sort_order, xp_reward)
select id, 'triage',      'Alert Triage',     'Read the alert. Read the process tree. Decide.',  2, 300
from public.learning_paths where slug = 'soc-analyst'
on conflict (path_id, slug) do nothing;

insert into public.modules (path_id, slug, title, description, sort_order, xp_reward)
select id, 'mitre',       'MITRE ATT&CK',     'Tactics, techniques, and your mental model.',     3, 250
from public.learning_paths where slug = 'soc-analyst'
on conflict (path_id, slug) do nothing;
