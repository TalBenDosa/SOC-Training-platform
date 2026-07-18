/**
 * Rooms Batch 14 — Gap-Fill Curriculum
 *
 * 6 rooms covering topics not yet in the curriculum, taking the student deeper
 * into cloud, data protection, automation, and the analyst's own thinking:
 * - aws-security        — AWS for SOC: IAM, S3, EC2, CloudTrail, GuardDuty, common attacks
 * - analyst-mindset     — how to think and ask the right questions (cognitive process)
 * - edge-case-usecases  — unusual attacks analysts miss (supply chain, insider, OAuth, LOLBins)
 * - dlp-fundamentals    — Data Loss Prevention: channels, policies, investigating DLP alerts
 * - gcp-security         — Google Cloud Platform security essentials + audit logs
 * - soar-automation     — SOAR playbooks, enrichment, automated containment, over-automation risk
 */

import r1 from "@/data/rooms-batch-14-r1";
import r2 from "@/data/rooms-batch-14-r2";
import r3 from "@/data/rooms-batch-14-r3";
import r4 from "@/data/rooms-batch-14-r4";
import r5 from "@/data/rooms-batch-14-r5";
import r6 from "@/data/rooms-batch-14-r6";

export default [...r1, ...r2, ...r3, ...r4, ...r5, ...r6];
