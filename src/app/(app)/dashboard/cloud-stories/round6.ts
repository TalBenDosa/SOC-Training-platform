/**
 * Cloud round (Tal's approved order, step 5, 2026-11-12): sixteen attack families on the three clouds, each a
 * parametric template with one single-player variant (mode "solo") and one Team Training variant (mode "team"),
 * never the same story, people or data. No cryptocurrency (T1496 is out of scope).
 *
 *  - round6-aws.ts   : IAM Identity Center device-code phishing; Lambda backdoor behind a public function URL;
 *                      bulk secret harvest (Secrets Manager / Parameter Store); account escape through
 *                      LeaveOrganization; SES abuse for phishing
 *  - round6-azure.ts : device-code phishing into Entra; VM Run Command from a cloud identity; Automation runbook
 *                      persistence; federated-domain backdoor; Function App takeover through its publish profile
 *  - round6-gcp.ts   : setIamPolicy granting an outside owner; bucket made public; Cloud Run / Functions deployed
 *                      with a privileged service account; startup-script injection on a VM; BigQuery export to an
 *                      outside bucket; logging sink / exclusion tampering
 */
import type { AiStoryDef } from "../ai-stories/wave2";
import { CLOUD_R6_AWS_STORIES } from "./round6-aws";
import { CLOUD_R6_AZURE_STORIES } from "./round6-azure";
import { CLOUD_R6_GCP_STORIES } from "./round6-gcp";

export const CLOUD_ROUND6_STORIES: AiStoryDef[] = [...CLOUD_R6_AWS_STORIES, ...CLOUD_R6_AZURE_STORIES, ...CLOUD_R6_GCP_STORIES];
