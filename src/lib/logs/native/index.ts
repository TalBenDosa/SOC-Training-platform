/**
 * Native log registry — one module per data source (docs/log-schemas cards).
 *
 *   nativize(ev, companyId, stack?)  → the event in its source's native format
 *   useCasesFor(sourceId?)            → the detection use cases written on those logs
 *
 * Windows Security and CyberArk have no native module yet: their events keep the
 * legacy rendering (nativize returns null for them).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeLog, NativeSource, SourceId, UseCase } from "./types";
import { makeCtx } from "./ctx";
import { COMPANY_STACKS, sourceFor, type Stack } from "./stack";

import { source as anyconnect } from "./sources/anyconnect";
import { source as aws_cloudtrail } from "./sources/aws_cloudtrail";
import { source as aws_guardduty } from "./sources/aws_guardduty";
import { source as aws_vpcflow } from "./sources/aws_vpcflow";
import { source as azure_activity } from "./sources/azure_activity";
import { source as checkpoint } from "./sources/checkpoint";
import { source as cisco_asa } from "./sources/cisco_asa";
import { source as cisco_ftd } from "./sources/cisco_ftd";
import { source as cloudflare_access } from "./sources/cloudflare_access";
import { source as crowdstrike } from "./sources/crowdstrike";
import { source as defender_o365 } from "./sources/defender_o365";
import { source as entra } from "./sources/entra";
import { source as fortigate } from "./sources/fortigate";
import { source as fortigate_sslvpn } from "./sources/fortigate_sslvpn";
import { source as gcp_audit } from "./sources/gcp_audit";
import { source as globalprotect } from "./sources/globalprotect";
import { source as google_workspace } from "./sources/google_workspace";
import { source as infoblox } from "./sources/infoblox";
import { source as k8s_audit } from "./sources/k8s_audit";
import { source as linux_auditd } from "./sources/linux_auditd";
import { source as m365 } from "./sources/m365";
import { source as mde } from "./sources/mde";
import { source as okta } from "./sources/okta";
import { source as paloalto } from "./sources/paloalto";
import { source as proofpoint } from "./sources/proofpoint";
import { source as sentinelone } from "./sources/sentinelone";
import { source as servicenow } from "./sources/servicenow";
import { source as sophos } from "./sources/sophos";
import { source as sysmon } from "./sources/sysmon";
import { source as windows_dns } from "./sources/windows_dns";
import { source as zscaler_zia } from "./sources/zscaler_zia";
import { source as zscaler_zpa } from "./sources/zscaler_zpa";

export const NATIVE_SOURCES: Partial<Record<SourceId, NativeSource>> = {
  anyconnect, aws_cloudtrail, aws_guardduty, aws_vpcflow, azure_activity, checkpoint, cisco_asa, cisco_ftd,
  cloudflare_access, crowdstrike, defender_o365, entra, fortigate, fortigate_sslvpn, gcp_audit, globalprotect,
  google_workspace, infoblox, k8s_audit, linux_auditd, m365, mde, okta, paloalto, proofpoint, sentinelone,
  servicenow, sophos, sysmon, windows_dns, zscaler_zia, zscaler_zpa,
};

export function stackFor(companyId: string, override?: Stack): Stack {
  return { ...(COMPANY_STACKS[companyId] ?? {}), ...(override ?? {}) };
}

/**
 * The event in its source's native format under the company's stack, or null when
 * no module covers its category yet / the chosen product has no such record.
 * Never throws — a converter bug must not take the feed down.
 */
export function nativize(ev: TelemetryEvent, companyId: string, stack?: Stack): NativeLog | null {
  const id = sourceFor(ev, stackFor(companyId, stack));
  const mod = id ? NATIVE_SOURCES[id] : undefined;
  if (!mod) return null;
  try { return mod.fromTelemetry(ev, makeCtx(companyId)); } catch { return null; }
}

/** Use cases for one source, or every source. */
export function useCasesFor(sourceId?: SourceId): UseCase[] {
  if (sourceId) return NATIVE_SOURCES[sourceId]?.useCases ?? [];
  return Object.values(NATIVE_SOURCES).flatMap(s => s?.useCases ?? []);
}

export type { NativeLog, NativeSource, SourceId, UseCase } from "./types";
export type { Stack } from "./stack";

/** nativize + the product display name, for the feed UI (NativeLogContext). */
export function nativeView(ev: TelemetryEvent, companyId: string, stack?: Stack): { log: NativeLog; product: string } | null {
  const log = nativize(ev, companyId, stack);
  if (!log) return null;
  return { log, product: NATIVE_SOURCES[log.sourceId]?.schema.product ?? log.sourceId };
}
