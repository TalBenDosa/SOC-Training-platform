/**
 * AWS CloudWatch alarm-state emitter (scenario-local companion for s3ExfilExposure).
 *
 * A CloudWatch alarm that enters ALARM is announced by the alarm's own state-change
 * notification; the SIEM keeps the alarm name, the metric, the threshold and the value
 * that tripped it. No shared emitter exists for CloudWatch, so the scenario renders it
 * here instead of hand-typing a `raw` block in the pack. Only the registry-valid
 * `cloudwatch.alarm.*` fields are written.
 */
import type { TelemetryEvent, Severity } from "@/lib/sim/types";

export interface AwsCloudWatchAlarmOpts {
  id: string;
  ts: string;
  accountId?: string;
  region?: string;
  incidentId?: string;
  alarmName: string;
  metric: string;
  threshold: number;
  actualValue: number;
  severity?: Severity;
  description: string;
}

export function awsCloudWatchAlarm(o: AwsCloudWatchAlarmOpts): TelemetryEvent {
  const record: Record<string, string> = {
    "cloudwatch.alarm.name": o.alarmName,
    "cloudwatch.alarm.state": "ALARM",
    "cloudwatch.alarm.metric": o.metric,
    "cloudwatch.alarm.threshold": String(o.threshold),
    "cloudwatch.alarm.actual_value": String(o.actualValue),
  };
  return {
    id: o.id, ts: o.ts, source: "cloudtrail", vendor: "AWS CloudWatch", event_type: "cloud_api_call",
    severity: o.severity ?? "high", is_detection: true, incident_id: o.incidentId,
    description: o.description,
    raw: record,
  };
}
