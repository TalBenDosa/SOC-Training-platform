/**
 * Raw fields that carry a CONCLUSION rather than an observable — the tool's own analyst
 * write-up of the event — and are withheld from the scenario page until the graded debrief
 * (F-02). Any ECS / vendor "*.description", and Falcon's detection text: DetectDescription
 * (DetectionSummaryEvent) / Description (EppDetectionSummaryEvent). The disposition
 * (PatternDispositionDescription — what the sensor DID) is an observable and stays.
 */
const CONCLUSION_RAW_KEY = /\.description$|^crowdstrike\.(Detect)?Description$/i;

export function isConclusionRawKey(key: string): boolean {
  return CONCLUSION_RAW_KEY.test(key);
}
