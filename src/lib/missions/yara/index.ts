/**
 * YARA for missions: a pure, browser-and-server rule engine for a learner subset of
 * YARA, run against synthetic samples (see samples.ts). Same input, same result on
 * client and server.
 *
 *   const c = compileYara(source);
 *   if (c.ok) {
 *     const { bytes, filesize } = buildSample(spec);
 *     const r = scanYara(c.rules, bytes, filesize);
 *   }
 */
export { compileYara, hexToRegex, MAX_SOURCE, MAX_STRINGS_PER_RULE } from "./compile";
export type { CompiledYaraRule, CompiledYaraString, YaraCompileResult, YaraExpr, YaraMetaValue } from "./compile";
export { scanYara, MAX_MATCHES_PER_STRING, SCAN_BUDGET } from "./scan";
export type { YaraFileResult, YaraStringResult } from "./scan";
export { buildSample, extractStrings, MAX_REAL_BYTES } from "./samples";
export type { BuiltSample, SampleSpec } from "./samples";
