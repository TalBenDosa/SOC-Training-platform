/**
 * The commands a PowerShell script invokes, as Defender for Endpoint records them (DeviceEvents ActionType
 * PowerShellCommand, AdditionalFields {"Command": "<name>"}): its cmdlets (Verb-Noun), else the program it calls.
 * The ones that fetch or start something come first, the way an analyst reads the row.
 */
const VERBS = "Add|Clear|Copy|ConvertFrom|ConvertTo|Enter|Export|Get|Import|Invoke|Move|New|Out|Read|Register|Remove|Rename|Resolve|Set|Start|Stop|Test|Write";
const ACTION = /^(Invoke|Start|Register|Set|New-Service|Remove)/;

export function scriptCommands(content: string): string[] {
  const cmdlets = [...content.matchAll(new RegExp(`(?<![\\w-])((?:${VERBS})-[A-Z][A-Za-z]+)`, "g"))].map(m => m[1]);
  if (cmdlets.length) {
    const unique = [...new Set(cmdlets)];
    return [...unique.filter(c => ACTION.test(c)), ...unique.filter(c => !ACTION.test(c))];
  }
  const call = /(?:^|[&;|]\s*)([\w.-]+\.exe)\b/i.exec(content.trim());
  return call ? [call[1]] : [];
}
