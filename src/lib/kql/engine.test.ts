import { describe, expect, it } from "vitest";
import { kqlCompletions, kqlSetsTimeRange, runKql, tokenizeKql } from "./index";
import { Regex, RegexError, compileRegex } from "./regex";
import { NOW, col, fail, fixtureEnv, names, ok } from "./test-fixture";
import type { KqlEnv } from "./types";

describe("analyst queries, end to end", () => {
  it("finds a password spray", () => {
    const r = ok(`SigninLogs
| where TimeGenerated > ago(1h) and ResultType != "0"
| summarize Failures = count(), Accounts = dcount(UserPrincipalName) by IPAddress
| where Accounts > 5
| order by Failures desc`);
    expect(names(r)).toEqual(["IPAddress", "Failures", "Accounts"]);
    expect(r.rows).toEqual([{ IPAddress: "203.0.113.50", Failures: 7, Accounts: 6 }]);
  });
  it("finds encoded PowerShell and download cradles", () => {
    const r = ok(`DeviceProcessEvents
| where ProcessCommandLine has_any ("-enc", "downloadstring")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine`);
    expect(names(r)).toEqual(["TimeGenerated", "DeviceName", "AccountName", "FileName", "ProcessCommandLine"]);
    expect(r.rows).toHaveLength(2);
    expect(r.rows.every((x) => x.DeviceName === "WKS-014")).toBe(true);
  });
  it("pivots from risky sign-ins into audit logs", () => {
    const r = ok(`let bad = SigninLogs | where RiskLevelDuringSignIn == "high" | distinct UserPrincipalName;
AuditLogs
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where Actor in (bad)`);
    expect(r.rows).toHaveLength(1);
    expect(r.rows[0].Actor).toBe("alice@nexacorp.example");
    expect(r.rows[0].OperationName).toBe("Add member to role");
  });
  it("charts failures over time", () => {
    const r = ok(`SigninLogs
| where ResultType != "0"
| summarize Failures = count() by bin(TimeGenerated, 1h)
| sort by TimeGenerated asc
| render timechart`);
    expect(r.chart).toEqual({ kind: "timechart" });
    expect(r.columns[0]).toEqual({ name: "TimeGenerated", type: "datetime" });
  });
  it("expands alert entities", () => {
    const r = ok(`SecurityAlert
| extend Parsed = parse_json(Entities)
| mv-expand Parsed
| where Parsed.Type == "ip"
| project AlertName, Ip = tostring(Parsed.Address)`);
    expect(r.rows).toEqual([{ AlertName: "Password spray", Ip: "203.0.113.50" }]);
  });
  it("finds the last sign-in per user from a public address", () => {
    const r = ok(`SigninLogs
| where not(ipv4_is_private(IPAddress)) and ResultType == "0"
| summarize arg_max(TimeGenerated, IPAddress, AppDisplayName) by UserPrincipalName
| project-rename LastSeen = TimeGenerated
| top 1 by LastSeen`);
    expect(r.rows[0].UserPrincipalName).toBe("alice@nexacorp.example");
  });
});

describe("time range", () => {
  const range = { from: new Date(NOW.getTime() - 60 * 60_000), to: NOW };
  const env = () => fixtureEnv({ timeRange: range });

  it("applies the picker to a query with no TimeGenerated filter", () => {
    const r = ok(`SigninLogs | count`, env());
    expect(r.rows[0].Count).toBe(10);
    expect(r.warnings).toEqual([]);
  });
  it("does not apply when no picker is set", () => {
    expect(ok(`SigninLogs | count`).rows[0].Count).toBe(12);
  });
  it("is overridden by a where on TimeGenerated, with a warning", () => {
    const r = ok(`SigninLogs | where TimeGenerated > ago(4h) | count`, env());
    expect(r.rows[0].Count).toBe(12);
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0]).toContain("Set in query");
  });
  it("sees a TimeGenerated filter nested in an expression, a let or a subquery", () => {
    expect(ok(`SigninLogs | where isnotnull(TimeGenerated) and Location == "US" | count`, env()).rows[0].Count).toBe(12);
    expect(ok(`let a = SigninLogs | where TimeGenerated > ago(4h); a | count`, env()).rows[0].Count).toBe(12);
    expect(ok(`print x = 1 | join kind=leftouter (SigninLogs | where TimeGenerated > ago(4h) | extend x = 1 | take 1) on x | count`, env()).warnings).toHaveLength(1);
  });
  it("a TimeGenerated use outside where still gets the picker", () => {
    const r = ok(`SigninLogs | summarize count() by bin(TimeGenerated, 1d)`, env());
    expect(r.rows[0].count_).toBe(10);
    expect(r.warnings).toEqual([]);
  });
  it("applies to every table in a union and both sides of a join", () => {
    const narrow = fixtureEnv({ timeRange: { from: new Date(NOW.getTime() - 5 * 60_000), to: NOW } });
    expect(ok(`union SigninLogs, SecurityAlert, AuditLogs | count`, narrow).rows[0].Count).toBe(3);
  });
  it("skips tables without TimeGenerated", () => {
    const e = fixtureEnv({ timeRange: range });
    e.tables.Plain = { name: "Plain", columns: [{ name: "a", type: "long" }], rows: [{ a: 1 }] };
    expect(ok(`Plain | count`, e).rows[0].Count).toBe(1);
  });
  it("kqlSetsTimeRange says when the portal would show Set in query", () => {
    expect(kqlSetsTimeRange(`SigninLogs | where TimeGenerated > ago(1h)`)).toBe(true);
    expect(kqlSetsTimeRange(`SigninLogs | where Location == "US"`)).toBe(false);
    expect(kqlSetsTimeRange(`SigninLogs | project TimeGenerated`)).toBe(false);
    expect(kqlSetsTimeRange(`SigninLogs |`)).toBe(false);
  });
});

describe("errors", () => {
  it("unknown table, with a near match", () => {
    const e = fail(`SigninLog | take 1`);
    expect(e.message).toBe("Failed to resolve table or column expression named 'SigninLog'. Did you mean 'SigninLogs'?");
    expect([e.line, e.column]).toEqual([1, 1]);
  });
  it("unknown table with no near match has no suggestion", () => {
    expect(fail(`Zzzzzz`).message).toBe("Failed to resolve table or column expression named 'Zzzzzz'");
  });
  it("table names are case-sensitive", () => {
    expect(fail(`signinlogs`).message).toContain("Did you mean 'SigninLogs'?");
  });
  it("unknown column names the column, with its position and a suggestion", () => {
    const e = fail(`SigninLogs\n| where UserPrincipalNam == "x"`);
    expect(e.message).toContain("'where' operator: Failed to resolve column or scalar expression named 'UserPrincipalNam'");
    expect(e.message).toContain("Did you mean 'UserPrincipalName'?");
    expect([e.line, e.column]).toEqual([2, 9]);
  });
  it("column names are case-sensitive", () => {
    expect(fail(`SigninLogs | project location`).message).toContain("Did you mean 'Location'?");
  });
  it("a column dropped earlier in the pipeline is unknown", () => {
    expect(fail(`SigninLogs | project Location | where IPAddress == "x"`).message).toContain("'IPAddress'");
  });
  it("unknown operator", () => {
    const e = fail(`SigninLogs\n| wher Location == "US"`);
    expect(e.message).toBe("'wher' is not a recognized operator. Did you mean 'where'?");
    expect([e.line, e.column]).toEqual([2, 3]);
  });
  it("a real operator this console lacks says so", () => {
    expect(fail(`SigninLogs | make-series count() on TimeGenerated step 1h`).message).toBe("The 'make-series' operator is not supported in this console.");
  });
  it("unknown function", () => {
    const e = fail(`print strlenn("a")`);
    expect(e.message).toContain("The name 'strlenn' does not refer to any known function.");
    expect(e.message).toContain("Did you mean 'strlen'?");
    expect([e.line, e.column]).toEqual([1, 7]);
  });
  it("wrong argument count and types", () => {
    expect(fail(`print strlen()`).message).toContain("incorrect number of arguments");
    expect(fail(`print abs("a")`).message).toBe("The function 'abs' is not compatible with arguments (string)");
    expect(fail(`print substring("a", "b")`).message).toContain("not compatible");
  });
  it("mismatched == gives the Kusto type error, not an empty result", () => {
    const e = fail(`SigninLogs\n| where ResultType == 0`);
    expect(e.message).toBe("Cannot compare values of types string and long. Try adding explicit casts");
    expect([e.line, e.column]).toEqual([2, 20]);
  });
  it("mismatched comparisons in every direction", () => {
    expect(fail(`SigninLogs | where DurationMs == "5"`).message).toBe("Cannot compare values of types long and string. Try adding explicit casts");
    expect(fail(`SigninLogs | where TimeGenerated > "2026-01-01"`).message).toBe("Cannot compare values of types datetime and string. Try adding explicit casts");
    expect(fail(`SigninLogs | where TimeGenerated != 5`).message).toContain("datetime and long");
    expect(fail(`SigninLogs | where ResultType > 5`).message).toContain("string and long");
    expect(fail(`SigninLogs | where DurationMs in ("a")`).message).toContain("long and string");
    expect(fail(`print true == 1`).message).toContain("bool and long");
  });
  it("the type error fires on an empty table too", () => {
    const env = fixtureEnv();
    env.tables.SigninLogs.rows = [];
    expect(fail(`SigninLogs | where ResultType == 0`, env).message).toContain("Cannot compare");
  });
  it("strings do not order with <", () => {
    expect(fail(`print "a" < "b"`).message).toContain("Cannot compare values of types string and string");
  });
  it("arithmetic on the wrong types", () => {
    expect(fail(`print "a" + 1`).message).toBe("Operator '+' cannot be applied to operands of types string and long.");
    expect(fail(`print now() + now()`).message).toContain("datetime and datetime");
  });
  it("where needs a bool", () => {
    expect(fail(`SigninLogs | where Location`).message).toBe("'where' operator: the predicate must be of type bool, got string.");
  });
  it("aggregates only run in summarize", () => {
    expect(fail(`SigninLogs | where count() > 1`).message).toBe("The aggregate function 'count' is not allowed in this context.");
    expect(fail(`SigninLogs | extend x = sum(DurationMs)`).message).toContain("'sum'");
  });
  it("summarize refuses a dynamic key and a non-aggregate", () => {
    expect(fail(`SigninLogs | summarize count() by DeviceDetail`).message).toContain("Summarize group key 'DeviceDetail' is of a 'dynamic' type");
    expect(fail(`SigninLogs | summarize Location`).message).toContain("not an aggregation");
    expect(fail(`SigninLogs | summarize strlen("a")`).message).toContain("aggregation function is expected");
    expect(fail(`SigninLogs | summarize sum(Location)`).message).toBe("The argument value must be summable: a number, timespan or datetime.");
  });
  it("sort and distinct refuse dynamic", () => {
    expect(fail(`SigninLogs | sort by DeviceDetail`).message).toBe("'sort' operator: key can't be of dynamic type");
    expect(fail(`SigninLogs | order by DeviceDetail`).message).toBe("'order' operator: key can't be of dynamic type");
    expect(fail(`SigninLogs | distinct DeviceDetail`).message).toContain("dynamic");
  });
  it("join keys must exist and match in type", () => {
    expect(fail(`SigninLogs | join SecurityAlert on Location`).message).toContain("'Location' must exist on both sides of the join");
    expect(fail(`let A = datatable(k:string)["a"]; let B = datatable(k:long)[1]; A | join B on k`).message).toBe("Inconsistent data types for join keys: (string, long)");
    expect(fail(`SigninLogs | join SigninLogs on DeviceDetail`).message).toBe("Join keys cannot be dynamic");
    expect(fail(`SigninLogs | join kind=weird SigninLogs on Location`).message).toContain("'weird' is not a valid join kind");
    expect(fail(`SigninLogs | join SigninLogs on a == b`).message).toBeDefined();
  });
  it("dynamic access on a string asks for parse_json", () => {
    expect(fail(`SecurityAlert | extend x = Entities.Type`).message).toContain("parse_json()");
  });
  it("mv-expand needs a dynamic", () => {
    expect(fail(`SigninLogs | mv-expand Location`).message).toContain("must be of type dynamic");
  });
  it("project-away of a missing column fails, a missing wildcard does not", () => {
    expect(fail(`SigninLogs | project-away Nope`).message).toContain("'Nope'");
    expect(ok(`SigninLogs | project-away Nope*`).columns).toHaveLength(11);
  });
  it("render with an unknown kind", () => {
    expect(fail(`SigninLogs | render bubblechart`).message).toContain("'bubblechart' is not a supported visualization");
  });
  it("syntax errors read like the portal and carry a position", () => {
    const e = fail(`SigninLogs | where`);
    expect(e.message).toBe("Query could not be parsed at '<EOF>' on line [1,19]");
    expect([e.line, e.column]).toEqual([1, 19]);
    const m = fail(`SigninLogs\n| project a b`);
    expect(m.message).toBe("Query could not be parsed at 'b' on line [2,13]");
    expect(fail(`SigninLogs where x`).message).toContain("'where'");
    expect(fail(`print 5xyz`).message).toContain("'5xyz'");
  });
  it("unterminated string", () => {
    const e = fail(`print "abc`);
    expect(e.message).toContain("Unterminated string literal");
    expect([e.line, e.column]).toEqual([1, 7]);
  });
  it("bad literals", () => {
    expect(fail(`print datetime(not a date)`).message).toContain("Failed to parse the datetime literal");
    expect(fail(`print guid(xyz)`).message).toContain("Failed to parse the guid literal");
    expect(fail(`print timespan(nope)`).message).toContain("Failed to parse the timespan literal");
  });
  it("a query of only lets, an empty query, a scalar used as a table", () => {
    expect(fail(`let a = 1;`).message).toContain("no tabular expression");
    expect(fail(``).message).toBe("The query is empty.");
    expect(fail(`// just a comment`).message).toBe("The query is empty.");
    expect(fail(`let a = 1; a`).message).toContain("refers to a scalar value");
    expect(fail(`print x = SigninLogs`).message).toContain("refers to a table");
  });
  it("user functions are refused by name", () => {
    expect(fail(`let f = (x:long) { x + 1 }; print f(1)`).message).toContain("does not support");
  });
  it("never throws, whatever the input", () => {
    const junk = ["|", "||", "((((", "))))", "let", "let =", "|where", "\"", "'", "[", "]", "{", "1 +", "print", "print ,", "T | | |", "\u0000", "$", "@", "=", "join", "union", "search", "datatable(", "dynamic(", "print dynamic([", "print datetime(", "T | parse x with", "T | top", "T | sort", "summarize", "\\"];
    for (const q of junk) {
      expect(() => runKql(q, fixtureEnv())).not.toThrow();
      expect(runKql(q, fixtureEnv()).ok).toBe(false);
    }
  });
  it("survives a broken env", () => {
    expect(() => runKql(`T`, { tables: {}, now: new Date(NaN) })).not.toThrow();
    expect(() => runKql(`print ago(1h)`, { tables: {}, now: new Date(NaN) })).not.toThrow();
  });
  it("does not resolve inherited object properties as tables", () => {
    expect(fail(`constructor`).message).toContain("Failed to resolve table");
    expect(fail(`__proto__`).message).toContain("Failed to resolve table");
    expect(fail(`print constructor("a")`).message).toContain("known function");
  });
});

describe("limits: a bad query cannot freeze the tab", () => {
  const started = () => Date.now();
  const bigEnv = (rows: number, width = 200): KqlEnv => ({
    now: NOW,
    tables: {
      Big: {
        name: "Big",
        columns: [{ name: "a", type: "string" }, { name: "k", type: "long" }],
        rows: Array.from({ length: rows }, (_, i) => ({ a: "a".repeat(width), k: i % 3 })),
      },
    },
  });

  it("catastrophic regexes run in linear time", () => {
    const t = started();
    const r = ok(`print s = strrep("a", 5000) | where s matches regex "(a+)+$"`);
    expect(r.rows).toHaveLength(1);
    const miss = ok(`print s = strcat(strrep("a", 5000), "!") | where s matches regex "^(a|a)*$"`);
    expect(miss.rows).toHaveLength(0);
    expect(ok(`print s = strrep("a", 3000) | where s matches regex "(a*)*b"`).rows).toHaveLength(0);
    expect(Date.now() - t).toBeLessThan(5000);
  });
  it("oversized regexes are refused", () => {
    expect(fail(`print "a" matches regex "((a{1000}){1000}){1000}"`).message).toContain("Invalid regular expression");
    expect(fail(`print "a" matches regex "a{5000}"`).message).toContain("invalid repeat count");
  });
  it("a cross join is stopped, not run", () => {
    const t = started();
    const e = fail(`Big | join kind=inner Big on k`, bigEnv(9000, 1));
    expect(e.message).toMatch(/more than 1000000 rows|resource limits/);
    expect(Date.now() - t).toBeLessThan(8000);
  });
  it("functions stay linear on hostile strings", () => {
    const t = started();
    expect(ok(`print x = tolong(strcat(strrep("1", 1000000), "x"))`).rows[0].x).toBeNull();
    expect(ok(`print x = parse_url(strcat("https://", strrep("a", 1000000), "#", "\\n", strrep("b", 1000000))).Fragment`).rows).toHaveLength(1);
    expect(ok(`print x = base64_decode_tostring(strcat(strrep("=", 1000000), "x"))`).rows).toHaveLength(1);
    expect(ok(`print x = todatetime(strrep("1", 1000000)), y = totimespan(strrep("1", 1000000))`).rows[0].x).toBeNull();
    expect(Date.now() - t).toBeLessThan(5000);
  });
  it("an overlapping countof on a huge string is stopped by the budget", () => {
    const t = started();
    const r = runKql(`print countof(strrep("a", 2000000), strrep("a", 1000000))`, fixtureEnv());
    expect(r.ok).toBe(false);
    expect(Date.now() - t).toBeLessThan(8000);
  });
  it("a limit failure points at its operator", () => {
    const steps = Array.from({ length: 60 }, () => `| extend s = strcat(s, s)`).join("\n");
    const e = fail(`print s = "xxxxxxxx"\n${steps}`);
    expect(e.line).toBeGreaterThan(1);
  });
  it("a doubling string or array is stopped", () => {
    const steps = Array.from({ length: 60 }, () => `| extend s = strcat(s, s)`).join(" ");
    expect(fail(`print s = "xxxxxxxx" ${steps}`).message).toMatch(/larger than the limit/);
    const arr = Array.from({ length: 60 }, () => `| extend s = array_concat(s, s)`).join(" ");
    expect(() => runKql(`print s = dynamic([1,2,3,4]) ${arr}`, fixtureEnv())).not.toThrow();
    expect(runKql(`print s = dynamic([1,2,3,4]) ${arr}`, fixtureEnv()).ok).toBe(false);
  });
  it("shared nested structure cannot explode when printed", () => {
    const t = started();
    const steps = Array.from({ length: 50 }, () => `| extend s = pack_array(s, s)`).join(" ");
    const r = runKql(`print s = dynamic([1]) ${steps} | extend t = tostring(s)`, fixtureEnv());
    expect(r.ok).toBe(false);
    expect(Date.now() - t).toBeLessThan(8000);
  });
  it("a huge range is refused", () => {
    expect(fail(`range x from 1 to 100000000 step 1`).message).toMatch(/more than 1000000 rows/);
  });
  it("deep nesting is refused", () => {
    const deep = `print ${"(".repeat(5000)}1${")".repeat(5000)}`;
    expect(runKql(deep, fixtureEnv()).ok).toBe(false);
    const long = `print ${Array.from({ length: 50000 }, () => "1").join("+")}`;
    expect(() => runKql(long, fixtureEnv())).not.toThrow();
    const dyn = `print dynamic(${"[".repeat(5000)}${"]".repeat(5000)})`;
    expect(runKql(dyn, fixtureEnv()).ok).toBe(false);
  });
  it("oversized query text is refused", () => {
    expect(fail(`print "${"x".repeat(300000)}"`).message).toContain("maximum safe limit");
  });
  it("heavy but legal work over many rows still finishes", () => {
    const r = ok(`Big | where a has "x" or a contains "b" or strlen(a) > 0 | summarize count() by k | sort by k asc`, bigEnv(30000, 50));
    expect(col(r, "k")).toEqual([0, 1, 2]);
  });
  it("the budget resets between queries", () => {
    const e = bigEnv(9000, 1);
    fail(`Big | join kind=inner Big on k`, e);
    expect(ok(`Big | count`, e).rows[0].Count).toBe(9000);
  });
});

describe("regex engine", () => {
  const m = (re: string, s: string) => {
    const r = compileRegex(re).exec(s);
    return r ? s.slice(r[0], r[1]) : null;
  };
  it("matches leftmost-first, greedy and lazy", () => {
    expect(m("a+", "baaa")).toBe("aaa");
    expect(m("a+?", "baaa")).toBe("a");
    expect(m("a|ab", "ab")).toBe("a");
    expect(m("(?U)a+", "aaa")).toBe("a");
    expect(m("x*", "aaa")).toBe("");
  });
  it("supports classes, anchors, boundaries, flags and counted repeats", () => {
    expect(m("[0-9]{2,3}", "a1234")).toBe("123");
    expect(m("^b", "ab")).toBeNull();
    expect(m("(?m)^b", "a\nb")).toBe("b");
    expect(m("a$", "a\n")).toBeNull();
    expect(m("(?i)HELLO", "say hello")).toBe("hello");
    expect(m("[[:digit:]]+", "ab12")).toBe("12");
    expect(m("\\bcat\\b", "concat cat")).toBe("cat");
    expect(m("a.c", "a\nc")).toBeNull();
    expect(m("(?s)a.c", "a\nc")).toBe("a\nc");
    expect(m("\\d+\\.\\d+", "v1.25")).toBe("1.25");
    expect(m("[^a-c]+", "abcde")).toBe("de");
    expect(m("\\x41", "A")).toBe("A");
    expect(m("\\p{L}+", "123שלום")).toBe("שלום");
    expect(m("😀.", "😀😀x")).toBe("😀😀");
    expect(m(".", "😀")).toBe("😀");
  });
  it("captures groups, including named and optional ones", () => {
    const r = new Regex("(?P<a>x)(y)?(z)").exec("xz") as number[];
    expect(r.slice(0, 8)).toEqual([0, 2, 0, 1, -1, -1, 1, 2]);
    expect(new Regex("(?P<a>x)").groupNames.get("a")).toBe(1);
  });
  it("rejects what RE2 rejects", () => {
    for (const bad of ["(?=a)", "(?!a)", "(?<=a)", "(?<!a)", "(a)\\1", "[", "(", ")", "a**", "*a", "\\", "a{2,1}"]) {
      expect(() => new Regex(bad), bad).toThrow(RegexError);
    }
  });
  it("treats a brace with no count as a literal", () => {
    expect(m("a{x}", "a{x}")).toBe("a{x}");
  });
});

describe("coverage of the language surface", () => {
  const scalars = `ago now todatetime tostring toint tolong toreal todouble tobool totimespan todynamic parse_json tolower toupper strlen substring strcat strcat_delim split trim trim_start trim_end replace_string replace_regex extract extract_all indexof countof reverse base64_decode_tostring base64_encode_tostring url_decode parse_url parse_ipv4 ipv4_is_private ipv4_is_in_range isnull isnotnull isempty isnotempty iff iif case coalesce bin floor ceiling round abs log10 sqrt pow min_of max_of format_datetime format_timespan datetime_diff datetime_add startofday startofhour endofday dayofweek hourofday getmonth getyear array_length array_sort_asc array_concat bag_keys pack bag_pack pack_array set_has_element gettype hash_md5 hash_sha256 column_ifexists`.split(" ");
  const aggregates = `count countif dcount dcountif sum sumif avg avgif min max minif maxif arg_max arg_min make_list make_set make_bag any take_any percentile stdev variance`.split(" ");
  const operators = `where filter project project-away project-keep project-rename project-reorder extend summarize count distinct top take limit sort order join union mv-expand parse search getschema sample render`.split(" ");

  it.each(scalars)("knows the scalar function %s", (name) => {
    const r = runKql(`print x = ${name}()`, fixtureEnv());
    if (!r.ok) expect(r.error.message).not.toContain("known function");
  });
  it.each(aggregates)("knows the aggregate %s", (name) => {
    const r = runKql(`SigninLogs | summarize x = ${name}()`, fixtureEnv());
    if (!r.ok) expect(r.error.message).not.toContain("known function");
  });
  it.each(operators)("knows the operator %s", (name) => {
    const r = runKql(`SigninLogs | ${name}`, fixtureEnv());
    if (!r.ok) expect(r.error.message).not.toContain("not a recognized operator");
  });
  it("offers every scalar and aggregate in completions", () => {
    const fns = kqlCompletions("print x = 1 | extend y = ", 25, fixtureEnv()).map((c) => c.label);
    for (const name of scalars) expect(fns).toContain(name);
    const aggs = kqlCompletions("SigninLogs | summarize ", 23, fixtureEnv()).map((c) => c.label);
    for (const name of aggregates) expect(aggs).toContain(name);
  });
});

describe("tokenizeKql", () => {
  const classes = (q: string) => tokenizeKql(q).filter((t) => t.text.trim() !== "").map((t) => [t.text, t.class]);

  it("covers the whole text, whitespace included", () => {
    const q = `SigninLogs // c\n| where x == "a"`;
    expect(tokenizeKql(q).map((t) => t.text).join("")).toBe(q);
  });
  it("classifies an ordinary query", () => {
    expect(classes(`SigninLogs\n| where TimeGenerated > ago(1h) and Name has "x" // note\n| summarize count() by bin(T, 5m)`)).toEqual([
      ["SigninLogs", "table"], ["|", "operator"], ["where", "keyword"], ["TimeGenerated", "other"], [">", "operator"],
      ["ago", "function"], ["(", "other"], ["1h", "number"], [")", "other"], ["and", "operator"], ["Name", "other"],
      ["has", "operator"], ['"x"', "string"], ["// note", "comment"], ["|", "operator"], ["summarize", "keyword"],
      ["count", "function"], ["(", "other"], [")", "other"], ["by", "keyword"], ["bin", "function"], ["(", "other"],
      ["T", "other"], [",", "other"], ["5m", "number"], [")", "other"],
    ]);
  });
  it("handles hyphenated operators, negated operators and literals", () => {
    const t = classes(`T | project-away A | where B !has "x" and C !in~ ("y") | mv-expand D | where E == 1.5 and F > datetime(2026-01-01) and G == @"v"`);
    expect(t).toContainEqual(["project-away", "keyword"]);
    expect(t).toContainEqual(["!has", "operator"]);
    expect(t).toContainEqual(["!in~", "operator"]);
    expect(t).toContainEqual(["mv-expand", "keyword"]);
    expect(t).toContainEqual(["1.5", "number"]);
    expect(t).toContainEqual(["datetime(2026-01-01)", "function"]);
    expect(t).toContainEqual(['@"v"', "string"]);
  });
  it("marks let, tables after let, and a table used in union", () => {
    const t = classes(`let a = SigninLogs | take 1; union Device, Other`);
    expect(t).toContainEqual(["let", "keyword"]);
    expect(t).toContainEqual(["SigninLogs", "table"]);
    expect(t).toContainEqual(["Device", "table"]);
  });
  it("uses env for exact table names when given", () => {
    const t = tokenizeKql(`foo | union SecurityAlert`, fixtureEnv()).find((x) => x.text === "SecurityAlert");
    expect(t?.class).toBe("table");
  });
  it("copes with unfinished text", () => {
    expect(() => tokenizeKql(`T | where x == "unterminated`)).not.toThrow();
    expect(tokenizeKql(`"open`).map((t) => t.class)).toEqual(["string"]);
    expect(tokenizeKql(``)).toEqual([]);
    expect(tokenizeKql(`\u0000 @ #`).map((t) => t.text).join("")).toBe(`\u0000 @ #`);
  });
});

describe("kqlCompletions", () => {
  const env = fixtureEnv();
  /** `^` marks the cursor. */
  const at = (text: string) => {
    const cursor = text.indexOf("^");
    return kqlCompletions(text.replace("^", ""), cursor, env);
  };
  const labels = (text: string) => at(text).map((c) => c.label);

  it("offers tables and first-position keywords at the start of a statement", () => {
    const c = at(`^`);
    expect(c.find((x) => x.label === "SigninLogs")).toMatchObject({ kind: "table", insert: "SigninLogs" });
    expect(c.map((x) => x.label)).toContain("let");
    expect(labels(`Sig^`)).toEqual(["SigninLogs"]);
    expect(labels(`let a = 1;\nSec^`)).toEqual(["SecurityAlert"]);
    expect(labels(`let a = Sec^`)).toEqual(["SecurityAlert"]);
  });
  it("offers tabular lets in later statements", () => {
    expect(labels(`let bad = SigninLogs | take 1;\n^`)).toContain("bad");
  });
  it("offers operators after a pipe", () => {
    const c = at(`SigninLogs | ^`);
    expect(c.find((x) => x.label === "where")).toMatchObject({ kind: "operator", insert: "where " });
    expect(labels(`SigninLogs\n| wh^`)).toEqual(["where", "parse-where"]);
    expect(labels(`SigninLogs | project-a^`)).toEqual(["project-away"]);
    expect(labels(`SigninLogs | project-^`)).toContain("project-rename");
    expect(labels(`SigninLogs | ^`)).toContain("mv-expand");
  });
  it("offers the columns in scope after where", () => {
    const c = at(`SigninLogs | where ^`);
    expect(c.find((x) => x.label === "IPAddress")).toMatchObject({ kind: "column", insert: "IPAddress", detail: "string" });
    expect(c.find((x) => x.label === "strlen")).toMatchObject({ kind: "function", insert: "strlen(" });
    expect(labels(`SigninLogs | where IP^`)[0]).toBe("IPAddress");
  });
  it("tracks columns through the pipeline", () => {
    const a = labels(`SigninLogs | project IPAddress, Who = UserPrincipalName | where ^`);
    expect(a).toContain("Who");
    expect(a).toContain("IPAddress");
    expect(a).not.toContain("Location");
    const b = labels(`SigninLogs | summarize N = count() by IPAddress | where ^`);
    expect(b).toContain("N");
    expect(b).not.toContain("Location");
    expect(labels(`SigninLogs | extend Foo = 1 | project ^`)).toContain("Foo");
  });
  it("uses let tables as a source of columns", () => {
    expect(labels(`let t = SecurityAlert | project AlertName;\nt | where ^`)).toContain("AlertName");
  });
  it("recovers from a broken earlier operator", () => {
    expect(labels(`SigninLogs | where Nope == 1 | project ^`)).toContain("IPAddress");
  });
  it("offers aggregates after summarize, and columns after by", () => {
    const a = labels(`SigninLogs | summarize ^`);
    expect(a).toContain("count");
    expect(a).toContain("dcount");
    expect(a).toContain("arg_max");
    expect(labels(`SigninLogs | summarize N = ^`)).toContain("dcount");
    const b = at(`SigninLogs | summarize count() by ^`);
    expect(b.map((x) => x.label)).toContain("IPAddress");
    expect(b.map((x) => x.label)).toContain("bin");
    expect(labels(`SigninLogs | summarize count() by `).length).toBeGreaterThan(0);
    expect(labels(`SigninLogs | summarize count() ^`)).toContain("by");
    expect(labels(`SigninLogs | summarize dcount(^`)).toContain("IPAddress");
  });
  it("offers columns for the project family, sort, top and join", () => {
    expect(labels(`SigninLogs | project-away ^`)).toContain("Location");
    expect(labels(`SigninLogs | distinct ^`)).toContain("Location");
    expect(labels(`SigninLogs | sort ^`)).toEqual(["by"]);
    expect(labels(`SigninLogs | sort by ^`)).toContain("Location");
    expect(labels(`SigninLogs | sort by Location ^`)).toContain("desc");
    expect(labels(`SigninLogs | top 5 ^`)).toEqual(["by"]);
    expect(labels(`SigninLogs | top 5 by ^`)).toContain("Location");
    expect(labels(`SigninLogs | join kind=^`)).toContain("leftouter");
    expect(labels(`SigninLogs | join kind=inner (^`)).toContain("AuditLogs");
    expect(labels(`SigninLogs | join kind=inner (AuditLogs | where ^`)).toContain("OperationName");
    expect(labels(`SigninLogs | join kind=inner (AuditLogs) on ^`)).toContain("Location");
  });
  it("offers comparison operators after a complete term", () => {
    const a = labels(`SigninLogs | where Location ^`);
    expect(a).toContain("has");
    expect(a).toContain("==");
    expect(a).toContain("startswith");
    expect(a).toContain("and");
    expect(labels(`SigninLogs | where Location == "US" ^`)).toContain("and");
    expect(labels(`SigninLogs | where Location == "US" and ^`)).toContain("IPAddress");
  });
  it("offers chart kinds after render, and tables after union", () => {
    expect(labels(`SigninLogs | render ^`)).toEqual(["timechart", "barchart", "columnchart", "piechart", "linechart", "areachart", "table"]);
    expect(labels(`union ^`)).toContain("AuditLogs");
    expect(labels(`SigninLogs | union ^`)).toContain("AuditLogs");
  });
  it("is silent inside strings, comments and dynamic paths", () => {
    expect(at(`SigninLogs | where Location == "U^`)).toEqual([]);
    expect(at(`// SigninLogs | ^`)).toEqual([]);
    expect(at(`SigninLogs | where LocationDetails.^`)).toEqual([]);
  });
  it("only looks at the text before the cursor", () => {
    const text = `SigninLogs | where  | project IPAddress`;
    expect(kqlCompletions(text, 19, env).map((c) => c.label)).toContain("Location");
  });
  it("quotes column names that need it", () => {
    const e = fixtureEnv();
    e.tables.T = { name: "T", columns: [{ name: "my col", type: "long" }], rows: [] };
    expect(kqlCompletions("T | where ", 10, e).find((c) => c.label === "my col")?.insert).toBe("['my col']");
  });
  it("never throws and clamps the cursor", () => {
    for (const q of ["", "|", "((((", "T | | ", "let", '"', "T | where (", "union (", "join"]) {
      for (const c of [-5, 0, 1, 100]) expect(() => kqlCompletions(q, c, env)).not.toThrow();
    }
  });
  it("runs no heavy query for suggestions", () => {
    const e = fixtureEnv();
    e.tables.SigninLogs.rows = Array.from({ length: 200000 }, () => e.tables.SigninLogs.rows[0]);
    const t = Date.now();
    kqlCompletions(`SigninLogs | where Location == "x" | summarize count() by Location | `, 66, e);
    expect(Date.now() - t).toBeLessThan(500);
  });
});
