import { describe, expect, it } from "vitest";
import { KqlTimespan } from "./index";
import { NOW, cell, col, fail, fixtureEnv, names, ok } from "./test-fixture";

const X = `let X = datatable(Key:string, Value1:long)['a',1,'b',2,'b',3,'c',4];`;
const Y = `let Y = datatable(Key:string, Value2:long)['b',10,'c',20,'c',30,'d',40];`;

describe("where and filter", () => {
  it("filters on a predicate, and filter is an alias", () => {
    expect(ok(`SigninLogs | where ResultType == "0"`).rows).toHaveLength(3);
    expect(ok(`SigninLogs | filter ResultType == "0"`).rows).toHaveLength(3);
  });
  it("evaluates and / or with the right precedence", () => {
    const r = ok(`SigninLogs | where ResultType == "0" or ResultType == "50053" and Location == "XX"`);
    expect(r.rows).toHaveLength(3);
  });
  it("searches every column with * has", () => {
    expect(ok(`DeviceProcessEvents | where * has "whoami"`).rows).toHaveLength(1);
  });
});

describe("project family", () => {
  it("project selects, renames and computes", () => {
    const r = ok(`SigninLogs | take 1 | project User = UserPrincipalName, Len = strlen(IPAddress), Location`);
    expect(names(r)).toEqual(["User", "Len", "Location"]);
    expect(r.rows[0].Len).toBe(12);
  });
  it("project names an unnamed expression Column1, Column2", () => {
    expect(names(ok(`SigninLogs | take 1 | project tolower(Location), toupper(Location)`))).toEqual(["Column1", "Column2"]);
  });
  it("project gives a repeated name a numeric suffix", () => {
    expect(names(ok(`SigninLogs | take 1 | project Location, Location`))).toEqual(["Location", "Location1"]);
  });
  it("derives names from dynamic paths and conversion functions", () => {
    const r = ok(`AuditLogs | take 1 | project tostring(InitiatedBy.user.userPrincipalName), TargetResources[0].displayName, InitiatedBy["user"]`);
    expect(names(r)).toEqual(["InitiatedBy_user_userPrincipalName", "TargetResources_0_displayName", "InitiatedBy_user"]);
  });
  it("project-away removes columns and wildcards", () => {
    expect(names(ok(`SecurityAlert | project-away Entities, Tactics, Alert*, Sys*`))).toEqual(["TimeGenerated", "CompromisedEntity", "ProductName"]);
  });
  it("project-keep keeps columns in table order", () => {
    expect(names(ok(`SecurityAlert | project-keep ProductName, Alert*`))).toEqual(["AlertName", "AlertSeverity", "ProductName"]);
  });
  it("project-rename keeps column positions", () => {
    const r = ok(`AuditLogs | project-rename Op = OperationName, When = TimeGenerated`);
    expect(names(r)).toEqual(["When", "Op", "Result", "InitiatedBy", "TargetResources"]);
    expect(r.rows[0].Op).toBe("Add member to role");
  });
  it("project-reorder moves the named columns first and keeps the rest", () => {
    expect(names(ok(`AuditLogs | project-reorder Result, Op*`))).toEqual(["Result", "OperationName", "TimeGenerated", "InitiatedBy", "TargetResources"]);
  });
  it("extend appends, later items see earlier ones, and an existing name is replaced", () => {
    const r = ok(`SecurityAlert | take 1 | project AlertName, AlertSeverity | extend A = 1, B = A + 1, AlertName = "x"`);
    expect(names(r)).toEqual(["AlertName", "AlertSeverity", "A", "B"]);
    expect(r.rows[0]).toMatchObject({ A: 1, B: 2, AlertName: "x" });
  });
});

describe("summarize", () => {
  it("names aggregates as Kusto does", () => {
    const r = ok(`SigninLogs | summarize count(), dcount(UserPrincipalName), sum(DurationMs), avg(DurationMs), min(DurationMs), max(DurationMs), countif(ResultType == "0"), countif(true), make_set(Location), make_list(Location), stdev(DurationMs), variance(DurationMs), percentile(DurationMs, 50), percentile(DurationMs, 99.5), sumif(DurationMs, true), dcountif(Location, true), any(Location), take_any(Location)`);
    expect(names(r)).toEqual([
      "count_", "dcount_UserPrincipalName", "sum_DurationMs", "avg_DurationMs", "min_DurationMs", "max_DurationMs",
      "countif_", "countif_1", "set_Location", "list_Location", "stdev_DurationMs", "variance_DurationMs",
      "percentile_DurationMs_50", "percentile_DurationMs_99_5", "sumif_DurationMs", "dcountif_Location", "any_Location", "Location",
    ]);
  });
  it("deduplicates repeated aggregate names with a numeric suffix", () => {
    expect(names(ok(`SigninLogs | summarize make_set(Location), make_set(Location)`))).toEqual(["set_Location", "set_Location1"]);
  });
  it("names bin() after its column, and puts by columns first", () => {
    const r = ok(`SigninLogs | summarize count() by bin(TimeGenerated, 1h), Location`);
    expect(names(r)).toEqual(["TimeGenerated", "Location", "count_"]);
    expect(r.rows[0].TimeGenerated).toEqual(new Date("2026-11-07T11:00:00Z"));
    expect(r.columns[0].type).toBe("datetime");
  });
  it("uses Column1 for a by expression with no derivable name", () => {
    expect(names(ok(`SigninLogs | summarize count() by tolower(Location)`))).toEqual(["Column1", "count_"]);
    expect(names(ok(`SigninLogs | summarize count() by strlen(Location)`))).toEqual(["strlen_Location", "count_"]);
    expect(names(ok(`AuditLogs | summarize count() by tostring(InitiatedBy.user.userPrincipalName)`))).toEqual(["InitiatedBy_user_userPrincipalName", "count_"]);
  });
  it("types: count is long, sum of int is long, avg is real, min keeps the type", () => {
    const r = ok(`SigninLogs | summarize count(), sum(DurationMs), avg(DurationMs), min(TimeGenerated), max(Location)`);
    expect(r.columns.map((c) => c.type)).toEqual(["long", "long", "real", "datetime", "string"]);
  });
  it("without by, over empty input, yields one row of defaults", () => {
    const r = ok(`SigninLogs | where Location == "none" | summarize count(), sum(DurationMs), dcount(Location), make_list(Location), make_set(Location), min(DurationMs), avg(DurationMs), stdev(DurationMs), max(Location)`);
    expect(r.rows).toHaveLength(1);
    expect(r.rows[0]).toMatchObject({ count_: 0, sum_DurationMs: 0, dcount_Location: 0, list_Location: [], set_Location: [], min_DurationMs: null, stdev_DurationMs: 0, max_Location: "" });
    expect(r.rows[0].avg_DurationMs).toBeNaN();
  });
  it("with by, over empty input, yields no rows", () => {
    expect(ok(`SigninLogs | where Location == "none" | summarize count() by Location`).rows).toHaveLength(0);
  });
  it("summarize by alone gives the distinct keys", () => {
    expect(ok(`SigninLogs | summarize by Location, AppDisplayName`).rows).toEqual([{ Location: "US", AppDisplayName: "Azure Portal" }]);
  });
  it("accepts expressions over aggregates", () => {
    const r = ok(`SigninLogs | summarize Rate = round(100.0 * countif(ResultType != "0") / count(), 1) by Location`);
    expect(r.rows[0].Rate).toBe(75);
  });
  it("arg_max(T, *) returns the whole row, by columns first", () => {
    const r = ok(`SigninLogs | summarize arg_max(TimeGenerated, *) by UserPrincipalName | where UserPrincipalName startswith "alice"`);
    expect(names(r).slice(0, 3)).toEqual(["UserPrincipalName", "TimeGenerated", "IPAddress"]);
    expect(names(r).filter((n) => n === "UserPrincipalName")).toHaveLength(1);
    expect(r.rows[0].IPAddress).toBe("203.0.113.50");
  });
  it("arg_max and arg_min keep the argument names", () => {
    const r = ok(`SecurityAlert | summarize arg_max(TimeGenerated, AlertName), arg_min(TimeGenerated, AlertSeverity)`);
    expect(names(r)).toEqual(["TimeGenerated", "AlertName", "TimeGenerated1", "AlertSeverity"]);
    expect(r.rows[0].AlertName).toBe("Password spray");
    expect(r.rows[0].AlertSeverity).toBe("Low");
  });
  it("arg_max follows the documented null handling", () => {
    const r = ok(`datatable(Fruit: string, Color: string, Version: int) [
      "Apple", "Red", 1, "Apple", "Green", int(null), "Banana", "Yellow", int(null), "Banana", "Green", int(null),
      "Pear", "Brown", 1, "Pear", "Green", 2 ] | summarize arg_max(Version, *) by Fruit`);
    expect(r.rows).toEqual([
      { Fruit: "Apple", Version: 1, Color: "Red" },
      { Fruit: "Banana", Version: null, Color: "Yellow" },
      { Fruit: "Pear", Version: 2, Color: "Green" },
    ]);
  });
  it("supports tuple names for arg_max", () => {
    const r = ok(`SecurityAlert | summarize (Last, Name) = arg_max(TimeGenerated, AlertName)`);
    expect(names(r)).toEqual(["Last", "Name"]);
  });
  it("min, max and avg skip nulls; make_list skips nulls; make_set dedupes", () => {
    const r = ok(`datatable(k:string, v:long)["a",1,"a",long(null),"a",3,"a",1] | summarize min(v), max(v), avg(v), sum(v), make_list(v), make_set(v), count(), count(v) by k`);
    expect(r.rows[0]).toMatchObject({ min_v: 1, max_v: 3, sum_v: 5, list_v: [1, 3, 1], set_v: [1, 3], count_: 4, count_v: 4 });
    expect(r.rows[0].avg_v).toBeCloseTo(5 / 3);
  });
  it("nearest-rank percentile, not interpolation", () => {
    const r = ok(`datatable(v:long)[1,2,3,4] | summarize percentile(v, 50), percentile(v, 0), percentile(v, 100), percentile(v, 25)`);
    expect(r.rows[0]).toEqual({ percentile_v_50: 2, percentile_v_0: 1, percentile_v_100: 4, percentile_v_25: 1 });
  });
  it("stdev and variance are the sample forms", () => {
    const r = ok(`datatable(v:long)[2,4,4,4,5,5,7,9] | summarize stdev(v), variance(v)`);
    expect(r.rows[0].variance_v).toBeCloseTo(32 / 7);
    expect(r.rows[0].stdev_v).toBeCloseTo(Math.sqrt(32 / 7));
  });
  it("make_bag merges property bags and skips the rest", () => {
    const r = ok(`datatable(d:dynamic)[dynamic({"a":1}), dynamic(1), dynamic({"b":2})] | summarize make_bag(d)`);
    expect(r.rows[0].bag_d).toEqual({ a: 1, b: 2 });
  });
  it("groups null keys together", () => {
    const r = ok(`datatable(k:long, v:long)[long(null),1,long(null),2,5,3] | summarize sum(v) by k`);
    expect(r.rows).toEqual([{ k: null, sum_v: 3 }, { k: 5, sum_v: 3 }]);
  });
  it("avgif, minif, maxif filter on the predicate", () => {
    const r = ok(`datatable(v:long, p:bool)[1,true,9,false,3,true] | summarize avgif(v, p), minif(v, p), maxif(v, p)`);
    expect(r.rows[0]).toEqual({ avgif_v: 2, minif_v: 1, maxif_v: 3 });
  });
});

describe("count, distinct, take, top, sort, sample", () => {
  it("count returns one Count column", () => {
    const r = ok(`SigninLogs | count`);
    expect(names(r)).toEqual(["Count"]);
    expect(r.columns[0].type).toBe("long");
    expect(r.rows).toEqual([{ Count: 12 }]);
  });
  it("distinct removes duplicates, and accepts *", () => {
    expect(ok(`SigninLogs | distinct IPAddress`).rows).toHaveLength(3);
    expect(ok(`datatable(a:long,b:long)[1,1,1,1,1,2] | distinct *`).rows).toHaveLength(2);
  });
  it("take and limit cut rows", () => {
    expect(ok(`SigninLogs | take 2`).rows).toHaveLength(2);
    expect(ok(`SigninLogs | limit 3`).rows).toHaveLength(3);
    expect(ok(`SigninLogs | take 0`).rows).toHaveLength(0);
  });
  it("sort and order default to descending", () => {
    expect(col(ok(`datatable(v:long)[2,3,1] | sort by v`), "v")).toEqual([3, 2, 1]);
    expect(col(ok(`datatable(v:long)[2,3,1] | order by v`), "v")).toEqual([3, 2, 1]);
    expect(col(ok(`datatable(v:long)[2,3,1] | order by v asc`), "v")).toEqual([1, 2, 3]);
  });
  it("places nulls first in asc and last in desc, and honours nulls first/last", () => {
    const t = `datatable(v:long)[2,long(null),1]`;
    expect(col(ok(`${t} | sort by v asc`), "v")).toEqual([null, 1, 2]);
    expect(col(ok(`${t} | sort by v desc`), "v")).toEqual([2, 1, null]);
    expect(col(ok(`${t} | sort by v asc nulls last`), "v")).toEqual([1, 2, null]);
    expect(col(ok(`${t} | sort by v desc nulls first`), "v")).toEqual([null, 2, 1]);
  });
  it("sorts by several keys and expressions, stably", () => {
    const r = ok(`datatable(a:string,b:long)["x",1,"y",2,"x",3] | sort by a asc, b desc`);
    expect(col(r, "b")).toEqual([3, 1, 2]);
    expect(col(ok(`datatable(a:string)["bb","a","ccc"] | sort by strlen(a) asc`), "a")).toEqual(["a", "bb", "ccc"]);
  });
  it("top defaults to descending", () => {
    expect(col(ok(`datatable(v:long)[2,3,1] | top 2 by v`), "v")).toEqual([3, 2]);
    expect(col(ok(`datatable(v:long)[2,3,1] | top 1 by v asc`), "v")).toEqual([1]);
    expect(col(ok(`datatable(v:long)[long(null),3] | top 1 by v`), "v")).toEqual([3]);
  });
  it("sample returns that many input rows and stays reproducible", () => {
    const a = ok(`SigninLogs | sample 4`);
    expect(a.rows).toHaveLength(4);
    expect(ok(`SigninLogs | sample 4`).rows).toEqual(a.rows);
    expect(ok(`SigninLogs | sample 100`).rows).toHaveLength(12);
  });
});

describe("join", () => {
  it("defaults to innerunique: left dedupe keeps the first row, right duplicates stay", () => {
    const r = ok(`${X}${Y} X | join Y on Key`);
    expect(names(r)).toEqual(["Key", "Value1", "Key1", "Value2"]);
    expect(r.rows).toEqual([
      { Key: "b", Value1: 2, Key1: "b", Value2: 10 },
      { Key: "c", Value1: 4, Key1: "c", Value2: 20 },
      { Key: "c", Value1: 4, Key1: "c", Value2: 30 },
    ]);
  });
  it("kind=inner keeps every combination", () => {
    const r = ok(`${X}${Y} X | join kind=inner Y on Key`);
    expect(r.rows.map((x) => [x.Key, x.Value1, x.Value2])).toEqual([["b", 2, 10], ["b", 3, 10], ["c", 4, 20], ["c", 4, 30]]);
  });
  it("leftouter keeps unmatched left rows, with right cells empty", () => {
    const r = ok(`${X}${Y} X | join kind=leftouter Y on Key`);
    expect(r.rows).toHaveLength(5);
    expect(r.rows[0]).toEqual({ Key: "a", Value1: 1, Key1: "", Value2: null });
  });
  it("rightouter keeps unmatched right rows", () => {
    const r = ok(`${X}${Y} X | join kind=rightouter Y on Key`);
    expect(r.rows).toHaveLength(5);
    expect(r.rows[4]).toEqual({ Key: "", Value1: null, Key1: "d", Value2: 40 });
  });
  it("fullouter keeps both sides", () => {
    expect(ok(`${X}${Y} X | join kind=fullouter Y on Key`).rows).toHaveLength(6);
  });
  it("leftsemi and leftanti return left columns only", () => {
    const semi = ok(`${X}${Y} X | join kind=leftsemi Y on Key`);
    expect(names(semi)).toEqual(["Key", "Value1"]);
    expect(col(semi, "Value1")).toEqual([2, 3, 4]);
    expect(col(ok(`${X}${Y} X | join kind=leftanti Y on Key`), "Value1")).toEqual([1]);
  });
  it("rightsemi and rightanti return right columns only", () => {
    const semi = ok(`${X}${Y} X | join kind=rightsemi Y on Key`);
    expect(names(semi)).toEqual(["Key", "Value2"]);
    expect(col(semi, "Value2")).toEqual([10, 20, 30]);
    expect(col(ok(`${X}${Y} X | join kind=rightanti Y on Key`), "Value2")).toEqual([40]);
  });
  it("joins on $left.A == $right.B, in either order, keeping both columns", () => {
    const q = `let L = datatable(A:string, V:long)["x",1]; let R = datatable(B:string, W:long)["x",2];`;
    expect(ok(`${q} L | join (R) on $left.A == $right.B`).rows).toEqual([{ A: "x", V: 1, B: "x", W: 2 }]);
    expect(ok(`${q} L | join (R) on $right.B == $left.A`).rows).toEqual([{ A: "x", V: 1, B: "x", W: 2 }]);
  });
  it("joins on several keys with a comma or and", () => {
    const q = `let L = datatable(A:string, B:long)["x",1,"x",2]; let R = datatable(A:string, B:long, W:long)["x",2,9];`;
    expect(col(ok(`${q} L | join kind=inner R on A, B`), "W")).toEqual([9]);
    expect(col(ok(`${q} L | join kind=inner R on $left.A == $right.A and $left.B == $right.B`), "W")).toEqual([9]);
  });
  it("accepts a parenthesized subquery and hints", () => {
    const r = ok(`SigninLogs | where ResultType == "50053" | join kind=inner hint.strategy=broadcast (SigninLogs | where ResultType == "0") on UserPrincipalName`);
    expect(r.rows).toHaveLength(1);
    expect(names(r)).toContain("ResultType1");
  });
  it("never matches null keys, while empty strings do match", () => {
    const n = `let L = datatable(K:long, V:long)[long(null),1]; let R = datatable(K:long, W:long)[long(null),2];`;
    expect(ok(`${n} L | join kind=inner R on K`).rows).toHaveLength(0);
    expect(ok(`${n} L | join kind=leftouter R on K`).rows).toEqual([{ K: null, V: 1, K1: null, W: null }]);
    expect(ok(`${n} L | join kind=leftanti R on K`).rows).toHaveLength(1);
    const s = `let L = datatable(K:string)[""]; let R = datatable(K:string)[""];`;
    expect(ok(`${s} L | join kind=inner R on K`).rows).toHaveLength(1);
  });
  it("correlates alerts with sign-ins", () => {
    const r = ok(`SecurityAlert | where AlertName == "Password spray" | extend UserPrincipalName = CompromisedEntity
      | join kind=inner (SigninLogs | where ResultType == "0") on UserPrincipalName | project AlertName, IPAddress`);
    expect(r.rows).toHaveLength(2);
    expect(r.rows[0].IPAddress).toBe("198.51.100.7");
  });
});

describe("union", () => {
  const A = `let A = datatable(x:long, s:string)[1,"a"]; let B = datatable(x:string, t:long)["b",2];`;
  it("defaults to outer, suffixing columns whose types differ", () => {
    const r = ok(`${A} union A, B`);
    expect(names(r)).toEqual(["x_long", "x_string", "s", "t"]);
    expect(r.rows[0]).toEqual({ x_long: 1, x_string: "", s: "a", t: null });
    expect(r.rows[1]).toEqual({ x_long: null, x_string: "b", s: "", t: 2 });
  });
  it("withsource adds the source table first", () => {
    const r = ok(`union withsource=Src SecurityAlert, AuditLogs | summarize count() by Src`);
    expect(r.rows).toEqual([{ Src: "SecurityAlert", count_: 3 }, { Src: "AuditLogs", count_: 3 }]);
  });
  it("kind=inner keeps the columns every table shares", () => {
    expect(names(ok(`union kind=inner SecurityAlert, AuditLogs`))).toEqual(["TimeGenerated"]);
  });
  it("expands wildcards", () => {
    const r = ok(`union withsource=T Device*, Sign* | distinct T`);
    expect(col(r, "T").sort()).toEqual(["DeviceProcessEvents", "SigninLogs"]);
  });
  it("works as a pipe operator with subqueries", () => {
    expect(ok(`SecurityAlert | union (AuditLogs | take 1) | count`).rows[0].Count).toBe(4);
  });
  it("isfuzzy=true downgrades a missing table to a warning", () => {
    const r = ok(`union isfuzzy=true SecurityAlert, NoSuchTable | count`);
    expect(r.rows[0].Count).toBe(3);
    expect(r.warnings).toContain("Failed to resolve entity 'NoSuchTable'");
  });
  it("isfuzzy=true still fails when nothing resolves, and without it a missing table fails", () => {
    expect(fail(`union isfuzzy=true Nope*, NoSuchTable`).message).toContain("Failed to resolve");
    expect(fail(`union SecurityAlert, NoSuchTable`).message).toContain("'NoSuchTable'");
  });
  it("includes tabular lets by name and in wildcards", () => {
    expect(ok(`let Mine = SecurityAlert | take 1; union Mine, AuditLogs | count`).rows[0].Count).toBe(4);
  });
});

describe("mv-expand", () => {
  it("expands an array, keeping the other columns", () => {
    const r = ok(`datatable(a:long, b:dynamic)[1, dynamic([10,20]), 2, dynamic(["x"])] | mv-expand b`);
    expect(r.rows).toEqual([{ a: 1, b: 10 }, { a: 1, b: 20 }, { a: 2, b: "x" }]);
    expect(r.columns[1].type).toBe("dynamic");
  });
  it("expands a bag into one-key bags, or pairs with kind=array", () => {
    const t = `datatable(b:dynamic)[dynamic({"p":"a","q":"b"})]`;
    expect(col(ok(`${t} | mv-expand b`), "b")).toEqual([{ p: "a" }, { q: "b" }]);
    expect(col(ok(`${t} | mv-expand kind=array b`), "b")).toEqual([["p", "a"], ["q", "b"]]);
  });
  it("zips several columns and pads with nulls", () => {
    const r = ok(`datatable(a:long, b:dynamic, c:dynamic)[1, dynamic({"p":"a","q":"b"}), dynamic([5,4,3])] | mv-expand b, c`);
    expect(r.rows).toEqual([{ a: 1, b: { p: "a" }, c: 5 }, { a: 1, b: { q: "b" }, c: 4 }, { a: 1, b: null, c: 3 }]);
  });
  it("a null value yields one row, an empty array yields none", () => {
    const r = ok(`datatable(a:long, b:dynamic)[1, dynamic(null), 2, dynamic([])] | mv-expand b`);
    expect(r.rows).toEqual([{ a: 1, b: null }]);
  });
  it("supports to typeof, with_itemindex, a new name, and limit", () => {
    const r = ok(`datatable(b:dynamic)[dynamic([1,2,3])] | mv-expand with_itemindex=I v = b to typeof(long) limit 2`);
    expect(r.rows.map((x) => [x.v, x.I])).toEqual([[1, 0], [2, 1]]);
    expect(r.columns.find((c) => c.name === "v")?.type).toBe("long");
  });
  it("expands AuditLogs targets", () => {
    const r = ok(`AuditLogs | mv-expand TargetResources | extend Target = tostring(TargetResources.displayName) | project Target`);
    expect(col(r, "Target")).toEqual(["Global Administrator", "backup-admin", "carol"]);
  });
});

describe("parse", () => {
  it("extracts columns between literals", () => {
    const r = ok(`datatable(m:string)["user=alice ip=198.51.100.7 port=443 end"] | parse m with * "user=" User " ip=" Ip " port=" Port:long " end" *`);
    expect(r.rows[0]).toMatchObject({ User: "alice", Ip: "198.51.100.7", Port: 443 });
    expect(r.columns.find((c) => c.name === "Port")?.type).toBe("long");
  });
  it("a final column takes the rest of the string", () => {
    expect(ok(`print m = "key=value here" | parse m with "key=" V`).rows[0].V).toBe("value here");
  });
  it("a failed match keeps the row with empty columns", () => {
    const r = ok(`datatable(m:string)["nothing here"] | parse m with "user=" User:string " id=" Id:long`);
    expect(r.rows).toEqual([{ m: "nothing here", User: "", Id: null }]);
  });
  it("kind=simple is strict about types: a bad value empties every column", () => {
    const r = ok(`datatable(m:string)["a=x b=notnum;"] | parse m with "a=" A " b=" B:long ";"`);
    expect(r.rows[0]).toMatchObject({ A: "", B: null });
  });
  it("kind=relaxed keeps what parsed", () => {
    const r = ok(`datatable(m:string)["a=x b=notnum;"] | parse kind=relaxed m with "a=" A " b=" B:long ";"`);
    expect(r.rows[0]).toMatchObject({ A: "x", B: null });
  });
  it("kind=regex treats literals as patterns", () => {
    const r = ok(`print m = "id: 42 end" | parse kind=regex m with @"id:\\s+" N:long`);
    expect(r.rows[0].N).toBe(42);
  });
  it("parse-where drops rows that do not match", () => {
    expect(ok(`datatable(m:string)["a=1","x"] | parse-where m with "a=" A:long`).rows).toEqual([{ m: "a=1", A: 1 }]);
  });
  it("converts non-string input to string first", () => {
    expect(ok(`print m = 12345 | parse m with "12" Rest`).rows[0].Rest).toBe("345");
  });
  it("rejects * after a string column", () => {
    expect(fail(`print m = "a" | parse m with "a" V *`).message).toBe("Using * after parsing a string column is ambiguous.");
  });
  it("handles the documented trace line", () => {
    const line = "Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=23, lockTime=02/17/2016 08:40:01, releaseTime=02/17/2016 08:40:01, previousLockTime=02/17/2016 08:39:01)";
    const r = ok(`print EventText = "${line}"
      | parse EventText with * "resourceName=" resourceName ", totalSlices=" totalSlices: long * "sliceNumber=" sliceNumber: long * "lockTime=" lockTime ", releaseTime=" releaseTime: date "," * "previousLockTime=" previousLockTime: date ")" *
      | project resourceName, totalSlices, sliceNumber, lockTime, releaseTime, previousLockTime`);
    expect(r.rows[0]).toMatchObject({ resourceName: "PipelineScheduler", totalSlices: 27, sliceNumber: 23, lockTime: "02/17/2016 08:40:01" });
    expect(r.rows[0].releaseTime).toEqual(new Date("2016-02-17T08:40:01Z"));
  });
});

describe("search", () => {
  it("a bare term searches every table with has and adds $table", () => {
    const r = ok(`search "whoami"`);
    expect(names(r)[0]).toBe("$table");
    expect(r.rows).toHaveLength(1);
    expect(r.rows[0].$table).toBe("DeviceProcessEvents");
  });
  it("is a term search, not a substring search", () => {
    expect(ok(`search "whoa"`).rows).toHaveLength(0);
  });
  it("restricts to tables with in (...)", () => {
    expect(ok(`search in (SecurityAlert, Audit*) "nexacorp"`).rows.map((r) => r.$table).sort()).toEqual(["AuditLogs", "AuditLogs", "SecurityAlert"]);
  });
  it("only keeps columns of tables that matched", () => {
    expect(names(ok(`search in (SecurityAlert, AuditLogs) "Password"`))).toEqual(["$table", "TimeGenerated", "AlertName", "AlertSeverity", "CompromisedEntity", "Entities", "Tactics", "SystemAlertId", "ProductName"]);
  });
  it("maps wildcards to prefix, suffix, contains and regex", () => {
    expect(ok(`search in (DeviceProcessEvents) "whoa*"`).rows).toHaveLength(1);
    expect(ok(`search in (DeviceProcessEvents) "*oami"`).rows).toHaveLength(1);
    expect(ok(`search in (DeviceProcessEvents) "*hoam*"`).rows).toHaveLength(1);
    expect(ok(`search in (DeviceProcessEvents) "who*mi"`).rows).toHaveLength(1);
    expect(ok(`search in (DeviceProcessEvents) "*hoam"`).rows).toHaveLength(0);
  });
  it("is case-insensitive unless asked, and supports col:term and boolean logic", () => {
    expect(ok(`search in (SecurityAlert) "password"`).rows).toHaveLength(1);
    expect(ok(`search kind=case_sensitive in (SecurityAlert) "password"`).rows).toHaveLength(0);
    expect(ok(`search in (SecurityAlert) AlertName:"spray"`).rows).toHaveLength(1);
    expect(ok(`search in (SecurityAlert) Tactics:"spray"`).rows).toHaveLength(0);
    expect(ok(`search in (SecurityAlert) "Suspicious" and "Low"`).rows).toHaveLength(1);
    expect(ok(`search in (SecurityAlert) "spray" or ("Low" and AlertName == "Suspicious PowerShell")`).rows).toHaveLength(2);
    expect(ok(`search in (SecurityAlert) *`).rows).toHaveLength(3);
  });
  it("works in a pipeline", () => {
    expect(ok(`SecurityAlert | search "Low"`).rows[0].$table).toBe("SecurityAlert");
  });
});

describe("getschema and render", () => {
  it("getschema reports Kusto type names", () => {
    const r = ok(`SigninLogs | project TimeGenerated, DurationMs, LocationDetails | extend b = true, r = 1.5, s = "x", i = toint(1), ts = 1h | getschema`);
    expect(names(r)).toEqual(["ColumnName", "ColumnOrdinal", "DataType", "ColumnType"]);
    expect(r.rows[0]).toEqual({ ColumnName: "TimeGenerated", ColumnOrdinal: 0, DataType: "System.DateTime", ColumnType: "datetime" });
    expect(col(r, "DataType")).toEqual(["System.DateTime", "System.Int64", "System.Object", "System.SByte", "System.Double", "System.String", "System.Int32", "System.TimeSpan"]);
  });
  it.each(["timechart", "barchart", "columnchart", "piechart", "linechart", "areachart", "table"])("render %s sets the chart and keeps the rows", (kind) => {
    const r = ok(`SigninLogs | summarize count() by Location | render ${kind}`);
    expect(r.chart).toEqual({ kind });
    expect(r.rows).toHaveLength(1);
  });
  it("render accepts a with clause", () => {
    expect(ok(`SigninLogs | count | render barchart with (title="x")`).chart).toEqual({ kind: "barchart" });
  });
  it("no render means no chart", () => {
    expect(ok(`SigninLogs | count`).chart).toBeUndefined();
  });
});

describe("let, print, datatable, range", () => {
  it("binds scalars, including computed ones and timespans", () => {
    expect(col(ok(`let n = 2; let m = n * 3; datatable(v:long)[1,6] | where v == m`), "v")).toEqual([6]);
    expect(ok(`let w = 15m; SigninLogs | where TimeGenerated > ago(w) | count`).rows[0].Count).toBe(8);
  });
  it("binds tabular values, shadowing a table of the same name", () => {
    expect(ok(`let SigninLogs = SigninLogs | where ResultType == "0"; SigninLogs | count`).rows[0].Count).toBe(3);
  });
  it("binds a dynamic list used with in", () => {
    expect(ok(`let bad = dynamic(["203.0.113.50"]); SigninLogs | where IPAddress in (bad) | count`).rows[0].Count).toBe(8);
  });
  it("toscalar reads a value from a table", () => {
    expect(ok(`let top = toscalar(SigninLogs | summarize max(DurationMs)); SigninLogs | where DurationMs == top | count`).rows[0].Count).toBe(1);
  });
  it("materialize is transparent", () => {
    expect(ok(`let m = materialize(SigninLogs | take 2); m | count`).rows[0].Count).toBe(2);
  });
  it("accepts comments and blank statements", () => {
    const r = ok(`// header comment
      let a = 1; // trailing
      ;
      print x = a // done`);
    expect(r.rows).toEqual([{ x: 1 }]);
  });
  it("names print columns print_0, print_1", () => {
    expect(names(ok(`print 1 + 1, strcat("a", "b")`))).toEqual(["print_0", "print_1"]);
  });
  it("range produces a sequence, datetime included", () => {
    expect(col(ok(`range x from 1 to 3 step 1`), "x")).toEqual([1, 2, 3]);
    expect(ok(`range t from datetime(2026-01-01) to datetime(2026-01-02) step 12h | count`).rows[0].Count).toBe(3);
  });
  it("shows the last result of several tabular statements, with a warning", () => {
    const r = ok(`SigninLogs | take 1; SecurityAlert | take 2`);
    expect(r.rows).toHaveLength(2);
    expect(r.warnings.join(" ")).toContain("several tabular statements");
  });
});

describe("result shape", () => {
  it("returns plain JS values, and tagged timespans", () => {
    const r = ok(`AuditLogs | take 1 | project TimeGenerated, Age = now() - TimeGenerated, InitiatedBy, n = 1, b = true, s = "x"`);
    const row = r.rows[0];
    expect(row.TimeGenerated).toBeInstanceOf(Date);
    expect(row.Age).toBeInstanceOf(KqlTimespan);
    expect((row.Age as KqlTimespan).kqlType).toBe("timespan");
    expect(String(row.Age)).toBe("00:03:00");
    expect(typeof row.InitiatedBy).toBe("object");
    expect(row.n).toBe(1);
    expect(row.b).toBe(true);
    expect(cell(`print datetime(2026-01-01)`)).toEqual(new Date("2026-01-01T00:00:00Z"));
  });
  it("cuts rows above maxRows and sets truncated", () => {
    const r = ok(`SigninLogs`, fixtureEnv({ maxRows: 5 }));
    expect(r.rows).toHaveLength(5);
    expect(r.truncated).toBe(true);
    const whole = ok(`SigninLogs`, fixtureEnv({ maxRows: 12 }));
    expect(whole.truncated).toBe(false);
  });
  it("defaults maxRows to 30000", () => {
    const r = ok(`range x from 1 to 30001 step 1`);
    expect(r.rows).toHaveLength(30000);
    expect(r.truncated).toBe(true);
  });
  it("uses env.now, never the wall clock", () => {
    expect(cell(`print now()`)).toEqual(NOW);
    expect(cell(`print ago(1h)`)).toEqual(new Date(NOW.getTime() - 3_600_000));
  });
  it("does not mutate the input tables", () => {
    const env = fixtureEnv();
    const before = JSON.stringify(env.tables);
    ok(`SigninLogs | extend Location = "ZZ" | project-away IPAddress | sort by DurationMs asc`, env);
    expect(JSON.stringify(env.tables)).toBe(before);
  });
  it("normalizes loose inputs: ISO strings, null strings, missing cells", () => {
    const env = fixtureEnv({
      tables: {
        T: {
          name: "T",
          columns: [{ name: "t", type: "datetime" }, { name: "s", type: "string" }, { name: "n", type: "long" }, { name: "d", type: "timespan" }],
          rows: [{ t: "2026-01-01T00:00:00Z", s: null, d: "00:05:00" }],
        },
      },
    });
    const r = ok(`T | extend isEmpty = isempty(s), isNullS = isnull(s), isNullN = isnull(n)`, env);
    expect(r.rows[0]).toMatchObject({ t: new Date("2026-01-01T00:00:00Z"), s: "", n: null, isEmpty: true, isNullS: false, isNullN: true });
    expect(String(r.rows[0].d)).toBe("00:05:00");
  });
});
