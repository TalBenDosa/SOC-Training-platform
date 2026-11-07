import { describe, expect, it } from "vitest";
import { KqlTimespan, formatKqlValue } from "./index";
import { NOW, col, fail, ok, scalar as v } from "./test-fixture";

const ts = (x: unknown) => String(x as KqlTimespan);

describe("has versus contains", () => {
  it("has matches whole terms, contains matches substrings", () => {
    expect(v(`"KustoExplorerQueryRun" has "Explorer"`)).toBe(false);
    expect(v(`"KustoExplorerQueryRun" contains "Explorer"`)).toBe(true);
    expect(v(`"North America" has "america"`)).toBe(true);
    expect(v(`"North America" has "amer"`)).toBe(false);
  });
  it("breaks terms on every non-alphanumeric character, underscore included", () => {
    expect(v(`"ad67d136-c1db-4f9f" has "c1db"`)).toBe(true);
    expect(v(`"svc_backup" has "backup"`)).toBe(true);
    expect(v(`"powershell.exe -enc AAA" has "exe"`)).toBe(true);
  });
  it("matches short terms too, by scanning", () => {
    expect(v(`"a b c" has "b"`)).toBe(true);
    expect(v(`"abc" has "b"`)).toBe(false);
  });
  it("accepts a needle with non-alphanumeric edges", () => {
    expect(v(`"powershell -enc AAA" has "-enc"`)).toBe(true);
    expect(v(`"powershell -encoded AAA" has "-enc"`)).toBe(false);
    expect(v(`"x-enc" has "-enc"`)).toBe(true);
  });
  it("handles a term repeated later in the string", () => {
    expect(v(`"encoded enc" has "enc"`)).toBe(true);
  });
  it("is case-insensitive unless _cs", () => {
    expect(v(`"North America" has "NORTH"`)).toBe(true);
    expect(v(`"North America" has_cs "NORTH"`)).toBe(false);
    expect(v(`"North America" has_cs "North"`)).toBe(true);
    expect(v(`"North America" !has_cs "north"`)).toBe(true);
    expect(v(`"North America" !has "north"`)).toBe(false);
  });
  it("works on rows", () => {
    expect(ok(`DeviceProcessEvents | where ProcessCommandLine has "enc"`).rows).toHaveLength(1);
    expect(ok(`DeviceProcessEvents | where ProcessCommandLine has "-enc"`).rows).toHaveLength(1);
    expect(ok(`DeviceProcessEvents | where ProcessCommandLine contains "enc"`).rows).toHaveLength(2);
    expect(ok(`DeviceProcessEvents | where ProcessCommandLine !contains "enc"`).rows).toHaveLength(2);
  });
});

describe("string operators", () => {
  it.each([
    [`"aBc" == "aBc"`, true], [`"abc" == "ABC"`, false], [`"abc" != "ABC"`, true],
    [`"abc" =~ "ABC"`, true], [`"aBc" !~ "xyz"`, true], [`"abc" !~ "ABC"`, false],
    [`"FabriKam" contains "BRik"`, true], [`"Fabrikam" !contains "xyz"`, true],
    [`"FabriKam" contains_cs "Kam"`, true], [`"Fabrikam" contains_cs "Kam"`, false], [`"Fabrikam" !contains_cs "Kam"`, true],
    [`"Fabrikam" startswith "fab"`, true], [`"Fabrikam" !startswith "kam"`, true], [`"Fabrikam" startswith_cs "fab"`, false], [`"Fabrikam" !startswith_cs "fab"`, true],
    [`"Fabrikam" endswith "Kam"`, true], [`"Fabrikam" !endswith "brik"`, true], [`"Fabrikam" endswith_cs "Kam"`, false], [`"Fabrikam" !endswith_cs "brik"`, true],
    [`"North America" hasprefix "ame"`, true], [`"North America" !hasprefix "mer"`, true], [`"North America" hasprefix_cs "Ame"`, true], [`"North America" !hasprefix_cs "CA"`, true],
    [`"North America" hassuffix "ica"`, true], [`"North America" !hassuffix "americ"`, true], [`"North America" hassuffix_cs "ica"`, true], [`"North America" !hassuffix_cs "icA"`, true],
    [`"Fabrikam" matches regex "b.*k"`, true], [`"Fabrikam" matches regex "^k"`, false],
    [`"abc" in ("123", "345", "abc")`, true], [`"bca" !in ("123", "345", "abc")`, true], [`"Abc" in ("abc")`, false],
    [`"Abc" in~ ("123", "345", "abc")`, true], [`"bCa" !in~ ("123", "345", "ABC")`, true], [`"ABC" !in~ ("abc")`, false],
    [`"North America" has_any ("south", "north")`, true], [`"North America" has_any ("south", "east")`, false],
    [`"North and South America" has_all ("south", "north")`, true], [`"North America" has_all ("south", "north")`, false],
  ])("%s is %s", (expr, want) => {
    expect(v(expr)).toBe(want);
  });
  it("has_any takes a dynamic list and a tabular list", () => {
    expect(ok(`let terms = dynamic(["whoami", "nothing"]); DeviceProcessEvents | where ProcessCommandLine has_any (terms)`).rows).toHaveLength(1);
    expect(ok(`let names = datatable(n:string)["whoami"]; DeviceProcessEvents | where ProcessCommandLine has_any (names)`).rows).toHaveLength(1);
  });
  it("in takes a dynamic array, a tabular let and a subquery", () => {
    expect(v(`2 in (dynamic([1, 2, 3]))`)).toBe(true);
    expect(ok(`SigninLogs | where IPAddress in ((SigninLogs | where ResultType == "50053" | project IPAddress)) | count`).rows[0].Count).toBe(2);
  });
  it("runs on dynamic values, which are compared by content", () => {
    expect(ok(`SigninLogs | where DeviceDetail.browser has "edge" | count`).rows[0].Count).toBe(12);
    expect(ok(`SigninLogs | where LocationDetails.city == "Redmond" | count`).rows[0].Count).toBe(11);
  });
  it("adjacent string literals concatenate", () => {
    expect(v(`"ab" "cd"`)).toBe("abcd");
  });
});

describe("between", () => {
  it("is inclusive on both ends", () => {
    expect(v(`5 between (5 .. 10)`)).toBe(true);
    expect(v(`10 between (5 .. 10)`)).toBe(true);
    expect(v(`11 between (5 .. 10)`)).toBe(false);
    expect(v(`11 !between (5 .. 10)`)).toBe(true);
  });
  it("works for datetime with a timespan end, and timespans", () => {
    expect(v(`datetime(2026-01-01 05:00) between (datetime(2026-01-01) .. 6h)`)).toBe(true);
    expect(v(`datetime(2026-01-01 05:00) between (datetime(2026-01-01) .. datetime(2026-01-02))`)).toBe(true);
    expect(v(`5m between (1m .. 10m)`)).toBe(true);
  });
  it("is null when a side is null", () => {
    expect(v(`int(null) between (1 .. 2)`)).toBeNull();
  });
});

describe("null rules", () => {
  it("equality: null to null is null, null to a value is false", () => {
    expect(v(`int(null) == int(null)`)).toBeNull();
    expect(v(`int(null) == 5`)).toBe(false);
  });
  it("inequality: null to null is null, null to a value is true", () => {
    expect(v(`int(null) != int(null)`)).toBeNull();
    expect(v(`int(null) != 5`)).toBe(true);
  });
  it("comparison and arithmetic are sticky", () => {
    expect(v(`int(null) > 3`)).toBeNull();
    expect(v(`int(null) + 10`)).toBeNull();
    expect(v(`10 * int(null)`)).toBeNull();
  });
  it("and / or short-circuit around null", () => {
    expect(v(`bool(null) and false`)).toBe(false);
    expect(v(`bool(null) and true`)).toBeNull();
    expect(v(`bool(null) or true`)).toBe(true);
    expect(v(`bool(null) or false`)).toBeNull();
    expect(v(`not(bool(null))`)).toBeNull();
    expect(v(`not(true)`)).toBe(false);
  });
  it("where drops a null predicate", () => {
    const t = `datatable(val:int)[5, int(null)]`;
    expect(ok(`${t} | where val > 3`).rows).toEqual([{ val: 5 }]);
    expect(ok(`${t} | where val > 3 or isnull(val)`).rows).toHaveLength(2);
  });
  it("!= keeps a null value, the documented example", () => {
    const r = ok(`datatable(ival:int, sval:string)[5, "a", int(null), "b"] | where ival != 5`);
    expect(r.rows).toEqual([{ ival: null, sval: "b" }]);
  });
  it("in behaves like OR of equalities, !in like AND of inequalities", () => {
    expect(v(`int(null) in (1, 2)`)).toBe(false);
    expect(v(`int(null) !in (1, 2)`)).toBe(true);
    expect(v(`int(null) in (1, int(null))`)).toBeNull();
    expect(v(`int(null) !in (1, int(null))`)).toBeNull();
    expect(v(`3 in (1, int(null))`)).toBe(false);
  });
  it("strings are never null: a missing string is empty", () => {
    expect(v(`isnull("")`)).toBe(false);
    expect(v(`isempty("")`)).toBe(true);
    expect(v(`isnotempty("x")`)).toBe(true);
    expect(v(`tostring(int(null))`)).toBe("");
    expect(v(`string(null)`)).toBe("");
    expect(v(`strlen(tostring(int(null)))`)).toBe(0);
  });
  it("isnull and isempty on numbers and dynamic", () => {
    expect(v(`isnull(int(null))`)).toBe(true);
    expect(v(`isnotnull(int(1))`)).toBe(true);
    expect(v(`isempty(int(null))`)).toBe(true);
    expect(v(`isnull(dynamic(null))`)).toBe(true);
    expect(v(`isnull(dynamic({}))`)).toBe(false);
    expect(v(`isnull(dynamic({"a":1}).b)`)).toBe(true);
  });
  it("a null dynamic path stays null without failing", () => {
    expect(ok(`SigninLogs | where isnull(LocationDetails) | extend c = tostring(LocationDetails.city) | project c`).rows).toEqual([{ c: "" }]);
  });
  it("iff treats a null condition as false", () => {
    expect(v(`iff(bool(null), "yes", "no")`)).toBe("no");
  });
  it("coalesce skips nulls and empty strings", () => {
    expect(v(`coalesce(int(null), int(null), 3)`)).toBe(3);
    expect(v(`coalesce("", "x")`)).toBe("x");
    expect(v(`coalesce(int(null), int(null))`)).toBeNull();
  });
  it("min_of and max_of prefer non-null", () => {
    expect(v(`min_of(int(null), 3)`)).toBe(3);
    expect(v(`max_of(1, 5, 2)`)).toBe(5);
    expect(v(`min_of(int(null), int(null))`)).toBeNull();
  });
});

describe("arithmetic", () => {
  it("integer division truncates and real division does not", () => {
    expect(v(`1 / 2`)).toBe(0);
    expect(v(`1.0 / 2`)).toBe(0.5);
    expect(v(`1 / 2.0`)).toBe(0.5);
    expect(v(`real(1) / 2`)).toBe(0.5);
    expect(v(`-7 / 2`)).toBe(-3);
  });
  it("modulo is non-negative, as documented", () => {
    expect(v(`14 % 12`)).toBe(2);
    expect(v(`-14 % 12`)).toBe(10);
    expect(v(`14 % -12`)).toBe(2);
    expect(v(`-14 % -12`)).toBe(10);
  });
  it("keeps precedence and parentheses", () => {
    expect(v(`2 + 3 * 4`)).toBe(14);
    expect(v(`(2 + 3) * 4`)).toBe(20);
    expect(v(`-2 * 3`)).toBe(-6);
  });
  it("integer division by zero is null, real division by zero is infinite", () => {
    expect(v(`1 / 0`)).toBeNull();
    expect(v(`1.0 / 0`)).toBe(Infinity);
  });
  it("types: int with int is long, anything with real is real", () => {
    const r = ok(`print a = toint(1) + toint(2), b = 1 + 2.0, c = 1 / 2`);
    expect(r.columns.map((c) => c.type)).toEqual(["long", "real", "long"]);
  });
  it("reads numbers from dynamic", () => {
    expect(v(`dynamic({"a":4}).a + 1`)).toBe(5);
    expect(v(`dynamic({"a":4}).a > 3`)).toBe(true);
  });
});

describe("datetime and timespan arithmetic", () => {
  it("datetime minus datetime is a timespan", () => {
    const r = ok(`print d = datetime(2026-01-02) - datetime(2026-01-01)`);
    expect(r.columns[0].type).toBe("timespan");
    expect(ts(r.rows[0].d)).toBe("1.00:00:00");
  });
  it("datetime plus or minus timespan is a datetime", () => {
    expect(v(`datetime(2026-01-01) + 1d`)).toEqual(new Date("2026-01-02T00:00:00Z"));
    expect(v(`datetime(2026-01-01) - 1h`)).toEqual(new Date("2025-12-31T23:00:00Z"));
    expect(v(`1d + datetime(2026-01-01)`)).toEqual(new Date("2026-01-02T00:00:00Z"));
  });
  it("timespan arithmetic", () => {
    expect(ts(v(`1h + 30m`))).toBe("01:30:00");
    expect(ts(v(`1h - 30m`))).toBe("00:30:00");
    expect(ts(v(`2 * 5m`))).toBe("00:10:00");
    expect(ts(v(`1h * 2`))).toBe("02:00:00");
    expect(ts(v(`1h / 2`))).toBe("00:30:00");
    expect(v(`1h / 1m`)).toBe(60);
    expect(ts(v(`-5m`))).toBe("-00:05:00");
  });
  it("compares datetimes and timespans", () => {
    expect(v(`now() > ago(1d)`)).toBe(true);
    expect(v(`10m > 1s`)).toBe(true);
    expect(v(`datetime(2026-01-01) == datetime(2026-01-01)`)).toBe(true);
  });
});

describe("literals", () => {
  it("string forms and escapes", () => {
    expect(v(`"a\\tb"`)).toBe("a\tb");
    expect(v(`'it\\'s'`)).toBe("it's");
    expect(v(`@"C:\\Temp\\new"`)).toBe("C:\\Temp\\new");
    expect(v(`@'say ''hi'''`)).toBe("say 'hi'");
    expect(v(`h"secret"`)).toBe("secret");
  });
  it("datetime forms", () => {
    const want = new Date("2026-11-07T10:00:00Z");
    expect(v(`datetime(2026-11-07 10:00:00)`)).toEqual(want);
    expect(v(`datetime(2026-11-07T10:00:00Z)`)).toEqual(want);
    expect(v(`datetime(2026-11-07T10:00:00.000Z)`)).toEqual(want);
    expect(v(`datetime('2026-11-07 10:00')`)).toEqual(want);
    expect(v(`datetime(2026-11-07)`)).toEqual(new Date("2026-11-07T00:00:00Z"));
    expect(v(`datetime(null)`)).toBeNull();
  });
  it("timespan forms", () => {
    expect(ts(v(`5m`))).toBe("00:05:00");
    expect(ts(v(`1h`))).toBe("01:00:00");
    expect(ts(v(`2d`))).toBe("2.00:00:00");
    expect(ts(v(`30s`))).toBe("00:00:30");
    expect(ts(v(`100ms`))).toBe("00:00:00.1000000");
    expect(ts(v(`1.5h`))).toBe("01:30:00");
    expect(ts(v(`timespan(00:05:00)`))).toBe("00:05:00");
    expect(ts(v(`timespan(1.02:03:04)`))).toBe("1.02:03:04");
    expect(ts(v(`timespan(5m)`))).toBe("00:05:00");
    expect(ts(v(`time(2)`))).toBe("2.00:00:00");
    expect(v(`timespan(null)`)).toBeNull();
  });
  it("typed literals", () => {
    const r = ok(`print a = int(5), b = long(6), c = real(1.5), d = bool(true), e = guid(aabbccdd-0011-2233-4455-66778899aabb), f = double(2), g = true, h = false, i = 1e3, j = 0x10`);
    expect(r.columns.map((c) => c.type)).toEqual(["int", "long", "real", "bool", "guid", "real", "bool", "bool", "real", "long"]);
    expect(r.rows[0]).toMatchObject({ a: 5, b: 6, c: 1.5, d: true, e: "aabbccdd-0011-2233-4455-66778899aabb", g: true, h: false, i: 1000, j: 16 });
  });
  it("real infinity and NaN", () => {
    expect(v(`real(+inf)`)).toBe(Infinity);
    expect(v(`real(-inf)`)).toBe(-Infinity);
    expect(v(`real(nan)`)).toBeNaN();
  });
  it("dynamic literals", () => {
    expect(v(`dynamic([1, "two", {"three": 3}, null, true])`)).toEqual([1, "two", { three: 3 }, null, true]);
    expect(v(`dynamic({"a": {"b": [1]}})`)).toEqual({ a: { b: [1] } });
    expect(v(`dynamic(null)`)).toBeNull();
    expect(v(`dynamic(['single'])`)).toEqual(["single"]);
  });
  it("bracketed column names", () => {
    const r = ok(`print ['my col'] = 1 | extend b = ['my col'] + 1`);
    expect(r.rows[0]).toEqual({ "my col": 1, b: 2 });
  });
});

describe("dynamic access", () => {
  const d = `dynamic({"a": {"b": [10, 20]}, "x y": 1})`;
  it("reads paths, keys and indexes", () => {
    expect(v(`${d}.a.b`)).toEqual([10, 20]);
    expect(v(`${d}["a"]["b"][1]`)).toBe(20);
    expect(v(`${d}["x y"]`)).toBe(1);
    expect(v(`${d}.a.b[-1]`)).toBe(20);
    expect(v(`${d}.a["b"][0]`)).toBe(10);
  });
  it("a missing key or out-of-range index is null", () => {
    expect(v(`${d}.nope`)).toBeNull();
    expect(v(`${d}.a.b[9]`)).toBeNull();
    expect(v(`${d}.a.b.c`)).toBeNull();
  });
  it("never reaches the object prototype", () => {
    expect(v(`${d}.constructor`)).toBeNull();
    expect(v(`${d}["__proto__"]`)).toBeNull();
    expect(v(`${d}.toString`)).toBeNull();
  });
  it("allows keywords as property names", () => {
    expect(v(`dynamic({"where": 1, "by": 2}).where`)).toBe(1);
    expect(v(`dynamic({"where": 1, "by": 2}).by`)).toBe(2);
  });
  it("works on parse_json of a string column", () => {
    const r = ok(`SecurityAlert | extend E = parse_json(Entities) | extend T = tostring(E[0].Type) | project T`);
    expect(col(r, "T")).toEqual(["ip", "host", ""]);
  });
});

describe("conversion functions", () => {
  it("tostring prints each type", () => {
    expect(v(`tostring(1)`)).toBe("1");
    expect(v(`tostring(1.5)`)).toBe("1.5");
    expect(v(`tostring(true)`)).toBe("true");
    expect(v(`tostring(5m)`)).toBe("00:05:00");
    expect(v(`tostring(datetime(2026-01-01 10:00:00))`)).toBe("2026-01-01T10:00:00Z");
    expect(v(`tostring(dynamic({"a":1}))`)).toBe('{"a":1}');
    expect(v(`tostring(dynamic("x"))`)).toBe("x");
    expect(v(`tostring(dynamic([1,"a"]))`)).toBe('[1,"a"]');
  });
  it("toint, tolong, toreal, todouble return null on failure and truncate", () => {
    expect(v(`toint("42")`)).toBe(42);
    expect(v(`toint(2.9)`)).toBe(2);
    expect(v(`toint("abc")`)).toBeNull();
    expect(v(`tolong("9")`)).toBe(9);
    expect(v(`tolong("")`)).toBeNull();
    expect(v(`toreal("1.5")`)).toBe(1.5);
    expect(v(`todouble("x")`)).toBeNull();
    expect(v(`tolong(1s)`)).toBe(10000000);
  });
  it("tobool follows the documented examples", () => {
    expect(v(`tobool("true")`)).toBe(true);
    expect(v(`tobool("false")`)).toBe(false);
    expect(v(`tobool(1)`)).toBe(true);
    expect(v(`tobool(123)`)).toBe(true);
    expect(v(`tobool("nope")`)).toBeNull();
  });
  it("todatetime and totimespan", () => {
    expect(v(`todatetime("2026-01-01T10:00:00Z")`)).toEqual(new Date("2026-01-01T10:00:00Z"));
    expect(v(`todatetime("garbage")`)).toBeNull();
    expect(ts(v(`totimespan("00:05:00")`))).toBe("00:05:00");
    expect(v(`totimespan("x")`)).toBeNull();
  });
  it("todynamic and parse_json parse JSON and keep a bad string as a string", () => {
    expect(v(`parse_json('{"a":1}')`)).toEqual({ a: 1 });
    expect(v(`todynamic('[1,2]')`)).toEqual([1, 2]);
    expect(v(`parse_json("not json")`)).toBe("not json");
    expect(v(`parse_json(dynamic({"a":1}))`)).toEqual({ a: 1 });
  });
});

describe("string functions", () => {
  it("tolower, toupper, strlen, reverse", () => {
    expect(v(`tolower("AbC")`)).toBe("abc");
    expect(v(`toupper("AbC")`)).toBe("ABC");
    expect(v(`strlen("hello")`)).toBe(5);
    expect(v(`strlen("שלום")`)).toBe(4);
    expect(v(`reverse("abc")`)).toBe("cba");
  });
  it("substring", () => {
    expect(v(`substring("123456", 1)`)).toBe("23456");
    expect(v(`substring("123456", 2, 2)`)).toBe("34");
    expect(v(`substring("ABCD", 0, 2)`)).toBe("AB");
    expect(v(`substring("123456", -2, 2)`)).toBe("56");
    expect(v(`substring("abc", 10)`)).toBe("");
    expect(v(`substring("abc", 1, 100)`)).toBe("bc");
  });
  it("strcat and strcat_delim convert their arguments", () => {
    expect(v(`strcat("a", 1, true)`)).toBe("a1true");
    expect(v(`strcat_delim(":", "a", 1, "c")`)).toBe("a:1:c");
  });
  it("split", () => {
    expect(v(`split("aa_bb", "_")`)).toEqual(["aa", "bb"]);
    expect(v(`split("aaa_bbb_ccc", "_", 1)`)).toEqual(["bbb"]);
    expect(v(`split("", "_")`)).toEqual([""]);
  });
  it("trim, trim_start, trim_end take a regex", () => {
    expect(v(`trim("--", "--abc--")`)).toBe("abc");
    expect(v(`trim(@"[^\\w]+", "  ab cd !")`)).toBe("ab cd");
    expect(v(`trim_start("-", "--a--")`)).toBe("a--");
    expect(v(`trim_end("-", "--a--")`)).toBe("--a");
  });
  it("replace_string and replace_regex", () => {
    expect(v(`replace_string("a.b.c", ".", "-")`)).toBe("a-b-c");
    expect(v(`replace_regex("ip 10.0.0.1 ok", @"(\\d+)\\.(\\d+)", @"\\2:\\1")`)).toBe("ip 0:10.1:0 ok");
    expect(v(`replace_regex("aaa", "a", "b")`)).toBe("bbb");
    expect(v(`replace_regex("abc", "", "-")`)).toBe("-a-b-c-");
  });
  it("extract", () => {
    expect(v(`extract(@"(\\d+)ms", 1, "took 120ms")`)).toBe("120");
    expect(v(`extract(@"(\\d+)ms", 0, "took 120ms")`)).toBe("120ms");
    expect(v(`extract(@"(\\d+)ms", 1, "nothing")`)).toBe("");
    expect(v(`extract(@"(\\d+)", 1, "n=5", typeof(long))`)).toBe(5);
    expect(v(`extract(@"(\\d+)", 1, "none", typeof(long))`)).toBeNull();
  });
  it("extract_all", () => {
    expect(v(`extract_all(@"(\\d+)", "a1 b22 c333")`)).toEqual(["1", "22", "333"]);
    expect(v(`extract_all(@"(\\w)=(\\d)", "a=1 b=2")`)).toEqual([["a", "1"], ["b", "2"]]);
    expect(v(`extract_all(@"(\\w)=(\\d)", dynamic([2]), "a=1 b=2")`)).toEqual(["1", "2"]);
    expect(v(`extract_all(@"(z)", "abc")`)).toBeNull();
  });
  it("indexof follows the documented table", () => {
    expect(v(`indexof("abcdefg", "cde")`)).toBe(2);
    expect(v(`indexof("abcdefg", "cde", 1, 4)`)).toBe(2);
    expect(v(`indexof("abcdefg", "cde", 1, 2)`)).toBe(-1);
    expect(v(`indexof("abcdefg", "cde", 3, 4)`)).toBe(-1);
    expect(v(`indexof("abcdefg", "cde", -5)`)).toBe(2);
    expect(v(`indexof(1234567, 5, 1, 4)`)).toBe(4);
    expect(v(`indexof("abcdefg", "cde", 2, -1)`)).toBe(2);
    expect(v(`indexof("abcdefgabcdefg", "cde", 1, 10, 2)`)).toBe(9);
    expect(v(`indexof("abcdefgabcdefg", "cde", 1, -1, 3)`)).toBe(-1);
  });
  it("countof counts overlapping plain matches and non-overlapping regex matches", () => {
    expect(v(`countof("aaa", "a")`)).toBe(3);
    expect(v(`countof("aaaa", "aa")`)).toBe(3);
    expect(v(`countof("ababa", "ab", "normal")`)).toBe(2);
    expect(v(`countof("ababa", "aba")`)).toBe(2);
    expect(v(`countof("aaaa", "aa", "regex")`)).toBe(2);
  });
  it("base64 and url_decode", () => {
    expect(v(`base64_encode_tostring("Kusto1")`)).toBe("S3VzdG8x");
    expect(v(`base64_decode_tostring("S3VzdG8x")`)).toBe("Kusto1");
    expect(v(`base64_decode_tostring(base64_encode_tostring("שלום"))`)).toBe("שלום");
    expect(v(`url_decode("https%3a%2f%2fwww.example.com%2fhello%20world")`)).toBe("https://www.example.com/hello world");
  });
  it("hashes are hex of UTF-8", () => {
    expect(v(`hash_md5("World")`)).toBe("f5a7924e621e84c9280a9a27e1bcb7f6");
    expect(v(`hash_md5("")`)).toBe("d41d8cd98f00b204e9800998ecf8427e");
    expect(v(`hash_sha256("World")`)).toBe("78ae647dc5544d227130a0682a51e30bc7777fbb6d8a8f17007463a3ecd1d524");
    expect(v(`hash_sha256("")`)).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(v(`hash_md5(strrep("a", 1000))`)).toBe("cabe45dcc9ae5b66ba86600cca6b8ba8");
  });
});

describe("network functions", () => {
  it("parse_url", () => {
    expect(v(`parse_url("scheme://username:password@host:1234/this/is/a/path?k1=v1&k2=v2#fragment")`)).toEqual({
      Scheme: "scheme", Host: "host", Port: "1234", Path: "this/is/a/path", Username: "username", Password: "password",
      "Query Parameters": { k1: "v1", k2: "v2" }, Fragment: "fragment",
    });
    expect(v(`parse_url("not a url").Host`)).toBe("");
    expect(v(`parse_url("https://portal.example:8443/a/b").Port`)).toBe("8443");
    expect(v(`parse_url("https://portal.example").Host`)).toBe("portal.example");
    expect(v(`parse_url("https://portal.example/?q=1")["Query Parameters"].q`)).toBe("1");
  });
  it("parse_ipv4", () => {
    expect(v(`parse_ipv4("127.0.0.1")`)).toBe(2130706433);
    expect(v(`parse_ipv4("192.0.2.5/24")`)).toBe(parseInt("C0000200", 16));
    expect(v(`parse_ipv4("999.1.1.1")`)).toBeNull();
  });
  it("ipv4_is_private", () => {
    expect(v(`ipv4_is_private("10.1.2.3")`)).toBe(true);
    expect(v(`ipv4_is_private("172.16.0.1")`)).toBe(true);
    expect(v(`ipv4_is_private("172.32.0.1")`)).toBe(false);
    expect(v(`ipv4_is_private("192.168.1.1")`)).toBe(true);
    expect(v(`ipv4_is_private("203.0.113.5")`)).toBe(false);
    expect(v(`ipv4_is_private("nope")`)).toBeNull();
  });
  it("ipv4_is_in_range", () => {
    expect(v(`ipv4_is_in_range("203.0.113.50", "203.0.113.0/24")`)).toBe(true);
    expect(v(`ipv4_is_in_range("203.0.114.1", "203.0.113.0/24")`)).toBe(false);
    expect(v(`ipv4_is_in_range("203.0.113.5", "203.0.113.5")`)).toBe(true);
    expect(v(`ipv4_is_in_range("x", "203.0.113.0/24")`)).toBeNull();
  });
});

describe("conditional and math functions", () => {
  it("iff, iif, case", () => {
    expect(v(`iff(1 > 0, "yes", "no")`)).toBe("yes");
    expect(v(`iif(1 < 0, 1, 2.5)`)).toBe(2.5);
    expect(v(`case(1 > 2, "a", 2 > 1, "b", "c")`)).toBe("b");
    expect(v(`case(false, "a", "c")`)).toBe("c");
    expect(fail(`print case("x", 1, 2)`).message).toContain("must be of type bool");
    expect(fail(`print iff(true, 1, "a")`).message).toContain("no common type");
  });
  it("bin and floor on numbers", () => {
    expect(v(`bin(4.5, 1)`)).toBe(4);
    expect(v(`bin(17, 5)`)).toBe(15);
    expect(v(`floor(-3.5, 1)`)).toBe(-4);
    expect(v(`bin(int(null), 5)`)).toBeNull();
    expect(v(`bin(5, -1)`)).toBeNull();
  });
  it("bin on timespans and datetimes", () => {
    expect(ts(v(`bin(time(16d), 7d)`))).toBe("14.00:00:00");
    expect(v(`bin(datetime(1970-05-11 13:45:07), 1d)`)).toEqual(new Date("1970-05-11T00:00:00Z"));
    expect(v(`bin(datetime(2026-11-07 10:37:00), 15m)`)).toEqual(new Date("2026-11-07T10:30:00Z"));
  });
  it("aligns week-long bins to the Kusto origin, a Monday", () => {
    expect(v(`bin(datetime(2026-11-07), 7d)`)).toEqual(new Date("2026-11-02T00:00:00Z"));
  });
  it("round, ceiling, abs", () => {
    expect(v(`round(2.98765, 3)`)).toBe(2.988);
    expect(v(`round(2.15, 1)`)).toBe(2.2);
    expect(v(`round(2.15)`)).toBe(2);
    expect(v(`round(-50.55, -2)`)).toBe(-100);
    expect(v(`round(21.5, -1)`)).toBe(20);
    expect(v(`round(1.4999999999)`)).toBe(1);
    expect(v(`round(2.5)`)).toBe(3);
    expect(v(`round(-2.5)`)).toBe(-3);
    expect(v(`round(int(null))`)).toBeNull();
    expect(v(`ceiling(1.2)`)).toBe(2);
    expect(v(`abs(-3)`)).toBe(3);
    expect(ts(v(`abs(-5m)`))).toBe("00:05:00");
  });
  it("log10, sqrt, pow", () => {
    expect(v(`log10(1000)`)).toBeCloseTo(3);
    expect(v(`log10(-1)`)).toBeNull();
    expect(v(`log10(0)`)).toBe(-Infinity);
    expect(v(`sqrt(16)`)).toBe(4);
    expect(v(`sqrt(-1)`)).toBeNull();
    expect(v(`pow(2, 10)`)).toBe(1024);
  });
});

describe("datetime functions", () => {
  const d = `datetime(2026-11-07 13:45:30.617)`;
  it("format_datetime follows the documented specifiers", () => {
    const t = `datetime(2017-01-29 09:00:05)`;
    expect(v(`format_datetime(${t}, 'yy-MM-dd [HH:mm:ss]')`)).toBe("17-01-29 [09:00:05]");
    expect(v(`format_datetime(${t}, 'yyyy-M-dd [H:mm:ss]')`)).toBe("2017-1-29 [9:00:05]");
    expect(v(`format_datetime(${t}, 'yy-MM-dd [hh:mm:ss tt]')`)).toBe("17-01-29 [09:00:05 AM]");
    expect(v(`format_datetime(${d}, 'yyyy.fff')`)).toBe("2026.617");
    expect(v(`format_datetime(${d}, 'h tt')`)).toBe("1 PM");
    expect(v(`format_datetime(datetime(2026-01-01 00:00:00.500), 's.F')`)).toBe("0.5");
    expect(v(`format_datetime(datetime(2026-01-01), 'ss.FFF')`)).toBe("00.");
  });
  it("format_timespan follows the documented example", () => {
    const t = `time(29.09:00:05.12345)`;
    expect(v(`format_timespan(${t}, 'dd.hh:mm:ss:FF')`)).toBe("29.09:00:05:12");
    expect(v(`format_timespan(${t}, 'ddd.h:mm:ss [fffffff]')`)).toBe("029.9:00:05 [1234500]");
  });
  it("datetime_diff counts period boundaries", () => {
    expect(v(`datetime_diff('year', datetime(2017-01-01), datetime(2000-12-31))`)).toBe(17);
    expect(v(`datetime_diff('quarter', datetime(2017-07-01), datetime(2017-03-30))`)).toBe(2);
    expect(v(`datetime_diff('month', datetime(2017-01-01), datetime(2015-12-30))`)).toBe(13);
    expect(v(`datetime_diff('week', datetime(2017-10-29 00:00), datetime(2017-09-30 23:59))`)).toBe(5);
    expect(v(`datetime_diff('day', datetime(2017-10-29 00:00), datetime(2017-09-30 23:59))`)).toBe(29);
    expect(v(`datetime_diff('hour', datetime(2017-10-31 01:00), datetime(2017-10-30 23:59))`)).toBe(2);
    expect(v(`datetime_diff('minute', datetime(2017-10-30 23:05:01), datetime(2017-10-30 23:00:59))`)).toBe(5);
    expect(v(`datetime_diff('second', datetime(2017-10-30 23:00:10.100), datetime(2017-10-30 23:00:00.900))`)).toBe(10);
    expect(v(`datetime_diff('millisecond', datetime(2017-10-30 23:00:00.200), datetime(2017-10-30 23:00:00.100))`)).toBe(100);
  });
  it("datetime_add", () => {
    const y = (p: string, n: number) => v(`datetime_add('${p}', ${n}, datetime(2017-01-01))`);
    expect(y("year", 1)).toEqual(new Date("2018-01-01T00:00:00Z"));
    expect(y("quarter", 1)).toEqual(new Date("2017-04-01T00:00:00Z"));
    expect(y("month", 1)).toEqual(new Date("2017-02-01T00:00:00Z"));
    expect(y("week", 1)).toEqual(new Date("2017-01-08T00:00:00Z"));
    expect(y("day", 1)).toEqual(new Date("2017-01-02T00:00:00Z"));
    expect(y("hour", 1)).toEqual(new Date("2017-01-01T01:00:00Z"));
    expect(y("minute", 1)).toEqual(new Date("2017-01-01T00:01:00Z"));
    expect(y("second", 1)).toEqual(new Date("2017-01-01T00:00:01Z"));
    expect(v(`datetime_add('month', 1, datetime(2026-01-31 08:00))`)).toEqual(new Date("2026-02-28T08:00:00Z"));
  });
  it("startofday, startofhour, endofday", () => {
    expect(v(`startofday(${d})`)).toEqual(new Date("2026-11-07T00:00:00Z"));
    expect(v(`startofday(${d}, -1)`)).toEqual(new Date("2026-11-06T00:00:00Z"));
    expect(v(`startofhour(${d})`)).toEqual(new Date("2026-11-07T13:00:00Z"));
    expect(v(`endofday(${d})`)).toEqual(new Date("2026-11-07T23:59:59.999Z"));
  });
  it("dayofweek is a timespan from Sunday; hourofday, getmonth, getyear", () => {
    expect(ts(v(`dayofweek(datetime(1947-11-29))`))).toBe("6.00:00:00");
    expect(ts(v(`dayofweek(datetime(2026-11-08))`))).toBe("00:00:00");
    expect(v(`hourofday(${d})`)).toBe(13);
    expect(v(`getmonth(${d})`)).toBe(11);
    expect(v(`getyear(${d})`)).toBe(2026);
  });
});

describe("dynamic functions", () => {
  it("array_length", () => {
    expect(v(`array_length(dynamic([1,2,3]))`)).toBe(3);
    expect(v(`array_length(dynamic({"a":1}))`)).toBeNull();
  });
  it("array_sort_asc puts nulls last unless told otherwise", () => {
    expect(v(`array_sort_asc(dynamic([null,"blue","yellow","green",null]))`)).toEqual(["blue", "green", "yellow", null, null]);
    expect(v(`array_sort_asc(dynamic([null,"blue","yellow","green",null]), false)`)).toEqual([null, null, "blue", "green", "yellow"]);
    expect(v(`array_sort_asc(dynamic([3,1,2]))`)).toEqual([1, 2, 3]);
  });
  it("array_concat, pack_array, bag_keys", () => {
    expect(v(`array_concat(dynamic([1]), dynamic([2,3]))`)).toEqual([1, 2, 3]);
    expect(v(`pack_array(1, "a", true)`)).toEqual([1, "a", true]);
    expect(v(`bag_keys(dynamic({"a":1,"b":2}))`)).toEqual(["a", "b"]);
  });
  it("pack and bag_pack build a bag", () => {
    expect(v(`pack("a", 1, "b", "x")`)).toEqual({ a: 1, b: "x" });
    expect(v(`bag_pack("k", datetime(2026-01-01))`)).toEqual({ k: "2026-01-01T00:00:00Z" });
  });
  it("set_has_element", () => {
    expect(v(`set_has_element(dynamic(["a","b"]), "a")`)).toBe(true);
    expect(v(`set_has_element(dynamic([1,2]), 3)`)).toBe(false);
  });
  it("gettype", () => {
    expect(v(`gettype("a")`)).toBe("string");
    expect(v(`gettype(111)`)).toBe("long");
    expect(v(`gettype(1==1)`)).toBe("bool");
    expect(v(`gettype(now())`)).toBe("datetime");
    expect(v(`gettype(1s)`)).toBe("timespan");
    expect(v(`gettype(parse_json('1'))`)).toBe("int");
    expect(v(`gettype(parse_json(' "abc" '))`)).toBe("string");
    expect(v(`gettype(parse_json(' {"abc":1} '))`)).toBe("dictionary");
    expect(v(`gettype(dynamic([1]))`)).toBe("array");
  });
  it("column_ifexists picks the column or the default", () => {
    const r = ok(`SecurityAlert | take 1 | project a = column_ifexists("AlertName", "?"), b = column_ifexists("Nope", "?")`);
    expect(r.rows[0]).toEqual({ a: "Password spray", b: "?" });
  });
});

describe("formatKqlValue, in the portal's forms", () => {
  it("timespans", () => {
    expect(formatKqlValue(new KqlTimespan(5 * 60 * 10_000_000), "timespan")).toBe("00:05:00");
    expect(formatKqlValue(new KqlTimespan(864_000_000_000 + 36_000_000_000), "timespan")).toBe("1.01:00:00");
    expect(formatKqlValue(new KqlTimespan(15_000_000), "timespan")).toBe("00:00:01.5000000");
    expect(formatKqlValue(new KqlTimespan(-600_000_000), "timespan")).toBe("-00:01:00");
    expect(formatKqlValue(new KqlTimespan(0), "timespan")).toBe("00:00:00");
    expect(formatKqlValue(ok(`print d = 5m`).rows[0].d, "timespan")).toBe("00:05:00");
  });
  it("datetimes, in UTC", () => {
    expect(formatKqlValue(new Date("2026-11-07T10:00:00Z"), "datetime")).toBe("11/7/2026, 10:00:00.000 AM");
    expect(formatKqlValue(new Date("2026-11-07T13:05:09.123Z"), "datetime")).toBe("11/7/2026, 1:05:09.123 PM");
    expect(formatKqlValue(new Date("2026-01-01T00:00:00Z"), "datetime")).toBe("1/1/2026, 12:00:00.000 AM");
    expect(formatKqlValue(new Date("2026-01-01T12:00:00Z"), "datetime")).toBe("1/1/2026, 12:00:00.000 PM");
  });
  it("everything else", () => {
    expect(formatKqlValue(null, "long")).toBe("");
    expect(formatKqlValue(undefined, "string")).toBe("");
    expect(formatKqlValue(null, "datetime")).toBe("");
    expect(formatKqlValue(0, "long")).toBe("0");
    expect(formatKqlValue(1.5, "real")).toBe("1.5");
    expect(formatKqlValue(false, "bool")).toBe("false");
    expect(formatKqlValue("x", "string")).toBe("x");
    expect(formatKqlValue({ a: [1, "b"] }, "dynamic")).toBe('{"a":[1,"b"]}');
    expect(formatKqlValue([1, 2], "dynamic")).toBe("[1,2]");
    expect(formatKqlValue("text", "dynamic")).toBe("text");
    expect(formatKqlValue(null, "dynamic")).toBe("");
  });
  it("tolerates a serialized row", () => {
    expect(formatKqlValue("2026-11-07T10:00:00.000Z", "datetime")).toBe("11/7/2026, 10:00:00.000 AM");
    expect(formatKqlValue("00:05:00", "timespan")).toBe("00:05:00");
  });
});

describe("failures in expressions keep to their row", () => {
  it("a bad runtime regex yields null rather than failing the query", () => {
    const r = ok(`datatable(p:string)["[", "a"] | extend m = "a" matches regex p`);
    expect(col(r, "m")).toEqual([null, true]);
  });
  it("a bad constant regex is reported", () => {
    expect(fail(`print "a" matches regex "["`).message).toContain("Invalid regular expression");
  });
  it("now() stays the same for every row", () => {
    expect(new Set(col(ok(`SigninLogs | project n = now()`), "n").map(String)).size).toBe(1);
  });
  it("no input mutation through NOW", () => {
    expect(NOW.toISOString()).toBe("2026-11-07T12:00:00.000Z");
  });
});
