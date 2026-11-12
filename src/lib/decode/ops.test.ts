import { describe, it, expect } from "vitest";
import { OP_BY_ID, suggestOp, looksEncoded, encodedCommandOf, runRecipe } from "./ops";

const run = async (id: string, input: string) => OP_BY_ID.get(id)!.run(input);

describe("decoder ops", () => {
  it("Base64 to text, and UTF-16LE PowerShell -EncodedCommand", async () => {
    expect(await run("from-base64", "aGVsbG8gd29ybGQ=")).toMatchObject({ ok: true, out: "hello world" });
    // "whoami" in UTF-16LE, as powershell -enc carries it
    const r = await run("from-base64", "dwBoAG8AYQBtAGkA");
    expect(r).toMatchObject({ ok: true, out: "whoami" });
    expect(r.ok && r.note).toMatch(/UTF-16LE/);
    expect((await run("from-base64", "not base64!")).ok).toBe(false);
  });

  it("URL, hex, entities, escapes, ROT13, reverse", async () => {
    expect(await run("url-decode", "%2Fadmin%3Fid%3D1%20OR%201%3D1")).toMatchObject({ out: "/admin?id=1 OR 1=1" });
    expect(await run("from-hex", "0x41 0x42 0x43")).toMatchObject({ out: "ABC" });
    expect(await run("html-entities", "&lt;script&gt;alert(&#39;x&#x27;)")).toMatchObject({ out: "<script>alert('x')" });
    expect(await run("unicode-escapes", "\\u0049\\x45X")).toMatchObject({ out: "IEX" });
    expect(await run("rot13", "Uryyb")).toMatchObject({ out: "Hello" });
    expect(await run("reverse", "llehsrewop")).toMatchObject({ out: "powershell" });
  });

  it("JWT header and payload", async () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9.sig";
    const r = await run("jwt", jwt);
    expect(r.ok && r.out).toContain("\"role\": \"admin\"");
  });

  it("refang and defang", async () => {
    expect(await run("refang", "hxxps://evil[.]example/a")).toMatchObject({ out: "https://evil.example/a" });
    expect(await run("defang", "https://evil.example/a")).toMatchObject({ out: "hxxps://evil[.]example/a" });
  });

  it("suggests the right first step", () => {
    expect(suggestOp("SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")).toBe("from-base64");
    expect(suggestOp("%2Fetc%2Fpasswd")).toBe("url-decode");
    expect(suggestOp("H4sIAAAAAAAA/ytJLS4BAMfE6G8EAAAA")).toBe("gunzip");
    expect(suggestOp("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig")).toBe("jwt");
    expect(suggestOp("svc_backup")).toBeNull();
    expect(suggestOp("DESKTOP-4821")).toBeNull();
  });

  it("decodes a whole PowerShell command line with -enc", async () => {
    const cmd = "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA";
    expect(suggestOp(cmd)).toBe("ps-enc");
    expect(await run("ps-enc", cmd)).toMatchObject({ ok: true, out: "IEX (New-Object Net.WebClient)" });
    // A sentence is never taken for Base64.
    expect(suggestOp("the analyst opened the alert and closed it later")).toBeNull();
  });

  it("finds the -enc blob in a command line", () => {
    const cmd = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA";
    expect(looksEncoded(cmd)).toBe(true);
    expect(encodedCommandOf(cmd)).toBe("SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA");
    expect(looksEncoded("C:\\Windows\\System32\\svchost.exe")).toBe(false);
  });

  it("chains steps and stops at the first error", async () => {
    const r = await runRecipe("JTJGYWRtaW4=", ["from-base64", "url-decode"]);
    expect(r.output).toBe("/admin");
    const bad = await runRecipe("@@@", ["from-base64", "url-decode"]);
    expect(bad.steps).toHaveLength(1);
    expect(bad.steps[0].result.ok).toBe(false);
  });
});

describe("the Decode tag is for values that decode to something readable", () => {
  it("never on a hash, an id, a token or a resource path", () => {
    for (const v of [
      "bbdd84e1abd4fd8128044e9e810d2f225ce454c66e45a6bbe5831f4e7a494197",       // SHA-256
      "5f4dcc3b5aa765d61d8327deb882cf99",                                         // MD5
      "a9993e364706816aba3e25717850c26c9cd0d89d",                                 // SHA-1
      "1-6731a2b9-0c4e7f1d2a3b5c6d7e8f9a0b",                                      // trace id
      "AAMkAGI2TG93AAA9kjZDAAAAAADbKx4AAA",                                       // mailbox item id
      "/subscriptions/0f1e2d3c/resourceGroups/rg-edge-prod/providers/Network",    // resource path
    ]) expect(looksEncoded(v), v).toBe(false);
  });
  it("still on Base64 and hex that hold text, a URL-encoded query, a JWT and an encoded command", () => {
    expect(looksEncoded("SW52b2tlLVdlYlJlcXVlc3QgLVVyaSBodHRwczovL2V4YW1wbGUu")).toBe(true);   // Base64 of a command
    expect(looksEncoded("496e766f6b652d576562526571756573")).toBe(true);                     // hex of text
    expect(looksEncoded("q=%3Cscript%3E...%3C%2Fscript%3E")).toBe(true);
    expect(looksEncoded("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.")).toBe(true);
  });
});
