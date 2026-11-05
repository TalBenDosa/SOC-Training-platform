import { describe, it, expect } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { InlineMd } from "./InlineMd";

const html = (text: string) => renderToStaticMarkup(React.createElement(InlineMd, { text }));

describe("InlineMd", () => {
  it("renders emphasis instead of showing the markers", () => {
    expect(html("**What the SIEM console tells you:** the rule fired")).toContain("<strong");
    expect(html("an *internal* address")).toBe("an <em>internal</em> address");
    expect(html("run `whoami` now")).toContain("<code");
  });
  it("leaves a lone asterisk and a multiplication alone", () => {
    expect(html("2 * 3 equals 6")).toBe("2 * 3 equals 6");
    expect(html("Files named *.log")).toBe("Files named *.log");
  });
  it("keeps line breaks", () => {
    expect(html("one\ntwo")).toBe("one<br/>two");
  });
});
