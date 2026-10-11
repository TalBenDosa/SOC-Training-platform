// Lesson markdown: fenced code comes back as a code card (it rendered as "CB0"
// before), and HTML in untrusted lesson text stays inert.
import { describe, it, expect } from "vitest";
import { lessonMarkdownToHtml } from "./lessonMarkdown";

describe("lessonMarkdownToHtml", () => {
  it("re-inserts fenced code blocks as <pre><code>", () => {
    const html = lessonMarkdownToHtml("Run this:\n\n```kql\nSigninLogs | where ResultType != 0\n```\n\nThen pivot.");
    expect(html).toContain("<pre");
    expect(html).toContain("SigninLogs | where ResultType != 0");
    expect(html).not.toMatch(/\u0000|CB\d/);
  });
  it("several blocks keep their order", () => {
    const html = lessonMarkdownToHtml("```\nfirst\n```\n\ntext\n\n```\nsecond\n```");
    expect(html.indexOf("first")).toBeLessThan(html.indexOf("second"));
  });
  it("HTML in lesson text and in code is inert", () => {
    const html = lessonMarkdownToHtml("<img src=x onerror=alert(1)>\n\n```html\n<script>alert(1)</script>\n```");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script>");
  });
});
