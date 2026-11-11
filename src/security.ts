import crypto from "node:crypto";
import dns from "node:dns";
import net from "node:net";
import { createChildLogger } from "./logger.js";

const log = createChildLogger("security");

// Algorithm: AES-256-GCM with 96-bit random IV and 128-bit authentication tag
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

/**
 * Vault for securely encrypting and decrypting sensitive credentials in memory and at rest.
 * Enforces strict 32-byte hex keys in production with zero predictable fallbacks.
 */
export class CredentialVault {
  private masterKey: Buffer;

  constructor(secretKeyHex?: string) {
    const keyCandidate = secretKeyHex || process.env.OMNIMCP_ENCRYPTION_KEY;

    if (keyCandidate && /^[0-9a-fA-F]{64}$/.test(keyCandidate)) {
      this.masterKey = Buffer.from(keyCandidate, "hex");
    } else {
      if (process.env.NODE_ENV === "production") {
        throw new Error(
          "FATAL SECURITY CONFIGURATION: OMNIMCP_ENCRYPTION_KEY must be a valid 64-character hexadecimal string (32 bytes) in production."
        );
      }

      // In non-production, generate an ephemeral cryptographically strong random 32-byte key
      // Never use hardcoded/predictable salt strings
      this.masterKey = crypto.randomBytes(32);
      log.warn(
        "OMNIMCP_ENCRYPTION_KEY not set or invalid. Generated ephemeral 32-byte key for current process session. Data will not persist across restarts."
      );
    }
  }

  public encrypt(plainText: string): string {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this.masterKey, iv, { authTagLength: TAG_LENGTH });

    let encrypted = cipher.update(plainText, "utf8", "hex");
    encrypted += cipher.final("hex");

    const tag = cipher.getAuthTag();
    // Format: iv:tag:cipherText
    return `${iv.toString("hex")}:${tag.toString("hex")}:${encrypted}`;
  }

  public decrypt(encryptedData: string): string {
    const parts = encryptedData.split(":");
    if (parts.length !== 3) {
      throw new Error("Invalid encrypted format. Expected iv:tag:cipherText");
    }

    const [ivHex, tagHex, cipherHex] = parts;
    const iv = Buffer.from(ivHex, "hex");
    const tag = Buffer.from(tagHex, "hex");

    const decipher = crypto.createDecipheriv(ALGORITHM, this.masterKey, iv, { authTagLength: TAG_LENGTH });
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(cipherHex, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }
}

// Global default vault instance
export const vault = new CredentialVault();

/**
 * Regular expressions for common secret patterns that must never appear in logs or model output
 */
const SECRET_PATTERNS = [
  /ghp_[a-zA-Z0-9]{36}/g, // GitHub Personal Access Token
  /github_pat_[a-zA-Z0-9_]{82}/g, // Fine-grained GitHub PAT
  /glpat-[a-zA-Z0-9_\-]{20}/g, // GitLab PAT
  /sbp_[a-zA-Z0-9]{40}/g, // Supabase PAT
  /sb_secret_[a-zA-Z0-9_]{32,}/g, // Supabase modern secret key
  /sk-[a-zA-Z0-9]{48}/g, // OpenAI standard API key
  /ey[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,}/g, // JWT / Service tokens
  /sntrys_[a-zA-Z0-9]{64}/g, // Sentry Token
  /sntryu_[a-zA-Z0-9]{64}/g, // Sentry User Token
  /Bearer\s+[a-zA-Z0-9_\-\.]{20,}/gi, // Generic Bearer tokens
  /AIza[0-9A-Za-z-_]{35}/g, // Google Cloud / Stitch API Key pattern
  /x-goog-api-key:\s*[^\s\r\n]+/gi, // Google API Key header
  /omnimcp_[a-zA-Z0-9_]{32,}/g, // OmniMCP tokens (approval, session, internal secrets)
  /(?:password|passwd|pwd|secret|api_key|apikey|key)=\S+/gi, // Inline key=value secrets in logs/strings
];

/**
 * Redacts secrets from any string or deeply nested JSON object.
 */
export function sanitizeData<T>(data: T): T {
  if (data === null || data === undefined) {
    return data;
  }

  if (typeof data === "string") {
    let sanitized: string = data;
    for (const pattern of SECRET_PATTERNS) {
      sanitized = sanitized.replace(pattern, "[REDACTED_SECRET]");
    }
    return sanitized as unknown as T;
  }

  if (Array.isArray(data)) {
    return data.map((item) => sanitizeData(item)) as unknown as T;
  }

  if (typeof data === "object") {
    const sanitizedObj: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data)) {
      const lowerKey = key.toLowerCase();
      if (
        lowerKey.includes("token") ||
        lowerKey.includes("secret") ||
        lowerKey.includes("password") ||
        lowerKey.includes("apikey") ||
        lowerKey.includes("api_key") ||
        lowerKey.includes("credential") ||
        lowerKey.includes("private_key") ||
        lowerKey.includes("authorization") ||
        lowerKey.includes("service_role_key")
      ) {
        sanitizedObj[key] = "[REDACTED_SECRET]";
      } else {
        sanitizedObj[key] = sanitizeData(value);
      }
    }
    return sanitizedObj as unknown as T;
  }

  return data;
}

/**
 * Checks whether an IP address belongs to private, loopback, link-local, or cloud metadata networks.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const normalized = ip.toLowerCase().trim().replace(/^\[|\]$/g, "");

  // IPv4 Loopback (127.0.0.0/8) or 0.0.0.0
  if (normalized === "0.0.0.0" || normalized.startsWith("127.")) {
    return true;
  }

  // IPv6 Loopback
  if (normalized === "::1" || normalized === "::") {
    return true;
  }

  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:10.0.0.1)
  if (normalized.startsWith("::ffff:")) {
    const mappedIpv4 = normalized.substring(7);
    return isPrivateOrReservedIp(mappedIpv4);
  }

  // Cloud Instance Metadata Service (AWS, GCP, Azure, DigitalOcean: 169.254.169.254)
  if (normalized === "169.254.169.254" || normalized.startsWith("169.254.")) {
    return true;
  }

  // AWS IPv6 metadata (fd00:ec2::254)
  if (normalized === "fd00:ec2::254") {
    return true;
  }

  // RFC 1918 Private IPv4 Ranges
  if (
    normalized.startsWith("10.") ||
    normalized.startsWith("192.168.") ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(normalized)
  ) {
    return true;
  }

  // IPv6 Unique Local Addresses (fc00::/7) or Link-Local (fe80::/10)
  if (/^f[cd][0-9a-f]{2}:/i.test(normalized) || /^fe80:/i.test(normalized)) {
    return true;
  }

  // Carrier Grade NAT (100.64.0.0/10)
  if (/^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./.test(normalized)) {
    return true;
  }

  return false;
}

/**
 * SSRF validator for remote HTTP MCP server URLs.
 * Synchronous validation against URLs, hostnames, and IP representations.
 */
export function validateRemoteServerUrl(
  urlString: string,
  allowLocalhost = false
): { valid: boolean; reason?: string } {
  try {
    const parsed = new URL(urlString);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { valid: false, reason: "Only http and https protocols are supported." };
    }

    // Reject URLs with embedded credentials (e.g., http://user:pass@example.com)
    if (parsed.username || parsed.password) {
      return { valid: false, reason: "Credentials in server URLs are prohibited for security." };
    }

    const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");

    // Known cloud metadata domain names
    if (
      host === "metadata.google.internal" ||
      host === "instance-data" ||
      host === "169.254.169.254"
    ) {
      return { valid: false, reason: "Access to cloud instance metadata service is strictly blocked." };
    }

    // Check hostname string directly
    if (!allowLocalhost) {
      if (host === "localhost" || isPrivateOrReservedIp(host)) {
        return { valid: false, reason: "Access to private, loopback, or internal networks is prohibited." };
      }

      // Check alternative decimal/octal/hex IP notations (e.g. 2130706433, 0177.0.0.1, 0x7f.0.0.1, 127.1)
      if (/^(0x[0-9a-f]+|\d+)$/i.test(host)) {
        return { valid: false, reason: "Alternative integer/hexadecimal IP representations are prohibited." };
      }
      if (host.includes(".")) {
        const parts = host.split(".");
        const hasAlternativeNotation = parts.some((p) => /^0x/i.test(p) || /^0\d+$/.test(p));
        const isTruncatedIp = parts.length < 4 && parts.every((p) => /^\d+$/.test(p));
        if (hasAlternativeNotation || isTruncatedIp) {
          return { valid: false, reason: "Alternative octal/hex/truncated IP representations are prohibited." };
        }
      }
    }

    return { valid: true };
  } catch {
    return { valid: false, reason: "Malformed URL format." };
  }
}

/**
 * Asynchronous SSRF validator that resolves DNS to protect against DNS rebinding attacks.
 */
export async function validateRemoteServerUrlAsync(
  urlString: string,
  allowLocalhost = false
): Promise<{ valid: boolean; reason?: string }> {
  const syncCheck = validateRemoteServerUrl(urlString, allowLocalhost);
  if (!syncCheck.valid) {
    return syncCheck;
  }

  if (allowLocalhost) {
    return { valid: true };
  }

  try {
    const parsed = new URL(urlString);
    const host = parsed.hostname.replace(/^\[|\]$/g, "");

    // If host is already an IP address, validate directly without network DNS query
    if (net.isIP(host)) {
      if (isPrivateOrReservedIp(host)) {
        return {
          valid: false,
          reason: `IP address (${host}) belongs to a private/reserved network.`,
        };
      }
      return { valid: true };
    }

    // Resolve DNS records to verify resolved IP is not internal/private (DNS rebinding defense)
    const lookupResult = await dns.promises.lookup(host, { all: true });
    for (const record of lookupResult) {
      if (isPrivateOrReservedIp(record.address)) {
        return {
          valid: false,
          reason: `Resolved IP address (${record.address}) for '${host}' belongs to a private/reserved network.`,
        };
      }
    }

    return { valid: true };
  } catch (err: unknown) {
    return { valid: false, reason: `DNS resolution failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}
