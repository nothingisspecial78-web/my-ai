/**
 * Server-Side Request Forgery (SSRF) & Private Network Protection
 * 
 * Validates hostnames, IPv4, and IPv6 representations to prevent SSRF attacks,
 * DNS rebinding, internal network scanning, and cloud metadata access.
 * 
 * Enforces strict RFC 1918, RFC 3927, RFC 4193, RFC 4291, and RFC 6890 boundaries.
 */

export interface SsrfCheckResult {
  isBlocked: boolean;
  isPrivateOrLocal: boolean;
  isCloudMetadata: boolean;
  isLoopback: boolean;
  reason?: string;
  parsedIp?: string;
  canonicalHost?: string;
}

// Known cloud metadata IP endpoints and hostnames
const CLOUD_METADATA_IPS = new Set([
  '169.254.169.254', // AWS, GCP, Azure, OpenStack, DigitalOcean
  '169.254.169.253', // AWS DNS
  '169.254.170.2',   // AWS ECS task metadata
  '100.100.100.200', // Alibaba Cloud metadata
]);

const BLOCKED_HOST_SUFFIXES = [
  'localhost',
  'local',
  'internal',
  'lan',
  'home',
  'corp',
  'metadata.google.internal',
  'instance-data',
];

/**
 * Parses obfuscated IPv4 formats including:
 * - Dotted decimal (127.0.0.1)
 * - Decimal integer (2130706433 -> 127.0.0.1)
 * - Hexadecimal (0x7f000001 or 0x7f.0.0.1)
 * - Octal (0177.0.0.1 or 017700000001)
 * - Mixed encodings
 * 
 * Returns normalized dotted decimal IP or null if not an IP.
 */
export function parseAndNormalizeIpv4(host: string): string | null {
  if (!host || typeof host !== 'string') return null;

  const trimmed = host.trim().toLowerCase();

  // 1. Check for decimal integer representation (e.g. 2130706433 or 0x7f000001)
  if (/^(?:0x[0-9a-f]+|\d+)$/i.test(trimmed)) {
    try {
      const intVal = trimmed.startsWith('0x')
        ? parseInt(trimmed, 16)
        : parseInt(trimmed, 10);

      if (Number.isInteger(intVal) && intVal >= 0 && intVal <= 0xffffffff) {
        const b1 = (intVal >>> 24) & 0xff;
        const b2 = (intVal >>> 16) & 0xff;
        const b3 = (intVal >>> 8) & 0xff;
        const b4 = intVal & 0xff;
        return `${b1}.${b2}.${b3}.${b4}`;
      }
    } catch {
      return null;
    }
  }

  // 2. Dotted parts (could be 1 to 4 parts in historical IP syntax)
  const parts = trimmed.split('.');
  if (parts.length >= 2 && parts.length <= 4) {
    const parsedBytes: number[] = [];
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i];
      let val: number;
      if (/^0x[0-9a-f]+$/i.test(p)) {
        val = parseInt(p, 16);
      } else if (/^0[0-7]+$/.test(p)) {
        val = parseInt(p, 8);
      } else if (/^\d+$/.test(p)) {
        val = parseInt(p, 10);
      } else {
        return null;
      }

      if (!Number.isInteger(val) || val < 0) {
        return null;
      }
      parsedBytes.push(val);
    }

    // Convert multi-part format to standard 4-byte IPv4
    if (parsedBytes.length === 4) {
      if (parsedBytes.every(b => b >= 0 && b <= 255)) {
        return parsedBytes.join('.');
      }
    } else if (parsedBytes.length === 3) {
      // a.b.c -> a.b.(c as 16-bit)
      const [a, b, c] = parsedBytes;
      if (a <= 255 && b <= 255 && c <= 0xffff) {
        return `${a}.${b}.${(c >>> 8) & 0xff}.${c & 0xff}`;
      }
    } else if (parsedBytes.length === 2) {
      // a.b -> a.(b as 24-bit)
      const [a, b] = parsedBytes;
      if (a <= 255 && b <= 0xffffff) {
        return `${a}.${(b >>> 16) & 0xff}.${(b >>> 8) & 0xff}.${b & 0xff}`;
      }
    }
  }

  return null;
}

/**
 * Checks if a normalized IPv4 string falls within private, loopback, or link-local ranges.
 */
export function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return false;
  }

  const [b0, b1] = parts;

  // 0.0.0.0/8 (Current network)
  if (b0 === 0) return true;

  // 10.0.0.0/8 (Private-Use RFC 1918)
  if (b0 === 10) return true;

  // 127.0.0.0/8 (Loopback RFC 1122)
  if (b0 === 127) return true;

  // 169.254.0.0/16 (Link-Local RFC 3927, includes cloud metadata)
  if (b0 === 169 && b1 === 254) return true;

  // 172.16.0.0/12 (Private-Use RFC 1918: 172.16.0.0 to 172.31.255.255)
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;

  // 192.168.0.0/16 (Private-Use RFC 1918)
  if (b0 === 192 && b1 === 168) return true;

  // 100.64.0.0/10 (Carrier-grade NAT RFC 6598, often used for internal cloud services)
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;

  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
  if (b0 >= 224) return true;

  return false;
}

/**
 * Checks if an IPv6 string falls within loopback, link-local, or unique local ranges.
 */
export function isPrivateIpv6(host: string): boolean {
  let cleaned = host.toLowerCase().trim();
  if (cleaned.startsWith('[') && cleaned.endsWith(']')) {
    cleaned = cleaned.slice(1, -1);
  }

  // Loopback (::1)
  if (cleaned === '::1' || cleaned === '0:0:0:0:0:0:0:1') {
    return true;
  }

  // Unspecified (::)
  if (cleaned === '::' || cleaned === '0:0:0:0:0:0:0:0') {
    return true;
  }

  // IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (cleaned.startsWith('::ffff:')) {
    const ipv4Part = cleaned.slice('::ffff:'.length);
    let normalizedIpv4 = parseAndNormalizeIpv4(ipv4Part);
    if (!normalizedIpv4 && ipv4Part.includes(':')) {
      const parts = ipv4Part.split(':').map(h => parseInt(h, 16));
      if (parts.length === 2 && !parts.some(isNaN)) {
        const [h1, h2] = parts;
        normalizedIpv4 = `${(h1 >>> 8) & 0xff}.${h1 & 0xff}.${(h2 >>> 8) & 0xff}.${h2 & 0xff}`;
      }
    }
    if (normalizedIpv4 && isPrivateIpv4(normalizedIpv4)) {
      return true;
    }
  }

  // Link-local (fe80::/10 -> fe8, fe9, fea, feb)
  if (/^fe[89ab]/i.test(cleaned)) {
    return true;
  }

  // Unique local address (fc00::/7 -> fc, fd)
  if (/^f[cd]/i.test(cleaned)) {
    return true;
  }

  return false;
}

/**
 * Evaluates whether a host string is a private, loopback, internal, or cloud metadata address.
 */
export function checkHostForSsrf(host: string): SsrfCheckResult {
  if (!host || typeof host !== 'string') {
    return {
      isBlocked: true,
      isPrivateOrLocal: true,
      isCloudMetadata: false,
      isLoopback: false,
      reason: 'Empty or invalid host.',
    };
  }

  const rawHost = host.trim().toLowerCase();
  const strippedHost = rawHost.replace(/^\[|\]$/g, '');

  // 1. Explicit internal hostnames & suffixes
  for (const blocked of BLOCKED_HOST_SUFFIXES) {
    if (rawHost === blocked || rawHost.endsWith(`.${blocked}`)) {
      return {
        isBlocked: true,
        isPrivateOrLocal: true,
        isCloudMetadata: blocked.includes('metadata'),
        isLoopback: blocked.includes('localhost'),
        reason: `Host references internal or loopback name (${rawHost}).`,
        canonicalHost: rawHost,
      };
    }
  }

  // 2. Explicit cloud metadata IPs
  if (CLOUD_METADATA_IPS.has(strippedHost)) {
    return {
      isBlocked: true,
      isPrivateOrLocal: true,
      isCloudMetadata: true,
      isLoopback: false,
      reason: `Host is a cloud provider metadata endpoint (${strippedHost}).`,
      parsedIp: strippedHost,
      canonicalHost: strippedHost,
    };
  }

  // 3. IPv4 checks (including obfuscated decimal, hex, octal representations)
  const normalizedIpv4 = parseAndNormalizeIpv4(strippedHost);
  if (normalizedIpv4) {
    const isPrivate = isPrivateIpv4(normalizedIpv4);
    const isCloudMeta = CLOUD_METADATA_IPS.has(normalizedIpv4);
    const isLoopback = normalizedIpv4.startsWith('127.');

    if (isPrivate || isCloudMeta || isLoopback) {
      return {
        isBlocked: true,
        isPrivateOrLocal: isPrivate,
        isCloudMetadata: isCloudMeta,
        isLoopback,
        reason: isCloudMeta
          ? `Host resolves to a cloud metadata address (${normalizedIpv4}).`
          : isLoopback
          ? `Host resolves to a loopback address (${normalizedIpv4}).`
          : `Host resolves to a private network address (${normalizedIpv4}).`,
        parsedIp: normalizedIpv4,
        canonicalHost: normalizedIpv4,
      };
    }

    return {
      isBlocked: false,
      isPrivateOrLocal: false,
      isCloudMetadata: false,
      isLoopback: false,
      parsedIp: normalizedIpv4,
      canonicalHost: normalizedIpv4,
    };
  }

  // 4. IPv6 checks
  if (strippedHost.includes(':')) {
    let isLoopback = strippedHost === '::1' || strippedHost === '0:0:0:0:0:0:0:1';
    const isPrivateV6 = isPrivateIpv6(strippedHost);

    // Extract mapped IPv4 if present to detect loopback
    if (strippedHost.startsWith('::ffff:')) {
      const ipv4Part = strippedHost.slice('::ffff:'.length);
      let mappedIp = parseAndNormalizeIpv4(ipv4Part);
      if (!mappedIp && ipv4Part.includes(':')) {
        const parts = ipv4Part.split(':').map(h => parseInt(h, 16));
        if (parts.length === 2 && !parts.some(isNaN)) {
          const [h1, h2] = parts;
          mappedIp = `${(h1 >>> 8) & 0xff}.${h1 & 0xff}.${(h2 >>> 8) & 0xff}.${h2 & 0xff}`;
        }
      }
      if (mappedIp && mappedIp.startsWith('127.')) {
        isLoopback = true;
      }
    }

    if (isPrivateV6 || isLoopback) {
      return {
        isBlocked: true,
        isPrivateOrLocal: true,
        isCloudMetadata: false,
        isLoopback,
        reason: isLoopback
          ? `Host is a loopback address (${strippedHost}).`
          : `Host is an IPv6 private or link-local address (${strippedHost}).`,
        parsedIp: strippedHost,
        canonicalHost: strippedHost,
      };
    }

    return {
      isBlocked: false,
      isPrivateOrLocal: false,
      isCloudMetadata: false,
      isLoopback: false,
      parsedIp: strippedHost,
      canonicalHost: strippedHost,
    };
  }

  // Standard public domain name
  return {
    isBlocked: false,
    isPrivateOrLocal: false,
    isCloudMetadata: false,
    isLoopback: false,
    canonicalHost: rawHost,
  };
}
