/**
 * HARIS (حارس) — Defensive Security Headers Configuration (SEC-FIND-04)
 *
 * Implements a comprehensive, defense-in-depth HTTP security header policy:
 * - Content-Security-Policy (CSP)
 * - X-Content-Type-Options: nosniff
 * - X-Frame-Options: DENY
 * - Referrer-Policy: strict-origin-when-cross-origin
 * - Permissions-Policy: restricts unused browser capabilities
 * - X-DNS-Prefetch-Control: off
 * - X-Permitted-Cross-Domain-Policies: none
 *
 * Note on HSTS (Strict-Transport-Security):
 * Omitted by default to support local and self-hosted HTTP environments (e.g. http://localhost:3000)
 * without causing browser HTTPS redirection errors. Configurable via ENABLE_HSTS in production.
 */

export interface SecurityHeaderItem {
  key: string;
  value: string;
}

export interface SecurityHeaderOptions {
  isDev?: boolean;
  enableHsts?: boolean;
}

/**
 * Build a robust Content-Security-Policy tailored specifically for Next.js 16 and HARIS
 */
export function buildCspHeader(options: SecurityHeaderOptions = {}): string {
  const isDev = options.isDev ?? process.env.NODE_ENV !== 'production';

  // Directives breakdown:
  // 1. default-src 'self': Only allow content from the same origin by default.
  // 2. script-src 'self' 'unsafe-inline': Required by Next.js 16 App Router for React Server Component
  //    hydration scripts. In development, 'unsafe-eval' is permitted for Fast Refresh / Turbopack source maps.
  // 3. style-src 'self' 'unsafe-inline': Required for React inline style attributes and Next.js font CSS variables.
  // 4. img-src 'self' data: blob:: Permits local icons and client-side Base64/Data URL screenshot thumbnails.
  // 5. font-src 'self' data:: Permits self-hosted fonts (IBM Plex Sans Arabic) loaded via next/font.
  // 6. connect-src 'self': Permits API requests to /api/analyze; includes WebSocket in dev for hot reload.
  // 7. object-src 'none': Disallows Flash, Java, and legacy browser plugins.
  // 8. base-uri 'self': Prevents malicious <base> tag injection.
  // 9. form-action 'self': Restricts form submissions to same-origin.
  // 10. frame-ancestors 'none': Complete defense against Clickjacking (cannot be embedded in any iframe).
  const directives: Record<string, string[]> = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'", ...(isDev ? ["'unsafe-eval'"] : [])],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:', 'blob:'],
    'font-src': ["'self'", 'data:'],
    'connect-src': ["'self'", ...(isDev ? ['ws:', 'wss:', 'http:', 'https:'] : [])],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'none'"],
  };

  return Object.entries(directives)
    .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
    .join('; ');
}

/**
 * Return array of security headers suitable for Next.js next.config.ts
 */
export function getSecurityHeaders(options: SecurityHeaderOptions = {}): SecurityHeaderItem[] {
  const headers: SecurityHeaderItem[] = [
    {
      key: 'Content-Security-Policy',
      value: buildCspHeader(options),
    },
    {
      key: 'X-Content-Type-Options',
      value: 'nosniff',
    },
    {
      key: 'X-Frame-Options',
      value: 'DENY',
    },
    {
      key: 'Referrer-Policy',
      value: 'strict-origin-when-cross-origin',
    },
    {
      key: 'Permissions-Policy',
      value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), screen-wake-lock=()',
    },
    {
      key: 'X-DNS-Prefetch-Control',
      value: 'off',
    },
    {
      key: 'X-Permitted-Cross-Domain-Policies',
      value: 'none',
    },
  ];

  // Optional HSTS: Only apply if explicitly configured in verified HTTPS production environments
  const shouldEnableHsts =
    options.enableHsts ?? (process.env.ENABLE_HSTS === 'true' && process.env.NODE_ENV === 'production');

  if (shouldEnableHsts) {
    headers.push({
      key: 'Strict-Transport-Security',
      value: 'max-age=31536000; includeSubDomains',
    });
  }

  return headers;
}

/**
 * Return key-value dictionary of security headers for direct Response object injection
 */
export function getSecurityHeadersMap(options: SecurityHeaderOptions = {}): Record<string, string> {
  const headers = getSecurityHeaders(options);
  const map: Record<string, string> = {};
  for (const h of headers) {
    map[h.key] = h.value;
  }
  return map;
}
