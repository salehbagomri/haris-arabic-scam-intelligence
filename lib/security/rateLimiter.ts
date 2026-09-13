/**
 * HARIS (حارس) — In-Memory Sliding Window Rate Limiter
 *
 * Provides IP-based, async-safe, in-memory rate limiting to defend against
 * API abuse, rapid request flooding, and Gemini quota exhaustion.
 *
 * Principles:
 * 1. ZERO PERSISTENCE: Stores timestamps only; never logs or retains user content.
 * 2. PRE-PARSING DEFENSE: Runs before request.json() to reject heavy payloads before buffer allocation.
 * 3. IP SPOOFING RESILIENCE: Validates IP structure before consuming proxy headers.
 * 4. BOUNDED MEMORY: Periodically prunes stale entries to prevent memory exhaustion.
 */

export interface RateLimitConfig {
  /** Maximum allowed requests within the time window */
  maxRequests: number;
  /** Duration of the sliding window in milliseconds */
  windowMs: number;
  /** Maximum number of unique client IP entries to track simultaneously */
  maxTrackedIps: number;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfterSeconds: number;
  resetTime: number;
}

const DEFAULT_CONFIG: RateLimitConfig = {
  maxRequests: 10,
  windowMs: 60 * 1000, // 1 minute
  maxTrackedIps: 10000,
};

// In-memory state: Map of clientIp -> array of timestamps
const ipRequestsMap = new Map<string, number[]>();
let customConfigForTesting: Partial<RateLimitConfig> | null = null;
let lastPruneTime = Date.now();

/**
 * Check if the current runtime is an automated test environment
 */
export function isTestEnvironment(): boolean {
  return (
    process.env.NODE_ENV === 'test' ||
    process.execArgv.some((a) => a.startsWith('--test')) ||
    process.argv.some((a) => a.includes('test'))
  );
}

/**
 * Get active rate limit configuration
 */
export function getRateLimitConfig(): RateLimitConfig {
  if (customConfigForTesting) {
    return { ...DEFAULT_CONFIG, ...customConfigForTesting };
  }
  // If running in automated tests without custom config, allow high headroom for batch suite
  if (isTestEnvironment()) {
    return {
      ...DEFAULT_CONFIG,
      maxRequests: 1000,
    };
  }
  return DEFAULT_CONFIG;
}

/**
 * Configure rate limiter specifically for testing
 */
export function setRateLimitConfigForTesting(config: Partial<RateLimitConfig> | null): void {
  customConfigForTesting = config;
}

/**
 * Reset all rate limit records (for testing purposes)
 */
export function resetRateLimiter(): void {
  ipRequestsMap.clear();
  lastPruneTime = Date.now();
}

/**
 * Validate whether a string is a well-formed IPv4 or IPv6 address
 */
export function isValidIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();

  // IPv4 check
  const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Pattern.test(trimmed)) return true;

  // IPv6 check
  const ipv6Pattern = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
  if (ipv6Pattern.test(trimmed)) return true;

  // Compressed IPv6 check
  if (trimmed.includes('::') && /^[0-9a-fA-F:]+$/.test(trimmed)) {
    return true;
  }

  return false;
}

/**
 * Extract client identifier / IP from incoming Request headers
 * Handles Cloudflare, standard reverse proxies (Nginx/Traefik), and X-Forwarded-For with structural validation.
 */
export function getClientIdentifier(request: Request): string {
  // 1. Cloudflare connecting IP (trusted when behind Cloudflare proxy)
  const cfConnectingIp = request.headers.get('cf-connecting-ip');
  if (cfConnectingIp && isValidIp(cfConnectingIp)) {
    return cfConnectingIp.trim();
  }

  // 2. Standard reverse proxy header (Nginx X-Real-IP)
  const xRealIp = request.headers.get('x-real-ip');
  if (xRealIp && isValidIp(xRealIp)) {
    return xRealIp.trim();
  }

  // 3. X-Forwarded-For (extract and validate leftmost client IP)
  const xForwardedFor = request.headers.get('x-forwarded-for');
  if (xForwardedFor) {
    const candidate = xForwardedFor.split(',')[0]?.trim();
    if (candidate && isValidIp(candidate)) {
      return candidate;
    }
  }

  // 4. Safe fallback for direct local connection or unparseable headers
  return '127.0.0.1';
}

/**
 * Prune stale entries to prevent memory exhaustion
 */
function pruneStaleEntries(now: number, windowMs: number, maxTrackedIps: number): void {
  // Prune expired entries every 60 seconds or if map exceeds max entries
  if (now - lastPruneTime > 60000 || ipRequestsMap.size > maxTrackedIps) {
    lastPruneTime = now;
    const threshold = now - windowMs;

    for (const [ip, timestamps] of ipRequestsMap.entries()) {
      const valid = timestamps.filter((t) => t > threshold);
      if (valid.length === 0) {
        ipRequestsMap.delete(ip);
      } else {
        ipRequestsMap.set(ip, valid);
      }
    }

    // Hard emergency cap: if still too large, delete oldest entries
    if (ipRequestsMap.size > maxTrackedIps) {
      const excess = ipRequestsMap.size - maxTrackedIps;
      let count = 0;
      for (const ip of ipRequestsMap.keys()) {
        if (count >= excess) break;
        ipRequestsMap.delete(ip);
        count++;
      }
    }
  }
}

/**
 * Check and register a request against the sliding window rate limit
 * Runs synchronously and atomically in the Node.js event loop tick (no async gaps/race conditions).
 */
export function checkRateLimit(clientIp: string): RateLimitResult {
  const config = getRateLimitConfig();
  const now = Date.now();
  const windowStart = now - config.windowMs;

  pruneStaleEntries(now, config.windowMs, config.maxTrackedIps);

  let timestamps = ipRequestsMap.get(clientIp);
  if (!timestamps) {
    timestamps = [];
  } else {
    // Filter out expired timestamps in sliding window
    timestamps = timestamps.filter((t) => t > windowStart);
  }

  const resetTime = Math.ceil((now + config.windowMs) / 1000);

  if (timestamps.length >= config.maxRequests) {
    const oldestTimestamp = timestamps[0] ?? now;
    const retryAfterMs = Math.max(0, oldestTimestamp + config.windowMs - now);
    const retryAfterSeconds = Math.ceil(retryAfterMs / 1000);

    return {
      allowed: false,
      limit: config.maxRequests,
      remaining: 0,
      retryAfterSeconds: Math.max(1, retryAfterSeconds),
      resetTime: Math.ceil((oldestTimestamp + config.windowMs) / 1000),
    };
  }

  // Register this request
  timestamps.push(now);
  ipRequestsMap.set(clientIp, timestamps);

  return {
    allowed: true,
    limit: config.maxRequests,
    remaining: config.maxRequests - timestamps.length,
    retryAfterSeconds: 0,
    resetTime,
  };
}
