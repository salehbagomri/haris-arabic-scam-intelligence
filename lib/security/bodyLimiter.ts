/**
 * HARIS (حارس) — HTTP Request Raw Body Size Limiter (SEC-FIND-03)
 *
 * Enforces a strict upper bound on incoming HTTP request bodies BEFORE JSON parsing.
 * Shields the server process from Memory Exhaustion (OOM), Garbage Collection thrashing,
 * and Denial-of-Service attacks via oversized payloads.
 *
 * Principles:
 * 1. PRE-PARSING DEFENSE: Rejects oversized bodies before JSON.parse() allocates memory.
 * 2. FAST-PATH REJECTION: Uses Content-Length header to drop oversized requests at byte 0.
 * 3. BOUNDED STREAM READER: Progressively measures stream chunks; aborts stream if limit exceeded.
 * 4. ZERO PERSISTENCE: Discarded chunks are never stored, logged, or inspected.
 * 5. SAFE LOCALIZED RESPONSE: Returns HTTP 413 with clean Arabic message.
 */

export const DEFAULT_MAX_RAW_BODY_BYTES = 16 * 1024 * 1024; // 16 MB

let customLimitForTesting: number | null = null;

/**
 * Configure raw body limit for test execution
 */
export function setRawBodyLimitBytesForTesting(bytes: number | null): void {
  customLimitForTesting = bytes;
}

/**
 * Retrieve the active maximum raw body byte limit
 */
export function getActiveMaxRawBodyBytes(): number {
  if (customLimitForTesting !== null && customLimitForTesting > 0) {
    return customLimitForTesting;
  }
  return DEFAULT_MAX_RAW_BODY_BYTES;
}

export const BODY_LIMIT_ERROR_MESSAGES = {
  PAYLOAD_TOO_LARGE: 'حجم حمولة الطلب يتجاوز الحد الأقصى المسموح به (16 ميجابايت).',
  STREAM_READ_ERROR: 'تعذر قراءة بيانات حمولة الطلب.',
  INVALID_JSON: 'Invalid JSON payload in request body.',
};

export interface BoundedBodyResult {
  ok: boolean;
  data?: unknown;
  status?: number;
  error?: string;
  bytesRead: number;
}

/**
 * Safely read and parse incoming Request JSON body with strict upper bound enforcement.
 * Aborts stream reading immediately if accumulated bytes exceed the limit.
 */
export async function readAndParseJsonWithLimit(
  request: Request,
  maxBytes: number = getActiveMaxRawBodyBytes()
): Promise<BoundedBodyResult> {
  // 1. Fast-Path: Inspect Content-Length header if present
  const contentLengthHeader = request.headers.get('content-length');
  if (contentLengthHeader) {
    const contentLength = parseInt(contentLengthHeader, 10);
    if (Number.isFinite(contentLength) && contentLength > maxBytes) {
      return {
        ok: false,
        status: 413,
        error: BODY_LIMIT_ERROR_MESSAGES.PAYLOAD_TOO_LARGE,
        bytesRead: 0,
      };
    }
  }

  // 2. Incremental Stream Reader with Byte Guard
  let bodyText: string;
  let bytesRead = 0;

  if (request.body) {
    const reader = request.body.getReader();
    const chunks: Uint8Array[] = [];

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        if (value) {
          bytesRead += value.byteLength;

          if (bytesRead > maxBytes) {
            // Cancel stream immediately to stop consuming network socket/buffer
            try {
              await reader.cancel('Payload exceeded maximum permitted raw body size.');
            } catch {
              // Ignore stream cancellation error
            }

            return {
              ok: false,
              status: 413,
              error: BODY_LIMIT_ERROR_MESSAGES.PAYLOAD_TOO_LARGE,
              bytesRead,
            };
          }

          chunks.push(value);
        }
      }
    } catch {
      if (bytesRead > maxBytes) {
        return {
          ok: false,
          status: 413,
          error: BODY_LIMIT_ERROR_MESSAGES.PAYLOAD_TOO_LARGE,
          bytesRead,
        };
      }
      return {
        ok: false,
        status: 400,
        error: BODY_LIMIT_ERROR_MESSAGES.STREAM_READ_ERROR,
        bytesRead,
      };
    }

    const combined = Buffer.concat(chunks, bytesRead);
    bodyText = combined.toString('utf-8');
  } else {
    // Fallback if request.body is null
    try {
      bodyText = await request.text();
      bytesRead = Buffer.byteLength(bodyText, 'utf-8');
      if (bytesRead > maxBytes) {
        return {
          ok: false,
          status: 413,
          error: BODY_LIMIT_ERROR_MESSAGES.PAYLOAD_TOO_LARGE,
          bytesRead,
        };
      }
    } catch {
      return {
        ok: false,
        status: 400,
        error: BODY_LIMIT_ERROR_MESSAGES.STREAM_READ_ERROR,
        bytesRead: 0,
      };
    }
  }

  // 3. JSON Parsing guarded behind byte limit
  try {
    const data = JSON.parse(bodyText);
    return {
      ok: true,
      data,
      bytesRead,
    };
  } catch {
    return {
      ok: false,
      status: 400,
      error: BODY_LIMIT_ERROR_MESSAGES.INVALID_JSON,
      bytesRead,
    };
  }
}
