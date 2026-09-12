/**
 * HARIS (حارس) — Screenshot Intelligence Configuration & Resource Limits
 *
 * Centralizes limits, permitted formats, and size constraints for screenshot
 * processing to safeguard server resources, prevent memory exhaustion, and
 * maintain strict privacy boundaries.
 */

export const VISION_CONFIG = {
  /** Maximum image payload size in bytes (10 MB) */
  maxImageSizeBytes: 10 * 1024 * 1024,

  /** Supported image MIME types for visual extraction */
  allowedMimeTypes: [
    'image/png',
    'image/jpeg',
    'image/webp',
    'image/heic',
    'image/gif',
  ] as const,

  /** Maximum character length of extracted text */
  maxExtractedTextLength: 10000,

  /** Maximum count of extracted URLs */
  maxExtractedUrls: 20,

  /** Maximum count of visible entities identified */
  maxVisibleEntities: 20,

  /** Maximum count of visual signals */
  maxVisualSignals: 20,

  /** Maximum count of analytical uncertainties */
  maxUncertainties: 20,

  /** Default timeout for Gemini Vision API requests in milliseconds */
  defaultTimeoutMs: 15000,
} as const;

export type AllowedImageMimeType = (typeof VISION_CONFIG.allowedMimeTypes)[number];

/**
 * Check if the provided MIME type is in the allowed list
 */
export function isAllowedImageMimeType(mimeType: string): mimeType is AllowedImageMimeType {
  const normalized = (mimeType || '').trim().toLowerCase();
  return (VISION_CONFIG.allowedMimeTypes as readonly string[]).includes(normalized);
}

export interface ImageValidationResult {
  valid: boolean;
  error?: string;
  byteLength?: number;
}

/**
 * Validate image buffer or base64 string against format and size constraints
 */
export function validateImageConstraints(input: {
  buffer?: Buffer;
  base64?: string;
  mimeType: string;
}): ImageValidationResult {
  // 1. MIME type validation
  if (!input.mimeType || !isAllowedImageMimeType(input.mimeType)) {
    return {
      valid: false,
      error: `Unsupported image MIME type '${input.mimeType}'. Supported formats: ${VISION_CONFIG.allowedMimeTypes.join(', ')}.`,
    };
  }

  // 2. Resolve byte length
  let byteLength = 0;
  if (input.buffer) {
    byteLength = input.buffer.length;
  } else if (input.base64) {
    const cleanBase64 = input.base64.replace(/^data:image\/[a-z]+;base64,/, '');
    byteLength = Buffer.from(cleanBase64, 'base64').length;
  } else {
    return {
      valid: false,
      error: 'No image data provided (neither buffer nor base64).',
    };
  }

  // 3. Check for empty or 0-byte image
  if (byteLength === 0) {
    return {
      valid: false,
      error: 'Provided image is empty (0 bytes).',
    };
  }

  // 4. Check maximum file size
  if (byteLength > VISION_CONFIG.maxImageSizeBytes) {
    return {
      valid: false,
      error: `Image size (${(byteLength / 1024 / 1024).toFixed(2)} MB) exceeds the maximum allowed limit of ${VISION_CONFIG.maxImageSizeBytes / 1024 / 1024} MB.`,
      byteLength,
    };
  }

  return {
    valid: true,
    byteLength,
  };
}
