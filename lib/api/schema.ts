/**
 * HARIS (حارس) — Unified Analysis API Contracts & Schemas
 *
 * Defines strict Zod validation schemas and TypeScript types for the unified
 * server-side analysis endpoint (POST /api/analyze).
 */

import { z } from 'zod';
import { VISION_CONFIG, isAllowedImageMimeType } from '../config/vision';

// ============================================================================
// 1. Request Contract
// ============================================================================

/**
 * Supported image MIME types per VISION_CONFIG:
 * - image/png
 * - image/jpeg
 * - image/webp
 * - image/heic
 * - image/gif
 * (Note: image/heif is not supported)
 */
export const screenshotPayloadSchema = z
  .object({
    mimeType: z
      .string()
      .trim()
      .min(1, 'Screenshot mimeType cannot be empty')
      .refine((val) => isAllowedImageMimeType(val), {
        message: `Unsupported screenshot MIME type. Allowed formats: ${VISION_CONFIG.allowedMimeTypes.join(', ')}`,
      }),
    data: z
      .string()
      .trim()
      .min(1, 'Screenshot data cannot be empty')
      .max(
        VISION_CONFIG.maxScreenshotDataLength,
        `Screenshot data exceeds maximum permitted length of ${VISION_CONFIG.maxScreenshotDataLength} characters`
      ),
  })
  .strict();

export type ScreenshotPayload = z.infer<typeof screenshotPayloadSchema>;

export const analyzeRequestSchema = z
  .object({
    text: z
      .string()
      .trim()
      .max(5000, 'Text input exceeds maximum permitted limit of 5000 characters')
      .optional(),
    url: z
      .string()
      .trim()
      .max(2048, 'URL input exceeds maximum permitted limit of 2048 characters')
      .optional(),
    screenshot: screenshotPayloadSchema.optional(),
  })
  .strict()
  .refine(
    (data) => {
      const hasText = typeof data.text === 'string' && data.text.length > 0;
      const hasUrl = typeof data.url === 'string' && data.url.length > 0;
      const hasScreenshot =
        data.screenshot !== undefined &&
        typeof data.screenshot.data === 'string' &&
        data.screenshot.data.length > 0;
      return hasText || hasUrl || hasScreenshot;
    },
    {
      message: 'Request must include at least one valid input: text, url, or screenshot.',
    }
  );

export type AnalyzeRequest = z.infer<typeof analyzeRequestSchema>;

// ============================================================================
// 2. Response Contract
// ============================================================================

export const scamDnaResponseItemSchema = z.object({
  featureId: z.string(),
  nameAr: z.string(),
  nameEn: z.string(),
  detected: z.boolean(),
  severity: z.enum(['low', 'medium', 'high']),
  provenance: z.enum(['deterministic', 'ai', 'both']),
  evidence: z.array(z.string()),
  explanations: z.array(z.string()),
});

export type ScamDnaResponseItem = z.infer<typeof scamDnaResponseItemSchema>;

export const evidenceResponseItemSchema = z.object({
  id: z.string(),
  title: z.string(),
  description: z.string(),
  severity: z.enum(['low', 'medium', 'high']),
  source: z.enum(['technical', 'linguistic', 'behavioral', 'ai', 'visual']),
  provenance: z.enum(['deterministic', 'ai', 'ocr', 'both']),
});

export type EvidenceResponseItem = z.infer<typeof evidenceResponseItemSchema>;

export const analyzeResponseSchema = z.object({
  riskLevel: z.enum(['low', 'suspicious', 'high']),
  riskScore: z.number().min(0).max(100),
  scamType: z.string(),
  scamTypeNameAr: z.string(),
  interpretation: z.string(),
  scamDna: z.array(scamDnaResponseItemSchema),
  evidence: z.array(evidenceResponseItemSchema),
  actionableAdvice: z.array(z.string()),
  uncertainties: z.array(z.string()),
  aiConfidence: z.number().min(0).max(1).nullable(),
  extractionConfidence: z.number().min(0).max(1).nullable(),
  isExtractionFailure: z.boolean(),
  analyzedAt: z.string(),
});

export type AnalyzeResponse = z.infer<typeof analyzeResponseSchema>;
