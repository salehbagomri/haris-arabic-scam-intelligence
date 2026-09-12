/**
 * HARIS (حارس) — Screenshot Intelligence Zod Schema & Types
 *
 * Strict validation schema for multimodal vision extraction, OCR text recovery,
 * visible entity recognition, and visual manipulation cues.
 */

import { z } from 'zod';
import { VISION_CONFIG } from '../config/vision';

/**
 * Controlled visual signal taxonomy (Section 8)
 */
export const VISUAL_SIGNAL_TYPES = [
  'impersonation_visual',
  'suspicious_verification_ui',
  'suspicious_payment_prompt',
  'urgency_visual',
  'fake_security_warning',
  'suspicious_branding',
  'suspicious_contact_identity',
  'credential_collection_ui',
] as const;

export type VisualSignalType = (typeof VISUAL_SIGNAL_TYPES)[number];

export const visualSignalSchema = z.object({
  type: z.enum(VISUAL_SIGNAL_TYPES),
  description: z
    .string()
    .min(1, 'Description cannot be empty')
    .max(1000, 'Description exceeds 1000 characters limit'),
  evidence: z
    .string()
    .min(1, 'Evidence cannot be empty')
    .max(500, 'Evidence exceeds 500 characters limit'),
  severity: z.enum(['low', 'medium', 'high']),
});

export type VisualSignal = z.infer<typeof visualSignalSchema>;

export const visibleEntitySchema = z.object({
  type: z
    .string()
    .min(1, 'Entity type cannot be empty')
    .max(100, 'Entity type exceeds 100 characters limit'),
  text: z
    .string()
    .min(1, 'Entity text cannot be empty')
    .max(500, 'Entity text exceeds 500 characters limit'),
  confidence: z
    .number()
    .min(0, 'Confidence must be at least 0')
    .max(1, 'Confidence cannot exceed 1'),
});

export type VisibleEntity = z.infer<typeof visibleEntitySchema>;

/**
 * Top-level Zod schema for screenshot extraction output from Gemini Vision
 */
export const screenshotExtractionSchema = z.object({
  /** Complete OCR text extracted from screenshot */
  extractedText: z
    .string()
    .max(VISION_CONFIG.maxExtractedTextLength, 'Extracted text exceeds maximum character limit'),

  /** All URLs, links, or domain references visibly present in image */
  extractedUrls: z
    .array(z.string().min(1).max(2000))
    .max(VISION_CONFIG.maxExtractedUrls, 'Too many extracted URLs'),

  /** Visible key entities (e.g. sender display name, logo text, button CTAs) */
  visibleEntities: z
    .array(visibleEntitySchema)
    .max(VISION_CONFIG.maxVisibleEntities, 'Too many visible entities'),

  /** Visual design or layout manipulation signals */
  visualSignals: z
    .array(visualSignalSchema)
    .max(VISION_CONFIG.maxVisualSignals, 'Too many visual signals'),

  /** Limitations, visual noise, or ambiguities encountered */
  uncertainties: z
    .array(z.string().min(1).max(500))
    .max(VISION_CONFIG.maxUncertainties, 'Too many uncertainties'),

  /**
   * Confidence that the model successfully read/interpreted the screenshot (0 - 1).
   * NOTE: This indicates extraction/reading fidelity, NOT scam probability!
   */
  extractionConfidence: z
    .number()
    .min(0, 'Extraction confidence must be >= 0')
    .max(1, 'Extraction confidence must be <= 1'),
});

export type ScreenshotExtractionData = z.infer<typeof screenshotExtractionSchema>;

export interface ScreenshotInput {
  buffer?: Buffer;
  base64?: string;
  mimeType: string;
}
