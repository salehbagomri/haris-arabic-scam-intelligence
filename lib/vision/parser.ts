/**
 * HARIS (حارس) — Screenshot Vision Response Parser & Grounding Guard
 *
 * Parses raw Gemini Multimodal output, validates against Zod schema,
 * and validates that extracted textual citations are grounded in the OCR text.
 */

import {
  screenshotExtractionSchema,
  ScreenshotExtractionData,
  VisualSignal,
  VisibleEntity,
} from './schema';
import {
  cleanJsonFence,
  isEvidenceGrounded,
  normalizeForEvidenceMatching,
} from '../ai/parser';

export interface VisionParseResult {
  success: boolean;
  data?: ScreenshotExtractionData;
  error?: string;
}

/**
 * Parse and validate multimodal vision extraction output
 */
export function parseAndValidateVisionOutput(rawResponseText: string): VisionParseResult {
  if (!rawResponseText || rawResponseText.trim().length === 0) {
    return {
      success: false,
      error: 'Empty response received from vision model.',
    };
  }

  // 1. Clean markdown code fences
  const cleanedJson = cleanJsonFence(rawResponseText);

  // 2. Safely parse JSON structure
  let parsedObject: unknown;
  try {
    parsedObject = JSON.parse(cleanedJson);
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    return {
      success: false,
      error: `Malformed JSON from vision model: ${errorMsg}`,
    };
  }

  // 3. Validate against Zod schema
  const validation = screenshotExtractionSchema.safeParse(parsedObject);
  if (!validation.success) {
    const fieldErrors = validation.error.issues
      .map((issue) => `${issue.path.join('.') || 'root'}: ${issue.message}`)
      .join('; ');
    return {
      success: false,
      error: `Vision schema validation failed: ${fieldErrors}`,
    };
  }

  const rawData = validation.data;
  const originalOcrText = rawData.extractedText || '';
  const normalizedOcrText = normalizeForEvidenceMatching(originalOcrText);

  // 4. Grounding & Anti-Hallucination Guard for Textual Citations
  // A. Filter visible entities if they claim to quote text not present in the extracted text
  const groundedEntities: VisibleEntity[] = [];
  for (const entity of rawData.visibleEntities) {
    if (!originalOcrText || originalOcrText.trim().length === 0) {
      // If OCR text is completely empty, entities claiming textual quotes are ungrounded
      if (entity.type === 'button_cta' || entity.type === 'account_number') {
        continue;
      }
      groundedEntities.push(entity);
      continue;
    }

    // Check if the entity text appears in the OCR text
    const isGrounded = isEvidenceGrounded(entity.text, originalOcrText, normalizedOcrText);
    if (isGrounded) {
      groundedEntities.push(entity);
    } else {
      // If not an exact quote, check if normalized substring matches
      const normEntity = normalizeForEvidenceMatching(entity.text);
      if (normEntity.length > 0 && normalizedOcrText.includes(normEntity)) {
        groundedEntities.push(entity);
      } else if (entity.type === 'brand_logo' || entity.type === 'visual_cue') {
        // Visual cues like brand logo observations may describe visual features
        groundedEntities.push(entity);
      }
      // Otherwise pruned as ungrounded hallucination
    }
  }

  // B. Ground visual signals
  const groundedSignals: VisualSignal[] = [];
  for (const signal of rawData.visualSignals) {
    // If evidence contains a direct quotation (e.g. "نص الدليل" or quotes)
    const quoteMatch = signal.evidence.match(/["'«]([^"'»]+)["'»]/);
    if (quoteMatch && originalOcrText.trim().length > 0) {
      const quotedText = quoteMatch[1].trim();
      const isQuoteGrounded = isEvidenceGrounded(quotedText, originalOcrText, normalizedOcrText);
      if (!isQuoteGrounded) {
        // Fabricated quote inside evidence -> reject ungrounded signal
        continue;
      }
    }

    groundedSignals.push(signal);
  }

  return {
    success: true,
    data: {
      ...rawData,
      visibleEntities: groundedEntities,
      visualSignals: groundedSignals,
    },
  };
}
