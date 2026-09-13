/**
 * HARIS (حارس) — Unified Multimodal Analysis Pipeline
 *
 * Implements the shared analysis pipeline (Section 1 & 19):
 *
 *              ┌→ Text Input ──────────────┐
 * Input ───────┤                           ├→ Deterministic → Semantic AI → Fusion → Scam DNA
 *              └→ Screenshot Extraction ───┘
 *                       ↓
 *               Extracted Text + Visual Evidence
 */

import { GoogleGenAI } from '@google/genai';
import { analyzeDeterministic, analyzeUrl, DeterministicAnalysisResult } from '../analysis';
import {
  analyzeSemantics,
  fuseEvidenceAndAssess,
  FusedAnalysisResult,
  GeminiInputContext,
} from '../ai';
import { ScreenshotInput, ScreenshotExtractionData } from './schema';
import { extractScreenshotContent } from './analyzer';
import { sanitizeToUserSafeUncertainty, USER_SAFE_ERROR_MESSAGES } from '../security/safeErrors';

export interface UnifiedAnalysisInput {
  text?: string;
  url?: string;
  screenshot?: ScreenshotInput;
}

export interface UnifiedPipelineOptions {
  client?: GoogleGenAI | null;
  model?: string;
  timeoutMs?: number;
  maxAiScoreContribution?: number;
  maxVisualScoreContribution?: number;
}

/**
 * Execute unified analysis across text, URL, and screenshot modalities
 */
export async function analyzeUnified(
  input: UnifiedAnalysisInput,
  options: UnifiedPipelineOptions = {}
): Promise<FusedAnalysisResult> {
  let visualData: ScreenshotExtractionData | null = null;
  let visualFallbackReason: string | undefined;

  // 1. Process Screenshot modality if provided
  if (input.screenshot) {
    const visionResult = await extractScreenshotContent(input.screenshot, options);
    if (visionResult.success && visionResult.data) {
      visualData = visionResult.data;
    } else {
      visualFallbackReason = visionResult.fallbackReason || 'Screenshot extraction failed.';
    }
  }

  // 2. Resolve aggregated text and URLs
  const rawTextParts: string[] = [];
  if (input.text && input.text.trim().length > 0) {
    rawTextParts.push(input.text.trim());
  }
  if (visualData && visualData.extractedText && visualData.extractedText.trim().length > 0) {
    rawTextParts.push(visualData.extractedText.trim());
  }
  const aggregatedText = rawTextParts.join('\n').trim();

  // 3. Early structured fallback if ONLY a screenshot was provided and extraction failed
  if (!aggregatedText && !input.url && input.screenshot && !visualData) {
    const emptyDeterministic = analyzeDeterministic({});
    const safeReason = sanitizeToUserSafeUncertainty(visualFallbackReason);
    return fuseEvidenceAndAssess(emptyDeterministic, null, {
      fallbackReason: visualFallbackReason,
      visualData: null,
      isExtractionFailure: true,
      overrideInterpretation: USER_SAFE_ERROR_MESSAGES.INTERPRETATION_EXTRACTION_FAILED,
      additionalAdvice: [
        'يرجى إعادة رفع لقطة شاشة بدقة أعلى وأكثر وضوحاً، مع التأكد من وضوح النصوص والإضاءة.',
        'يمكنك نسخ نص الرسالة أو الرابط المريب ولصقه مباشرة في حقل الفحص لإجراء فحص أمني دقيق ومباشر.',
      ],
      additionalUncertainties: [
        `فشل استخراج محتوى لقطة الشاشة: ${safeReason}`,
        USER_SAFE_ERROR_MESSAGES.UNREADABLE_IMAGE_DISCLAIMER,
      ],
    });
  }

  // 4. Execute deterministic analysis on aggregated text and explicit URL
  const deterministic: DeterministicAnalysisResult = analyzeDeterministic({
    text: aggregatedText,
    url: input.url,
  });

  // 4b. Incorporate any URLs discovered by Vision that were not in the text
  if (visualData && visualData.extractedUrls.length > 0) {
    for (const vUrl of visualData.extractedUrls) {
      const trimmed = (vUrl || '').trim();
      if (trimmed.length > 0 && !deterministic.urlResults.some((r) => r.rawUrl === trimmed)) {
        deterministic.urlResults.push(analyzeUrl(trimmed));
      }
    }
  }

  // 5. If no text is available, return deterministic assessment with visual data
  if (aggregatedText.length === 0) {
    return fuseEvidenceAndAssess(deterministic, null, {
      fallbackReason: 'No text content available for semantic analysis.',
      visualData,
    });
  }

  // 6. Assemble context for Gemini semantic intelligence
  const context: GeminiInputContext = {
    originalText: aggregatedText,
    normalizedText: deterministic.normalizedText?.normalizedText || aggregatedText,
    extractedUrls: deterministic.urlResults.map((u) => u.rawUrl),
    deterministicSignals: deterministic.extractedSignals.map((s) => ({
      featureId: s.featureId,
      evidenceText: s.evidenceText,
      explanation: s.explanation,
      severity: s.severity,
    })),
    deterministicUrlFindings: deterministic.urlResults.map((u) => ({
      url: u.rawUrl,
      hostname: u.hostname,
      isSuspicious: u.signals.length > 0 || u.brandSpoofing.detected,
      anomalies: u.anomalies,
    })),
  };

  // 7. Execute Gemini semantic intelligence
  const semanticResult = await analyzeSemantics(context, options);

  // 8. Fuse deterministic findings + semantic analysis + visual evidence
  return fuseEvidenceAndAssess(
    deterministic,
    semanticResult.success ? semanticResult.data : null,
    {
      modelUsed: semanticResult.modelUsed,
      fallbackReason:
        semanticResult.fallbackReason ||
        (visualFallbackReason ? `Visual extraction warning: ${visualFallbackReason}` : undefined),
      visualData,
      maxAiScoreContribution: options.maxAiScoreContribution,
      maxVisualScoreContribution: options.maxVisualScoreContribution,
      additionalUncertainties: visualFallbackReason
        ? [USER_SAFE_ERROR_MESSAGES.PARTIAL_EXTRACTION_WARNING]
        : undefined,
    }
  );
}
