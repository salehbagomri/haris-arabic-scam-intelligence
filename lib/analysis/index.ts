/**
 * HARIS (حارس) — Deterministic Analysis Core Facade
 *
 * Provides a unified integration boundary for text normalization, passive URL analysis,
 * signal extraction, and risk assessment.
 */

import { normalizeArabicText, NormalizedTextResult } from './normalizer';
import { analyzeUrl, UrlAnalysisResult } from './urlAnalyzer';
import { extractDeterministicSignals, SignalExtractionResult } from './signals';
import { calculateRiskScore, RiskAssessmentResult } from './riskEngine';
import { ExtractedSignal, FeatureKey } from './taxonomy';

export * from './taxonomy';
export * from './normalizer';
export * from './urlAnalyzer';
export * from './signals';
export * from './riskEngine';

export interface DeterministicAnalysisResult {
  normalizedText?: NormalizedTextResult;
  urlResults: UrlAnalysisResult[];
  extractedSignals: ExtractedSignal[];
  detectedFeatures: FeatureKey[];
  hasCriticalThreat: boolean;
  assessment: RiskAssessmentResult;
}

/**
 * Top-level deterministic analyzer for standalone text and/or URL inputs
 */
export function analyzeDeterministic(input: {
  text?: string;
  url?: string;
}): DeterministicAnalysisResult {
  const urlResults: UrlAnalysisResult[] = [];
  let normalizedText: NormalizedTextResult | undefined;

  // 1. Process explicit URL if provided
  if (input.url && input.url.trim().length > 0) {
    urlResults.push(analyzeUrl(input.url.trim()));
  }

  // 2. Process text if provided
  if (input.text && input.text.trim().length > 0) {
    normalizedText = normalizeArabicText(input.text.trim());

    // Also analyze any embedded URLs detected inside text
    for (const extractedUrl of normalizedText.extractedUrls) {
      // Don't duplicate if already analyzed
      if (!urlResults.some((r) => r.rawUrl === extractedUrl)) {
        urlResults.push(analyzeUrl(extractedUrl));
      }
    }
  }

  // 3. Extract deterministic signals
  const dummyNormalized: NormalizedTextResult = {
    originalText: '',
    normalizedText: '',
    tokens: [],
    extractedUrls: [],
    hasObfuscation: false,
    hasArabizi: false,
    hasExcessiveRepetition: false,
  };

  const signalResult: SignalExtractionResult = extractDeterministicSignals(
    normalizedText || dummyNormalized,
    urlResults
  );

  // 4. Calculate Risk Assessment across all extracted and analyzed URLs
  const assessment = calculateRiskScore(signalResult.signals, urlResults);

  return {
    normalizedText,
    urlResults,
    extractedSignals: signalResult.signals,
    detectedFeatures: signalResult.detectedFeatures,
    hasCriticalThreat: signalResult.hasCriticalThreat,
    assessment,
  };
}
