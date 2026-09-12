/**
 * HARIS (حارس) — Semantic Intelligence Core Facade
 *
 * Provides a unified integration pipeline:
 * Input
 * → Arabic normalization
 * → deterministic analysis
 * → Gemini semantic interpretation
 * → evidence fusion
 * → Scam DNA
 * → risk assessment
 * → actionable explanation
 */

import { analyzeDeterministic } from '../analysis';
import { GeminiInputContext } from './schema';
import { analyzeSemantics, SemanticAnalyzerOptions } from './analyzer';
import { fuseEvidenceAndAssess, FusedAnalysisResult } from './fusion';

export * from './schema';
export * from './client';
export * from './prompts';
export * from './parser';
export * from './analyzer';
export * from './fusion';

/**
 * Top-level semantic analysis pipeline for text and/or URL inputs
 */
export async function analyzeWithSemanticIntelligence(
  input: {
    text?: string;
    url?: string;
  },
  options: SemanticAnalyzerOptions = {}
): Promise<FusedAnalysisResult> {
  // 1. Always execute passive deterministic analysis first
  const deterministic = analyzeDeterministic(input);

  const rawText = (input.text || '').trim();

  // 2. If no text is provided, return pure deterministic result without calling Gemini
  if (rawText.length === 0) {
    return fuseEvidenceAndAssess(deterministic, null, {
      fallbackReason: 'No textual message content provided for semantic analysis.',
    });
  }

  // 3. Assemble structured context for Gemini
  const context: GeminiInputContext = {
    originalText: rawText,
    normalizedText: deterministic.normalizedText?.normalizedText || rawText,
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

  // 4. Run semantic reasoning through Gemini
  const semanticResult = await analyzeSemantics(context, options);

  // 5. Fuse deterministic evidence with semantic intelligence
  if (semanticResult.success && semanticResult.data) {
    return fuseEvidenceAndAssess(deterministic, semanticResult.data, {
      modelUsed: semanticResult.modelUsed,
    });
  }

  // 6. Graceful Fallback if Gemini failed or is unconfigured
  return fuseEvidenceAndAssess(deterministic, null, {
    fallbackReason: semanticResult.fallbackReason || 'Semantic analysis unavailable',
  });
}
