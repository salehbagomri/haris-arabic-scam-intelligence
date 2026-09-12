/**
 * HARIS (حارس) — Gemini Response Parser & Hallucination Guard
 *
 * Parses raw model output, enforces Zod schema validation,
 * and validates that cited evidence actually exists in user text.
 */

import { GeminiSemanticAnalysis, GeminiSemanticAnalysisSchema } from './schema';

export interface ParseResult {
  success: boolean;
  data?: GeminiSemanticAnalysis;
  error?: string;
}

/**
 * Strip Markdown code fences and whitespace from raw LLM responses
 */
export function cleanJsonFence(rawText: string): string {
  let cleaned = (rawText || '').trim();

  // Match ```json ... ``` or ``` ... ```
  if (cleaned.startsWith('```')) {
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, '');
    cleaned = cleaned.replace(/\s*```$/, '');
  }

  return cleaned.trim();
}

/**
 * Check if evidence text has plausible overlap with the source message
 */
function isEvidenceGrounded(evidence: string, originalText: string, normalizedText: string): boolean {
  if (!evidence || evidence.trim().length === 0) {
    return false;
  }

  const cleanEv = evidence.trim().toLowerCase();
  const cleanOrig = originalText.toLowerCase();
  const cleanNorm = normalizedText.toLowerCase();

  // 1. Exact substring match in original or normalized text
  if (cleanOrig.includes(cleanEv) || cleanNorm.includes(cleanEv)) {
    return true;
  }

  // 2. Token overlap check (at least 50% of non-trivial words must appear in source)
  const tokens = cleanEv.split(/\s+/).filter((t) => t.length >= 3);
  if (tokens.length === 0) {
    return cleanOrig.includes(cleanEv);
  }

  const matchingTokens = tokens.filter((t) => cleanOrig.includes(t) || cleanNorm.includes(t));
  return matchingTokens.length / tokens.length >= 0.5;
}

/**
 * Parse and validate Gemini response with schema and anti-hallucination checks
 */
export function parseAndValidateSemanticOutput(
  rawText: string,
  originalText: string,
  normalizedText: string
): ParseResult {
  const cleanedJson = cleanJsonFence(rawText);

  let parsedObject: unknown;
  try {
    parsedObject = JSON.parse(cleanedJson);
  } catch (err) {
    return {
      success: false,
      error: `Malformed JSON from model: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const zodValidation = GeminiSemanticAnalysisSchema.safeParse(parsedObject);
  if (!zodValidation.success) {
    const errorIssues = zodValidation.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join(', ');
    return {
      success: false,
      error: `Zod schema validation failed: ${errorIssues}`,
    };
  }

  const analysis = zodValidation.data;

  // Anti-Hallucination Evidence Filter:
  // Prune any candidate signals whose evidence does not appear in the source message
  const validDnaCandidates = analysis.scamDnaCandidates.filter((c) =>
    isEvidenceGrounded(c.evidence, originalText, normalizedText)
  );

  const validSemanticSignals = analysis.semanticSignals.filter((s) =>
    isEvidenceGrounded(s.evidence, originalText, normalizedText)
  );

  const validTactics = analysis.psychologicalTactics.filter((t) =>
    isEvidenceGrounded(t.evidence, originalText, normalizedText)
  );

  return {
    success: true,
    data: {
      ...analysis,
      scamDnaCandidates: validDnaCandidates,
      semanticSignals: validSemanticSignals,
      psychologicalTactics: validTactics,
    },
  };
}
