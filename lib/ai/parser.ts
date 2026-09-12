/**
 * HARIS (حارس) — Gemini Response Parser & Hallucination Guard
 *
 * Parses raw model output, enforces Zod schema validation,
 * and symmetrically validates that cited evidence actually exists in user text.
 */

import { GeminiSemanticAnalysis, GeminiSemanticAnalysisSchema } from './schema';
import { stripDiacriticsAndTatweel, normalizeArabicLetters } from '../analysis/normalizer';

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
 * Normalize text symmetrically for evidence grounding verification
 * Applies the exact same Arabic cleaning strategy (diacritics, tatweel, letter normalization)
 */
export function normalizeForEvidenceMatching(text: string): string {
  if (!text) return '';

  let cleaned = text
    .toLowerCase()
    .replace(/[\u200B-\u200D\uFEFF\u00A0]/g, ' ');

  cleaned = stripDiacriticsAndTatweel(cleaned);
  cleaned = normalizeArabicLetters(cleaned);
  cleaned = cleaned.replace(/\s+/g, ' ').trim();

  return cleaned;
}

/**
 * Check if evidence text actually exists in the source message after symmetric normalization.
 *
 * STRICT PRECISION PRINCIPLE:
 * Evidence presented by the model as a quotation MUST actually appear as a contiguous substring
 * in the source text. Partial-token overlap or paraphrasing is strictly rejected.
 */
export function isEvidenceGrounded(evidence: string, originalText: string, normalizedText: string): boolean {
  if (!evidence || evidence.trim().length === 0) {
    return false;
  }

  const normEv = normalizeForEvidenceMatching(evidence);
  if (normEv.length === 0) {
    return false;
  }

  // Strip leading/trailing quotation punctuation that the model might wrap around evidence
  const cleanEv = normEv.replace(/^["'«»“”„]+|["'«»“”„]+$/g, '').trim();
  if (cleanEv.length === 0) {
    return false;
  }

  const normOrig = normalizeForEvidenceMatching(originalText);
  const normText = normalizeForEvidenceMatching(normalizedText);

  // 1. Direct normalized contiguous substring match
  if (normOrig.includes(cleanEv) || normText.includes(cleanEv)) {
    return true;
  }

  // 2. Normalized punctuation-agnostic contiguous substring match
  // Handles minor internal punctuation differences (e.g. "البطاقة، ورمز" vs "البطاقة ورمز")
  const noPunctEv = cleanEv.replace(/[.,;:\n!?؟،؛\-_\/\\()[\]{}«»"']/g, ' ').replace(/\s+/g, ' ').trim();
  if (noPunctEv.length >= 3) {
    const noPunctOrig = normOrig.replace(/[.,;:\n!?؟،؛\-_\/\\()[\]{}«»"']/g, ' ').replace(/\s+/g, ' ').trim();
    const noPunctText = normText.replace(/[.,;:\n!?؟،؛\-_\/\\()[\]{}«»"']/g, ' ').replace(/\s+/g, ' ').trim();

    if (noPunctOrig.includes(noPunctEv) || noPunctText.includes(noPunctEv)) {
      return true;
    }
  }

  // Any other candidate (such as partial token overlap, disjoint words, or paraphrases) is REJECTED
  return false;
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
