/**
 * HARIS (حارس) — Gemini Semantic Analysis Schemas & Contracts
 *
 * Strict Zod validation schemas for Gemini model responses.
 * Guarantees schema compliance and runtime type safety.
 */

import { z } from 'zod';
import { SCAM_TYPES, SCAM_DNA_FEATURES, FeatureKey, Severity } from '../analysis/taxonomy';

export const ScamTypeEnum = z.enum(SCAM_TYPES);
export const ScamDnaFeatureEnum = z.enum(SCAM_DNA_FEATURES);

export const SemanticSignalSchema = z.object({
  type: z.string().min(1, 'Signal type is required'),
  description: z.string().min(1, 'Signal description is required'),
  evidence: z.string().min(1, 'Signal evidence quote is required'),
  severity: z.enum(['low', 'medium', 'high']),
});

export const PsychologicalTacticSchema = z.object({
  type: z.string().min(1, 'Tactic type is required'),
  description: z.string().min(1, 'Tactic description is required'),
  evidence: z.string().min(1, 'Tactic evidence quote is required'),
});

export const ScamTypeCandidateSchema = z.object({
  type: ScamTypeEnum,
  confidence: z.number().min(0).max(1),
});

export const ScamDnaCandidateSchema = z.object({
  feature: ScamDnaFeatureEnum,
  evidence: z.string().min(1, 'Scam DNA candidate requires explicit evidence quote'),
  confidence: z.number().min(0).max(1),
});

export const GeminiSemanticAnalysisSchema = z.object({
  interpretation: z.string().min(1, 'Interpretation is required'),
  scamTypeCandidates: z.array(ScamTypeCandidateSchema),
  semanticSignals: z.array(SemanticSignalSchema),
  psychologicalTactics: z.array(PsychologicalTacticSchema),
  scamDnaCandidates: z.array(ScamDnaCandidateSchema),
  aiConfidence: z.number().min(0).max(1),
  uncertainties: z.array(z.string()),
});

export type SemanticSignal = z.infer<typeof SemanticSignalSchema>;
export type PsychologicalTactic = z.infer<typeof PsychologicalTacticSchema>;
export type ScamTypeCandidate = z.infer<typeof ScamTypeCandidateSchema>;
export type ScamDnaCandidate = z.infer<typeof ScamDnaCandidateSchema>;
export type GeminiSemanticAnalysis = z.infer<typeof GeminiSemanticAnalysisSchema>;

/**
 * Input context supplied to Gemini semantic analyzer
 */
export interface GeminiInputContext {
  originalText: string;
  normalizedText: string;
  extractedUrls: string[];
  deterministicSignals: Array<{
    featureId: FeatureKey;
    evidenceText: string;
    explanation: string;
    severity: Severity;
  }>;
  deterministicUrlFindings?: Array<{
    url: string;
    hostname: string;
    isSuspicious: boolean;
    anomalies: string[];
  }>;
}
