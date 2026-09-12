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
  type: z.string().min(1, 'Signal type is required').max(200, 'Signal type exceeds 200 characters limit'),
  description: z.string().min(1, 'Signal description is required').max(1000, 'Signal description exceeds 1000 characters limit'),
  evidence: z.string().min(1, 'Signal evidence quote is required').max(500, 'Signal evidence exceeds 500 characters limit'),
  severity: z.enum(['low', 'medium', 'high']),
});

export const PsychologicalTacticSchema = z.object({
  type: z.string().min(1, 'Tactic type is required').max(200, 'Tactic type exceeds 200 characters limit'),
  description: z.string().min(1, 'Tactic description is required').max(1000, 'Tactic description exceeds 1000 characters limit'),
  evidence: z.string().min(1, 'Tactic evidence quote is required').max(500, 'Tactic evidence exceeds 500 characters limit'),
});

export const ScamTypeCandidateSchema = z.object({
  type: ScamTypeEnum,
  confidence: z.number().min(0).max(1),
});

export const ScamDnaCandidateSchema = z.object({
  feature: ScamDnaFeatureEnum,
  evidence: z.string().min(1, 'Scam DNA candidate requires explicit evidence quote').max(500, 'Scam DNA evidence exceeds 500 characters limit'),
  confidence: z.number().min(0).max(1),
});

export const GeminiSemanticAnalysisSchema = z.object({
  interpretation: z.string().min(1, 'Interpretation is required').max(2000, 'Interpretation exceeds 2000 characters limit'),
  scamTypeCandidates: z.array(ScamTypeCandidateSchema).max(20, 'scamTypeCandidates cannot exceed 20 items'),
  semanticSignals: z.array(SemanticSignalSchema).max(20, 'semanticSignals cannot exceed 20 items'),
  psychologicalTactics: z.array(PsychologicalTacticSchema).max(20, 'psychologicalTactics cannot exceed 20 items'),
  scamDnaCandidates: z.array(ScamDnaCandidateSchema).max(20, 'scamDnaCandidates cannot exceed 20 items'),
  aiConfidence: z.number().min(0).max(1),
  uncertainties: z.array(z.string().max(500, 'Uncertainty item exceeds 500 characters limit')).max(20, 'uncertainties cannot exceed 20 items'),
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
