/**
 * HARIS (حارس) — Adversarial Red-Team Types & Taxonomies (Phase 6B)
 *
 * Defines strictly typed structures for all 16 adversarial threat taxonomy categories,
 * attack vectors, failure classifications, severity tiers, evidence integrity rules,
 * and comprehensive benchmark summary statistics.
 */

import { ScamType, FeatureKey } from '../../lib/analysis/taxonomy';
import { RiskLevel } from '../../lib/types/analysis';
import { ScreenshotInput } from '../../lib/vision/schema';

export type RedTeamDialect = 'msa' | 'yemeni' | 'gulf' | 'egyptian' | 'mixed_en' | 'arabizi' | 'broken_arabic';

export const RED_TEAM_CATEGORIES = [
  'brand_mention_no_impersonation',
  'legitimate_otp_warnings',
  'legitimate_urgency',
  'benign_suspicious_domains',
  'arabizi_obfuscation',
  'unicode_confusables',
  'excessive_punctuation_emojis',
  'broken_arabic',
  'mixed_arabic_english',
  'misleading_screenshots',
  'visual_brand_resemblance',
  'multiple_contradictory_urls',
  'contradictory_evidence_fusion',
  'scam_language_no_url',
  'suspicious_url_in_legitimate_msg',
  'long_distracting_text',
] as const;

export type RedTeamTaxonomyCategory = (typeof RED_TEAM_CATEGORIES)[number];

export const RED_TEAM_CATEGORY_NAMES: Record<RedTeamTaxonomyCategory, string> = {
  brand_mention_no_impersonation: '1. Brand Mention Without Impersonation',
  legitimate_otp_warnings: '2. Legitimate OTP Warnings (Polarity Inversion)',
  legitimate_urgency: '3. Legitimate Urgency (Operational Deadlines)',
  benign_suspicious_domains: '4. Benign Suspicious-Looking Domains',
  arabizi_obfuscation: '5. Arabizi Obfuscation (Script Evasion)',
  unicode_confusables: '6. Unicode Confusables / Zero-Width / Tatweel',
  excessive_punctuation_emojis: '7. Excessive Punctuation / Emojis',
  broken_arabic: '8. Broken / Machine-Translated Arabic',
  mixed_arabic_english: '9. Mixed Arabic + English Concealment',
  misleading_screenshots: '10. Misleading Screenshots / Layout Spoofing',
  visual_brand_resemblance: '11. Visual Brand Resemblance (Color/Icon)',
  multiple_contradictory_urls: '12. Multiple / Decoy URLs',
  contradictory_evidence_fusion: '13. Contradictory Evidence Fusion',
  scam_language_no_url: '14. Scam Language Without Any URL',
  suspicious_url_in_legitimate_msg: '15. Suspicious URL Inside Legitimate Message',
  long_distracting_text: '16. Long Distracting Text Containing Malicious Instructions',
};

export type AdversarialFailureCategory =
  | 'FALSE_NEGATIVE'
  | 'FALSE_POSITIVE'
  | 'WRONG_SCAM_TYPE'
  | 'MISSED_DNA'
  | 'UNSUPPORTED_EVIDENCE'
  | 'EXTRACTION_FAILURE'
  | 'CONTRADICTORY_FUSION_FAILURE'
  | 'OTHER';

export type FailureSeverity = 'Critical' | 'High' | 'Medium' | 'Low';

export type AttackModality = 'text' | 'url' | 'text_url' | 'screenshot';

export interface RedTeamInput {
  text?: string;
  url?: string;
  screenshot?: ScreenshotInput;
}

export interface RedTeamItem {
  id: string;
  title: string;
  description: string;
  taxonomyCategory: RedTeamTaxonomyCategory;
  dialect: RedTeamDialect;
  modality: AttackModality;
  input: RedTeamInput;
  expectedRiskCategory: RiskLevel; // 'low' | 'suspicious' | 'high'
  expectedScamType: ScamType;
  expectedDnaFeatures: FeatureKey[];
  forbiddenDnaFeatures?: FeatureKey[]; // Features that must NOT be triggered (e.g. impersonation on mere brand mentions)
  rationale: string;
}

export interface EvidenceIntegrityViolation {
  rule: string;
  description: string;
  severity: FailureSeverity;
}

export interface RedTeamCaseFailure {
  category: AdversarialFailureCategory;
  severity: FailureSeverity;
  description: string;
}

export interface RedTeamCaseResult {
  id: string;
  title: string;
  taxonomyCategory: RedTeamTaxonomyCategory;
  taxonomyCategoryName: string;
  dialect: RedTeamDialect;
  modality: AttackModality;
  expectedRiskCategory: RiskLevel;
  actualRiskCategory: RiskLevel;
  riskScore: number;
  expectedScamType: ScamType;
  actualScamType: string;
  expectedDnaFeatures: FeatureKey[];
  actualDnaFeatures: FeatureKey[];
  isRiskCategoryCorrect: boolean;
  isScamTypeCorrect: boolean;
  isFalsePositive: boolean;
  isFalseNegative: boolean;
  isIndeterminate: boolean;
  evidenceItemsCount: number;
  evidenceItems: {
    type: string;
    description?: string;
    quote?: string;
    severity?: string;
    source?: string;
  }[];
  uncertainties: string[];
  actionableAdvice: string[];
  aiConfidence: number | null;
  extractionConfidence: number | null;
  failures: RedTeamCaseFailure[];
  evidenceIntegrityViolations: EvidenceIntegrityViolation[];
  hasFailure: boolean;
}

export interface CategoryMetricSummary {
  category: RedTeamTaxonomyCategory;
  categoryName: string;
  totalCases: number;
  failedCases: number;
  failureRate: number;
  falsePositives: number;
  falseNegatives: number;
  evidenceViolations: number;
  averageScore: number;
}

export interface DialectMetricSummary {
  dialect: RedTeamDialect;
  totalCases: number;
  failedCases: number;
  failureRate: number;
}

export interface ModalityMetricSummary {
  modality: AttackModality;
  totalCases: number;
  failedCases: number;
  failureRate: number;
}

export interface DnaFeatureRecallSummary {
  feature: FeatureKey;
  expectedCount: number;
  detectedCount: number;
  recall: number;
}

export interface RedTeamBenchmarkSummary {
  version: string;
  evaluatedAt: string;
  metadata: {
    datasetVersion: string;
    datasetSha256: string;
    runnerVersion: string;
    evaluationSourceCommit: string;
    nodeVersion: string;
    pipelineMode: string;
    geminiConfigured: boolean;
  };
  totalCases: number;
  failedCasesCount: number;
  overallFailureRate: number;
  falsePositivesCount: number;
  falsePositiveRate: number;
  falseNegativesCount: number;
  falseNegativeRate: number;
  indeterminateCount: number;
  indeterminateRate: number;
  totalFailuresCount: number;
  failuresByCategoryType: Record<AdversarialFailureCategory, number>;
  failuresBySeverity: Record<FailureSeverity, number>;
  evidenceIntegrityViolationsCount: number;
  scamTypeDeterminateAccuracy: number;
  scamTypeEvaluatedCases: number;
  categoryBreakdown: Record<RedTeamTaxonomyCategory, CategoryMetricSummary>;
  dialectBreakdown: Record<string, DialectMetricSummary>;
  modalityBreakdown: Record<string, ModalityMetricSummary>;
  dnaFeatureRecall: DnaFeatureRecallSummary[];
  highestSeverityFailures: RedTeamCaseResult[];
  caseResults: RedTeamCaseResult[];
}
