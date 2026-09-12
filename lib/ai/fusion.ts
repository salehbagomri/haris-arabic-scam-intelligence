/**
 * HARIS (حارس) — Evidence Fusion & Provenance Engine
 *
 * Implements the fusion boundary:
 * Deterministic Evidence + AI Semantic Evidence
 *               ↓
 *         Evidence Fusion
 *               ↓
 *            Scam DNA
 *               ↓
 *           Risk Engine
 *
 * CRITICAL ARCHITECTURAL RULES:
 * 1. PROVENANCE: Deterministic ('deterministic') vs AI ('ai') evidence remain strictly distinct.
 * 2. DETERMINISTIC PRIORITY: AI cannot overwrite or erase concrete technical findings.
 * 3. BOUNDED AI CONTRIBUTION: Purely semantic AI signals have a capped score contribution (max 15 pts).
 * 4. AI CONFIDENCE ≠ RISK SCORE: aiConfidence is semantic certainty, NOT scam probability.
 */

import { DeterministicAnalysisResult } from '../analysis';
import {
  FeatureKey,
  ScamType,
  Severity,
  SCAM_DNA_FEATURES,
  SCAM_DNA_METADATA,
  SCAM_TYPES_METADATA,
} from '../analysis/taxonomy';
import { DEFAULT_RISK_WEIGHTS } from '../config/weights';
import { GeminiSemanticAnalysis, SemanticSignal, PsychologicalTactic } from './schema';
import { ScreenshotExtractionData, VisualSignal } from '../vision/schema';

export interface FusedEvidenceItem {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  source: 'technical' | 'linguistic' | 'behavioral' | 'ai' | 'visual';
  provenance: 'deterministic' | 'ai' | 'ocr' | 'both';
}

export interface FusedDnaIndicator {
  featureId: FeatureKey;
  detected: boolean;
  nameAr: string;
  nameEn: string;
  severity: Severity;
  provenance: 'deterministic' | 'ai' | 'both';
  evidence: string[];
  explanations: string[];
}

export interface FusedAnalysisResult {
  /** Whether Gemini semantic intelligence was successfully applied */
  aiAvailable: boolean;

  /** Failure reason if AI was unavailable or skipped */
  aiFallbackReason?: string;

  /** Specific model used for semantic analysis */
  modelUsed?: string;

  /** Gemini's confidence in its semantic interpretation (0 - 1). NOT a fraud probability */
  aiConfidence: number | null;

  /** Arabic executive interpretation synthesized from semantics and evidence */
  interpretation: string;

  /** Final resolved Scam Type */
  scamType: ScamType;

  /** Human-readable Arabic name of the scam type */
  scamTypeNameAr: string;

  /** Final heuristic risk score (0 - 100) — "درجة الاشتباه" */
  riskScore: number;

  /** Final risk level classification */
  riskLevel: 'low' | 'suspicious' | 'high';

  /** Aggregated Scam DNA with clear evidence provenance */
  scamDna: FusedDnaIndicator[];

  /** All detected threat features across deterministic and semantic layers */
  detectedFeatures: FeatureKey[];

  /** Structured evidence items with explicit provenance */
  evidence: FusedEvidenceItem[];

  /** Semantic signals identified by AI */
  semanticSignals: SemanticSignal[];

  /** Psychological manipulation tactics identified by AI */
  psychologicalTactics: PsychologicalTactic[];

  /** Visual extraction data if analyzed from a screenshot */
  visualExtraction?: ScreenshotExtractionData;

  /** Observable visual signals from screenshot */
  visualSignals?: VisualSignal[];

  /** Actionable, context-tailored safety advice */
  actionableAdvice: string[];

  /** Analytical limitations and uncertainties */
  uncertainties: string[];

  /** Full preserved deterministic analysis result */
  deterministicResult: DeterministicAnalysisResult;

  /** Raw semantic analysis result if available */
  rawAiResult?: GeminiSemanticAnalysis;
}

export interface FusionOptions {
  modelUsed?: string;
  fallbackReason?: string;
  maxAiScoreContribution?: number;
  maxVisualScoreContribution?: number;
  visualData?: ScreenshotExtractionData | null;
}

/**
 * Fuse deterministic technical/linguistic evidence with Gemini semantic reasoning
 */
export function fuseEvidenceAndAssess(
  deterministic: DeterministicAnalysisResult,
  aiSemanticResult?: GeminiSemanticAnalysis | null,
  options: FusionOptions = {}
): FusedAnalysisResult {
  // Consume centralized heuristic cap from weights configuration
  const maxAiContribution = options.maxAiScoreContribution ?? DEFAULT_RISK_WEIGHTS.maxAiScoreContribution;
  const isAiAvailable = !!aiSemanticResult;

  // 1. Resolve Evidence Items with explicit provenance
  const evidence: FusedEvidenceItem[] = [];

  // 1a. Ingest all deterministic evidence
  for (const detItem of deterministic.assessment.evidence) {
    evidence.push({
      id: detItem.id,
      title: detItem.title,
      description: detItem.description,
      severity: detItem.severity,
      source: detItem.source,
      provenance: 'deterministic',
    });
  }

  // 1b. Ingest AI semantic signals as distinct evidence
  if (aiSemanticResult) {
    for (let i = 0; i < aiSemanticResult.semanticSignals.length; i++) {
      const sig = aiSemanticResult.semanticSignals[i];
      evidence.push({
        id: `ai-signal-${i}-${Date.now()}`,
        title: sig.type,
        description: `${sig.description} — الدليل: "${sig.evidence}"`,
        severity: sig.severity,
        source: 'ai',
        provenance: 'ai',
      });
    }
  }

  // 1c. Ingest visual signals and visible entities from screenshot
  if (options.visualData) {
    for (let i = 0; i < options.visualData.visualSignals.length; i++) {
      const vs = options.visualData.visualSignals[i];
      evidence.push({
        id: `visual-signal-${i}-${Date.now()}`,
        title: vs.type,
        description: `${vs.description} — الدليل المرئي: "${vs.evidence}"`,
        severity: vs.severity,
        source: 'visual',
        provenance: 'ai',
      });
    }

    // Ingest high-confidence OCR visible entities
    for (let i = 0; i < options.visualData.visibleEntities.length; i++) {
      const ent = options.visualData.visibleEntities[i];
      if (ent.confidence >= 0.8) {
        evidence.push({
          id: `ocr-entity-${i}-${Date.now()}`,
          title: `كيان مرئي: ${ent.type}`,
          description: `تم استخراج الكيان المرئي "${ent.text}" (ثقة القراءة: ${Math.round(ent.confidence * 100)}%)`,
          severity: 'low',
          source: 'visual',
          provenance: 'ocr',
        });
      }
    }

    // Synergistic Brand Contradiction: Visual brand resemblance + Suspicious domain
    const hasVisualBrand =
      options.visualData.visualSignals.some(
        (s) => s.type === 'impersonation_visual' || s.type === 'suspicious_branding'
      ) || options.visualData.visibleEntities.some((e) => e.type === 'brand_logo');

    const hasSuspiciousDomain = deterministic.urlResults.some(
      (u) => u.brandSpoofing.detected || u.signals.length > 0
    );

    if (hasVisualBrand && hasSuspiciousDomain) {
      evidence.push({
        id: `brand-contradiction-${Date.now()}`,
        title: 'تعارض الهوية البصرية مع النطاق الفعلي',
        description: 'تُظهر الصورة عناصر تشبه علامة تجارية معروفة، بينما النطاق الإلكتروني الفعلي مشبوه أو منتحل.',
        severity: 'high',
        source: 'visual',
        provenance: 'both',
      });
    }
  }

  // 2. Resolve Scam DNA features and track provenance
  const detectedFeaturesSet = new Set<FeatureKey>(deterministic.detectedFeatures);
  const aiDetectedFeatures = new Set<FeatureKey>();

  if (aiSemanticResult) {
    for (const cand of aiSemanticResult.scamDnaCandidates) {
      if (cand.confidence >= 0.5) {
        aiDetectedFeatures.add(cand.feature);
        detectedFeaturesSet.add(cand.feature);
      }
    }
  }

  const detectedFeatures = Array.from(detectedFeaturesSet);

  const scamDna: FusedDnaIndicator[] = SCAM_DNA_FEATURES.map((featKey) => {
    const meta = SCAM_DNA_METADATA[featKey];
    const isDet = deterministic.detectedFeatures.includes(featKey);
    const isAi = aiDetectedFeatures.has(featKey);
    const detected = isDet || isAi;

    let provenance: 'deterministic' | 'ai' | 'both' = 'deterministic';
    if (isDet && isAi) provenance = 'both';
    else if (isDet) provenance = 'deterministic';
    else if (isAi) provenance = 'ai';

    const evidenceList: string[] = [];
    const explanationList: string[] = [];

    // Add deterministic signals
    if (deterministic.assessment.featureEvidence[featKey]) {
      for (const sig of deterministic.assessment.featureEvidence[featKey]) {
        evidenceList.push(sig.evidenceText);
        explanationList.push(sig.explanation);
      }
    }

    // Add AI candidate signals
    if (aiSemanticResult) {
      const cand = aiSemanticResult.scamDnaCandidates.find((c) => c.feature === featKey);
      if (cand && !evidenceList.includes(cand.evidence)) {
        evidenceList.push(cand.evidence);
        explanationList.push(`رصد دلالي سياقي (ثقة النموذج: ${Math.round(cand.confidence * 100)}%)`);
      }
    }

    return {
      featureId: featKey,
      detected,
      nameAr: meta.nameAr,
      nameEn: meta.nameEn,
      severity: meta.defaultSeverity,
      provenance,
      evidence: evidenceList,
      explanations: explanationList,
    };
  });

  // 3. Score Fusion with strict bounded AI contribution
  const baseDeterministicScore = deterministic.assessment.score;
  let fusedScore = baseDeterministicScore;

  if (aiSemanticResult) {
    // Only features detected solely by AI add a conservative contribution
    let rawAiContribution = 0;
    for (const cand of aiSemanticResult.scamDnaCandidates) {
      if (!deterministic.detectedFeatures.includes(cand.feature) && cand.confidence >= 0.5) {
        // Base weight bounded by candidate confidence
        rawAiContribution += Math.round(5 * cand.confidence);
      }
    }

    // Additional bounded contribution if psychological tactics exist
    if (aiSemanticResult.psychologicalTactics.length > 0 && deterministic.detectedFeatures.length === 0) {
      rawAiContribution += Math.min(5, aiSemanticResult.psychologicalTactics.length * 2);
    }

    // Strictly cap total AI contribution
    const cappedAiContribution = Math.min(rawAiContribution, maxAiContribution);
    fusedScore = Math.min(100, Math.max(0, baseDeterministicScore + cappedAiContribution));
  }

  // 3b. Add conservative bounded visual score contribution if screenshot was analyzed
  if (options.visualData && options.visualData.visualSignals.length > 0) {
    let rawVisualContribution = 0;
    for (const vs of options.visualData.visualSignals) {
      if (vs.severity === 'high') rawVisualContribution += 3;
      else if (vs.severity === 'medium') rawVisualContribution += 2;
      else rawVisualContribution += 1;
    }
    const maxVisualContribution =
      options.maxVisualScoreContribution ?? DEFAULT_RISK_WEIGHTS.maxVisualScoreContribution;
    const cappedVisualContribution = Math.min(rawVisualContribution, maxVisualContribution);
    fusedScore = Math.min(100, Math.max(0, fusedScore + cappedVisualContribution));
  }

  // 4. Resolve Risk Level
  let riskLevel: 'low' | 'suspicious' | 'high' = 'low';
  if (fusedScore >= DEFAULT_RISK_WEIGHTS.thresholds.highMin) {
    riskLevel = 'high';
  } else if (fusedScore >= DEFAULT_RISK_WEIGHTS.thresholds.lowMax + 1) {
    riskLevel = 'suspicious';
  }

  // 5. Resolve Scam Type
  // Rule: Strong deterministic technical classifications have strict priority
  let scamType: ScamType = deterministic.assessment.scamType;

  if (scamType === 'UNKNOWN' || scamType === 'SOCIAL_ENGINEERING') {
    if (aiSemanticResult && aiSemanticResult.scamTypeCandidates.length > 0) {
      const bestCandidate = aiSemanticResult.scamTypeCandidates.reduce((best, cur) =>
        cur.confidence > best.confidence ? cur : best
      );
      if (bestCandidate.confidence >= 0.6 && bestCandidate.type !== 'UNKNOWN') {
        scamType = bestCandidate.type;
      }
    }
  }

  const scamTypeNameAr = SCAM_TYPES_METADATA[scamType]?.nameAr || 'غير مصنف بدقة';

  // 6. Synthesize Interpretation
  let interpretation = '';
  if (aiSemanticResult && aiSemanticResult.interpretation) {
    interpretation = aiSemanticResult.interpretation;
  } else {
    interpretation = deterministic.assessment.summary;
  }

  // 7. Merge Actionable Advice & Uncertainties
  const adviceSet = new Set<string>(deterministic.assessment.actionableAdvice);
  if (aiSemanticResult) {
    for (const tactic of aiSemanticResult.psychologicalTactics) {
      const lower = tactic.type.toLowerCase();
      if (lower.includes('خوف') || lower.includes('ترهيب') || lower.includes('threat')) {
        adviceSet.add('لا تتخذ أي إجراء تحت وطأة التهديد أو الخوف؛ تواصل مع الدعم الرسمي أولاً.');
      }
      if (lower.includes('استعجال') || lower.includes('إلحاح') || lower.includes('urgency')) {
        adviceSet.add('الاحتيال يعتمد على الضغط الزمني لحرمانك من التفكير؛ تمهل ولا تستجب لطلب العجلة.');
      }
    }
  }
  const actionableAdvice = Array.from(adviceSet);

  const uncertaintiesSet = new Set<string>(deterministic.assessment.uncertainties);
  if (aiSemanticResult && aiSemanticResult.uncertainties) {
    for (const unc of aiSemanticResult.uncertainties) {
      uncertaintiesSet.add(unc);
    }
  } else if (!isAiAvailable) {
    uncertaintiesSet.add(
      'لم يتم تطبيق التحليل الدلالي بالذكاء الاصطناعي في هذا الفحص (يعتمد التقييم على القواعد الحتمية المحلية فقط).'
    );
  }
  if (options.visualData && options.visualData.uncertainties.length > 0) {
    for (const unc of options.visualData.uncertainties) {
      uncertaintiesSet.add(`محدودية بصرية: ${unc}`);
    }
  }
  const uncertainties = Array.from(uncertaintiesSet);

  return {
    aiAvailable: isAiAvailable,
    aiFallbackReason: options.fallbackReason,
    modelUsed: options.modelUsed,
    aiConfidence: aiSemanticResult ? aiSemanticResult.aiConfidence : null,
    interpretation,
    scamType,
    scamTypeNameAr,
    riskScore: fusedScore,
    riskLevel,
    scamDna,
    detectedFeatures,
    evidence,
    semanticSignals: aiSemanticResult?.semanticSignals || [],
    psychologicalTactics: aiSemanticResult?.psychologicalTactics || [],
    visualExtraction: options.visualData || undefined,
    visualSignals: options.visualData?.visualSignals || [],
    actionableAdvice,
    uncertainties,
    deterministicResult: deterministic,
    rawAiResult: aiSemanticResult || undefined,
  };
}
