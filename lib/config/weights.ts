/**
 * HARIS (حارس) — Configurable Risk Engine Weights & Heuristics
 *
 * NOTE: These weights represent initial empirical baseline heuristics and are NOT
 * scientific probabilities. They are designed to be calibrated and tuned
 * based on evaluation benchmark datasets.
 */

import { FeatureKey, Severity, Confidence } from '../analysis/taxonomy';

export interface WeightsConfig {
  /** Base weight allocated to each detected Scam DNA feature */
  featureWeights: Record<FeatureKey, number>;

  /** Multiplier based on extraction confidence */
  confidenceMultipliers: Record<Confidence, number>;

  /** Multiplier based on signal severity */
  severityMultipliers: Record<Severity, number>;

  /** Maximum points any single feature can contribute to prevent unilateral 100 score spikes */
  maxSingleFeatureContribution: number;

  /** Multi-feature synergy bonus (when multiple correlated high-threat features appear together) */
  synergyBonusMultiplier: number;

  /** Classification thresholds for "درجة الاشتباه" (0 - 100) */
  thresholds: {
    lowMax: number;        // 0 - 29: منخفض
    suspiciousMax: number; // 30 - 69: مشبوه
    highMin: number;       // 70 - 100: مرتفع
  };
}

export const DEFAULT_RISK_WEIGHTS: WeightsConfig = {
  featureWeights: {
    // Top critical threat features
    otp_request: 32,
    credential_request: 30,
    suspicious_url: 28,
    impersonation: 24,

    // Secondary high-threat features
    suspicious_payment_request: 22,
    threat_language: 20,
    urgency: 18,
    financial_lure: 18,
    secrecy_pressure: 18,

    // Supporting behavioral indicators
    action_pressure: 12,
    unexpected_contact: 10,
  },

  confidenceMultipliers: {
    high: 1.0,
    medium: 0.75,
    low: 0.45,
  },

  severityMultipliers: {
    high: 1.0,
    medium: 0.7,
    low: 0.4,
  },

  // A single feature alone cannot push the risk score into "مرتفع" (> 40)
  maxSingleFeatureContribution: 38,

  // Synergy bonus: when 3+ high-severity features combine (e.g. impersonation + urgency + credential_request)
  synergyBonusMultiplier: 1.15,

  thresholds: {
    lowMax: 29,
    suspiciousMax: 69,
    highMin: 70,
  },
};
