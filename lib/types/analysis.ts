/**
 * HARIS (حارس) — Core Types & Schemas
 * Type definitions for UI presentation, mock data, and future analysis pipeline.
 */

export type InputMode = 'text' | 'url' | 'screenshot';

export type RiskLevel = 'low' | 'suspicious' | 'high';

export interface ScamDnaIndicator {
  id: string;
  nameAr: string;
  nameEn: string;
  detected: boolean;
  severity: 'low' | 'medium' | 'high';
  detail: string;
}

export interface EvidenceItem {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  source: 'linguistic' | 'technical' | 'behavioral';
}

export interface AnalysisResult {
  isMockData: boolean;
  inputMode: InputMode;
  inputPreview: string;
  riskScore: number; // 0 - 100 (درجة الاشتباه)
  riskLevel: RiskLevel;
  scamType: string;
  summary: string;
  scamDna: ScamDnaIndicator[];
  evidence: EvidenceItem[];
  actionableAdvice: string[];
  uncertainties: string[];
  analyzedAt: string;
}

export interface DemoScenario {
  id: string;
  title: string;
  badge: string;
  mode: InputMode;
  content: string;
  description: string;
  mockResult: AnalysisResult;
}
