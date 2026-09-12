'use client';

import React from 'react';
import { RotateCcw, AlertOctagon, AlertTriangle, ShieldCheck, Sparkles } from 'lucide-react';
import { AnalysisResult } from '../lib/types/analysis';
import { ScamDnaGrid } from './ScamDnaGrid';
import { EvidenceList } from './EvidenceList';
import { ActionableAdvice } from './ActionableAdvice';
import { UncertaintyNotice } from './UncertaintyNotice';

interface ResultsViewProps {
  result: AnalysisResult;
  onReset: () => void;
}

export function ResultsView({ result, onReset }: ResultsViewProps) {
  const getRiskDetails = () => {
    switch (result.riskLevel) {
      case 'high':
        return {
          label: 'درجة الاشتباه: مرتفعة',
          badgeClass: 'danger',
          icon: <AlertOctagon size={16} />,
          boxClass: 'danger',
        };
      case 'suspicious':
        return {
          label: 'درجة الاشتباه: مشبوهة',
          badgeClass: 'warning',
          icon: <AlertTriangle size={16} />,
          boxClass: 'warning',
        };
      case 'low':
        return {
          label: 'درجة الاشتباه: منخفضة',
          badgeClass: 'success',
          icon: <ShieldCheck size={16} />,
          boxClass: 'success',
        };
    }
  };

  const risk = getRiskDetails();

  return (
    <div className="haris-results">
      {result.isMockData && (
        <div className="haris-mock-banner" role="status">
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Sparkles size={16} />
            <span>
              <strong>عرض تجريبي (UI Mock Shell):</strong> هذه النتائج مجهزة لنمذجة تجربة المستخدم في المرحلة الحالية، وستربط بالمحرك في المراحل القادمة.
            </span>
          </div>
          <button
            type="button"
            className="haris-secondary-btn"
            onClick={onReset}
            style={{ padding: '4px 10px', fontSize: 'var(--font-xs)' }}
          >
            <RotateCcw size={12} />
            <span>فحص جديد</span>
          </button>
        </div>
      )}

      {/* Main Verdict Card */}
      <div className="haris-results-header-card">
        <div className={`haris-score-box ${risk.boxClass}`}>
          <div className="haris-score-num">{result.riskScore}</div>
          <span className="haris-score-max">من 100</span>
          <span className="haris-score-label">درجة الاشتباه</span>
          <span className="haris-score-disclaimer">مؤشر دلائل أمنية</span>
        </div>

        <div className="haris-verdict-details">
          <div className="haris-verdict-badges">
            <span className={`haris-badge ${risk.badgeClass}`}>
              {risk.icon}
              <span>{risk.label}</span>
            </span>

            <span className="haris-badge" style={{ background: 'var(--bg-surface-elevated)', color: 'var(--text-secondary)' }}>
              <span>النمط المكتشف: {result.scamType}</span>
            </span>

            <span className="haris-badge" style={{ background: 'var(--bg-surface-subtle)', color: 'var(--text-muted)' }}>
              <span>{result.analyzedAt}</span>
            </span>
          </div>

          <h2 className="haris-scam-type-title">{result.scamType}</h2>
          <p className="haris-summary-text">{result.summary}</p>
        </div>
      </div>

      {/* Scam DNA Grid */}
      <ScamDnaGrid indicators={result.scamDna} />

      {/* Evidence List */}
      <EvidenceList evidence={result.evidence} />

      {/* Actionable Advice */}
      <ActionableAdvice advice={result.actionableAdvice} />

      {/* Uncertainty Notice */}
      <UncertaintyNotice uncertainties={result.uncertainties} />

      {/* Bottom Reset Button */}
      <div style={{ display: 'flex', justifyContent: 'center', paddingTop: 'var(--space-4)' }}>
        <button
          type="button"
          className="haris-secondary-btn"
          onClick={onReset}
          style={{ padding: 'var(--space-3) var(--space-6)', fontSize: 'var(--font-base)' }}
        >
          <RotateCcw size={16} />
          <span>إجراء فحص جديد لمحتوى آخر</span>
        </button>
      </div>
    </div>
  );
}
