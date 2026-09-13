'use client';

import React from 'react';
import { RotateCcw, AlertOctagon, AlertTriangle, ShieldCheck, Sparkles, Image as ImageIcon } from 'lucide-react';
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
    if (result.isExtractionFailure) {
      return {
        label: 'تعذر التحليل: قراءة لقطة الشاشة غير مكتملة',
        badgeClass: 'warning',
        icon: <AlertTriangle size={16} />,
        boxClass: 'warning',
      };
    }

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

      {result.isExtractionFailure && (
        <div
          className="haris-mock-banner"
          style={{
            borderColor: 'var(--warning-border)',
            background: 'var(--warning-subtle)',
            color: 'var(--warning-text)',
          }}
          role="alert"
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <AlertTriangle size={18} />
            <span>
              <strong>تنبيه: تعذر استخراج أو قراءة محتوى لقطة الشاشة.</strong> نتيجة الفحص غير محددة ولا تعني أن المحتوى آمن. يرجى رفع لقطة شاشة أكثر وضوحاً أو نسخ نص الرسالة ولصقه مباشرة.
            </span>
          </div>
        </div>
      )}

      {/* Main Verdict Card */}
      <div className="haris-results-header-card">
        <div className={`haris-score-box ${risk.boxClass}`}>
          {result.isExtractionFailure ? (
            <>
              <div className="haris-score-num" style={{ fontSize: 'var(--font-xl)', color: 'var(--warning-text)' }}>
                غير محدد
              </div>
              <span className="haris-score-max">فشل قراءة الصورة</span>
              <span className="haris-score-label">حالة الفحص</span>
              <span className="haris-score-disclaimer">لا تعني بأي حال أن المحتوى آمن</span>
            </>
          ) : (
            <>
              <div className="haris-score-num">{result.riskScore}</div>
              <span className="haris-score-max">من 100</span>
              <span className="haris-score-label">درجة الاشتباه</span>
              <span className="haris-score-disclaimer">مؤشر دلائل أمنية</span>
            </>
          )}
        </div>

        <div className="haris-verdict-details">
          <div className="haris-verdict-badges">
            <span className={`haris-badge ${risk.badgeClass}`}>
              {risk.icon}
              <span>{risk.label}</span>
            </span>

            <span className="haris-badge" style={{ background: 'var(--bg-surface-elevated)', color: 'var(--text-secondary)' }}>
              <span>النمط: {result.scamTypeNameAr || result.scamType}</span>
            </span>

            {result.aiConfidence !== null && result.aiConfidence !== undefined && (
              <span
                className="haris-badge"
                style={{ background: 'var(--bg-surface-elevated)', color: 'var(--text-secondary)' }}
                title="ثقة النموذج الدلالي في فهم سياق الرسالة (منفصلة تماماً عن درجة اشتباه الاحتيال)"
              >
                <Sparkles size={12} />
                <span>ثقة النموذج الدلالي: {Math.round(result.aiConfidence * 100)}%</span>
              </span>
            )}

            {result.extractionConfidence !== null && result.extractionConfidence !== undefined && (
              <span
                className="haris-badge"
                style={{ background: 'var(--bg-surface-elevated)', color: 'var(--text-secondary)' }}
                title="مستوى دقة قراءة واستخراج النصوص والروابط من لقطة الشاشة"
              >
                <ImageIcon size={12} />
                <span>دقة الاستخراج: {Math.round(result.extractionConfidence * 100)}%</span>
              </span>
            )}

            <span className="haris-badge" style={{ background: 'var(--bg-surface-subtle)', color: 'var(--text-muted)' }}>
              <span>{result.analyzedAt}</span>
            </span>
          </div>

          <h2 className="haris-scam-type-title">{result.scamTypeNameAr || result.scamType}</h2>
          <p className="haris-summary-text">{result.summary}</p>
        </div>
      </div>

      {/* Scam DNA Grid */}
      <ScamDnaGrid indicators={result.scamDna} />

      {/* Evidence List */}
      <EvidenceList evidence={result.evidence} />

      {/* Actionable Advice */}
      <ActionableAdvice advice={result.actionableAdvice} riskLevel={result.riskLevel} />

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
