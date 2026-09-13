'use client';

import React, { useEffect, useState } from 'react';
import { CheckCircle2, Loader2, Shield } from 'lucide-react';

interface AnalysisLoadingProps {
  onComplete?: () => void;
  speedMs?: number;
}

const STAGES = [
  { id: 1, title: 'معالجة وتطبيع المحتوى العربي (Arabic Normalization)' },
  { id: 2, title: 'استخراج المؤشرات والأدلة التقنية (Technical Evidence)' },
  { id: 3, title: 'التحليل الدلالي واستدلال السياق (Semantic Analysis)' },
  { id: 4, title: 'مطابقة بصمة الاحتيال وبناء التهديد (Scam DNA)' },
  { id: 5, title: 'احتساب درجة الاشتباه والتقييم النهائي (Risk Assessment)' },
];

export function AnalysisLoading({ onComplete, speedMs = 140 }: AnalysisLoadingProps) {
  const [currentStageIndex, setCurrentStageIndex] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentStageIndex((prev) => {
        if (prev < STAGES.length) {
          return prev + 1;
        } else {
          clearInterval(timer);
          if (onComplete) {
            onComplete();
          }
          return prev;
        }
      });
    }, speedMs);

    return () => clearInterval(timer);
  }, [onComplete, speedMs]);

  return (
    <div className="haris-loading-card animate-fade-in" role="status" aria-live="polite">
      <div className="haris-spinner" />
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
        <Shield size={18} color="var(--accent)" />
        <h2 className="haris-loading-title" style={{ margin: 0 }}>
          جاري الفحص الأمني عبر حارس...
        </h2>
      </div>

      <div className="haris-stages-list">
        {STAGES.map((stage, idx) => {
          const isCompleted = idx < currentStageIndex;
          const isActive = idx === currentStageIndex;

          return (
            <div
              key={stage.id}
              className={`haris-stage-item ${isActive ? 'active' : ''} ${isCompleted ? 'completed' : ''}`}
            >
              {isCompleted ? (
                <CheckCircle2 size={16} color="var(--success)" style={{ flexShrink: 0 }} />
              ) : isActive ? (
                <Loader2 size={16} className="animate-spin" color="var(--accent)" style={{ flexShrink: 0 }} />
              ) : (
                <span
                  style={{
                    width: 16,
                    height: 16,
                    borderRadius: '50%',
                    border: '1px solid var(--border-default)',
                    display: 'inline-block',
                    flexShrink: 0,
                  }}
                />
              )}
              <span>{stage.title}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
