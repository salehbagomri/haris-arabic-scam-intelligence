import React from 'react';
import { Dna, CheckCircle2, MinusCircle, AlertTriangle } from 'lucide-react';
import { ScamDnaIndicator } from '../lib/types/analysis';

interface ScamDnaGridProps {
  indicators: ScamDnaIndicator[];
}

export function ScamDnaGrid({ indicators }: ScamDnaGridProps) {
  const observed = indicators.filter((item) => item.detected);
  const unobserved = indicators.filter((item) => !item.detected);

  return (
    <section className="haris-dna-section" aria-labelledby="dna-heading">
      <div className="haris-section-title">
        <Dna size={20} color="var(--accent)" />
        <h2 id="dna-heading" style={{ fontSize: 'inherit', fontWeight: 'inherit', color: 'inherit' }}>
          بصمة الاحتيال | Scam DNA
        </h2>
      </div>
      <p className="haris-section-desc">
        تفكيك التهديد إلى جينات ومؤشرات بنيوية تحدد استراتيجية المحتال النفسية والتقنية مع مقارنة صريحة بين ما تم رصده وما تم استبعاده.
      </p>

      {/* Primary Section: Observed Threat DNA */}
      <div className="haris-dna-group">
        <div className="haris-dna-group-header">
          <span className="haris-badge danger" style={{ fontSize: '12px', padding: '4px 10px', gap: '6px' }}>
            <AlertTriangle size={14} />
            <span>المؤشرات المرصودة في المحتوى ({observed.length} من {indicators.length})</span>
          </span>
          <span style={{ fontSize: 'var(--font-xs)', color: 'var(--text-muted)' }}>
            تشكل البصمة الجينية للهجمة الحالية
          </span>
        </div>

        {observed.length > 0 ? (
          <div className="haris-dna-grid">
            {observed.map((item) => (
              <div
                key={item.id}
                className="haris-dna-card detected"
              >
                <div className="haris-dna-card-header">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <AlertTriangle size={16} color="var(--danger)" />
                    <span className="haris-dna-card-name">{item.nameAr}</span>
                  </div>
                  <span className="haris-dna-card-en font-mono">{item.nameEn}</span>
                </div>

                {item.explanations && item.explanations.length > 1 ? (
                  <ul
                    className="haris-dna-detail"
                    style={{
                      margin: 0,
                      paddingRight: 'var(--space-4)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '3px',
                    }}
                  >
                    {item.explanations.map((exp, expIdx) => (
                      <li key={expIdx}>{exp}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="haris-dna-detail">{item.detail}</p>
                )}

                {item.evidence && item.evidence.length > 0 && (
                  <div className="haris-dna-evidence-tag">
                    <span style={{ color: 'var(--text-muted)' }}>الدليل المستخرج: </span>
                    <span className="font-mono" style={{ color: 'var(--danger-text)', fontWeight: 600 }}>
                      {item.evidence.map((ev) => `«${ev}»`).join('، ')}
                    </span>
                  </div>
                )}

                <div className="haris-dna-card-footer">
                  {item.provenance && (
                    <span
                      className="haris-badge"
                      style={{ background: 'var(--bg-surface-elevated)', color: 'var(--text-muted)', fontSize: '10px' }}
                    >
                      <span>
                        {item.provenance === 'both'
                          ? 'رصد متعدد المصادر'
                          : item.provenance === 'ai'
                          ? 'استدلال ذكي'
                          : 'فحص حتمي'}
                      </span>
                    </span>
                  )}

                  <span className="haris-badge danger" style={{ marginLeft: item.provenance ? undefined : 'auto' }}>
                    <span>تم الرصد • Observed</span>
                  </span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="haris-dna-empty-observed">
            <CheckCircle2 size={16} color="var(--success)" />
            <span>لم يُسجل المحتوى أياً من مؤشرات بصمة الاحتيال الثمانية (سياق طبيعي سليم).</span>
          </div>
        )}
      </div>

      {/* Secondary Section: Unobserved Signals (Ruled Out) */}
      {unobserved.length > 0 && (
        <div className="haris-dna-group" style={{ marginTop: 'var(--space-5)' }}>
          <div className="haris-dna-group-header">
            <span className="haris-badge" style={{ background: 'var(--bg-surface-subtle)', color: 'var(--text-muted)', fontSize: '11px', gap: '6px' }}>
              <MinusCircle size={13} />
              <span>مؤشرات تم فحصها ولم تُرصد ({unobserved.length} مؤشر)</span>
            </span>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              تم التحقق من خلو المحتوى منها
            </span>
          </div>

          <div className="haris-dna-unobserved-grid">
            {unobserved.map((item) => (
              <div key={item.id} className="haris-dna-unobserved-item">
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <MinusCircle size={13} color="var(--text-muted)" style={{ flexShrink: 0 }} />
                  <span className="haris-dna-unobserved-name">{item.nameAr}</span>
                  <span className="haris-dna-unobserved-en font-mono">{item.nameEn}</span>
                </div>
                <span className="haris-badge" style={{ background: 'transparent', color: 'var(--text-muted)', fontSize: '10px', padding: '1px 6px' }}>
                  لم يُرصد
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
