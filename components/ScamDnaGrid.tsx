import React from 'react';
import { Dna, CheckCircle2, MinusCircle, AlertTriangle } from 'lucide-react';
import { ScamDnaIndicator } from '../lib/types/analysis';

interface ScamDnaGridProps {
  indicators: ScamDnaIndicator[];
}

export function ScamDnaGrid({ indicators }: ScamDnaGridProps) {
  return (
    <section className="haris-dna-section" aria-labelledby="dna-heading">
      <div className="haris-section-title">
        <Dna size={20} color="var(--accent)" />
        <h2 id="dna-heading" style={{ fontSize: 'inherit', fontWeight: 'inherit', color: 'inherit' }}>
          بصمة الاحتيال | Scam DNA
        </h2>
      </div>
      <p className="haris-section-desc">
        تفكيك التهديد غير المنظم إلى جينات ومؤشرات بنيوية تحدد استراتيجية المحتال النفسية والتقنية.
      </p>

      <div className="haris-dna-grid">
        {indicators.map((item) => (
          <div
            key={item.id}
            className={`haris-dna-card ${item.detected ? 'detected' : 'not-detected'}`}
          >
            <div className="haris-dna-card-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                {item.detected ? (
                  <AlertTriangle size={16} color="var(--danger)" />
                ) : (
                  <MinusCircle size={16} color="var(--text-muted)" />
                )}
                <span className="haris-dna-card-name">{item.nameAr}</span>
              </div>
              <span className="haris-dna-card-en font-mono">{item.nameEn}</span>
            </div>

            <p className="haris-dna-detail">{item.detail}</p>

            <div style={{ marginTop: 'auto', paddingTop: 'var(--space-1)', display: 'flex', justifyContent: 'flex-end' }}>
              {item.detected ? (
                <span className="haris-badge danger">
                  <span>تم الرصد</span>
                </span>
              ) : (
                <span className="haris-badge" style={{ background: 'var(--bg-surface-subtle)', color: 'var(--text-muted)' }}>
                  <CheckCircle2 size={12} />
                  <span>غير مرصود</span>
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
