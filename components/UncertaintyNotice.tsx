import React from 'react';
import { HelpCircle } from 'lucide-react';

interface UncertaintyNoticeProps {
  uncertainties: string[];
}

export function UncertaintyNotice({ uncertainties }: UncertaintyNoticeProps) {
  return (
    <aside className="haris-uncertainty-card" aria-label="تنويه الشفافية وحدود التحليل">
      <HelpCircle size={18} className="haris-uncertainty-icon" />
      <div>
        <strong style={{ display: 'block', color: 'var(--text-secondary)', marginBottom: 'var(--space-1)' }}>
          حدود التحليل والشفافية الأمنية:
        </strong>
        <p style={{ marginBottom: 'var(--space-2)' }}>
          حارس أداة توعوية استدلالية لتقدير مستوى الشبهة بناءً على المؤشرات اللغوية والهندسية والتقنية. لا يدّعي النظام يقيناً رياضياً مطلقاً بنسبة 100%.
        </p>
        <ul style={{ paddingRight: 'var(--space-4)', margin: 0, display: 'flex', flexDirection: 'column', gap: '4px' }}>
          {uncertainties.map((item, idx) => (
            <li key={idx}>{item}</li>
          ))}
        </ul>
      </div>
    </aside>
  );
}
