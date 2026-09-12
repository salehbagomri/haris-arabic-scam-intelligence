import React from 'react';
import { ShieldAlert, CheckCircle2 } from 'lucide-react';

interface ActionableAdviceProps {
  advice: string[];
}

export function ActionableAdvice({ advice }: ActionableAdviceProps) {
  return (
    <section className="haris-advice-card" aria-labelledby="advice-heading">
      <div className="haris-section-title" style={{ marginBottom: 0 }}>
        <ShieldAlert size={20} color="var(--warning)" />
        <h2 id="advice-heading" style={{ fontSize: 'inherit', fontWeight: 'inherit', color: 'inherit' }}>
          ماذا تفعل الآن؟ (إرشادات وقائية مباشرة)
        </h2>
      </div>

      <ul className="haris-advice-list">
        {advice.map((item, idx) => (
          <li key={idx} className="haris-advice-item">
            <CheckCircle2 size={18} className="haris-advice-bullet" />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
