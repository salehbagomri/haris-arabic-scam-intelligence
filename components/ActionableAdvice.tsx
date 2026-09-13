import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { RiskLevel } from '../lib/types/analysis';

interface ActionableAdviceProps {
  advice: string[];
  riskLevel?: RiskLevel;
}

export function ActionableAdvice({ advice, riskLevel = 'suspicious' }: ActionableAdviceProps) {
  const getConfig = () => {
    switch (riskLevel) {
      case 'high':
        return {
          cardClass: 'risk-high',
          icon: <ShieldAlert size={20} color="var(--danger)" />,
          badgeClass: 'danger',
          badgeText: 'إجراءات عاجلة وحاسمة',
          bulletColor: 'var(--danger)',
        };
      case 'low':
        return {
          cardClass: 'risk-low',
          icon: <ShieldCheck size={20} color="var(--success)" />,
          badgeClass: 'success',
          badgeText: 'إرشادات وقائية عامة',
          bulletColor: 'var(--success)',
        };
      case 'suspicious':
      default:
        return {
          cardClass: 'risk-suspicious',
          icon: <AlertTriangle size={20} color="var(--warning)" />,
          badgeClass: 'warning',
          badgeText: 'إجراءات احترازية مطلوبة',
          bulletColor: 'var(--warning)',
        };
    }
  };

  const config = getConfig();

  return (
    <section className={`haris-advice-card ${config.cardClass}`} aria-labelledby="advice-heading">
      <div className="haris-advice-header">
        <div className="haris-section-title" style={{ marginBottom: 0 }}>
          {config.icon}
          <h2 id="advice-heading" style={{ fontSize: 'inherit', fontWeight: 'inherit', color: 'inherit' }}>
            ماذا تفعل الآن؟ (إرشادات وقائية مباشرة)
          </h2>
        </div>
        <span className={`haris-badge ${config.badgeClass}`}>
          <span>{config.badgeText}</span>
        </span>
      </div>

      <ul className="haris-advice-list">
        {advice.map((item, idx) => (
          <li key={idx} className="haris-advice-item">
            <CheckCircle2 size={18} className="haris-advice-bullet" style={{ color: config.bulletColor }} />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
