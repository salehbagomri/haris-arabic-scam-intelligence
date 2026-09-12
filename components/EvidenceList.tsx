import React from 'react';
import { Search, ShieldAlert, Cpu, MessageSquareWarning, Eye, Sparkles } from 'lucide-react';
import { EvidenceItem } from '../lib/types/analysis';

interface EvidenceListProps {
  evidence: EvidenceItem[];
}

export function EvidenceList({ evidence }: EvidenceListProps) {
  const getSourceBadge = (source: EvidenceItem['source']) => {
    switch (source) {
      case 'technical':
        return { label: 'مؤشر تقني', icon: <Cpu size={14} /> };
      case 'linguistic':
        return { label: 'تحليل لغوي وسياقي', icon: <MessageSquareWarning size={14} /> };
      case 'behavioral':
        return { label: 'نمط سلوكي', icon: <ShieldAlert size={14} /> };
      case 'visual':
        return { label: 'دليل بصري من الصورة', icon: <Eye size={14} /> };
      case 'ai':
        return { label: 'استدلال ذكاء اصطناعي', icon: <Sparkles size={14} /> };
      default:
        return { label: 'مؤشر استدلالي', icon: <ShieldAlert size={14} /> };
    }
  };

  return (
    <section className="haris-evidence-section" aria-labelledby="evidence-heading">
      <div className="haris-section-title">
        <Search size={20} color="var(--accent)" />
        <h2 id="evidence-heading" style={{ fontSize: 'inherit', fontWeight: 'inherit', color: 'inherit' }}>
          الأدلة والمؤشرات الملموسة
        </h2>
      </div>
      <p className="haris-section-desc">
        العناصر الصريحة المستخلصة من المحتوى والتي بُني عليها تقييم درجة الاشتباه.
      </p>

      <div className="haris-evidence-list">
        {evidence.map((item) => {
          const sourceInfo = getSourceBadge(item.source);

          return (
            <div key={item.id} className="haris-evidence-card">
              <div className="haris-evidence-icon">
                {sourceInfo.icon}
              </div>
              <div className="haris-evidence-body">
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                  <h3 className="haris-evidence-title">{item.title}</h3>
                  <span className="haris-badge" style={{ background: 'var(--bg-surface-elevated)', color: 'var(--text-secondary)' }}>
                    {sourceInfo.label}
                  </span>
                </div>
                <p className="haris-evidence-desc">{item.description}</p>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
