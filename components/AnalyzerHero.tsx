import React from 'react';
import { ShieldAlert } from 'lucide-react';

export function AnalyzerHero() {
  return (
    <section className="haris-hero" aria-labelledby="hero-title">
      <div className="haris-hero-badge">
        <ShieldAlert size={14} />
        <span>كاشف الاحتيال العربي الذكي</span>
      </div>
      <h1 id="hero-title" className="haris-hero-title">
        قبل ما تثق… <span>خلّ حارس يفحص.</span>
      </h1>
      <p className="haris-hero-desc">
        حلّل الرسائل والروابط ولقطات الشاشة المشبوهة، وافهم مؤشرات الاحتيال وبصمة التهديد قبل أن تتصرف.
      </p>
    </section>
  );
}
