# HARIS (حارس) — Phase 6A Baseline Evaluation Benchmark Report

> **Dataset Version:** 1.0.0  
> **Evaluation Date:** 2026-09-12T19:43:49.104Z  
> **Execution Environment:** Node.js v24.14.0 | Gemini Active: NO (Deterministic Baseline)  
> **Total Test Cases:** 70 (Scams: 34, Legitimate: 22, Ambiguous: 14, Screenshots: 5)

---

## 1. Executive Summary & Key Measured Metrics

| Metric | Measured Baseline Value | Target / Benchmark Threshold |
|---|---|---|
| **Overall Classification Accuracy** | **47.1%** (33/70) | > 85.0% |
| **False Positive Rate (FPR)** | **9.1%** (2/22) | < 5.0% (Critical for user trust) |
| **False Negative Rate (FNR)** | **67.6%** (23/34) | < 10.0% |
| **Scam Type Classification Accuracy** | **50.0%** | > 70.0% |

> [!IMPORTANT]
> **Measurement Principle:** All metrics above are measured directly from the 70-case labeled evaluation dataset. AI confidence is recorded separately and never conflated with classification probability.

---

## 2. Category Performance Breakdown

| Category | Cases | Correct Risk | Category Accuracy | Average Suspicion Score |
|---|---|---|---|---|
| **Scam / Malicious** | 34 | 3 | **8.8%** | 23.8 / 100 |
| **Legitimate / Benign** | 22 | 20 | **90.9%** | 2.8 / 100 |
| **Ambiguous / Adversarial** | 14 | 10 | **71.4%** | 6.7 / 100 |

---

## 3. Dialect & Regional Coverage Breakdown

| Dialect / Variant | Cases | Correct Risk | Dialect Accuracy |
|---|---|---|---|
| **Modern Standard Arabic (MSA)** | 34 | 18 | **52.9%** |
| **Yemeni Arabic & Local Services** | 13 | 6 | **46.2%** |
| **Gulf / Saudi / UAE** | 9 | 5 | **55.6%** |
| **Egyptian Arabic & Local Wallets** | 4 | 1 | **25.0%** |
| **Mixed Arabic + English** | 6 | 2 | **33.3%** |
| **Arabizi (Latin Script)** | 4 | 1 | **25.0%** |

---

## 4. Scam DNA Feature Detection Benchmark

| Scam DNA Feature Key | Ground Truth Count | Detected Count | True Positives | False Positives | False Negatives | Precision | Recall | F1 Score |
|---|---|---|---|---|---|---|---|---|
| `urgency` | 23 | 13 | 9 | 4 | 14 | 69.2% | 39.1% | **50.0%** |
| `credential_request` | 11 | 2 | 1 | 1 | 10 | 50.0% | 9.1% | **15.4%** |
| `otp_request` | 6 | 4 | 2 | 2 | 4 | 50.0% | 33.3% | **40.0%** |
| `impersonation` | 22 | 4 | 4 | 0 | 18 | 100.0% | 18.2% | **30.8%** |
| `financial_lure` | 12 | 2 | 2 | 0 | 10 | 100.0% | 16.7% | **28.6%** |
| `suspicious_url` | 18 | 13 | 13 | 0 | 5 | 100.0% | 72.2% | **83.9%** |
| `threat_language` | 9 | 3 | 2 | 1 | 7 | 66.7% | 22.2% | **33.3%** |
| `unexpected_contact` | 5 | 0 | 0 | 0 | 5 | 0.0% | 0.0% | **0.0%** |
| `secrecy_pressure` | 2 | 0 | 0 | 0 | 2 | 0.0% | 0.0% | **0.0%** |
| `suspicious_payment_request` | 10 | 2 | 2 | 0 | 8 | 100.0% | 20.0% | **33.3%** |
| `action_pressure` | 6 | 1 | 0 | 1 | 6 | 0.0% | 0.0% | **0.0%** |

---

## 5. Failure Case Diagnosis & Baseline Anomalies

Total Mismatches: **37** / 70

### 5.1 False Positives (Legitimate Flagged as Suspicious/High)
- **[LEGIT-007] تأكيد تغيير كلمة مرور حسابك بنجاح (فصحى)**: Expected `low`, got `suspicious` (Score: 30). Notes: ⚠️ FALSE POSITIVE: Legitimate flagged as suspicious (score 30)
- **[LEGIT-011] تأكيد رمز الدخول لمرة واحدة من جهة حكومية دون رابط (فصحى)**: Expected `low`, got `suspicious` (Score: 32). Notes: ⚠️ FALSE POSITIVE: Legitimate flagged as suspicious (score 32)

### 5.2 False Negatives (Scam Missed as Low Risk)
- **[SCAM-004] إيقاف محفظة فودافون كاش (لهجة مصرية)**: Expected `high`, got `low` (Score: 20). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-005] تحديث البطاقة البنكية الائتمانية (لهجة خليجية)**: Expected `high`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-007] حوالة واردة معلقة عبر النجم للصرافة (لهجة يمنية)**: Expected `high`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-011] يانصيب شركة الاتصالات الكبرى (لهجة خليجية)**: Expected `high`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-012] منصة استثمار وتداول بضمان أرباح يومية 30% (فصحى)**: Expected `high`, got `low` (Score: 18). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-013] تداول العملات المشفرة وسهم أرامكو الوهمي (مختلط إنجليزي-عربي)**: Expected `high`, got `low` (Score: 20). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-014] وظيفة بدوام جزئي عبر الإنترنت براتب 300 دولار يومياً (فصحى)**: Expected `high`, got `low` (Score: 18). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-015] عقد عمل بدولة الخليج وتأشيرة فورية (لهجة مصرية)**: Expected `high`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-017] الضرائب والجمارك اليمنية ورسوم ترقيم السيارات (لهجة يمنية)**: Expected `high`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-018] كود تأكيد واتساب بالخطأ (لهجة يمنية)**: Expected `high`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-019] رمز التحقق الثنائي تيليجرام (مختلط إنجليزي-عربي)**: Expected `high`, got `low` (Score: 18). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-020] تحديث كلمة مرور انستغرام وشارة التوثيق (عربيزي)**: Expected `high`, got `low` (Score: 20). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-021] استغاثة من رقم جديد وحادث سير مفاجئ (لهجة خليجية)**: Expected `high`, got `low` (Score: 18). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-022] سلفه مالية عاجلة من صديق في الغربة (لهجة يمنية)**: Expected `high`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-024] حملة تبرعات إغاثية وهمية لعلاج أطفال (لهجة يمنية)**: Expected `suspicious`, got `low` (Score: 18). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-025] تأكيد موعد حجز فندقي عبر رابط مصغر (فصحى)**: Expected `suspicious`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-027] سداد فواتير الكهرباء بخصم 40% (لهجة مصرية)**: Expected `high`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-028] طلب إعادة تعيين كلمة مرور البريد الوظيفي (مختلط إنجليزي-عربي)**: Expected `high`, got `low` (Score: 20). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-029] تسوية قضائية مالية سريعة قبل الحجز التنفيذي (فصحى)**: Expected `high`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-030] مكافأة اشتراك متجر إلكتروني شهير (عربيزي)**: Expected `high`, got `low` (Score: 20). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-032] رابط فقط: موقع تصيد لمنصة أبشر عبر عنوان IP مباشر**: Expected `high`, got `low` (Score: 28). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 28)
- **[SCAM-033] لقطة شاشة: تنبيه بنكي احتيالي مصور**: Expected `high`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-034] لقطة شاشة: نافذة منبثقة مزيفة تطلب رمز OTP**: Expected `high`, got `low` (Score: 0). Notes: 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)

### 5.3 Ambiguous & Boundary Calibration Failures
- **[SCAM-001] تجميد الحساب المصرفي ومصادرة البطاقة (فصحى معاصرة)** (scam/msa): Expected `high`, got `suspicious` (Score: 38). Expected Type: `BANK_IMPERSONATION`, Actual: `BANK_IMPERSONATION`.
- **[SCAM-002] طلب رمز التحقق OTP بنك الكريمي (لهجة يمنية)** (scam/yemeni): Expected `high`, got `suspicious` (Score: 50). Expected Type: `ACCOUNT_TAKEOVER`, Actual: `BANK_IMPERSONATION`.
- **[SCAM-003] تحديث بيانات محفظة جيب Jeeb (لهجة يمنية)** (scam/yemeni): Expected `high`, got `suspicious` (Score: 38). Expected Type: `PAYMENT_SCAM`, Actual: `DELIVERY_SCAM`.
- **[SCAM-008] شحنة دي إتش إل معلقة مع رابط مصغر مريب (مختلط إنجليزي-عربي)** (scam/mixed_en): Expected `high`, got `suspicious` (Score: 69). Expected Type: `DELIVERY_SCAM`, Actual: `DELIVERY_SCAM`.
- **[SCAM-009] جائزة مسابقة المليون وسيارة لاندكروزر (فصحى)** (scam/msa): Expected `high`, got `suspicious` (Score: 32). Expected Type: `FAKE_PRIZE`, Actual: `SOCIAL_ENGINEERING`.
- **[SCAM-023] تحديث أمان مايكروسوفت واختراق جهازك (فصحى)** (scam/msa): Expected `high`, got `suspicious` (Score: 38). Expected Type: `SOCIAL_ENGINEERING`, Actual: `DELIVERY_SCAM`.
- **[SCAM-026] طلب تفعيل شريحة eSIM برمز التحقق (لهجة خليجية)** (scam/gulf): Expected `high`, got `suspicious` (Score: 50). Expected Type: `ACCOUNT_TAKEOVER`, Actual: `BANK_IMPERSONATION`.
- **[SCAM-031] رابط فقط: موقع تصيد بنكي صريح بنطاق مريب** (scam/msa): Expected `high`, got `suspicious` (Score: 44). Expected Type: `BANK_IMPERSONATION`, Actual: `BANK_IMPERSONATION`.
- **[ADV-007] احتيال خفي بلغة عربية ركيكة ومترجمة آلياً بدون رابط صريح** (ambiguous/msa): Expected `suspicious`, got `low` (Score: 0). Expected Type: `JOB_SCAM`, Actual: `UNKNOWN`.
- **[ADV-008] رسالة عربيزي تستدرج الضحية برابط مريب متنكر** (ambiguous/arabizi): Expected `high`, got `low` (Score: 20). Expected Type: `BANK_IMPERSONATION`, Actual: `SOCIAL_ENGINEERING`.
- **[ADV-009] نص إخباري طويل يختتم بطلب مالي وتبرع غير مرخص** (ambiguous/msa): Expected `suspicious`, got `low` (Score: 0). Expected Type: `PAYMENT_SCAM`, Actual: `UNKNOWN`.
- **[ADV-010] رابط مشبوه مرفق مع رسالة تهنئة أسرية بريئة ظاهرياً** (ambiguous/msa): Expected `suspicious`, got `low` (Score: 20). Expected Type: `SOCIAL_ENGINEERING`, Actual: `SOCIAL_ENGINEERING`.

---

## 6. Recommendations for Phase 6B Red-Team Hardening

1. **Maintain Zero False Positives Guardrail:** Protect negation handling on security warnings (`"لن يطلب منك OTP"`).
2. **Refine Borderline Heuristic Thresholds:** Calibrate score contributions on dialectal payment requests without explicit links.
3. **Targeted Red-Team Adversarial Testing:** Execute the 16 attack categories defined in [RED_TEAM_TAXONOMY.md](file:///c:/my_projects/haris/evaluation/RED_TEAM_TAXONOMY.md).
