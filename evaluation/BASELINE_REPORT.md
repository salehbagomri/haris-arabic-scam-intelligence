# HARIS (حارس) — Arabic Scam Intelligence Baseline Benchmark Report
**Report Version:** 1.1.0  
**Evaluation Date:** 2026-09-12T20:16:18.345Z  
**Pipeline Mode:** DETERMINISTIC-BASELINE  

---

## 1. Reproducibility & Audit Metadata

| Metadata Field | Value | Notes |
|---|---|---|
| **Git Commit Hash** | `50103c9bd7b0adca8d2d078449b5e20ba8778bb5` | Exact repository revision at time of benchmark run |
| **Dataset Version** | `1.1.0` | Versioned evaluation dataset |
| **Dataset SHA-256** | `abe2cdaa2ee5b1d22a15fd2a09a15281...` | Cryptographic tamper-evident hash of all 70 test cases |
| **Runner Version** | `1.1.0` | Evaluation harness release |
| **Node.js Environment** | `v24.14.0` | Runtime environment |
| **Gemini AI Configuration** | `Disabled / Offline Baseline` | Deterministic baseline runs purely offline |
| **Max AI Score Contribution** | `+15 pts` | Centralized bounded cap |
| **Max Visual Score Contribution** | `+15 pts` | Centralized bounded cap |

---

## 2. Metric Definitions & Benchmark Results

### 2.1 Core Classification Metrics

| Metric | Formula & Denominator | Measured Baseline | Interpretation |
|---|---|---|---|
| **Overall Classification Accuracy** | $\frac{\text{Correct Risk Category}}{\text{Total Cases}} = \frac{30}{70}$ | **42.9%** | All 70 evaluation cases (including unextracted screenshots) |
| **Text/URL Baseline Accuracy** | $\frac{\text{Correct Risk on Text/URL}}{\text{Total Text/URL Cases}} = \frac{30}{65}$ | **46.2%** | Evaluates only cases where input could be processed offline |
| **Legitimate Accuracy (Specificity)** | $\frac{\text{Correct Legitimate}}{\text{Total Legitimate}} = \frac{18}{22}$ | **81.8%** | Specificity against clean Arabic messages |
| **False Positive Rate (FPR)** | $\frac{\text{False Positives}}{\text{Total Legitimate}} = \frac{2}{22}$ | **9.1%** | Critical metric for user trust (Target: < 5%) |
| **False Negative Rate (FNR)** | $\frac{\text{False Negatives}}{\text{Total Scams}} = \frac{21}{34}$ | **61.8%** | Offline deterministic miss rate on conversational dialect scams |

### 2.2 Scam-Type Attribution Metrics

> [!IMPORTANT]
> **Scam-Type Metric Separation:**
> - `scamTypeAccuracyScamOnly` strictly measures scam cases ($N = 34$) and excludes `UNKNOWN` matches on legitimate/ambiguous cases from inflating the score.
> - `scamTypeAccuracyAllCases` measures classification across all cases ($N = 70$).

| Metric | Formula & Denominator | Measured Value |
|---|---|---|
| **Scam-Type Accuracy (Scam Only)** | $\frac{\text{Correct Non-UNKNOWN Scam Type in Scams}}{\text{Total Scam Cases}} = \frac{7}{34}$ | **20.6%** |
| **Scam-Type Accuracy (All Cases)** | $\frac{\text{Correct Scam Type Across All Cases}}{\text{Total Cases}} = \frac{35}{70}$ | **50.0%** |

### 2.3 Confusion Matrix

| | Predicted: High / Suspicious | Predicted: Low (Benign) | Indeterminate / Unextractable | Total Ground Truth |
|---|---|---|---|---|
| **Actual Scam** | **11** (TP) | **21** (FN) | **2** | **34** |
| **Actual Legitimate** | **2** (FP) | **18** (TN) | **2** | **22** |
| **Actual Ambiguous** | **0** | **13** | **1** | **14** |

---

## 3. Modality Separation: Text/URL vs. Screenshot Multimodal

| Modality | Total Cases | Processed | Extraction Failures | Accuracy | Notes |
|---|---|---|---|---|---|
| **Text & URL Inputs** | 65 | 65 | 0 | **46.2%** | Active deterministic engine baseline |
| **Screenshot Inputs** | 5 | 0 | 5 | **0.0%** | Gemini offline; all 5 fixtures produced structured indeterminate status |

> [!NOTE]
> **Vision Evaluation Guardrail:** The benchmark does NOT claim or simulate vision extraction when Gemini is disabled. When Gemini is offline, screenshot fixtures safely produce `isExtractionFailure: true` and are marked as indeterminate rather than being falsely credited as `low` risk.

---

## 4. Category & Dialect Performance Breakdown

### Category Breakdown
| Category | Cases | Correct Risk | Accuracy | Avg Score |
|---|---|---|---|---|
| **Scam / Malicious** | 34 | 3 | **8.8%** | 23.8 / 100 |
| **Legitimate / Benign** | 22 | 18 | **81.8%** | 2.8 / 100 |
| **Ambiguous / Adversarial** | 14 | 9 | **64.3%** | 6.7 / 100 |

### Regional & Dialect Breakdown
| Dialect / Variant | Cases | Correct Risk | Dialect Accuracy |
|---|---|---|---|
| **Modern Standard Arabic (MSA)** | 34 | 15 | **44.1%** |
| **Yemeni Arabic & Local Services** | 13 | 6 | **46.2%** |
| **Gulf / Saudi / UAE** | 9 | 5 | **55.6%** |
| **Egyptian Arabic & Local Wallets** | 4 | 1 | **25.0%** |
| **Mixed Arabic + English** | 6 | 2 | **33.3%** |
| **Arabizi (Latin Script)** | 4 | 1 | **25.0%** |

---

## 5. Scam DNA Feature Detection Benchmark

| Feature Key | Ground Truth | Detected | True Positives | False Positives | False Negatives | Precision | Recall | F1 Score |
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

## 6. Failure Case Diagnosis & Anomaly Audit

### 6.1 False Positives (Legitimate Flagged as Suspicious/High)
- **[LEGIT-007] تأكيد تغيير كلمة مرور حسابك بنجاح (فصحى)**: Expected `low`, got `suspicious` (Score: 30). ⚠️ FALSE POSITIVE: Legitimate flagged as suspicious (score 30)
- **[LEGIT-011] تأكيد رمز الدخول لمرة واحدة من جهة حكومية دون رابط (فصحى)**: Expected `low`, got `suspicious` (Score: 32). ⚠️ FALSE POSITIVE: Legitimate flagged as suspicious (score 32)

### 6.2 False Negatives (Scams Missed as Low Risk)
- **[SCAM-004] إيقاف محفظة فودافون كاش (لهجة مصرية)**: Expected `high`, got `low` (Score: 20). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-005] تحديث البطاقة البنكية الائتمانية (لهجة خليجية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-007] حوالة واردة معلقة عبر النجم للصرافة (لهجة يمنية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-011] يانصيب شركة الاتصالات الكبرى (لهجة خليجية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-012] منصة استثمار وتداول بضمان أرباح يومية 30% (فصحى)**: Expected `high`, got `low` (Score: 18). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-013] تداول العملات المشفرة وسهم أرامكو الوهمي (مختلط إنجليزي-عربي)**: Expected `high`, got `low` (Score: 20). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-014] وظيفة بدوام جزئي عبر الإنترنت براتب 300 دولار يومياً (فصحى)**: Expected `high`, got `low` (Score: 18). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-015] عقد عمل بدولة الخليج وتأشيرة فورية (لهجة مصرية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-017] الضرائب والجمارك اليمنية ورسوم ترقيم السيارات (لهجة يمنية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-018] كود تأكيد واتساب بالخطأ (لهجة يمنية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-019] رمز التحقق الثنائي تيليجرام (مختلط إنجليزي-عربي)**: Expected `high`, got `low` (Score: 18). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-020] تحديث كلمة مرور انستغرام وشارة التوثيق (عربيزي)**: Expected `high`, got `low` (Score: 20). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-021] استغاثة من رقم جديد وحادث سير مفاجئ (لهجة خليجية)**: Expected `high`, got `low` (Score: 18). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-022] سلفه مالية عاجلة من صديق في الغربة (لهجة يمنية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-024] حملة تبرعات إغاثية وهمية لعلاج أطفال (لهجة يمنية)**: Expected `suspicious`, got `low` (Score: 18). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-025] تأكيد موعد حجز فندقي عبر رابط مصغر (فصحى)**: Expected `suspicious`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-027] سداد فواتير الكهرباء بخصم 40% (لهجة مصرية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-028] طلب إعادة تعيين كلمة مرور البريد الوظيفي (مختلط إنجليزي-عربي)**: Expected `high`, got `low` (Score: 20). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-029] تسوية قضائية مالية سريعة قبل الحجز التنفيذي (فصحى)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-030] مكافأة اشتراك متجر إلكتروني شهير (عربيزي)**: Expected `high`, got `low` (Score: 20). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-032] رابط فقط: موقع تصيد لمنصة أبشر عبر عنوان IP مباشر**: Expected `high`, got `low` (Score: 28). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 28)

### 6.3 Screenshot Indeterminate Cases (Offline Vision Fallback)
- **[SCAM-033] لقطة شاشة: تنبيه بنكي احتيالي مصور**: Resulted in structured extraction failure as expected in offline test mode.
- **[SCAM-034] لقطة شاشة: نافذة منبثقة مزيفة تطلب رمز OTP**: Resulted in structured extraction failure as expected in offline test mode.
- **[LEGIT-021] لقطة شاشة: ملصق توعوي رسمي من بنك**: Resulted in structured extraction failure as expected in offline test mode.
- **[LEGIT-022] لقطة شاشة: واجهة نظام داخلية ذات ألوان حمراء**: Resulted in structured extraction failure as expected in offline test mode.
- **[ADV-014] لقطة شاشة: صورة غير واضحة ومشوشة تماماً لقطة رديئة الجودة**: Resulted in structured extraction failure as expected in offline test mode.

### 6.4 Ambiguous / Boundary Calibration Mismatches
- **[SCAM-001] تجميد الحساب المصرفي ومصادرة البطاقة (فصحى معاصرة)**: Expected `high`, got `suspicious` (Score: 38). Expected Scam Type: `BANK_IMPERSONATION`, Actual: `BANK_IMPERSONATION`.
- **[SCAM-002] طلب رمز التحقق OTP بنك الكريمي (لهجة يمنية)**: Expected `high`, got `suspicious` (Score: 50). Expected Scam Type: `ACCOUNT_TAKEOVER`, Actual: `BANK_IMPERSONATION`.
- **[SCAM-003] تحديث بيانات محفظة جيب Jeeb (لهجة يمنية)**: Expected `high`, got `suspicious` (Score: 38). Expected Scam Type: `PAYMENT_SCAM`, Actual: `DELIVERY_SCAM`.
- **[SCAM-008] شحنة دي إتش إل معلقة مع رابط مصغر مريب (مختلط إنجليزي-عربي)**: Expected `high`, got `suspicious` (Score: 69). Expected Scam Type: `DELIVERY_SCAM`, Actual: `DELIVERY_SCAM`.
- **[SCAM-009] جائزة مسابقة المليون وسيارة لاندكروزر (فصحى)**: Expected `high`, got `suspicious` (Score: 32). Expected Scam Type: `FAKE_PRIZE`, Actual: `SOCIAL_ENGINEERING`.
- **[SCAM-023] تحديث أمان مايكروسوفت واختراق جهازك (فصحى)**: Expected `high`, got `suspicious` (Score: 38). Expected Scam Type: `SOCIAL_ENGINEERING`, Actual: `DELIVERY_SCAM`.
- **[SCAM-026] طلب تفعيل شريحة eSIM برمز التحقق (لهجة خليجية)**: Expected `high`, got `suspicious` (Score: 50). Expected Scam Type: `ACCOUNT_TAKEOVER`, Actual: `BANK_IMPERSONATION`.
- **[SCAM-031] رابط فقط: موقع تصيد بنكي صريح بنطاق مريب**: Expected `high`, got `suspicious` (Score: 44). Expected Scam Type: `BANK_IMPERSONATION`, Actual: `BANK_IMPERSONATION`.
- **[ADV-007] احتيال خفي بلغة عربية ركيكة ومترجمة آلياً بدون رابط صريح**: Expected `suspicious`, got `low` (Score: 0). Expected Scam Type: `JOB_SCAM`, Actual: `UNKNOWN`.
- **[ADV-008] رسالة عربيزي تستدرج الضحية برابط مريب متنكر**: Expected `high`, got `low` (Score: 20). Expected Scam Type: `BANK_IMPERSONATION`, Actual: `SOCIAL_ENGINEERING`.
- **[ADV-009] نص إخباري طويل يختتم بطلب مالي وتبرع غير مرخص**: Expected `suspicious`, got `low` (Score: 0). Expected Scam Type: `PAYMENT_SCAM`, Actual: `UNKNOWN`.
- **[ADV-010] رابط مشبوه مرفق مع رسالة تهنئة أسرية بريئة ظاهرياً**: Expected `suspicious`, got `low` (Score: 20). Expected Scam Type: `SOCIAL_ENGINEERING`, Actual: `SOCIAL_ENGINEERING`.
