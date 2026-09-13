# HARIS (حارس) — Arabic Scam Intelligence Baseline Benchmark Report
**Report Version:** 1.2.0  
**Evaluation Date:** 2026-09-13T04:38:53.591Z  
**Pipeline Mode:** DETERMINISTIC-BASELINE  

---

## 1. Reproducibility & Audit Metadata

| Metadata Field | Value | Notes |
|---|---|---|
| **Evaluation Source Commit** | `f1e80fef3642ce7f26f254d07e742345f1cebd6f` | Exact Git commit of codebase at execution |
| **Artifact Revision** | `f1e80fef3642ce7f26f254d07e742345f1cebd6f` | Commit capturing baseline artifact files |
| **Dataset Version** | `1.2.0` | Versioned evaluation dataset |
| **Dataset SHA-256** | `4e82b82e4d4822921cf8c2ee70b39bc5...` | Tamper-evident hash of all 70 test cases |
| **Configuration & Weights Hash** | `a169d90c9c088f8bcf9e62abc9cd2707...` | Cryptographic hash of DEFAULT_RISK_WEIGHTS + VISION_CONFIG |
| **Runner Version** | `1.2.0` | Evaluation harness release |
| **Node.js Environment** | `v24.14.0` | Runtime environment |
| **Gemini AI Configuration** | `Disabled / Offline Baseline` | Deterministic baseline runs purely offline |
| **Max AI Contribution Cap** | `+15 pts` | Centralized bounded cap |
| **Max Visual Contribution Cap** | `+15 pts` | Centralized bounded cap |

---

## 2. Granular Metric Definitions & Measured Baseline Results

### 2.1 Risk Classification Accuracy Metrics

| Metric | Formula & Denominator | Value | Definition & Notes |
|---|---|---|---|
| **Coverage-Adjusted Accuracy** | $\frac{\text{Total Correct}}{\text{Total Cases}} = \frac{37}{70}$ | **52.9%** | Evaluates all 70 cases; unextracted screenshots count as failure |
| **Determinate Risk Accuracy** | $\frac{\text{Correct Determinate}}{\text{Determinate Cases}} = \frac{37}{65}$ | **56.9%** | Evaluates only cases where inputs were determinately processed |
| **Determinate Cases Count** | Total Cases - Indeterminate = 70 - 5 | **65** | 65 Text/URL cases |
| **Indeterminate Cases Count** | Cases with unextracted screenshots | **5** | 5 screenshot cases offline |

### 2.2 Legitimate Message Evaluation Metrics

| Metric | Formula & Denominator | Value | Definition & Notes |
|---|---|---|---|
| **Legitimate Determinate Accuracy** | $\frac{\text{TN}}{\text{TN} + \text{FP}} = \frac{19}{20}$ | **95.0%** | True negative rate among determinate legitimate messages |
| **Legitimate Coverage-Adjusted Accuracy** | $\frac{\text{TN}}{\text{Total Legitimate}} = \frac{19}{22}$ | **86.4%** | Penalizes indeterminate screenshot cases |
| **False Positive Rate (FPR)** | $\frac{\text{FP}}{\text{TN} + \text{FP}} = \frac{1}{20}$ | **5.0%** | $\frac{2}{20} = 10.0\%$; standard epidemiological FPR formula |
| **Legitimate Indeterminate Rate** | $\frac{\text{Legit Indeterminate}}{\text{Total Legitimate}} = \frac{2}{22}$ | **9.1%** | $\frac{2}{22} = 9.1\%$ |

### 2.3 Scam Detection & Miss Rate Metrics

| Metric | Formula & Denominator | Value | Definition & Notes |
|---|---|---|---|
| **Scam Determinate Detection Rate (Recall)** | $\frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{14}{32}$ | **43.8%** | $\frac{11}{32} = 34.4\%$ (Determinate sensitivity) |
| **Scam Determinate False Negative Rate (FNR)** | $\frac{\text{FN}}{\text{TP} + \text{FN}} = \frac{18}{32}$ | **56.3%** | $\frac{21}{32} = 65.6\%$ (Miss rate on determinate scams) |
| **Scam Miss Rate (Including Indeterminate)** | $\frac{\text{FN} + \text{Scam Indet}}{\text{Total Scams}} = \frac{20}{34}$ | **58.8%** | $\frac{23}{34} = 67.6\%$ (Penalizes unextracted scams) |
| **Scam Indeterminate Rate** | $\frac{\text{Scam Indet}}{\text{Total Scams}} = \frac{2}{34}$ | **5.9%** | $\frac{2}{34} = 5.9\%$ |

### 2.4 Scam-Type Attribution Metrics

| Metric | Formula & Denominator | Value | Definition & Notes |
|---|---|---|---|
| **Scam-Only Determinate Accuracy** | $\frac{\text{Correct Non-UNKNOWN}}{\text{Determinate Scams}} = \frac{8}{30}$ | **25.0%** | $\frac{7}{32} = 21.9\%$ (Strictly excludes UNKNOWN matches) |
| **Scam-Only Coverage-Adjusted Accuracy** | $\frac{\text{Correct Non-UNKNOWN}}{\text{Total Scams}} = \frac{8}{34}$ | **23.5%** | $\frac{7}{34} = 20.6\%$ |
| **All-Cases Coverage-Adjusted Match** | $\frac{\text{All Matches (incl. UNKNOWN)}}{\text{Total Cases}} = \frac{39}{70}$ | **55.7%** | $\frac{35}{70} = 50.0\%$ (Reference only) |

---

## 3. Detailed Confusion Matrix

| Ground Truth Category | High / Suspicious (Positive) | Low (Negative) | Indeterminate (Offline Screenshot) | Total Cases |
|---|---|---|---|---|
| **Actual Scam** | **14** (TP) | **18** (FN) | **2** | **34** |
| **Actual Legitimate** | **1** (FP) | **19** (TN) | **2** | **22** |
| **Actual Ambiguous** | **2** | **11** | **1** | **14** |
| **Total** | **17** | **48** | **5** | **70** |

---

## 4. Modality Separation & Screenshot Contract Verification

| Modality | Total Cases | Processed Determinate | Extraction Failures | Accuracy | Pipeline Status |
|---|---|---|---|---|---|
| **Text & URL Modality** | 65 | 65 | 0 | **56.9%** | Deterministic engine executed offline |
| **Screenshot Modality** | 5 | 0 | 5 | **0.0%** | Gemini offline; structured fallback generated |

> [!IMPORTANT]
> **Screenshot Payload Contract Verification:**
> - All 5 screenshot cases pass genuine Base64 PNG payloads matching the production `ScreenshotInput` contract (`base64` property).
> - `validateImageConstraints` verified all payloads as valid (>1KB PNG with valid magic header).
> - The fallback reason is strictly `'Gemini client is unconfigured or disabled.'` and NOT `'Missing image payload'`.
> - `simulatedVisualDescription` is NOT present in `input.screenshot` and never enters production analysis.

---

## 5. Category & Dialect Breakdown

### 5.1 Category Performance
| Category | Cases | Correct Risk | Accuracy | Avg Suspicion Score |
|---|---|---|---|---|
| **Scam / Malicious** | 34 | 7 | **20.6%** | 32.3 / 100 |
| **Legitimate / Benign** | 22 | 19 | **86.4%** | 2.4 / 100 |
| **Ambiguous / Adversarial** | 14 | 11 | **78.6%** | 14.1 / 100 |

### 5.2 Regional & Dialect Performance
| Dialect / Variant | Cases | Correct Risk | Dialect Accuracy |
|---|---|---|---|
| **Modern Standard Arabic (MSA)** | 34 | 19 | **55.9%** |
| **Yemeni Arabic & Local Services** | 13 | 7 | **53.8%** |
| **Gulf / Saudi / UAE** | 9 | 5 | **55.6%** |
| **Egyptian Arabic & Local Wallets** | 4 | 1 | **25.0%** |
| **Mixed Arabic + English** | 6 | 2 | **33.3%** |
| **Arabizi (Latin Script)** | 4 | 3 | **75.0%** |

---

## 6. Scam DNA Feature Detection Benchmark

| Feature Key | Ground Truth | Detected | True Positives | False Positives | False Negatives | Precision | Recall | F1 Score |
|---|---|---|---|---|---|---|---|---|
| `urgency` | 23 | 16 | 13 | 3 | 10 | 81.3% | 56.5% | **66.7%** |
| `credential_request` | 11 | 3 | 2 | 1 | 9 | 66.7% | 18.2% | **28.6%** |
| `otp_request` | 6 | 4 | 3 | 1 | 3 | 75.0% | 50.0% | **60.0%** |
| `impersonation` | 22 | 9 | 8 | 1 | 14 | 88.9% | 36.4% | **51.7%** |
| `financial_lure` | 12 | 4 | 4 | 0 | 8 | 100.0% | 33.3% | **50.0%** |
| `suspicious_url` | 18 | 13 | 13 | 0 | 5 | 100.0% | 72.2% | **83.9%** |
| `threat_language` | 9 | 3 | 2 | 1 | 7 | 66.7% | 22.2% | **33.3%** |
| `unexpected_contact` | 5 | 3 | 1 | 2 | 4 | 33.3% | 20.0% | **25.0%** |
| `secrecy_pressure` | 2 | 0 | 0 | 0 | 2 | 0.0% | 0.0% | **0.0%** |
| `suspicious_payment_request` | 10 | 4 | 3 | 1 | 7 | 75.0% | 30.0% | **42.9%** |
| `action_pressure` | 6 | 6 | 0 | 6 | 6 | 0.0% | 0.0% | **0.0%** |

---

## 7. Failure & Boundary Diagnosis

### 7.1 False Positives (Legitimate Flagged as Suspicious/High)
- **[LEGIT-007] تأكيد تغيير كلمة مرور حسابك بنجاح (فصحى)**: Expected `low`, got `suspicious` (Score: 30). ⚠️ FALSE POSITIVE: Legitimate flagged as suspicious (score 30)

### 7.2 False Negatives (Scams Missed as Low Risk)
- **[SCAM-005] تحديث البطاقة البنكية الائتمانية (لهجة خليجية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-011] يانصيب شركة الاتصالات الكبرى (لهجة خليجية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-012] منصة استثمار وتداول بضمان أرباح يومية 30% (فصحى)**: Expected `high`, got `low` (Score: 18). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-013] تداول العملات المشفرة وسهم أرامكو الوهمي (مختلط إنجليزي-عربي)**: Expected `high`, got `low` (Score: 20). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-014] وظيفة بدوام جزئي عبر الإنترنت براتب 300 دولار يومياً (فصحى)**: Expected `high`, got `low` (Score: 18). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-015] عقد عمل بدولة الخليج وتأشيرة فورية (لهجة مصرية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-017] الضرائب والجمارك اليمنية ورسوم ترقيم السيارات (لهجة يمنية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-018] كود تأكيد واتساب بالخطأ (لهجة يمنية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-019] رمز التحقق الثنائي تيليجرام (مختلط إنجليزي-عربي)**: Expected `high`, got `low` (Score: 18). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-021] استغاثة من رقم جديد وحادث سير مفاجئ (لهجة خليجية)**: Expected `high`, got `low` (Score: 18). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-022] سلفه مالية عاجلة من صديق في الغربة (لهجة يمنية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-024] حملة تبرعات إغاثية وهمية لعلاج أطفال (لهجة يمنية)**: Expected `suspicious`, got `low` (Score: 18). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 18)
- **[SCAM-025] تأكيد موعد حجز فندقي عبر رابط مصغر (فصحى)**: Expected `suspicious`, got `low` (Score: 8). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 8)
- **[SCAM-027] سداد فواتير الكهرباء بخصم 40% (لهجة مصرية)**: Expected `high`, got `low` (Score: 0). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 0)
- **[SCAM-028] طلب إعادة تعيين كلمة مرور البريد الوظيفي (مختلط إنجليزي-عربي)**: Expected `high`, got `low` (Score: 20). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 20)
- **[SCAM-029] تسوية قضائية مالية سريعة قبل الحجز التنفيذي (فصحى)**: Expected `high`, got `low` (Score: 8). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 8)
- **[SCAM-030] مكافأة اشتراك متجر إلكتروني شهير (عربيزي)**: Expected `high`, got `low` (Score: 28). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 28)
- **[SCAM-032] رابط فقط: موقع تصيد لمنصة أبشر عبر عنوان IP مباشر**: Expected `high`, got `low` (Score: 28). 🚨 FALSE NEGATIVE: Scam missed as low risk (score 28)

### 7.3 Indeterminate Cases (Offline Screenshot Modality)
- **[SCAM-033] لقطة شاشة: تنبيه بنكي احتيالي مصور**: Resulted in structured extraction failure as expected in offline test mode.
- **[SCAM-034] لقطة شاشة: نافذة منبثقة مزيفة تطلب رمز OTP**: Resulted in structured extraction failure as expected in offline test mode.
- **[LEGIT-021] لقطة شاشة: ملصق توعوي رسمي من بنك**: Resulted in structured extraction failure as expected in offline test mode.
- **[LEGIT-022] لقطة شاشة: واجهة نظام داخلية ذات ألوان حمراء**: Resulted in structured extraction failure as expected in offline test mode.
- **[ADV-014] لقطة شاشة: صورة غير واضحة ومشوشة تماماً لقطة رديئة الجودة**: Resulted in structured extraction failure as expected in offline test mode.

### 7.4 Ambiguous / Boundary Calibration Mismatches
- **[SCAM-003] تحديث بيانات محفظة جيب Jeeb (لهجة يمنية)**: Expected `high`, got `suspicious` (Score: 38). Expected Scam Type: `PAYMENT_SCAM`, Actual: `SOCIAL_ENGINEERING`.
- **[SCAM-004] إيقاف محفظة فودافون كاش (لهجة مصرية)**: Expected `high`, got `suspicious` (Score: 38). Expected Scam Type: `PAYMENT_SCAM`, Actual: `BANK_IMPERSONATION`.
- **[SCAM-008] شحنة دي إتش إل معلقة مع رابط مصغر مريب (مختلط إنجليزي-عربي)**: Expected `high`, got `suspicious` (Score: 69). Expected Scam Type: `DELIVERY_SCAM`, Actual: `DELIVERY_SCAM`.
- **[SCAM-010] مكافأة السحب الأسبوعي لمحفظة ون كاش (لهجة يمنية)**: Expected `high`, got `suspicious` (Score: 65). Expected Scam Type: `FAKE_PRIZE`, Actual: `GOVERNMENT_IMPERSONATION`.
- **[SCAM-023] تحديث أمان مايكروسوفت واختراق جهازك (فصحى)**: Expected `high`, got `suspicious` (Score: 38). Expected Scam Type: `SOCIAL_ENGINEERING`, Actual: `SOCIAL_ENGINEERING`.
- **[SCAM-026] طلب تفعيل شريحة eSIM برمز التحقق (لهجة خليجية)**: Expected `high`, got `suspicious` (Score: 50). Expected Scam Type: `ACCOUNT_TAKEOVER`, Actual: `BANK_IMPERSONATION`.
- **[SCAM-031] رابط فقط: موقع تصيد بنكي صريح بنطاق مريب**: Expected `high`, got `suspicious` (Score: 44). Expected Scam Type: `BANK_IMPERSONATION`, Actual: `BANK_IMPERSONATION`.
- **[ADV-007] احتيال خفي بلغة عربية ركيكة ومترجمة آلياً بدون رابط صريح**: Expected `suspicious`, got `low` (Score: 26). Expected Scam Type: `JOB_SCAM`, Actual: `JOB_SCAM`.
- **[ADV-009] نص إخباري طويل يختتم بطلب مالي وتبرع غير مرخص**: Expected `suspicious`, got `low` (Score: 0). Expected Scam Type: `PAYMENT_SCAM`, Actual: `UNKNOWN`.
