# HARIS (حارس) — Adversarial Red-Team Evaluation Report
**Report Version:** 1.0.0  
**Phase:** Phase 6B (Red-Team & Adversarial Evaluation)  
**Evaluation Date:** 2026-09-12T23:30:40.324Z  
**Pipeline Mode:** deterministic-baseline-redteam  

---

## 1. Executive Summary

This report documents the formal **Phase 6B Red-Team and Adversarial Evaluation** of the **HARIS Arabic Scam Intelligence Engine** across all **16 threat taxonomy categories** specified in `evaluation/RED_TEAM_TAXONOMY.md`.

The goal of this evaluation is to systematically stress-test and probe vulnerabilities in the approved baseline system before implementing tuning, weights adjustments, or prompt changes.

### Key Headline Metrics
- **Total Attack Corpus:** 48 cases across 16 categories.
- **Overall Failure Rate:** **68.8%** (33/48 cases triggered at least one failure mode).
- **False Positive Rate (Benign Stress Tests):** **5.3%** (1 benign cases misclassified as suspicious/high).
- **False Negative Rate (Evasion Attacks):** **48.3%** (14 malicious evasion cases misclassified as low risk).
- **Indeterminate Rate (Screenshots):** **12.5%** (6/48 offline screenshot extraction state).
- **Evidence Integrity Violations:** **2** recorded across all cases.
- **Scam-Type Attribution Accuracy (Determinate Scams):** **23.1%**.

---

## 2. Attack Coverage & Reproducibility Metadata

| Metadata Field | Value | Notes |
|---|---|---|
| **Evaluation Source Commit** | `cbf5ce7537dca30789b89dd69001a8c491c57f88` | Exact Git commit of codebase during evaluation |
| **Dataset Version** | `1.0.0` | 48-case dedicated Red-Team corpus |
| **Dataset SHA-256** | `72c5a8ac8de7fdd750f94a89f1a81ff6...` | Tamper-evident cryptographic hash |
| **Runner Version** | `1.0.0` | Phase 6B Red-Team evaluator |
| **Node.js Environment** | `v24.14.0` | Runtime environment |
| **Gemini AI Configuration** | `Disabled / Offline Baseline` | Deterministic baseline mode |
| **Categories Evaluated** | `16 / 16 (100%)` | Full coverage of RED_TEAM_TAXONOMY.md |

---

## 3. Results by Taxonomy Category

| Category # | Adversarial Taxonomy Category | Total | Failed | Failure Rate | FP | FN | Evidence Violations | Avg Score |
|---|---|---|---|---|---|---|---|---|
| **1** | Brand Mention Without Impersonation | 3 | 0 | **0.0%** | 0 | 0 | 0 | 0 |
| **2** | Legitimate OTP Warnings (Polarity Inversion) | 3 | 1 | **33.3%** | 1 | 0 | 1 | 10.7 |
| **3** | Legitimate Urgency (Operational Deadlines) | 3 | 0 | **0.0%** | 0 | 0 | 0 | 12 |
| **4** | Benign Suspicious-Looking Domains | 3 | 0 | **0.0%** | 0 | 0 | 0 | 0 |
| **5** | Arabizi Obfuscation (Script Evasion) | 3 | 3 | **100.0%** | 0 | 3 | 0 | 21.3 |
| **6** | Unicode Confusables / Zero-Width / Tatweel | 3 | 3 | **100.0%** | 0 | 1 | 1 | 72.7 |
| **7** | Excessive Punctuation / Emojis | 3 | 0 | **0.0%** | 0 | 0 | 0 | 6 |
| **8** | Broken / Machine-Translated Arabic | 3 | 3 | **100.0%** | 0 | 3 | 0 | 20 |
| **9** | Mixed Arabic + English Concealment | 3 | 3 | **100.0%** | 0 | 0 | 0 | 38 |
| **10** | Misleading Screenshots / Layout Spoofing | 3 | 3 | **100.0%** | 0 | 0 | 0 | 0 |
| **11** | Visual Brand Resemblance (Color/Icon) | 3 | 3 | **100.0%** | 0 | 0 | 0 | 0 |
| **12** | Multiple / Decoy URLs | 3 | 2 | **66.7%** | 0 | 0 | 0 | 29.3 |
| **13** | Contradictory Evidence Fusion | 3 | 3 | **100.0%** | 0 | 1 | 0 | 41.3 |
| **14** | Scam Language Without Any URL | 3 | 3 | **100.0%** | 0 | 2 | 0 | 18.7 |
| **15** | Suspicious URL Inside Legitimate Message | 3 | 3 | **100.0%** | 0 | 2 | 0 | 26 |
| **16** | Long Distracting Text Containing Malicious Instructions | 3 | 3 | **100.0%** | 0 | 2 | 0 | 26 |

---

## 4. Results by Dialect

| Dialect | Description | Total Cases | Failed Cases | Failure Rate |
|---|---|---|---|---|
| **YEMENI** | Yemeni Colloquial Arabic (لهجة يمنية) | 6 | 3 | **50.0%** |
| **GULF** | Gulf Colloquial Arabic (لهجة خليجية) | 8 | 5 | **62.5%** |
| **MSA** | Modern Standard Arabic (فصحى) | 21 | 15 | **71.4%** |
| **MIXED_EN** | Bilingual Arabic + English (ثنائي اللغة) | 5 | 3 | **60.0%** |
| **ARABIZI** | Arabizi Latin Transliteration (عربيزي) | 3 | 3 | **100.0%** |
| **EGYPTIAN** | Egyptian Colloquial Arabic (لهجة مصرية) | 2 | 1 | **50.0%** |
| **BROKEN_ARABIC** | Machine-Translated / Broken Arabic (لغة مترجمة ركيكة) | 3 | 3 | **100.0%** |

---

## 5. Results by Modality

| Modality | Description | Total Cases | Failed Cases | Failure Rate |
|---|---|---|---|---|
| **TEXT** | Text Message Only (رسالة نصية فقط) | 15 | 4 | **26.7%** |
| **URL** | URL Link Only (رابط إنترنت فقط) | 3 | 0 | **0.0%** |
| **TEXT_URL** | Text + Embedded Link (نص + رابط) | 24 | 23 | **95.8%** |
| **SCREENSHOT** | Screenshot Image (لقطة شاشة مصورة) | 6 | 6 | **100.0%** |

---

## 6. False Positives Breakdown (Benign Stress Tests)

### [RED-006] تذكير أمني صارم ضد الهندسة الاجتماعية (لهجة خليجية)
- **Category:** 2. Legitimate OTP Warnings (Polarity Inversion) (GULF)
- **Actual Assigned Risk:** `SUSPICIOUS` (Score: 32) | Expected: `LOW`
- **Triggered Features:** `[otp_request]`
- **Failures:**
  - **[High]** False alarm on benign stress input: expected LOW risk, but engine classified as SUSPICIOUS (Score: 32).
  - **[High]** Negative security advisory mentioning OTP was falsely treated as OTP harvesting request.


---

## 7. False Negatives Breakdown (Malicious Evasion Attacks)

### [RED-013] تصيد بنكي بالأرابيزي لسرقة رمز الـ OTP
- **Category:** 5. Arabizi Obfuscation (Script Evasion) (ARABIZI)
- **Actual Assigned Risk:** `LOW` (Score: 20) | Expected: `HIGH`
- **Expected Scam Type:** `BANK_IMPERSONATION` | Actual: `SOCIAL_ENGINEERING`
- **Expected Features:** `[impersonation, otp_request, urgency]` | Detected: `[suspicious_url]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### [RED-014] جائزة وهمية بالأرابيزي تطلب رقم البطاقة
- **Category:** 5. Arabizi Obfuscation (Script Evasion) (ARABIZI)
- **Actual Assigned Risk:** `LOW` (Score: 20) | Expected: `HIGH`
- **Expected Scam Type:** `FAKE_PRIZE` | Actual: `SOCIAL_ENGINEERING`
- **Expected Features:** `[financial_lure, credential_request]` | Detected: `[suspicious_url]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### [RED-015] احتيال توصيل طرود بالأرابيزي ورسوم غير مدفوعة
- **Category:** 5. Arabizi Obfuscation (Script Evasion) (ARABIZI)
- **Actual Assigned Risk:** `LOW` (Score: 24) | Expected: `HIGH`
- **Expected Scam Type:** `DELIVERY_SCAM` | Actual: `DELIVERY_SCAM`
- **Expected Features:** `[impersonation, suspicious_payment_request]` | Detected: `[impersonation]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 24).

### [RED-018] تصيد يخلط محارف كيريلية شبيهة بالعربية واللاتينية (Homoglyphs)
- **Category:** 6. Unicode Confusables / Zero-Width / Tatweel (MSA)
- **Actual Assigned Risk:** `LOW` (Score: 24) | Expected: `HIGH`
- **Expected Scam Type:** `ACCOUNT_TAKEOVER` | Actual: `BANK_IMPERSONATION`
- **Expected Features:** `[credential_request, threat_language]` | Detected: `[impersonation]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 24).

### [RED-022] احتيال توظيف بركاكة لغوية ناتجة عن ترجمة آلية أجنبية
- **Category:** 8. Broken / Machine-Translated Arabic (BROKEN_ARABIC)
- **Actual Assigned Risk:** `LOW` (Score: 20) | Expected: `HIGH`
- **Expected Scam Type:** `JOB_SCAM` | Actual: `SOCIAL_ENGINEERING`
- **Expected Features:** `[financial_lure, unexpected_contact]` | Detected: `[suspicious_url]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### [RED-023] احتيال عملات مشفرة مترجم آلياً من عصابات أجنبية
- **Category:** 8. Broken / Machine-Translated Arabic (BROKEN_ARABIC)
- **Actual Assigned Risk:** `LOW` (Score: 20) | Expected: `HIGH`
- **Expected Scam Type:** `INVESTMENT_SCAM` | Actual: `SOCIAL_ENGINEERING`
- **Expected Features:** `[financial_lure]` | Detected: `[suspicious_url]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### [RED-024] احتيال الميراث والرسوم المسبقة بلغة مترجمة متهالكة
- **Category:** 8. Broken / Machine-Translated Arabic (BROKEN_ARABIC)
- **Actual Assigned Risk:** `LOW` (Score: 20) | Expected: `HIGH`
- **Expected Scam Type:** `PAYMENT_SCAM` | Actual: `SOCIAL_ENGINEERING`
- **Expected Features:** `[financial_lure, suspicious_payment_request]` | Detected: `[suspicious_url]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### [RED-039] تحية عائلية ومشاعر قرابة متبوعة بطلب رمز تحقق (لهجة يمنية)
- **Category:** 13. Contradictory Evidence Fusion (YEMENI)
- **Actual Assigned Risk:** `LOW` (Score: 20) | Expected: `HIGH`
- **Expected Scam Type:** `ACCOUNT_TAKEOVER` | Actual: `SOCIAL_ENGINEERING`
- **Expected Features:** `[otp_request, impersonation]` | Detected: `[suspicious_url]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### [RED-040] جائزة نقدية تدعو للاتصال الهاتفي والتوجه للصراف (لهجة يمنية)
- **Category:** 14. Scam Language Without Any URL (YEMENI)
- **Actual Assigned Risk:** `LOW` (Score: 18) | Expected: `HIGH`
- **Expected Scam Type:** `FAKE_PRIZE` | Actual: `SOCIAL_ENGINEERING`
- **Expected Features:** `[financial_lure, action_pressure]` | Detected: `[financial_lure]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 18).

### [RED-042] منحة بنكية وهمية توجه للاتصال بالهاتف فوراً (لهجة مصرية)
- **Category:** 14. Scam Language Without Any URL (EGYPTIAN)
- **Actual Assigned Risk:** `LOW` (Score: 0) | Expected: `HIGH`
- **Expected Scam Type:** `FAKE_PRIZE` | Actual: `UNKNOWN`
- **Expected Features:** `[financial_lure, impersonation, action_pressure]` | Detected: `[]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 0).

### [RED-043] تهنئة عيد فطر دافئة ملغمة برابط تصيد خبيث (فصحى)
- **Category:** 15. Suspicious URL Inside Legitimate Message (MSA)
- **Actual Assigned Risk:** `LOW` (Score: 20) | Expected: `HIGH`
- **Expected Scam Type:** `SOCIAL_ENGINEERING` | Actual: `SOCIAL_ENGINEERING`
- **Expected Features:** `[unexpected_contact]` | Detected: `[suspicious_url]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### [RED-045] تبريكات بشهر رمضان الكريم ملحومة برابط باقة مجانية (لهجة يمنية)
- **Category:** 15. Suspicious URL Inside Legitimate Message (YEMENI)
- **Actual Assigned Risk:** `LOW` (Score: 20) | Expected: `HIGH`
- **Expected Scam Type:** `FAKE_PRIZE` | Actual: `SOCIAL_ENGINEERING`
- **Expected Features:** `[financial_lure]` | Detected: `[suspicious_url]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### [RED-047] مقال علمي عن الذكاء الاصطناعي يخفي رابط استثمار وهمي عالي الربح
- **Category:** 16. Long Distracting Text Containing Malicious Instructions (MSA)
- **Actual Assigned Risk:** `LOW` (Score: 20) | Expected: `HIGH`
- **Expected Scam Type:** `INVESTMENT_SCAM` | Actual: `SOCIAL_ENGINEERING`
- **Expected Features:** `[financial_lure, suspicious_payment_request]` | Detected: `[suspicious_url]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### [RED-048] تعميم إداري لموظفي شركة يحتوي على طلب إدخال كلمة مرور بريد داخلي
- **Category:** 16. Long Distracting Text Containing Malicious Instructions (MSA)
- **Actual Assigned Risk:** `LOW` (Score: 20) | Expected: `HIGH`
- **Expected Scam Type:** `ACCOUNT_TAKEOVER` | Actual: `SOCIAL_ENGINEERING`
- **Expected Features:** `[credential_request, otp_request]` | Detected: `[suspicious_url]`
- **Vulnerability Reason:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).


---

## 8. Scam DNA Failures & Feature Recall

| Feature Key | Feature Name (Arabic) | Expected Count | Detected Count | Recall |
|---|---|---|---|---|
| `urgency` | استعجال وضغط زمني | 3 | 1 | **33.3%** |
| `credential_request` | طلب بيانات اعتماد | 10 | 0 | **0.0%** |
| `otp_request` | طلب رمز التحقق OTP | 5 | 1 | **20.0%** |
| `impersonation` | انتحال صفة رسمية | 16 | 4 | **25.0%** |
| `financial_lure` | إغراء مالي وجوائز | 10 | 1 | **10.0%** |
| `suspicious_url` | رابط مشبوه وتصيد | 0 | 0 | **100.0%** |
| `threat_language` | تهديد وإيقاف خدمات | 11 | 4 | **36.4%** |
| `unexpected_contact` | اتصال غير متوقع | 2 | 0 | **0.0%** |
| `secrecy_pressure` | ضغط كتمان وسرية | 0 | 0 | **100.0%** |
| `suspicious_payment_request` | طلب دفع مالي مريب | 4 | 0 | **0.0%** |
| `action_pressure` | ضغط لاتخاذ إجراء فوري | 3 | 0 | **0.0%** |

---

## 9. Scam-Type Failures & Misattributions

- **[RED-016] تصيد بنكي بحروف مطولة عمداً (تطويل/تطعيج الكلمات)**: Expected `ACCOUNT_TAKEOVER`, but engine assigned `BANK_IMPERSONATION` (Score: 100).
- **[RED-025] تصيد Apple ID يجمع بين إشعار أمني إنجليزي وتوجيه عربي**: Expected `ACCOUNT_TAKEOVER`, but engine assigned `DELIVERY_SCAM` (Score: 38).
- **[RED-026] تنبيه بنكي ثنائي اللغة يطلب تحديث KYC عبر رابط تصيد**: Expected `BANK_IMPERSONATION`, but engine assigned `DELIVERY_SCAM` (Score: 38).
- **[RED-027] تصيد محفظة رقمية Metamask بطلب الكلمات المفتاحية (Seed Phrase)**: Expected `INVESTMENT_SCAM`, but engine assigned `DELIVERY_SCAM` (Score: 38).
- **[RED-035] رابط حساب تويتر رسمي مرفق مع رابط مسابقة وجائزة وهمية**: Expected `FAKE_PRIZE`, but engine assigned `DELIVERY_SCAM` (Score: 44).
- **[RED-038] مخاطبة حكومية رسمية مهذبة تتضمن تحويلاً مالياً لجهة مجهولة**: Expected `GOVERNMENT_IMPERSONATION`, but engine assigned `DELIVERY_SCAM` (Score: 38).
- **[RED-044] تهنئة باليوم الوطني تحتوي على رابط سحب احتيالي (لهجة خليجية)**: Expected `FAKE_PRIZE`, but engine assigned `DELIVERY_SCAM` (Score: 38).
- **[RED-046] مقال تحليلي اقتصادي مطول يخفي في نهايته رابط تحديث بنكي عاجل**: Expected `BANK_IMPERSONATION`, but engine assigned `DELIVERY_SCAM` (Score: 38).

---

## 10. Evidence Integrity Failures

### [RED-006] تذكير أمني صارم ضد الهندسة الاجتماعية (لهجة خليجية)
- **Category:** 2. Legitimate OTP Warnings (Polarity Inversion)
- **[High] Rule `negative_otp_warning_as_scam`:** Negative security advisory mentioning OTP was falsely treated as OTP harvesting request.

### [RED-017] تصيد بفواصل ومسافات صفرية (Zero-Width Space)
- **Category:** 6. Unicode Confusables / Zero-Width / Tatweel
- **[High] Rule `ungrounded_evidence_quote`:** Evidence quote "تم حظر حسابك" is not grounded in source input text.


---

## 11. Highest-Severity Attack Cases (Critical & High)

### 1. [RED-039] تحية عائلية ومشاعر قرابة متبوعة بطلب رمز تحقق (لهجة يمنية)
- **Category:** 13. Contradictory Evidence Fusion | **Dialect:** YEMENI | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `LOW` (Score: 20)
- **Failures:**
  - **[Critical] FALSE_NEGATIVE:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).
  - **[Critical] CONTRADICTORY_FUSION_FAILURE:** Signal dilution or decoy URL bypassed threat detection (actual risk: low).

### 2. [RED-013] تصيد بنكي بالأرابيزي لسرقة رمز الـ OTP
- **Category:** 5. Arabizi Obfuscation (Script Evasion) | **Dialect:** ARABIZI | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `LOW` (Score: 20)
- **Failures:**
  - **[Critical] FALSE_NEGATIVE:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### 3. [RED-014] جائزة وهمية بالأرابيزي تطلب رقم البطاقة
- **Category:** 5. Arabizi Obfuscation (Script Evasion) | **Dialect:** ARABIZI | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `LOW` (Score: 20)
- **Failures:**
  - **[Critical] FALSE_NEGATIVE:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### 4. [RED-015] احتيال توصيل طرود بالأرابيزي ورسوم غير مدفوعة
- **Category:** 5. Arabizi Obfuscation (Script Evasion) | **Dialect:** ARABIZI | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `LOW` (Score: 24)
- **Failures:**
  - **[Critical] FALSE_NEGATIVE:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 24).

### 5. [RED-018] تصيد يخلط محارف كيريلية شبيهة بالعربية واللاتينية (Homoglyphs)
- **Category:** 6. Unicode Confusables / Zero-Width / Tatweel | **Dialect:** MSA | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `LOW` (Score: 24)
- **Failures:**
  - **[Critical] FALSE_NEGATIVE:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 24).

### 6. [RED-022] احتيال توظيف بركاكة لغوية ناتجة عن ترجمة آلية أجنبية
- **Category:** 8. Broken / Machine-Translated Arabic | **Dialect:** BROKEN_ARABIC | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `LOW` (Score: 20)
- **Failures:**
  - **[Critical] FALSE_NEGATIVE:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### 7. [RED-023] احتيال عملات مشفرة مترجم آلياً من عصابات أجنبية
- **Category:** 8. Broken / Machine-Translated Arabic | **Dialect:** BROKEN_ARABIC | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `LOW` (Score: 20)
- **Failures:**
  - **[Critical] FALSE_NEGATIVE:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### 8. [RED-024] احتيال الميراث والرسوم المسبقة بلغة مترجمة متهالكة
- **Category:** 8. Broken / Machine-Translated Arabic | **Dialect:** BROKEN_ARABIC | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `LOW` (Score: 20)
- **Failures:**
  - **[Critical] FALSE_NEGATIVE:** Scam evasion successful: expected HIGH risk, but engine classified as LOW (Score: 20).

### 9. [RED-034] رسالة تحوي رابطاً رسمياً كتمويه وبجانبه رابط تصيد بنكي خبيث
- **Category:** 12. Multiple / Decoy URLs | **Dialect:** MSA | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `SUSPICIOUS` (Score: 44)
- **Failures:**
  - **[Critical] CONTRADICTORY_FUSION_FAILURE:** Signal dilution or decoy URL bypassed threat detection (actual risk: suspicious).
  - **[Low] MISSED_DNA:** Missed expected Scam DNA feature(s): [credential_request].

### 10. [RED-035] رابط حساب تويتر رسمي مرفق مع رابط مسابقة وجائزة وهمية
- **Category:** 12. Multiple / Decoy URLs | **Dialect:** GULF | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `SUSPICIOUS` (Score: 44)
- **Failures:**
  - **[Critical] CONTRADICTORY_FUSION_FAILURE:** Signal dilution or decoy URL bypassed threat detection (actual risk: suspicious).
  - **[Medium] WRONG_SCAM_TYPE:** Misattribution of threat category: expected FAKE_PRIZE, but attributed to DELIVERY_SCAM.
  - **[Low] MISSED_DNA:** Missed expected Scam DNA feature(s): [financial_lure].


---

## 12. Recommended Fix Areas (For Phase 6C/7 — WITHOUT IMPLEMENTATION)

> [!IMPORTANT]
> In accordance with Phase 6B constraints, **NO fixes or weights modifications have been made**. These recommendations are logged for future hardening phases:

1. **Arabizi Transliteration Normalizer (Category 5):**
   - The deterministic engine relies exclusively on Arabic characters. Adding an Arabizi phonetic dictionary or transliteration preprocessor is required to capture scams written in Latin numerals (e.g. `7sabk`, `t36l`, `3shan`).

2. **Unicode Normalization & Tatweel Stripping (Category 6):**
   - Implementing NFKC canonical normalization and stripping zero-width spaces (`\u200B`) and tatweel (`ـ`) prior to regex scanning will close simple evasion loops.

3. **Multi-URL Exhaustive Inspection (Category 12):**
   - When multiple URLs are detected, ensure the worst-case malicious indicator strictly dominates rather than averaging signals or only evaluating the primary link.

4. **Phone Directing & Social Engineering Patterns (Category 14):**
   - Enhance non-URL scam detection by recognizing unsolicited phone directives combined with cash lures (`2 مليون ريال`, `صراف الكريمي`, `تواصل عبر الواتساب`).

5. **Contextual Polarity Preservation (Category 1 & 2):**
   - Continue strictly enforcing clause-level negation (`لن يطلب قط`, `إياك ومشاركة`) to guarantee zero false positives on institutional security advisories.
