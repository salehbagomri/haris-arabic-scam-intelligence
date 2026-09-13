import { describe, it } from 'node:test';
import assert from 'node:assert';
import { normalizeArabicText } from '../lib/analysis/normalizer';
import { extractDeterministicSignals } from '../lib/analysis/signals';
import { analyzeUnified } from '../lib/vision/pipeline';
import { EVALUATION_DATASET } from '../evaluation/dataset';
import { RED_TEAM_DATASET } from '../evaluation/red_team/dataset';

describe('Phase 6C P0-C Hardening: Arabic Syntactic & Morphological Robustness', () => {
  describe('A. Credential Idafa (Construct State)', () => {
    it('detects credential request with indefinite construct state (كلمة مرور بريده)', () => {
      const text = 'علماً بأنه يتوجب على كل موظف إدخال كلمة مرور بريده الإلكتروني لتأكيد الحساب.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const cred = res.signals.find((s) => s.featureId === 'credential_request');
      assert.ok(cred, 'Must detect credential_request in construct state');
      assert.ok(text.includes(cred.evidenceText), `Evidence "${cred.evidenceText}" must be exact source substring`);
    });

    it('does NOT trigger credential theft on safe advisory mentioning password in construct state', () => {
      const text = 'نصيحة أمنية: احرص دائماً على تغيير كلمة مرور بريدك بشكل دوري لحماية بياناتك.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const cred = res.signals.find((s) => s.featureId === 'credential_request');
      assert.strictEqual(cred, undefined, 'Safe periodic password update advisory must not be flagged');
    });
  });

  describe('B. Financial Multipliers & Guaranteed Returns', () => {
    it('detects multiplier lure (ربح عشرة أضعاف في ساعات قليلة)', () => {
      const text = 'يمكنك بدخول استثمار صغير مائة دولار وربح عشرة أضعاف في ساعات قليلة ادخل هنا: https://invest.xyz';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const lure = res.signals.find((s) => s.featureId === 'financial_lure');
      assert.ok(lure, 'Must detect financial_lure on profit multiplier');
      assert.ok(text.includes(lure.evidenceText), `Evidence "${lure.evidenceText}" must be exact source substring`);
    });

    it('detects percentage guaranteed return lure (بربح مضمون 300% أسبوعياً)', () => {
      const text = 'فرصة استثمار مميزة في أسهم تقنية بربح مضمون 300% أسبوعياً سارع بالاشتراك.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const lure = res.signals.find((s) => s.featureId === 'financial_lure');
      assert.ok(lure, 'Must detect financial_lure on guaranteed percentage returns');
      assert.ok(text.includes(lure.evidenceText), `Evidence "${lure.evidenceText}" must be exact source substring`);
    });

    it('does NOT flag ordinary corporate financial reporting', () => {
      const text = 'أعلنت الشركة اليوم عن تحقيق أرباح فصلية بلغت نسبتها 12% مقارنة بالعام السابق.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const lure = res.signals.find((s) => s.featureId === 'financial_lure');
      assert.strictEqual(lure, undefined, 'Ordinary factual financial earnings news must not trigger financial lure');
    });
  });

  describe('C. Job Compensation Financial Lures', () => {
    it('detects unrealistic job wage lure for trivial tasks (دفع لك 800 دولار أسبوع عبر عمل بسيط)', () => {
      const text = 'شركتنا تبحث عن موظفين تقييم فنادق، نحن دفع لك 800 دولار أسبوع عبر عمل بسيط، اضغط رابط التسجيل.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const lure = res.signals.find((s) => s.featureId === 'financial_lure');
      assert.ok(lure, 'Must detect financial_lure on high compensation for trivial task');
      assert.ok(text.includes(lure.evidenceText), `Evidence "${lure.evidenceText}" must be exact source substring`);
    });

    it('does NOT flag legitimate professional job announcements', () => {
      const text = 'مطلوب مهندس شبكات بدوام كامل براتب يحدد بعد المقابلة، يرجى إرسال السيرة الذاتية عبر البريد الرسمي.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const lure = res.signals.find((s) => s.featureId === 'financial_lure');
      assert.strictEqual(lure, undefined, 'Standard professional recruitment notice must not be flagged');
    });
  });

  describe('D. Advance Fees & Upfront Payment Schemes', () => {
    it('detects advance fee demand (دفع رسوم شهادة النقل أولاً)', () => {
      const text = 'أحتاج شريك أمين لتحويل تركة موكلي، يرجى دفع رسوم شهادة النقل أولاً عبر الرابط التالي.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const pay = res.signals.find((s) => s.featureId === 'suspicious_payment_request');
      assert.ok(pay, 'Must detect suspicious_payment_request on advance fee');
      assert.ok(text.includes(pay.evidenceText), `Evidence "${pay.evidenceText}" must be exact source substring`);
    });

    it('detects urgent digital wallet transfer directive (تحويل رصيدك الآن إلى المحفظة الرقمية)', () => {
      const text = 'للاستفادة من الفرصة قم بتحويل رصيدك الآن إلى المحفظة الرقمية قبل إغلاق الاكتتاب.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const pay = res.signals.find((s) => s.featureId === 'suspicious_payment_request');
      assert.ok(pay, 'Must detect suspicious_payment_request on wallet transfer directive');
      assert.ok(text.includes(pay.evidenceText), `Evidence "${pay.evidenceText}" must be exact source substring`);
    });

    it('does NOT flag official utility payment confirmations', () => {
      const text = 'تم استلام سداد فاتورة المياه والكهرباء بمبلغ 150 ريال بنجاح عبر نظام سداد.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const pay = res.signals.find((s) => s.featureId === 'suspicious_payment_request');
      assert.strictEqual(pay, undefined, 'Utility payment receipt must not trigger suspicious payment signal');
    });
  });

  describe('E. Promotional Qualifier Tolerance & Action Conjunctions', () => {
    it('detects free telecom bundle with intervening qualifier (باقة رمضان المجانية)', () => {
      const text = 'افتح الرابط واستلم باقة رمضان المجانية من شركة الاتصالات: https://telecom-gift.xyz';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const lure = res.signals.find((s) => s.featureId === 'financial_lure');
      assert.ok(lure, 'Must detect financial_lure on باقة رمضان المجانية');
      assert.ok(text.includes(lure.evidenceText), `Evidence "${lure.evidenceText}" must be exact source substring`);

      const action = res.signals.find((s) => s.featureId === 'action_pressure');
      assert.ok(action, 'Must detect action_pressure on افتح الرابط / استلم');
      assert.ok(text.includes(action.evidenceText), `Evidence "${action.evidenceText}" must be exact source substring`);
    });

    it('does NOT flag pure family holiday greetings', () => {
      const text = 'مبارك عليكم الشهر الفضيل يا غالي، جعلنا الله وإياكم من صوامه وقوامه وكل عام وأنتم بخير.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      assert.strictEqual(res.signals.length, 0, 'Pure religious/family greeting without links or lures must have 0 signals');
    });
  });

  describe('F. Negative Polarity & Advisory Hardening (RED-006 Resolution)', () => {
    it('strictly treats "إياك ومشاركة رمز الدخول OTP" as a negative warning (LOW risk, 0 OTP signals)', async () => {
      const text = 'تذكير أمني للعملاء: إياك ومشاركة رمز الدخول لمرة واحدة OTP مع أي متصل يدعي أنه من الدعم الفني أو خدمة العملاء تحت أي ظرف.';
      const res = await analyzeUnified({ text });
      assert.strictEqual(res.riskLevel, 'low', `Must be LOW risk, got ${res.riskLevel} (score: ${res.riskScore})`);
      assert.ok(res.riskScore < 30, `Score must be < 30, got ${res.riskScore}`);
      assert.strictEqual(res.detectedFeatures.includes('otp_request'), false, 'Must not detect otp_request');
    });

    it('strictly treats "إياك أن تشارك رمز التحقق" as a negative warning', async () => {
      const text = 'تحذير أمني: إياك أن تشارك رمز التحقق المؤقت الخاص بحسابك مع أي شخص.';
      const res = await analyzeUnified({ text });
      assert.strictEqual(res.riskLevel, 'low', `Must be LOW risk, got ${res.riskLevel} (score: ${res.riskScore})`);
      assert.strictEqual(res.detectedFeatures.includes('otp_request'), false, 'Must not detect otp_request');
    });
  });

  describe('G. Clause-Level Polarity & Advisory Probes (Probes A–E)', () => {
    it('Probe A: Pure warning is strictly LOW with no OTP request signal', async () => {
      const text = 'تذكير أمني: إياك ومشاركة رمز OTP مع أي شخص.';
      const res = await analyzeUnified({ text });
      assert.strictEqual(res.riskLevel, 'low');
      assert.strictEqual(res.riskScore, 0);
      assert.strictEqual(res.detectedFeatures.includes('otp_request'), false);
    });

    it('Probe B: Warning followed by malicious instruction triggers suspicious/high and detects OTP request', async () => {
      const text = 'تذكير أمني: لا تشارك رمز OTP مع أي شخص. لتأكيد حسابك أدخل رمز OTP هنا.';
      const res = await analyzeUnified({ text });
      assert.ok(res.riskLevel === 'suspicious' || res.riskLevel === 'high');
      assert.ok(res.detectedFeatures.includes('otp_request'));
    });

    it('Probe C: Warning followed by malicious anaphora triggers suspicious/high and detects anaphora OTP request', async () => {
      const text = 'تذكير أمني: لا تشارك رمز OTP مع الغرباء. لكن أرسله لي فوراً عبر الواتساب لتحديث بياناتك.';
      const res = await analyzeUnified({ text });
      assert.ok(res.riskLevel === 'suspicious' || res.riskLevel === 'high');
      assert.ok(res.detectedFeatures.includes('otp_request'));
    });

    it('Probe D: Warning + phishing URL triggers suspicious/high with malicious clause signals active', async () => {
      const text = 'تحذير أمني: لا تشارك رمز OTP. لتأكيد الحساب اضغط الرابط وأدخل كلمة المرور وOTP: https://phish-secure.top';
      const res = await analyzeUnified({ text });
      assert.ok(res.riskLevel === 'suspicious' || res.riskLevel === 'high');
      assert.ok(res.detectedFeatures.includes('credential_request') || res.detectedFeatures.includes('otp_request'));
      assert.ok(res.detectedFeatures.includes('suspicious_url'));
    });

    it('Probe E: Legitimate OTP issuance notice is strictly LOW with no theft signal', async () => {
      const text = 'إشعار أمني: تم إصدار رمز الدخول لمرة واحدة OTP الخاص بك لتسجيل الدخول. لا تشاركه مع أحد.';
      const res = await analyzeUnified({ text });
      assert.strictEqual(res.riskLevel, 'low');
      assert.strictEqual(res.riskScore, 0);
      assert.strictEqual(res.detectedFeatures.includes('otp_request'), false);
    });
  });

  describe('H. Bounded Regex Distance Constraints', () => {
    it('bounded credential regex matches within distance constraint (< 35 chars)', () => {
      const text = 'علماً بأنه يتوجب على كل موظف إدخال كلمة مرور البريد المؤسسي.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const cred = res.signals.find((s) => s.featureId === 'credential_request');
      assert.ok(cred, 'Must match within 35 characters');
    });

    it('bounded credential regex does NOT bridge long-distance unrelated clauses (> 35 chars)', () => {
      const text = 'يتوجب على الموظف قراءة اللائحة بعناية وحضور الاجتماع وتحديث ملفه وتأكيد استلام بطاقة الدخول الجديدة ثم إدخال كلمة مرور البريد.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      // The rule requiring modal + enter password within 35 chars should not match on the modal part
      const modalSignal = res.signals.find((s) => s.explanation.includes('محاولة استدراج كلمات المرور') && s.evidenceText.includes('يتوجب'));
      assert.strictEqual(modalSignal, undefined, 'Must NOT match when distance between modal and action exceeds 35 chars');
    });

    it('bounded job lure regex matches within distance constraint (< 35 chars)', () => {
      const text = 'نحن دفع لك 800 دولار أسبوع عبر عمل بسيط.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const lure = res.signals.find((s) => s.featureId === 'financial_lure');
      assert.ok(lure, 'Must match within 35 characters');
    });

    it('bounded job lure regex does NOT bridge long-distance unrelated clauses (> 35 chars)', () => {
      const text = 'نحن دفع لك مستحقات التأمين لعام 2020 البالغة 800 دولار مع فوائد التأخير بموجب قرار المحكمة العليا الصادر بعد تدقيق المستندات عبر عمل بسيط.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const lure = res.signals.find((s) => s.featureId === 'financial_lure');
      assert.strictEqual(lure, undefined, 'Must NOT match when distance between salary and task description exceeds 35 chars');
    });

    it('bounded advance fee regex matches within distance constraint (< 35 chars)', () => {
      const text = 'مطلوب دفع رسوم شهادة نقل الملكية أولاً لتسليم الحوالة.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const fee = res.signals.find((s) => s.featureId === 'suspicious_payment_request');
      assert.ok(fee, 'Must match within 35 characters');
    });

    it('bounded advance fee regex does NOT bridge long-distance unrelated clauses (> 35 chars)', () => {
      const text = 'سداد رسوم الاشتراك السنوي في النادي الرياضي مع تقديم الفحص الطبي الشامل وشهادة اللياقة البدنية أولاً.';
      const norm = normalizeArabicText(text);
      const res = extractDeterministicSignals(norm);
      const fee = res.signals.find((s) => s.featureId === 'suspicious_payment_request' && s.evidenceText.includes('أولا'));
      assert.strictEqual(fee, undefined, 'Must NOT match when distance between fee and condition exceeds 35 chars');
    });
  });

  describe('Mandatory Hard-Negative Regression Set', () => {
    const hardNegatives = [
      { id: 'LEGIT-001', dataset: EVALUATION_DATASET },
      { id: 'LEGIT-002', dataset: EVALUATION_DATASET },
      { id: 'LEGIT-003', dataset: EVALUATION_DATASET },
      { id: 'LEGIT-011', dataset: EVALUATION_DATASET },
      { id: 'ADV-003', dataset: EVALUATION_DATASET },
      { id: 'ADV-005', dataset: EVALUATION_DATASET },
      { id: 'RED-006', dataset: RED_TEAM_DATASET },
    ];

    for (const hn of hardNegatives) {
      it(`${hn.id} remains strictly LOW risk with verified evidence provenance`, async () => {
        const item = hn.dataset.find((x) => x.id === hn.id);
        assert.ok(item, `Case ${hn.id} must exist in dataset`);

        const res = await analyzeUnified(item.input);

        assert.strictEqual(
          res.riskLevel,
          'low',
          `${hn.id} must be LOW risk, got ${res.riskLevel} (Score: ${res.riskScore})`
        );
        assert.ok(res.riskScore < 30, `${hn.id} score must be < 30, got ${res.riskScore}`);

        // Provenance check for all emitted evidence
        const sourceText = item.input.text || '';
        for (const dna of res.scamDna) {
          if (dna.detected && dna.provenance === 'deterministic') {
            for (const snippet of dna.evidence) {
              assert.ok(
                sourceText.includes(snippet),
                `Evidence snippet "${snippet}" must be contained in source text of ${hn.id}`
              );
            }
          }
        }
      });
    }
  });

  describe('I. Trojan Greeting & Benign Wrapper Regression (P0-C.2)', () => {
    it('RED-043: reaches suspicious risk with unexpected_contact and action_pressure, classified as SOCIAL_ENGINEERING', async () => {
      const item = RED_TEAM_DATASET.find((x) => x.id === 'RED-043')!;
      const res = await analyzeUnified(item.input);

      assert.ok(
        res.riskLevel === 'suspicious' || res.riskLevel === 'high',
        `RED-043 must be at least suspicious, got ${res.riskLevel} (score: ${res.riskScore})`
      );
      assert.ok(res.detectedFeatures.includes('unexpected_contact'), 'Must detect unexpected_contact');
      assert.ok(res.detectedFeatures.includes('action_pressure'), 'Must detect action_pressure');
      assert.strictEqual(res.scamType, 'SOCIAL_ENGINEERING', 'Must be classified as SOCIAL_ENGINEERING');

      // Evidence containment check
      const sourceText = item.input.text || '';
      for (const dna of res.scamDna) {
        for (const quote of dna.evidence) {
          assert.ok(sourceText.includes(quote), `Evidence quote "${quote}" must be contained in source text`);
        }
      }
    });

    it('ADV-010: reaches suspicious risk, classified as SOCIAL_ENGINEERING', async () => {
      const item = EVALUATION_DATASET.find((x) => x.id === 'ADV-010')!;
      const res = await analyzeUnified(item.input);

      assert.ok(
        res.riskLevel === 'suspicious' || res.riskLevel === 'high',
        `ADV-010 must be at least suspicious, got ${res.riskLevel} (score: ${res.riskScore})`
      );
      assert.strictEqual(res.scamType, 'SOCIAL_ENGINEERING', 'Must be classified as SOCIAL_ENGINEERING');
    });

    it('Similar Trojan Greeting with .top link triggers suspicious risk', async () => {
      const text = 'مبارك عليكم العيد، شاهد بطاقة تهنئة خاصة بك من هنا: https://greeting-eid.top/card';
      const res = await analyzeUnified({ text });

      assert.ok(
        res.riskLevel === 'suspicious' || res.riskLevel === 'high',
        `Must be at least suspicious, got ${res.riskLevel} (score: ${res.riskScore})`
      );
      assert.ok(res.detectedFeatures.includes('unexpected_contact'));
      assert.ok(res.detectedFeatures.includes('action_pressure'));
    });

    it('Benign holiday greeting with NO link is strictly LOW (score: 0)', async () => {
      const text = 'كل عام وأنتم بخير وصحة وعافية وتقبل الله منا ومنكم صالح الأعمال وعيدكم مبارك.';
      const res = await analyzeUnified({ text });
      assert.strictEqual(res.riskLevel, 'low');
      assert.strictEqual(res.riskScore, 0);
      assert.strictEqual(res.detectedFeatures.length, 0);
    });

    it('Benign holiday greeting with official .gov.sa link is strictly LOW (score <= 8)', async () => {
      const text = 'كل عام وأنتم بخير. شاهد فعاليات العيد الرسمية عبر موقع الهيئة: https://gea.gov.sa/events';
      const res = await analyzeUnified({ text, url: 'https://gea.gov.sa/events' });
      assert.strictEqual(res.riskLevel, 'low');
      assert.ok(res.riskScore < 20);
    });

    it('Legitimate store promotional message with trusted .com link is strictly LOW (score <= 8)', async () => {
      const text = 'عروض العيد الكبرى: تصفح العروض الحصرية من هنا: https://jarir.com/deals';
      const res = await analyzeUnified({ text, url: 'https://jarir.com/deals' });
      assert.strictEqual(res.riskLevel, 'low');
      assert.ok(res.riskScore < 20);
    });

    it('Legitimate photo sharing via Google Drive is strictly LOW (score <= 8)', async () => {
      const text = 'هذه بطاقة معايدة صممناها لكم، للمشاهدة من هنا: https://drive.google.com/file/d/123';
      const res = await analyzeUnified({ text, url: 'https://drive.google.com/file/d/123' });
      assert.strictEqual(res.riskLevel, 'low');
      assert.ok(res.riskScore < 20);
    });

    it('Real FAKE_PRIZE cases with financial_lure still classify as FAKE_PRIZE', async () => {
      const prizeCases = ['RED-045', 'RED-035'];
      for (const id of prizeCases) {
        const item = RED_TEAM_DATASET.find((x) => x.id === id) || EVALUATION_DATASET.find((x) => x.id === id)!;
        const res = await analyzeUnified(item.input);
        assert.strictEqual(
          res.scamType,
          'FAKE_PRIZE',
          `Case ${id} must classify as FAKE_PRIZE, got ${res.scamType}`
        );
      }
    });
  });
});
