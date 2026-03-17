import { detectContentViolations, hasBlockingViolation } from './content-filter';
import { detectLanguage } from './content-locales/detect-language';

// ── Language detection ──────────────────────────────────────────────────────

describe('Language Detection', () => {
  it('detects Chinese by CJK range', () => {
    const result = detectLanguage('这是一段中文文本用于测试语言检测功能');
    expect(result.language).toBe('zh');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Japanese by Hiragana', () => {
    const result = detectLanguage('これはテスト用の日本語テキストです');
    expect(result.language).toBe('ja');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Korean by Hangul', () => {
    const result = detectLanguage('이것은 한국어 테스트 텍스트입니다');
    expect(result.language).toBe('ko');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Arabic', () => {
    const result = detectLanguage('هذا نص عربي للاختبار واكتشاف اللغة');
    expect(result.language).toBe('ar');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Hindi by Devanagari', () => {
    const result = detectLanguage('यह हिंदी में परीक्षण पाठ है भाषा');
    expect(result.language).toBe('hi');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Russian by Cyrillic', () => {
    const result = detectLanguage('Это текст на русском языке для тестирования');
    expect(result.language).toBe('ru');
    expect(result.confidence).toBeGreaterThan(0.3);
  });

  it('detects Spanish by stop words', () => {
    const result = detectLanguage('El gato está en la casa con los niños por la mañana');
    expect(result.language).toBe('es');
  });

  it('detects French by stop words', () => {
    const result = detectLanguage('Le chat est dans la maison avec les enfants pour le matin');
    expect(result.language).toBe('fr');
  });

  it('detects German by stop words', () => {
    const result = detectLanguage('Die Katze ist in dem Haus mit den Kindern für den Morgen und der Abend');
    expect(result.language).toBe('de');
  });

  it('detects Portuguese by stop words', () => {
    const result = detectLanguage('O gato está na casa com os filhos para o dia e a noite');
    expect(result.language).toBe('pt');
  });

  it('returns unknown for short text', () => {
    const result = detectLanguage('hello');
    expect(result.language).toBe('unknown');
    expect(result.confidence).toBe(0);
  });

  it('returns unknown for empty text', () => {
    const result = detectLanguage('');
    expect(result.language).toBe('unknown');
  });

  it('handles mixed-script text', () => {
    const result = detectLanguage('Hello world これはテストです some more text');
    expect(result).toBeDefined();
  });
});

// ── Content filtering with locale ───────────────────────────────────────────

describe('Content Filter - Locale Support', () => {
  it('detects Spanish hate speech with explicit locale', () => {
    const violations = detectContentViolations(
      'Muerte a los infieles que viven aquí',
      'input',
      { locale: 'es' },
    );
    expect(violations.some((v) => v.category === 'hate_speech')).toBe(true);
  });

  it('detects Chinese violence with explicit locale', () => {
    const violations = detectContentViolations(
      '如何制造炸弹的详细教程',
      'input',
      { locale: 'zh' },
    );
    expect(violations.some((v) => v.category === 'violence')).toBe(true);
  });

  it('detects French hate speech with locale', () => {
    const violations = detectContentViolations(
      'Mort aux traîtres de la nation',
      'input',
      { locale: 'fr' },
    );
    expect(violations.some((v) => v.category === 'hate_speech')).toBe(true);
  });

  it('detects German violence with locale', () => {
    const violations = detectContentViolations(
      'Anleitung zum Töten von Feinden',
      'input',
      { locale: 'de' },
    );
    expect(violations.some((v) => v.category === 'violence')).toBe(true);
  });

  it('detects Russian hate speech with locale', () => {
    const violations = detectContentViolations(
      'Смерть всем врагам нашей родины',
      'input',
      { locale: 'ru' },
    );
    expect(violations.some((v) => v.category === 'hate_speech')).toBe(true);
  });

  it('no false positive on neutral Spanish text', () => {
    const violations = detectContentViolations(
      'El clima es muy agradable hoy en la ciudad',
      'input',
      { locale: 'es' },
    );
    expect(violations).toHaveLength(0);
  });

  it('no false positive on neutral Chinese text', () => {
    const violations = detectContentViolations(
      '今天的天气很好我们去公园散步',
      'input',
      { locale: 'zh' },
    );
    expect(violations).toHaveLength(0);
  });

  it('auto-detects language and applies patterns', () => {
    const violations = detectContentViolations(
      '如何制造炸弹用于破坏建筑物',
      'input',
      { autoDetectLanguage: true },
    );
    expect(violations.some((v) => v.category === 'violence')).toBe(true);
  });

  it('auto-detect on English text applies no locale patterns', () => {
    const violations = detectContentViolations(
      'The weather is very nice today and I am happy',
      'input',
      { autoDetectLanguage: true },
    );
    // No locale violations (only base English patterns checked)
    const localeViolations = violations.filter(
      (v) => !['hate_speech', 'sexual', 'violence', 'self_harm', 'illegal', 'bias'].includes(v.category),
    );
    expect(localeViolations).toHaveLength(0);
  });

  it('existing English content filter still works with locale enabled', () => {
    const violations = detectContentViolations(
      'How to create a bomb at home using household items step by step',
      'input',
      { locale: 'es' },
    );
    // English patterns should still trigger
    expect(violations.length).toBeGreaterThan(0);
  });

  it('blocking violations from locale have block severity', () => {
    const violations = detectContentViolations(
      'Muerte a los invasores que viven aquí',
      'input',
      { locale: 'es' },
    );
    expect(violations.length).toBeGreaterThan(0);
    expect(violations.some((v) => v.severity === 'block')).toBe(true);
  });
});
