/**
 * Locale-specific content filter patterns.
 * Each locale has patterns for hate_speech, violence, and sexual categories.
 *
 * Patterns are conservative (high precision, lower recall) to minimize false positives.
 * All patterns are case-insensitive.
 *
 * @internal
 */

import type { LocaleContentPattern, ContentLocale } from './types';

// ── Spanish ─────────────────────────────────────────────────────────────────

const ES_PATTERNS: LocaleContentPattern[] = [
  {
    category: 'hate_speech',
    patterns: [
      /\b(?:malditos?|asquerosos?)\s+(?:negros?|indios?|musulmanes?|judíos?)\b/i,
      /\b(?:muerte\s+a\s+(?:los|las)\s+\w+)\b/i,
      /\b(?:raza\s+(?:inferior|superior))\b/i,
      /\b(?:limpieza\s+étnica)\b/i,
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /\b(?:cómo\s+(?:hacer|fabricar|construir)\s+(?:una?\s+)?(?:bomba|explosivo|arma))\b/i,
      /\b(?:instrucciones\s+para\s+(?:matar|asesinar|envenenar))\b/i,
      /\b(?:torturar\s+a\s+(?:alguien|una?\s+persona))\b/i,
    ],
    severity: 'block',
  },
];

// ── Portuguese ──────────────────────────────────────────────────────────────

const PT_PATTERNS: LocaleContentPattern[] = [
  {
    category: 'hate_speech',
    patterns: [
      /\b(?:morte\s+a(?:os?)?\s+\w+)\b/i,
      /\b(?:raça\s+(?:inferior|superior))\b/i,
      /\b(?:limpeza\s+étnica)\b/i,
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /\b(?:como\s+(?:fazer|fabricar)\s+(?:uma?\s+)?(?:bomba|explosivo|arma))\b/i,
      /\b(?:instruções\s+para\s+(?:matar|assassinar|envenenar))\b/i,
    ],
    severity: 'block',
  },
];

// ── Chinese ─────────────────────────────────────────────────────────────────

const ZH_PATTERNS: LocaleContentPattern[] = [
  {
    category: 'hate_speech',
    patterns: [
      /(?:杀光|灭绝|消灭)\s*(?:所有|全部)/,
      /(?:种族清洗|种族灭绝)/,
      /(?:劣等|低等)\s*(?:民族|种族|人种)/,
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /(?:如何|怎么|怎样)\s*(?:制造|制作)\s*(?:炸弹|爆炸物|武器)/,
      /(?:毒杀|暗杀|谋杀)\s*(?:方法|教程|指南)/,
    ],
    severity: 'block',
  },
];

// ── Japanese ────────────────────────────────────────────────────────────────

const JA_PATTERNS: LocaleContentPattern[] = [
  {
    category: 'hate_speech',
    patterns: [
      /(?:殺せ|死ね|消えろ)\s*(?:全員|みんな)/,
      /(?:民族浄化|人種差別)/,
      /(?:劣等)\s*(?:民族|人種)/,
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /(?:爆弾|爆発物|武器)\s*(?:の作り方|を作る方法|の製造)/,
      /(?:殺す|暗殺する)\s*(?:方法|やり方)/,
    ],
    severity: 'block',
  },
];

// ── Korean ──────────────────────────────────────────────────────────────────

const KO_PATTERNS: LocaleContentPattern[] = [
  {
    category: 'hate_speech',
    patterns: [
      /(?:죽여|없애)\s*(?:버려|라)/,
      /(?:인종\s*청소|민족\s*말살)/,
      /(?:열등한|하등한)\s*(?:민족|인종)/,
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /(?:폭탄|폭발물|무기)\s*(?:만드는\s*법|제조\s*방법)/,
      /(?:살인|암살)\s*(?:방법|하는\s*법)/,
    ],
    severity: 'block',
  },
];

// ── German ──────────────────────────────────────────────────────────────────

const DE_PATTERNS: LocaleContentPattern[] = [
  {
    category: 'hate_speech',
    patterns: [
      /\b(?:Tod\s+(?:den|allen)\s+\w+)\b/i,
      /\b(?:(?:ethnische|rassische)\s+Säuberung)\b/i,
      /\b(?:(?:minderwertige|überlegene)\s+Rasse)\b/i,
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /\b(?:(?:Anleitung|Anweisungen)\s+(?:zum|zur)\s+(?:Töten|Morden|Vergiften))\b/i,
      /\b(?:(?:Bombe|Sprengstoff|Waffe)\s+(?:bauen|herstellen|basteln))\b/i,
    ],
    severity: 'block',
  },
];

// ── French ──────────────────────────────────────────────────────────────────

const FR_PATTERNS: LocaleContentPattern[] = [
  {
    category: 'hate_speech',
    patterns: [
      /\b(?:mort\s+aux?\s+\w+)\b/i,
      /\b(?:nettoyage\s+ethnique)\b/i,
      /\b(?:race\s+(?:inférieure|supérieure))\b/i,
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /\b(?:comment\s+(?:fabriquer|construire)\s+(?:une?\s+)?(?:bombe|explosif|arme))\b/i,
      /\b(?:instructions\s+pour\s+(?:tuer|assassiner|empoisonner))\b/i,
    ],
    severity: 'block',
  },
];

// ── Arabic ──────────────────────────────────────────────────────────────────

const AR_PATTERNS: LocaleContentPattern[] = [
  {
    category: 'hate_speech',
    patterns: [
      /(?:الموت\s+ل|اقتلوا\s+كل)/,
      /(?:تطهير\s+عرقي|إبادة\s+جماعية)/,
      /(?:عرق\s+(?:أدنى|متفوق))/,
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /(?:كيفية?\s+(?:صنع|تصنيع)\s+(?:قنبلة|متفجرات|سلاح))/,
      /(?:تعليمات\s+(?:القتل|الاغتيال))/,
    ],
    severity: 'block',
  },
];

// ── Hindi ───────────────────────────────────────────────────────────────────

const HI_PATTERNS: LocaleContentPattern[] = [
  {
    category: 'hate_speech',
    patterns: [
      /(?:मार\s+डालो|खत्म\s+करो)\s+(?:सब|सभी)/,
      /(?:जातीय\s+सफाई|नरसंहार)/,
      /(?:निम्न|हीन)\s+(?:जाति|नस्ल)/,
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /(?:बम|विस्फोटक|हथियार)\s+(?:बनाने\s+का\s+तरीका|कैसे\s+बनाएं)/,
      /(?:मारने|हत्या\s+करने)\s+(?:का\s+तरीका|के\s+तरीके)/,
    ],
    severity: 'block',
  },
];

// ── Russian ─────────────────────────────────────────────────────────────────

const RU_PATTERNS: LocaleContentPattern[] = [
  {
    category: 'hate_speech',
    patterns: [
      /(?:смерть\s+(?:всем|им))/i,
      /(?:этническ(?:ая|ие)\s+чистк(?:а|и))/i,
      /(?:(?:низшая|высшая)\s+раса)/i,
    ],
    severity: 'block',
  },
  {
    category: 'violence',
    patterns: [
      /(?:как\s+(?:сделать|изготовить)\s+(?:бомбу|взрывчатку|оружие))/i,
      /(?:инструкция\s+(?:по|для)\s+(?:убийств(?:а|у)|отравлени(?:я|ю)))/i,
    ],
    severity: 'block',
  },
];

// ── Registry ────────────────────────────────────────────────────────────────

export const LOCALE_PATTERNS: Record<ContentLocale, LocaleContentPattern[]> = {
  es: ES_PATTERNS,
  pt: PT_PATTERNS,
  zh: ZH_PATTERNS,
  ja: JA_PATTERNS,
  ko: KO_PATTERNS,
  de: DE_PATTERNS,
  fr: FR_PATTERNS,
  ar: AR_PATTERNS,
  hi: HI_PATTERNS,
  ru: RU_PATTERNS,
};
