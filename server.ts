// server.ts — Production backend (single file, Firestore schema + Cloudinary preset fully revised)
// Run: npm i express cors helmet morgan firebase-admin cloudinary node-fetch rate-limiter-flexible jsonwebtoken
// Env (Render secrets):
//  - FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY (escaped \n)
//  - CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET, CLOUDINARY_UPLOAD_PRESET=bazarigo_image
//  - YANDEX_FOLDER_ID
//  - YANDEX_KEY_JSON_PATH=/opt/render/secret/key.json
//  - HOSTING_BASE=https://bazarigo-1876d.web.app/moderation
//  - ADMIN_UID (optional)
//  - PORT=10000
//  - CURRENCY_RATE_GEL_TO_USD=2.7 (optional)

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import fetch from 'node-fetch';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import crypto from 'crypto';
import fs from 'fs/promises';
import jwt from 'jsonwebtoken';

// Firebase Admin
import admin from 'firebase-admin';
const firebaseApp = admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID!,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL!,
    privateKey: (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
  }),
});
const db = admin.firestore();

// Cloudinary
import { v2 as cloudinary } from 'cloudinary';
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME!,
  api_key: process.env.CLOUDINARY_API_KEY!,
  api_secret: process.env.CLOUDINARY_API_SECRET!,
});

// App setup
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(cors());
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(morgan('combined'));

// Config
const HOSTING_BASE = process.env.HOSTING_BASE!;
const YANDEX_FOLDER_ID = process.env.YANDEX_FOLDER_ID!;
const YANDEX_KEY_JSON_PATH = process.env.YANDEX_KEY_JSON_PATH!;
const UPLOAD_PRESET = process.env.CLOUDINARY_UPLOAD_PRESET || 'bazarigo_image';
const ADMIN_UID = process.env.ADMIN_UID || '';
const GEL_TO_USD = Number(process.env.CURRENCY_RATE_GEL_TO_USD || 2.7);

// Rate limits
const rlTranslate = new RateLimiterMemory({ points: 60, duration: 60 });
const rlModeration = new RateLimiterMemory({ points: 120, duration: 60 });
const rlReports = new RateLimiterMemory({ points: 20, duration: 3600 });

// Logging
function logEvent(event: string, meta: Record<string, any> = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), event, ...meta }));
}

// Auth middleware
async function requireAuth(req: any, res: any, next: any) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'missing_token' });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = { uid: decoded.uid, admin: decoded.uid === ADMIN_UID };
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// Owner check
function ensureOwner(uid: string, ownerId: string) {
  if (uid !== ownerId) throw new Error('forbidden_owner_mismatch');
}

// Language detection
type Lang = 'ka' | 'ru' | 'en';
function detectLanguage(text: string): Lang {
  const t = (text || '').trim();
  if (/[ა-ჰ]/.test(t)) return 'ka';
  if (/[а-яА-ЯёЁ]/.test(t)) return 'ru';
  return 'en';
}

// Moderation config loader
let modConfig: any = null;
let modHash = '';
async function fetchJson(path: string) {
  const url = `${HOSTING_BASE}/${path}`;
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`hosting_fetch_failed_${path}`);
  return resp.json();
}
async function loadModerationConfig() {
  const [config, auto_block, categories, ka, ru, en, profanity, scam, evasion, contact_info, payment, base, bonus, reported, suggestions, exceptions] =
    await Promise.all([
      fetchJson('config.json'),
      fetchJson('auto_block.json'),
      fetchJson('categories.json'),
      fetchJson('words/ka.json'),
      fetchJson('words/ru.json'),
      fetchJson('words/en.json'),
      fetchJson('patterns/profanity.json'),
      fetchJson('patterns/scam.json'),
      fetchJson('patterns/evasion.json'),
      fetchJson('patterns/contact_info.json'),
      fetchJson('patterns/payment.json'),
      fetchJson('scores/base.json'),
      fetchJson('scores/bonus.json'),
      fetchJson('learning/reported.json'),
      fetchJson('learning/suggestions.json'),
      fetchJson('exceptions.json'),
    ]);
  const blob = JSON.stringify({ config, auto_block, categories, ka, ru, en, profanity, scam, evasion, contact_info, payment, base, bonus, reported, suggestions, exceptions });
  modHash = crypto.createHash('sha256').update(blob).digest('hex');
  modConfig = {
    config,
    auto_block,
    categories,
    words: { ka, ru, en },
    patterns: { profanity, scam, evasion, contact_info, payment },
    scores: { base, bonus },
    learning: { reported, suggestions },
    exceptions,
  };
  logEvent('moderation_config_loaded', { hash: modHash });
}
loadModerationConfig().catch(e => logEvent('moderation_config_load_failed', { error: String(e) }));
setInterval(() => loadModerationConfig().catch(e => logEvent('moderation_config_load_failed', { error: String(e) })), 10 * 60 * 1000);

// Text moderation engine
function normalize(text: string) {
  return (text || '').toLowerCase().trim();
}
function scoreText(text: string, lang: Lang, context: 'title' | 'description' | 'chat') {
  if (!modConfig) throw new Error('moderation_config_missing');
  const t = normalize(text);
  const words = modConfig.words[lang] || {};
  const patterns = modConfig.patterns;
  const baseScores = modConfig.scores.base || {};
  const bonusScores = modConfig.scores.bonus || {};
  const exceptions = modConfig.exceptions || [];

  for (const ex of exceptions) {
    if (t.includes(normalize(ex))) return { score: 0, reasons: ['exception'], blocks: [], decision: 'allow', threshold: modConfig.auto_block?.threshold || 100 };
  }

  let score = 0;
  const reasons: string[] = [];
  const blocks: string[] = [];

  for (const [key, val] of Object.entries(words)) {
    if (t.includes(normalize(String(key)))) {
      score += Number(val) || 0;
      reasons.push(`word:${key}`);
    }
  }

  for (const [group, defs] of Object.entries(patterns)) {
    for (const def of defs as any[]) {
      const re = new RegExp(def.regex, def.flags || 'i');
      if (re.test(t)) {
        score += Number(def.score || baseScores[group] || 0);
        reasons.push(`pattern:${group}:${def.name || 'unnamed'}`);
        if (def.block) blocks.push(group);
      }
    }
  }

  if (bonusScores[context]) score += Number(bonusScores[context]);

  const threshold = modConfig.auto_block?.threshold || 100;
  const decision = score >= threshold ? 'block' : 'allow';
  return { score, reasons, blocks, decision, threshold };
}

// Yandex IAM token
let iamToken = '';
let iamExpiresAt = 0;
async function refreshYandexToken() {
  const keyRaw = await fs.readFile(YANDEX_KEY_JSON_PATH, 'utf8');
  const key = JSON.parse(keyRaw);
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    aud: 'https://iam.api.cloud.yandex.net/iam/v1/tokens',
    iss: key.service_account_id,
    iat: nowSec,
    exp: nowSec + 3600,
  };
  const signed = jwt.sign(payload, key.private_key, { algorithm: 'RS256', keyid: key.id });
  const resp = await fetch('https://iam.api.cloud.yandex.net/iam/v1/tokens', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jwt: signed }),
  });
  if (!resp.ok) throw new Error('yandex_token_failed');
  const data = await resp.json() as any;
  iamToken = data.iamToken;
  iamExpiresAt = new Date(data.expiresAt).getTime();
  logEvent('yandex_iam_token_generated', { expiresAt: data.expiresAt });
}
async function getIamToken() {
  const now = Date.now();
  if (!iamToken || now > iamExpiresAt - 5 * 60 * 1000) {
    await refreshYandexToken();
  }
  return iamToken;
}
