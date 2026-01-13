// server.ts — Production backend
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import fetch from 'node-fetch';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import crypto from 'crypto';
import fs from 'fs/promises';
import jwt from 'jsonwebtoken';
import admin from 'firebase-admin';
import { v2 as cloudinary } from 'cloudinary';

// Firebase Admin
const firebaseApp = admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID!,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL!,
    privateKey: (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
  }),
});
const db = admin.firestore();

// Cloudinary
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
  console.log('🔍 KEY PATH:', YANDEX_KEY_JSON_PATH);
  
  try {
    const keyRaw = await fs.readFile(YANDEX_KEY_JSON_PATH, 'utf8');
    const key = JSON.parse(keyRaw);
    console.log('🔍 Service Account:', key.service_account_id);
    
    const nowSec = Math.floor(Date.now() / 1000);
    const payload = {
      aud: 'https://iam.api.cloud.yandex.net/iam/v1/tokens',
      iss: key.service_account_id,
      iat: nowSec,
      exp: nowSec + 3600,
    };
    
    // JWT oluştur
    const signed = jwt.sign(payload, key.private_key, { algorithm: 'RS256', keyid: key.id });
    console.log('🔍 JWT created, first 50 chars:', signed.substring(0, 50));
    
    // API isteği
    console.log('🔍 Sending to Yandex API...');
    const resp = await fetch('https://iam.api.cloud.yandex.net/iam/v1/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jwt: signed }),
    });
    
    console.log('🔍 API Status:', resp.status, resp.statusText);
    const responseText = await resp.text();
    console.log('🔍 API Response (first 300 chars):', responseText.substring(0, 300));
    
    if (!resp.ok) {
      throw new Error(`Yandex API Error ${resp.status}: ${responseText}`);
    }
    
    const data = JSON.parse(responseText);
    iamToken = data.iamToken;
    iamExpiresAt = new Date(data.expiresAt).getTime();
    console.log('✅✅ Token received, expires:', data.expiresAt);
    logEvent('yandex_iam_token_generated', { expiresAt: data.expiresAt });
    
  } catch (error) {
    console.error('❌❌ FULL ERROR:', error);
    throw error;
  }
}

async function getIamToken() {
  const now = Date.now();
  if (!iamToken || now > iamExpiresAt - 5 * 60 * 1000) {
    await refreshYandexToken();
  }
  return iamToken;
}

// Preload token + periodic refresh
getIamToken().catch(e => logEvent('yandex_token_boot_failed', { error: String(e) }));
setInterval(() => getIamToken().catch(e => logEvent('yandex_token_refresh_failed', { error: String(e) })), 10 * 60 * 1000);

// Translation (Yandex via IAM token)
async function yandexTranslate(text: string, source: Lang, target: Lang) {
  const token = await getIamToken();
  const resp = await fetch('https://translate.api.cloud.yandex.net/translate/v2/translate', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      folderId: YANDEX_FOLDER_ID,
      texts: [text],
      sourceLanguageCode: source,
      targetLanguageCode: target,
    }),
  });
  if (!resp.ok) throw new Error('yandex_translate_failed');
  const data = await resp.json() as any;
  const translated = data.translations?.[0]?.text || '';
  return translated;
}

// Firestore translation cache
async function cacheTranslation(uid: string, text: string, source: Lang, target: Lang, translated: string) {
  const key = crypto.createHash('sha256').update(`${source}:${target}:${text}`).digest('hex');
  await db.collection('translations_cache').doc(key).set({
    originalText: text,
    sourceLang: source,
    targetLang: target,
    translatedText: translated,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  }, { merge: true });
  return key;
}

async function getCachedTranslation(text: string, source: Lang, target: Lang) {
  const key = crypto.createHash('sha256').update(`${source}:${target}:${text}`).digest('hex');
  const snap = await db.collection('translations_cache').doc(key).get();
  if (snap.exists) return { key, data: snap.data() };
  return null;
}

// Cloudinary signed upload
function signUploadParams(folder: string, uid: string) {
  const timestamp = Math.floor(Date.now() / 1000);
  const params = {
    timestamp,
    folder,
    upload_preset: UPLOAD_PRESET,
    context: `uid=${uid}`,
  };
  const signature = cloudinary.utils.api_sign_request(params, process.env.CLOUDINARY_API_SECRET!);
  return { ...params, signature, api_key: process.env.CLOUDINARY_API_KEY };
}

// Endpoints

// Health
app.get('/health', async (req, res) => {
  try {
    const ttl = iamExpiresAt ? Math.floor((iamExpiresAt - Date.now()) / 1000) : -1;
    res.json({
      status: 'ok',
      moderationConfigLoaded: !!modConfig,
      cloudinary: !!cloudinary.config().cloud_name,
      firestore: firebaseApp.name ? 'ok' : 'init',
      yandexTokenTTLsec: ttl,
    });
  } catch (e) {
    res.status(500).json({ status: 'error', error: String(e) });
  }
});

// Version
app.get('/version', (req, res) => {
  res.json({ moderationHash: modHash || 'n/a', build: process.env.RENDER_GIT_COMMIT || 'local' });
});

// Moderation (text)
app.post('/moderation/text', requireAuth, async (req: any, res) => {
  try {
    await rlModeration.consume(req.ip);
    const { text, context } = req.body;
    if (!text || !context) return res.status(400).json({ error: 'missing_fields' });
    const lang = detectLanguage(String(text));
    const result = scoreText(String(text), lang, context);
    res.json({ lang, ...result });
  } catch (e: any) {
    if (e.msBeforeNext) return res.status(429).json({ error: 'rate_limited', retryMs: e.msBeforeNext });
    res.status(500).json({ error: String(e) });
  }
});

// Translate (single)
app.post('/translate', requireAuth, async (req: any, res) => {
  try {
    await rlTranslate.consume(req.ip);
    const { text, source, target } = req.body;
    const src: Lang = source || detectLanguage(String(text));
    const tgt: Lang = target || (src === 'en' ? 'ka' : 'en');
    if (!text) return res.status(400).json({ error: 'missing_text' });

    const cached = await getCachedTranslation(text, src, tgt);
    if (cached) return res.json({ 
      translated: cached.data!.translatedText, 
      cacheKey: cached.key, 
      cached: true, 
      source: src, 
      target: tgt 
    });

    const translated = await yandexTranslate(text, src, tgt);
    const key = await cacheTranslation(req.user.uid, text, src, tgt, translated);
    res.json({ 
      translated, 
      cacheKey: key, 
      cached: false, 
      source: src, 
      target: tgt 
    });
  } catch (e: any) {
    if (e.msBeforeNext) return res.status(429).json({ error: 'rate_limited', retryMs: e.msBeforeNext });
    res.status(500).json({ error: String(e) });
  }
});

// Listings create
app.post('/listings/create', requireAuth, async (req: any, res) => {
  try {
    const { title, description, category, price, condition, location } = req.body;
    if (!title || !description || !category) return res.status(400).json({ error: 'missing_fields' });

    const lt = detectLanguage(String(title));
    const ld = detectLanguage(String(description));
    const modTitle = scoreText(String(title), lt, 'title');
    const modDesc = scoreText(String(description), ld, 'description');
    if (modTitle.decision === 'block' || modDesc.decision === 'block') {
      return res.status(400).json({ error: 'moderation_block', reasons: [...modTitle.reasons, ...modDesc.reasons] });
    }

    const doc = await db.collection('listings').add({
      ownerId: req.user.uid,
      title: String(title),
      description: String(description),
      category: String(category),
      condition: condition || "new",
      price: {
        GEL: Number(price) || 0,
        USD: Math.round((Number(price) || 0) / GEL_TO_USD)
      },
      language: lt,
      images: [],
      location: location || { city: "", lat: "", lng: "" },
      status: "active",
      viewCount: 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      score: Math.max(modTitle.score, modDesc.score),
    });
    res.json({ id: doc.id });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Listings update
app.patch('/listings/:id', requireAuth, async (req: any, res) => {
  try {
    const id = req.params.id;
    const snap = await db.collection('listings').doc(id).get();
    if (!snap.exists) return res.status(404).json({ error: 'not_found' });
    const data = snap.data()!;
    ensureOwner(req.user.uid, data.ownerId);

    const { title, description, category, price } = req.body;
    const updates: any = {};
    
    if (title) {
      const lt = detectLanguage(String(title));
      const mt = scoreText(String(title), lt, 'title');
      if (mt.decision === 'block') return res.status(400).json({ error: 'moderation_block_title', reasons: mt.reasons });
      updates.title = title; 
      updates.score = Math.max(data.score || 0, mt.score);
      updates.language = lt;
    }
    
    if (description) {
      const ld = detectLanguage(String(description));
      const md = scoreText(String(description), ld, 'description');
      if (md.decision === 'block') return res.status(400).json({ error: 'moderation_block_desc', reasons: md.reasons });
      updates.description = description; 
      updates.score = Math.max(updates.score || data.score || 0, md.score);
    }
    
    if (category) updates.category = category;
    if (price !== undefined) updates.price = {
      GEL: Number(price),
      USD: Math.round(Number(price) / GEL_TO_USD)
    };

    await db.collection('listings').doc(id).set(updates, { merge: true });
    res.json({ id, updated: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Reports
app.post('/reports/create', requireAuth, async (req: any, res) => {
  try {
    await rlReports.consume(req.ip);
    const { listingId, reason, reportedImageUrl } = req.body;
    if (!listingId || !reason) return res.status(400).json({ error: 'missing_fields' });
    
    await db.collection('reported_content').add({
      reporterUserId: req.user.uid,
      listingId,
      reason,
      reportedImageUrl: reportedImageUrl || null,
      status: "pending",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.json({ ok: true });
  } catch (e: any) {
    if (e.msBeforeNext) return res.status(429).json({ error: 'rate_limited', retryMs: e.msBeforeNext });
    res.status(500).json({ error: String(e) });
  }
});

// Cloudinary signed upload
app.post('/media/upload', requireAuth, async (req: any, res) => {
  try {
    const { listingId } = req.body;
    if (!listingId) return res.status(400).json({ error: 'missing_listingId' });
    const snap = await db.collection('listings').doc(listingId).get();
    if (!snap.exists) return res.status(404).json({ error: 'listing_not_found' });
    ensureOwner(req.user.uid, snap.data()!.ownerId);

    const params = signUploadParams(`listings/${listingId}`, req.user.uid);
    res.json(params);
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Cloudinary webhook
app.post('/media/webhook', async (req, res) => {
  try {
    const payload = req.body;
    const { public_id, secure_url, folder, context } = payload;
    const listingId = (folder || '').split('/')[1] || 'unknown';
    const uid = (context || '').split('=')[1] || 'unknown';

    await db.collection('listings').doc(listingId).collection('media').doc(public_id).set({
      uid,
      url: secure_url,
      public_id,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      moderation: payload.moderation || null,
    }, { merge: true });

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Warm-up
async function warmUp() {
  try {
    await loadModerationConfig();
    await getIamToken();
    logEvent('warmup_done');
  } catch (e) {
    logEvent('warmup_failed', { error: String(e) });
  }
}
warmUp();

// Start server
const port = Number(process.env.PORT || 10000);
app.listen(port, () => {
  console.log(`🚀 Server started on port ${port}`);
  logEvent('server_started', { port });
});
