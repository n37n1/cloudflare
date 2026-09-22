const express = require('express');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const verificationWindowMs = 15 * 60 * 1000;
const reloadBlockMs = 60 * 60 * 1000;
const reloadRequestHistory = new Map();
const sessions = new Map();

const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,https://localhost:3000')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        'default-src': ["'self'"],
        'script-src': ["'self'", 'https://challenges.cloudflare.com', "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'data:', 'https://challenges.cloudflare.com'],
        'frame-src': ["'self'", 'https://challenges.cloudflare.com'],
        'connect-src': ["'self'", 'https://challenges.cloudflare.com']
      }
    }
  })
);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Blocked by CORS strategy'));
    },
    methods: ['GET', 'POST']
  })
);

app.use(express.json({ limit: '10kb' }));

function readCookie(req, name) {
  const cookieHeader = req.get('cookie') || '';
  const cookie = cookieHeader
    .split(';')
    .map((entry) => entry.trim())
    .find((entry) => entry.startsWith(`${name}=`));

  if (!cookie) {
    return '';
  }

  try {
    return decodeURIComponent(cookie.slice(`${name}=`.length));
  } catch {
    return '';
  }
}

function getRequestFingerprint(req) {
  return crypto
    .createHash('sha256')
    .update(`${req.ip}|${req.get('user-agent') || 'unknown'}`)
    .digest('hex');
}

function trackReload(key, now, limits) {
  const state = reloadRequestHistory.get(key) || { requests: [], blockedUntil: 0 };
  state.requests = state.requests.filter((timestamp) => timestamp > now - 10 * 60 * 1000);

  if (state.blockedUntil > now) {
    reloadRequestHistory.set(key, state);
    return state.blockedUntil;
  }

  state.requests.push(now);
  const recentMinute = state.requests.filter((timestamp) => timestamp > now - 60 * 1000).length;
  if (recentMinute >= limits.perMinute || state.requests.length >= limits.perTenMinutes) {
    state.blockedUntil = now + reloadBlockMs;
    state.requests = [];
  }

  reloadRequestHistory.set(key, state);
  return state.blockedUntil;
}

function reloadProtection(req, res, next) {
  const now = Date.now();
  let deviceId = readCookie(req, 'device_id');

  if (!/^[A-Za-z0-9_-]{32}$/.test(deviceId)) {
    deviceId = '';
  }

  if (!deviceId) {
    deviceId = crypto.randomBytes(24).toString('base64url');
    res.setHeader(
      'Set-Cookie',
      `device_id=${encodeURIComponent(deviceId)}; Max-Age=${60 * 60 * 24 * 365}; Path=/; HttpOnly; SameSite=Lax${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`
    );
  }

  const fingerprint = getRequestFingerprint(req);
  const deviceKey = crypto
    .createHash('sha256')
    .update(`${deviceId}|${fingerprint}`)
    .digest('hex');
  const blockedUntil = Math.max(
    trackReload(`device:${deviceKey}`, now, { perMinute: 10, perTenMinutes: 25 }),
    trackReload(`ip:${req.ip}`, now, { perMinute: 100, perTenMinutes: 250 })
  );

  if (blockedUntil > now) {
    res.set('Retry-After', Math.ceil((blockedUntil - now) / 1000));
    return res.status(429).send('Too many page requests. Try again later.');
  }

  return next();
}

app.get(['/', '/index.html'], reloadProtection);
app.use(express.static(path.join(__dirname, 'public')));

function createSession() {
  const now = Date.now();
  for (const [sessionId, expiresAt] of sessions) {
    if (expiresAt <= now) {
      sessions.delete(sessionId);
    }
  }

  const sessionId = crypto.randomBytes(32).toString('base64url');
  sessions.set(sessionId, now + verificationWindowMs);
  return sessionId;
}

function getValidSession(sessionId) {
  if (!sessionId || typeof sessionId !== 'string') {
    return false;
  }

  const expiresAt = sessions.get(sessionId);
  if (!expiresAt) {
    return false;
  }

  if (expiresAt <= Date.now()) {
    sessions.delete(sessionId);
    return false;
  }

  return true;
}

function readSessionCookie(req) {
  const cookieHeader = req.get('cookie') || '';
  const sessionCookie = cookieHeader
    .split(';')
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith('verification_session='));

  if (!sessionCookie) {
    return '';
  }

  try {
    return decodeURIComponent(sessionCookie.slice('verification_session='.length));
  } catch {
    return '';
  }
}

function setSessionCookie(res, sessionId) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `verification_session=${encodeURIComponent(sessionId)}; Max-Age=${verificationWindowMs / 1000}; Path=/; HttpOnly; SameSite=Strict${secure}`
  );
}

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Traffic threshold exceeded. Try again shortly.'
  }
});

app.get('/api/config', (req, res) => {
  if (!process.env.TURNSTILE_SITE_KEY) {
    return res.status(500).json({ error: 'Turnstile site key is not configured.' });
  }

  res.json({ siteKey: process.env.TURNSTILE_SITE_KEY });
});

app.post(
  '/api/verify',
  apiLimiter,
  body('token').isString().trim().notEmpty().isLength({ min: 10, max: 2048 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, error: 'Invalid verification token.' });
    }

    const { token } = req.body;
    const secretKey = process.env.TURNSTILE_SECRET_KEY;

    if (!secretKey) {
      console.error('TURNSTILE_SECRET_KEY is missing.');
      return res.status(500).json({ success: false, error: 'Verification service is not configured.' });
    }

    try {
      const formData = new URLSearchParams({
        secret: secretKey,
        response: token
      });

      if (req.ip) {
        formData.append('remoteip', req.ip);
      }

      const cfResponse = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData
      });

      const cfData = await cfResponse.json();

      if (!cfResponse.ok || !cfData.success) {
        console.warn(`Turnstile validation failed: ${JSON.stringify(cfData['error-codes'] || [])}`);
        return res.status(403).json({ success: false, error: 'Security challenge failed.' });
      }

      setSessionCookie(res, createSession());
      res.set('Cache-Control', 'no-store');
      return res.json({ success: true });
    } catch (error) {
      console.error('Turnstile verification error:', error);
      return res.status(500).json({ success: false, error: 'Verification request failed.' });
    }
  }
);

app.get('/api/content', (req, res) => {
  if (!getValidSession(readSessionCookie(req))) {
    return res.status(403).json({ success: false, error: 'Verification required.' });
  }

  res.set('Cache-Control', 'no-store');
  return res.json({
    success: true,
    content: 'This content is served only after the server validates your verification.'
  });
});

app.get('/verified.html', (req, res) => {
  if (!getValidSession(readSessionCookie(req))) {
    return res.redirect(303, '/');
  }

  res.set('Cache-Control', 'no-store');
  return res.sendFile(path.join(__dirname, 'verified.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Turnstile demo running on port ${PORT}`);
});
