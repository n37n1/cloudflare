const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

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
app.use(express.static(path.join(__dirname, 'public')));

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

      return res.json({ success: true });
    } catch (error) {
      console.error('Turnstile verification error:', error);
      return res.status(500).json({ success: false, error: 'Verification request failed.' });
    }
  }
);

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Turnstile demo running on port ${PORT}`);
});
