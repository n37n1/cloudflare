const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// 1. Production Security Headers (Helmet)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "https://cloudflare.com"],
            "frame-src": ["'self'", "https://cloudflare.com"],
        },
    },
}));

// 2. Strict CORS Boundaries
const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',') 
    : ['http://localhost:3000'];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Blocked by CORS strategy'));
        }
    },
    methods: ['GET', 'POST']
}));

// 3. Size boundaries to counter RAM exhaustion spikes
app.use(express.json({ limit: '10kb' }));

// 4. Rate-limiting configurations
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 mins
    max: 30, 
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: "Traffic threshold exceeded. Try again shortly." }
});

// Serve frontend build static files seamlessly
app.use(express.static(path.join(__dirname, 'public')));

// Safe public site key access endpoint
app.get('/api/config', (req, res) => {
    if (!process.env.TURNSTILE_SITE_KEY) {
        return res.status(500).json({ error: "Configuration anomaly detected." });
    }
    res.json({ siteKey: process.env.TURNSTILE_SITE_KEY });
});

// Hardened verification endpoint
app.post('/api/verify', 
    apiLimiter,
    body('token').isString().trim().notEmpty().isLength({ min: 10, max: 2048 }), 
    async (req, res) => {
        
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ success: false, error: "Invalid operational parameter payloads." });
        }

        const { token } = req.body;
        const SECRET_KEY = process.env.TURNSTILE_SECRET_KEY;

        if (!SECRET_KEY) {
            console.error("CRITICAL: TURNSTILE_SECRET_KEY is absent.");
            return res.status(500).json({ success: false, error: "System isolation block error." });
        }

        try {
            const formData = new URLSearchParams();
            formData.append('secret', SECRET_KEY);
            formData.append('response', token);
            if (req.ip) formData.append('remoteip', req.ip); 

            const cfResponse = await fetch('https://cloudflare.com/turnstile/v0/siteverify', {
                method: 'POST',
                body: formData,
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });

            const cfData = await cfResponse.json();

            if (cfData.success) {
                return res.json({ success: true });
            } 
            
            console.warn(`Turnstile Check Failed: ${JSON.stringify(cfData['error-codes'])}`);
            return res.status(403).json({ success: false, error: "Security checkpoint verification rejected." });

        } catch (error) {
            console.error("Internal Gateway Verification Fault:", error);
            return res.status(500).json({ success: false, error: "Verification node structurally unavailable." });
        }
    }
);

// Tells Express to expect Render's single routing upstream proxy for explicit IP readings
app.set('trust proxy', 1);

// Fallback handling to direct traffic correctly
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server executing securely on port ${PORT}`);
});
