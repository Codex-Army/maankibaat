const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

const JWT_SECRET = 'modi_hai_to_admin_hai';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Existing CTF flags
const FLAG1 = 'MODI{Desh_Bachalo_Guys}';
const FLAG2 = 'MODI{BECHO_JANTA_PARTY}';
const FLAG3 = 'MODI{Sab_Jaan_Gaye}';

const MASTER_FLAG =
    'MASTER{Desh_Bachalo_BECHO_JANTA_Sab_Jaan_Gaye_Mann_Ki_Baat_Yogi_Rush}';

const XSS_FLAG = 'MODI{Mann_Ki_Baat_XSS}';
const RACE_FLAG = 'MODI{Chor_Ke_Ghar_Mein_Chori}';

const RACE_THRESHOLD = 2;

// Local development storage.
const laptopClaims = new Map();

// Shared Redis storage is enabled when both environment variables exist.
const USE_REDIS = Boolean(
    process.env.UPSTASH_REDIS_REST_URL &&
    process.env.UPSTASH_REDIS_REST_TOKEN
);

let redis = null;

if (USE_REDIS) {
    const { Redis } = require('@upstash/redis');

    redis = new Redis({
        url: process.env.UPSTASH_REDIS_REST_URL,
        token: process.env.UPSTASH_REDIS_REST_TOKEN
    });
}

async function getClaimCount(sessionId) {
    if (redis) {
        const value = await redis.get(`mitron:laptop:${sessionId}`);
        return Number(value || 0);
    }

    return laptopClaims.get(sessionId) || 0;
}

async function incrementClaimCount(sessionId) {
    if (redis) {
        const key = `mitron:laptop:${sessionId}`;
        const count = await redis.incr(key);

        await redis.expire(key, 3600);

        return Number(count);
    }

    const count = (laptopClaims.get(sessionId) || 0) + 1;

    laptopClaims.set(sessionId, count);

    return count;
}

async function resetClaimCount(sessionId) {
    if (redis) {
        await redis.del(`mitron:laptop:${sessionId}`);
        return;
    }

    laptopClaims.delete(sessionId);
}

// Authentication middleware
function auth(req, res, next) {
    const token = req.cookies && req.cookies.token;

    req.user = null;

    if (!token) {
        return next();
    }

    try {
        req.user = jwt.verify(token, JWT_SECRET, {
            algorithms: ['HS256']
        });
    } catch (error) {
        res.clearCookie('token', { path: '/' });
    }

    return next();
}

app.use(auth);

// Home page
app.get('/', (req, res) => {
    res.render('index', {
        user: req.user || null
    });
});

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (username === 'amit' && password === 'mitron@2026') {
        const token = jwt.sign(
            {
                username,
                role: 'user'
            },
            JWT_SECRET
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure:
                process.env.NODE_ENV === 'production' ||
                Boolean(process.env.VERCEL),
            sameSite: 'lax',
            path: '/',
            maxAge: 60 * 60 * 1000
        });

        return res.status(200).json({
            success: true,
            message: 'Login Successful'
        });
    }

    return res.status(401).json({
        success: false,
        message: 'Wrong Credentials'
    });
});

// Robots
app.get('/robots.txt', (req, res) => {
    res.type('text/plain');

    res.send(`
User-agent: *
Disallow: /modi
Disallow: /admin
`);
});

// Existing pages
app.get('/modi', (req, res) => {
    res.render('modi');
});

app.get('/mann-ki-baat', (req, res) => {
    res.render('mann-ki-baat');
});

app.get('/yogi-laptop', (req, res) => {
    res.render('yogi-laptop');
});

// XSS training endpoint
app.get('/api/xss-flag', (req, res) => {
    res.json({
        success: true,
        flag: XSS_FLAG
    });
});

// RACE CONDITION CLAIM ENDPOINT
app.post('/api/laptop/claim', async (req, res) => {
    try {
        const sessionId = String(req.body.sessionId || '');

        if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid challenge session.'
            });
        }

        const current = await getClaimCount(sessionId);

        if (current >= 1) {
            return res.status(409).json({
                success: false,
                claimed: current,
                message:
                    'Arre Mitron! Aap pehle hi ek laptop claim kar chuke hain!'
            });
        }

        // Intentional check-then-act race window for this isolated CTF.
        await new Promise(resolve => setTimeout(resolve, 180));

        const claimed = await incrementClaimCount(sessionId);

        const solved = claimed >= RACE_THRESHOLD;

        return res.json({
            success: true,
            claimed,
            message: solved
                ? 'Arre Mitron, ek laptop lene aaye the aur dukaan khaali kar di!'
                : 'Laptop claim successful! Ek hi laptop allowed hai.',
            ...(solved ? { flag: RACE_FLAG } : {})
        });
    } catch (error) {
        console.error('Laptop claim error:', error);

        return res.status(500).json({
            success: false,
            message: 'Laptop claim service temporarily unavailable.'
        });
    }
});

// RACE CONDITION RESET ENDPOINT
app.post('/api/laptop/reset', async (req, res) => {
    try {
        const sessionId = String(req.body.sessionId || '');

        if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid challenge session.'
            });
        }

        await resetClaimCount(sessionId);

        return res.json({
            success: true,
            message: 'Laptop claim counter reset for this challenge session.'
        });
    } catch (error) {
        console.error('Laptop reset error:', error);

        return res.status(500).json({
            success: false,
            message: 'Could not reset the challenge.'
        });
    }
});

// Secure Message page
app.get('/secure-message', (req, res) => {
    res.render('secure-message');
});

// Intentional IDOR training endpoint
app.get('/api/secure-message', (req, res) => {
    const userId = String(req.query.userId || '');

    const messages = {
        '101': {
            username: 'amit',
            title: 'Message for Amit',
            body:
                'Mitron, report ka first draft ready hai. Meeting se pehle review kar lena.'
        },

        '102': {
            username: 'yogi',
            title: 'Message for Yogi',
            body:
                'Yogi ji, event ke arrangements confirm hain. Final update ka intezar hai.'
        },

        '420': {
            username: 'gyanesh',
            title: 'Private message for Gyanesh',
            body:
                'Gyanesh, sab jaan gaye... asli raaz yahin tha. Flag: ' + FLAG3
        }
    };

    const message = messages[userId];

    if (!message) {
        return res.status(404).json({
            success: false,
            message: 'User/message not found. Check the request and userId.'
        });
    }

    return res.json({
        success: true,
        message
    });
});

// Price manipulation challenge
app.post('/buy', (req, res) => {
    const price = Number(req.body.price);

    if (price === 0) {
        return res.json({
            success: true,
            flag: FLAG1
        });
    }

    return res.json({
        success: false,
        message: 'Price too high'
    });
});

// Admin / JWT challenge
app.get('/admin', (req, res) => {
    if (!req.user) {
        return res.redirect(302, '/');
    }

    if (req.user.role !== 'admin') {
        return res.status(403).render('notadmin');
    }

    return res.render('admin', {
        flag: FLAG2
    });
});

// Final flag submission
app.post('/submit-flags', (req, res) => {
    const {
        flag1,
        flag2,
        flag3,
        flag4,
        flag5
    } = req.body;

    if (
        flag1 === FLAG1 &&
        flag2 === FLAG2 &&
        flag3 === FLAG3 &&
        flag4 === XSS_FLAG &&
        flag5 === RACE_FLAG
    ) {
        return res.json({
            success: true,
            reward: 'MITRON-CTF-WINNER-2026',
            masterFlag: MASTER_FLAG
        });
    }

    return res.json({
        success: false,
        message: 'Wrong Flags'
    });
});

// Export for Vercel
module.exports = app;

// Local development
if (require.main === module && !process.env.VERCEL) {
    const PORT = process.env.PORT || 3000;

    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
        console.log(
            `Laptop storage: ${redis ? 'Upstash Redis' : 'Local in-memory Map'}`
        );
    });
}
