const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const { Redis } = require('@upstash/redis');

const app = express();

const JWT_SECRET = 'modi_hai_to_admin_hai';

// ==================== REDIS CONFIGURATION ====================

const redisUrl =
    process.env.UPSTASH_REDIS_REST_URL ||
    process.env.KV_REST_API_URL;

const redisToken =
    process.env.UPSTASH_REDIS_REST_TOKEN ||
    process.env.KV_REST_API_TOKEN;

const redis =
    redisUrl && redisToken
        ? new Redis({
              url: redisUrl,
              token: redisToken
          })
        : null;

// ==================== EXPRESS CONFIGURATION ====================

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ==================== CTF FLAGS ====================

const FLAG1 = 'MODI{Desh_Bachalo_Guys}';
const FLAG2 = 'MODI{BECHO_JANTA_PARTY}';
const FLAG3 = 'MODI{Sab_Jaan_Gaye}';
const XSS_FLAG = 'MODI{Mann_Ki_Baat_XSS}';
const RACE_FLAG = 'MODI{Chor_Ke_Ghar_Mein_Chori}';

const MASTER_FLAG =
    'MASTER{Desh_Bachalo_BECHO_JANTA_Sab_Jaan_Gaye_Mann_Ki_Baat_Yogi_Rush}';

// ==================== AUTH MIDDLEWARE ====================

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

// ==================== HOME ====================

app.get('/', (req, res) => {
    res.render('index', {
        user: req.user || null
    });
});

// ==================== LOGIN / JWT ====================

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (
        username === 'amit' &&
        password === 'mitron@2026'
    ) {
        const token = jwt.sign(
            {
                username,
                role: 'user'
            },
            JWT_SECRET,
            {
                algorithm: 'HS256',
                expiresIn: '1h'
            }
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

// ==================== ROBOTS.TXT ====================

app.get('/robots.txt', (req, res) => {
    res.type('text/plain');

    res.send(`User-agent: *
Disallow: /modi
Disallow: /admin
`);
});

// ==================== CTF PAGES ====================

app.get('/', (req, res) => {
    res.render('index', {
        user: req.user || null
    });
});

app.get('/modi', (req, res) => {
    res.render('modi');
});

app.get('/mann-ki-baat', (req, res) => {
    res.render('mann-ki-baat');
});

app.get('/yogi-laptop', (req, res) => {
    res.render('yogi-laptop');
});

app.get('/secure-message', (req, res) => {
    res.render('secure-message');
});

// ==================== XSS CHALLENGE ====================

// Kept compatible with the existing frontend.
// NOTE: This endpoint exposes the flag directly.
// A participant can request it without executing an XSS payload.

app.get('/api/xss-flag', (req, res) => {
    return res.json({
        success: true,
        flag: XSS_FLAG
    });
});

// ==================== RACE CONDITION CHALLENGE ====================

// Uses shared Redis state across Vercel instances.
//
// Intentionally vulnerable check-then-act behavior for the isolated
// CTF lab. Never use this pattern for real payments or inventory.
//
// Redis keys are scoped to the supplied challenge session ID.

function raceKeys(sessionId) {
    const prefix = `ctf:laptop:${sessionId}`;

    return {
        claimedKey: `${prefix}:claimed`,
        inFlightKey: `${prefix}:inflight`
    };
}

app.post('/api/laptop/claim', async (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    if (!redis) {
        return res.status(503).json({
            success: false,
            message:
                'Race challenge storage is not configured. Set the Upstash Redis environment variables and redeploy.'
        });
    }

    const { claimedKey, inFlightKey } = raceKeys(sessionId);

    let entered = false;

    try {
        // Read the shared state.
        // The check and the following update are deliberately separate
        // to create a race window for the training challenge.
        const claimedValue = await redis.get(claimedKey);
        const inFlightValue = await redis.get(inFlightKey);

        const claimed = Number(claimedValue) || 0;
        const inFlight = Number(inFlightValue) || 0;

        // Reject a new sequential claim after the previous claim finishes.
        // Allow overlapping requests while other claims are in progress.
        if (claimed >= 1 && inFlight === 0) {
            return res.status(409).json({
                success: false,
                claimed,
                message:
                    'Arre Mitron! Aap pehle hi ek laptop claim kar chuke hain!'
            });
        }

        // Track the active request in shared storage.
        await redis.incr(inFlightKey);
        await redis.expire(inFlightKey, 3600);

        // Mark that this request successfully entered the race window.
        entered = true;

        // Intentional delay for the CTF exercise.
        await new Promise(resolve => setTimeout(resolve, 180));

        // Atomic increment on shared Redis state.
        // Concurrent requests cannot overwrite each other's increments.
        const newClaimed = await redis.incr(claimedKey);

        // Avoid retaining challenge counters indefinitely.
        await redis.expire(claimedKey, 3600);

        const solved = newClaimed >= 20;

        return res.json({
            success: true,
            claimed: newClaimed,
            message: solved
                ? 'Arre Mitron, ek laptop lene aaye the aur dukaan khaali kar di!'
                : 'Laptop claim successful! Ek hi laptop allowed hai.',
            ...(solved ? { flag: RACE_FLAG } : {})
        });
    } catch (error) {
        console.error('Race challenge error:', error);

        return res.status(500).json({
            success: false,
            message: 'Race challenge storage error.'
        });
    } finally {
        // Always decrement the in-flight counter for requests that entered.
        if (entered) {
            try {
                await redis.decr(inFlightKey);
            } catch (error) {
                console.error(
                    'Failed to decrement race in-flight counter:',
                    error
                );
            }
        }
    }
});

// ==================== RESET RACE CHALLENGE ====================

// Reset is for CTF maintenance and testing.
// Do not reset while claims for the same session are running.

app.post('/api/laptop/reset', async (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    if (!redis) {
        return res.status(503).json({
            success: false,
            message: 'Redis storage is not configured.'
        });
    }

    const { claimedKey, inFlightKey } = raceKeys(sessionId);

    try {
        const inFlightValue = await redis.get(inFlightKey);
        const inFlight = Number(inFlightValue) || 0;

        if (inFlight > 0) {
            return res.status(409).json({
                success: false,
                inFlight,
                message:
                    'Claims are still running. Wait for them to finish, then reset.'
            });
        }

        await redis.del(claimedKey, inFlightKey);

        return res.json({
            success: true,
            message: 'Laptop claim counter reset for this challenge session.'
        });
    } catch (error) {
        console.error('Race reset error:', error);

        return res.status(500).json({
            success: false,
            message: 'Could not reset race challenge.'
        });
    }
});

// ==================== IDOR CHALLENGE ====================

// Intentionally vulnerable object access for the isolated CTF.
// The requested userId is not checked against the logged-in user.

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

        '103': {
            username: 'gyanesh',
            title: 'Message for Gyanesh',
            body:
                'Gyanesh, meeting ke notes ready hain. Please review them.'
        },

        '420': {
            username: 'gyanesh',
            title: 'Private message for Gyanesh',
            body:
                'Gyanesh, sab jaan gaye... asli raaz yahin tha. Flag: ' +
                FLAG3
        }
    };

    const message = messages[userId];

    if (!message) {
        return res.status(404).json({
            success: false,
            message:
                'User/message not found. Check the request and userId.'
        });
    }

    return res.json({
        success: true,
        message
    });
});

// ==================== PRICE MANIPULATION ====================

app.post('/buy', (req, res) => {
    const price = Number(req.body.price);

    if (!Number.isFinite(price)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid price.'
        });
    }

    // Intentionally vulnerable for the CTF.
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

// ==================== ADMIN / JWT ROLE CHALLENGE ====================

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

// ==================== MASTER FLAG SUBMISSION ====================

app.post('/submit-flags', (req, res) => {
    const {
        flag1,
        flag2,
        flag3,
        flag4,
        flag5
    } = req.body;

    const allCorrect =
        flag1 === FLAG1 &&
        flag2 === FLAG2 &&
        flag3 === FLAG3 &&
        flag4 === XSS_FLAG &&
        flag5 === RACE_FLAG;

    if (allCorrect) {
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

// ==================== EXPORT / LOCAL SERVER ====================

module.exports = app;

if (require.main === module && !process.env.VERCEL) {
    const PORT = process.env.PORT || 3000;

    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}
