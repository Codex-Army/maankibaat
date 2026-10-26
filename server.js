```javascript
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

// ================= FLAGS =================

const FLAG1 = 'MODI{Desh_Bachalo_Guys}';
const FLAG2 = 'MODI{BECHO_JANTA_PARTY}';
const FLAG3 = 'MODI{Sab_Jaan_Gaye}';
const XSS_FLAG = 'MODI{Mann_Ki_Baat_XSS}';
const RACE_FLAG = 'MODI{Chor_Ke_Ghar_Mein_Chori}';

const MASTER_FLAG =
    'MASTER{Desh_Bachalo_BECHO_JANTA_Sab_Jaan_Gaye_Mann_Ki_Baat_Yogi_Rush}';

// ================= RACE CONDITION STATE =================

// Simple in-memory state for the CTF race condition challenge.
// On Vercel, memory is not shared across separate serverless instances.
const laptopClaims = new Map();

// ================= AUTHENTICATION =================

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

// ================= HOME =================

app.get('/', (req, res) => {
    res.render('index', {
        user: req.user || null
    });
});

// ================= LOGIN =================

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

// ================= ROBOTS.TXT =================

app.get('/robots.txt', (req, res) => {
    res.type('text/plain');

    res.send(`
User-agent: *
Disallow: /modi
Disallow: /admin
`);
});

// ================= PAGES =================

app.get('/modi', (req, res) => {
    res.render('modi');
});

app.get('/mann-ki-baat', (req, res) => {
    res.render('mann-ki-baat');
});

app.get('/yogi-laptop', (req, res) => {
    res.render('yogi-laptop');
});

// ================= XSS CHALLENGE =================

app.get('/api/xss-flag', (req, res) => {
    res.json({
        success: true,
        flag: XSS_FLAG
    });
});

// ================= RACE CONDITION CHALLENGE =================

// Intentionally vulnerable check-then-act logic for the CTF.
// Multiple concurrent requests can pass the initial check before
// any request updates the counter.

app.post('/api/laptop/claim', async (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    // Step 1: Check the current claim count.
    const current = laptopClaims.get(sessionId) || {
        claimed: 0
    };

    if (current.claimed >= 1) {
        return res.status(409).json({
            success: false,
            claimed: current.claimed,
            message:
                'Arre Mitron! Aap pehle hi ek laptop claim kar chuke hain!'
        });
    }

    // Step 2: Artificial delay creates the race window.
    await new Promise(resolve => setTimeout(resolve, 200));

    // Step 3: Increment the latest count.
    const latest = laptopClaims.get(sessionId) || {
        claimed: 0
    };

    latest.claimed += 1;

    laptopClaims.set(sessionId, latest);

    // Flag unlocks after more than 20 claims.
    const solved = latest.claimed > 20;

    return res.json({
        success: true,
        claimed: latest.claimed,
        message: solved
            ? 'Arre Mitron, ek laptop lene aaye the aur dukaan khaali kar di!'
            : 'Laptop claim successful! Ek hi laptop allowed hai.',
        ...(solved ? { flag: RACE_FLAG } : {})
    });
});

// ================= RESET RACE CHALLENGE =================

app.post('/api/laptop/reset', (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    laptopClaims.delete(sessionId);

    return res.json({
        success: true,
        message: 'Laptop claim counter reset for this challenge session.'
    });
});

// ================= SECURE MESSAGE PAGE =================

app.get('/secure-message', (req, res) => {
    res.render('secure-message');
});

// ================= IDOR CHALLENGE =================

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
                'Gyanesh, sab jaan gaye... asli raaz yahin tha. Flag: ' +
                FLAG3
        }
    };

    const message = messages[userId];

    if (!message) {
        return res.status(404).json({
            success: false,
            message: 'User/message not found. Check the request and userId.'
        });
    }

    // Intentionally vulnerable IDOR challenge.
    return res.json({
        success: true,
        message
    });
});

// ================= PRICE TAMPERING =================

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

// ================= ADMIN / JWT CHALLENGE =================

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

// ================= SUBMIT FLAGS =================

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

// ================= EXPORT APP =================

module.exports = app;

// Run locally using npm start / node server.js.
// Vercel imports the exported Express app.
if (require.main === module && !process.env.VERCEL) {
    const PORT = process.env.PORT || 3000;

    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}
```
