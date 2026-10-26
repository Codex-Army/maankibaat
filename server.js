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

// ==================== CTF FLAGS ====================

const FLAG1 = 'MODI{Desh_Bachalo_Guys}';
const FLAG2 = 'MODI{BECHO_JANTA_PARTY}';
const FLAG3 = 'MODI{Sab_Jaan_Gaye}';
const XSS_FLAG = 'MODI{Mann_Ki_Baat_XSS}';
const RACE_FLAG = 'MODI{Chor_Ke_Ghar_Mein_Chori}';

const MASTER_FLAG =
    'MASTER{Desh_Bachalo_BECHO_JANTA_Sab_Jaan_Gaye_Mann_Ki_Baat_Yogi_Rush}';

// In-memory state for the local CTF lab.
// This is not reliable across Vercel serverless instances.
const laptopClaims = new Map();

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

// ==================== LOGIN / JWT CHALLENGE ====================

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (username === 'amit' && password === 'mitron@2026') {
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

// ==================== STORED XSS CHALLENGE ====================

// Browser-local XSS challenge endpoint.
//
// IMPORTANT:
// This endpoint deliberately exposes the flag for the training exercise.
// Calling it directly will also return the flag, so it does not prove
// that an XSS payload actually executed. See the note below.
app.get('/api/xss-flag', (req, res) => {
    return res.json({
        success: true,
        flag: XSS_FLAG
    });
});

// ==================== RACE CONDITION CHALLENGE ====================

// Intended behavior for the local CTF:
// - One normal request must not return the flag.
// - Concurrent requests may all pass the initial check.
// - The flag is returned when the count reaches 20.
//
// This intentionally uses check-then-act logic.
// DO NOT use this pattern for real payments, inventory, or production claims.

app.post('/api/laptop/claim', async (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    // Step 1: Every overlapping request checks the same initial state.
    const current = laptopClaims.get(sessionId) || { claimed: 0 };

    if (current.claimed >= 1) {
        return res.status(409).json({
            success: false,
            claimed: current.claimed,
            message:
                'Arre Mitron! Aap pehle hi ek laptop claim kar chuke hain!'
        });
    }

    // Step 2: Intentional race window for the CTF.
    await new Promise(resolve => setTimeout(resolve, 180));

    // Step 3: Re-read and increment the latest shared state.
    // Requests that passed Step 1 can all reach this point.
    const latest = laptopClaims.get(sessionId) || { claimed: 0 };

    latest.claimed += 1;

    laptopClaims.set(sessionId, latest);

    // Flag appears at 20 successful overlapping claims, not 21.
    const solved = latest.claimed >= 20;

    return res.json({
        success: true,
        claimed: latest.claimed,
        message: solved
            ? 'Arre Mitron, ek laptop lene aaye the aur dukaan khaali kar di!'
            : 'Laptop claim successful! Ek hi laptop allowed hai.',
        ...(solved ? { flag: RACE_FLAG } : {})
    });
});

// Reset the race challenge state for local testing.
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

// ==================== IDOR CHALLENGE ====================

// Intentionally vulnerable for the isolated CTF.
// The requested userId is not checked against the logged-in user.

app.get('/api/secure-message', (req, res) => {
    const userId = String(req.query.userId || '');

    const messages = {
        // Normal message for Amit.
        '101': {
            username: 'amit',
            title: 'Message for Amit',
            body: 'Mitron, report ka first draft ready hai. Meeting se pehle review kar lena.'
        },

        // Normal message for Yogi.
        '102': {
            username: 'yogi',
            title: 'Message for Yogi',
            body: 'Yogi ji, event ke arrangements confirm hain. Final update ka intezar hai.'
        },

        // Normal message for Gyanesh.
        '103': {
            username: 'gyanesh',
            title: 'Message for Gyanesh',
            body: 'Gyanesh, meeting ke notes ready hain. Please review them.'
        },

        // Private object accessible by changing the requested ID.
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

    // Intentionally vulnerable business logic for the CTF.
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
