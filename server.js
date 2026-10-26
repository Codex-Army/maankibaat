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

// ==================== FLAGS ====================

const FLAG1 = 'MODI{Desh_Bachalo_Guys}';
const FLAG2 = 'MODI{BECHO_JANTA_PARTY}';
const FLAG3 = 'MODI{Sab_Jaan_Gaye}';
const XSS_FLAG = 'MODI{Mann_Ki_Baat_XSS}';
const RACE_FLAG = 'MODI{Chor_Ke_Ghar_Mein_Chori}';

const MASTER_FLAG =
    'MASTER{Desh_Bachalo_BECHO_JANTA_Sab_Jaan_Gaye_Mann_Ki_Baat_Yogi_Rush}';

// ==================== RACE CONDITION STATE ====================

// Local CTF only. This Map is shared within one Node.js process.
// It is NOT shared between separate Vercel serverless instances.
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

// ==================== LOGIN / JWT ====================

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

        return res.json({
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

// ==================== XSS CHALLENGE ====================

// NOTE: This endpoint exposes the flag directly.
// A participant can call it without proving that XSS executed.
// For a real XSS challenge, the frontend and flag-verification
// design must be changed together.

app.get('/api/xss-flag', (req, res) => {
    return res.json({
        success: true,
        flag: XSS_FLAG
    });
});

// ==================== RACE CONDITION CHALLENGE ====================

// Intended CTF behavior:
// 1. A single request must not reveal the flag.
// 2. Overlapping requests can pass the initial check.
// 3. Shared state is mutated after the delay.
// 4. The flag is returned when the shared counter reaches 20.
//
// This intentionally vulnerable pattern is for an isolated lab only.
// Never use this logic for real payments, inventory, or claims.

app.post('/api/laptop/claim', async (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    // Get or create ONE shared state object for this session.
    let state = laptopClaims.get(sessionId);

    if (!state) {
        state = {
            claimed: 0,
            inFlight: 0
        };

        laptopClaims.set(sessionId, state);
    }

    // If an earlier claim has completed and no requests are
    // currently overlapping, reject another normal claim.
    if (state.claimed >= 1 && state.inFlight === 0) {
        return res.status(409).json({
            success: false,
            claimed: state.claimed,
            message:
                'Arre Mitron! Aap pehle hi ek laptop claim kar chuke hain!'
        });
    }

    // IMPORTANT:
    // Increment inFlight BEFORE awaiting. Other overlapping requests
    // can pass the check while the first request is still waiting.
    state.inFlight += 1;

    try {
        // Intentional race window for the CTF.
        await new Promise(resolve => setTimeout(resolve, 180));

        // Mutate the SAME shared object.
        // Within one Node.js process, each increment runs synchronously.
        state.claimed += 1;

        const solved = state.claimed >= 20;

        return res.json({
            success: true,
            claimed: state.claimed,
            message: solved
                ? 'Arre Mitron, ek laptop lene aaye the aur dukaan khaali kar di!'
                : 'Laptop claim successful! Ek hi laptop allowed hai.',
            ...(solved ? { flag: RACE_FLAG } : {})
        });
    } finally {
        state.inFlight -= 1;
    }
});

// ==================== RESET RACE CHALLENGE ====================

// Useful for resetting the lab between tests.
// Do not reset while requests for the same session are still running.

app.post('/api/laptop/reset', (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    const state = laptopClaims.get(sessionId);

    if (state && state.inFlight > 0) {
        return res.status(409).json({
            success: false,
            message: 'Cannot reset while claims are in progress.'
        });
    }

    laptopClaims.delete(sessionId);

    return res.json({
        success: true,
        message: 'Laptop claim counter reset for this challenge session.'
    });
});

// ==================== IDOR CHALLENGE ====================

// Intentionally vulnerable: userId is caller-controlled and
// there is no ownership/authorization check.

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
