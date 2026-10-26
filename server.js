const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();

const JWT_SECRET = "modi_hai_to_admin_hai";

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const FLAG1 = "MODI{Desh_Bachalo_Guys}";
const FLAG2 = "MODI{BECHO_JANTA_PARTY}";
const FLAG3 = "MODI{Sab_Jaan_Gaye}";
const MASTER_FLAG = "MASTER{Desh_Bachalo_BECHO_JANTA_Sab_Jaan_Gaye_Mann_Ki_Baat_Yogi_Rush}";

const XSS_FLAG = "MODI{Mann_Ki_Baat_XSS}";
const RACE_FLAG = "MODI{Chor_Ke_Ghar_Mein_Chori}";

// In-memory state for the CTF lab.
// State is shared only within the same Node.js process.
const laptopClaims = new Map();
const activeClaims = new Map();

function auth(req, res, next) {
    const token = req.cookies && req.cookies.token;
    req.user = null;

    if (!token) return next();

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

// Home
app.get('/', (req, res) => {
    res.render('index', {
        user: req.user || null
    });
});

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (username === 'amit' && password === 'mitron@2026') {
        const token = jwt.sign({
            username,
            role: 'user'
        }, JWT_SECRET);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL),
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

// Challenge pages
app.get('/modi', (req, res) => {
    res.render('modi');
});

app.get('/mann-ki-baat', (req, res) => {
    res.render('mann-ki-baat');
});

app.get('/yogi-laptop', (req, res) => {
    res.render('yogi-laptop');
});

// XSS training flag
app.get('/api/xss-flag', (req, res) => {
    res.json({
        success: true,
        flag: XSS_FLAG
    });
});

// Race Condition challenge
// Flag is returned only when 20 or more requests overlap
// for the same sessionId within this Node.js process.
app.post('/api/laptop/claim', async (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    // Register this request before the delay.
    const active = (activeClaims.get(sessionId) || 0) + 1;
    activeClaims.set(sessionId, active);

    // Capture the number of active requests at entry.
    // Later requests can trigger the threshold while this request waits.
    const reachedTwenty = active >= 20;

    try {
        // Artificial race window for the educational lab.
        await new Promise(resolve => setTimeout(resolve, 500));

        const current = laptopClaims.get(sessionId) || { claimed: 0 };
        current.claimed += 1;
        laptopClaims.set(sessionId, current);

        if (reachedTwenty) {
            return res.json({
                success: true,
                claimed: current.claimed,
                message: 'Race condition triggered! 20+ requests overlapped.',
                flag: RACE_FLAG
            });
        }

        return res.json({
            success: true,
            claimed: current.claimed,
            message: 'Laptop claim successful. Send 20 or more requests simultaneously to trigger the race condition.'
        });

    } finally {
        // Always decrement active count when this request finishes.
        const remaining = (activeClaims.get(sessionId) || 1) - 1;

        if (remaining <= 0) {
            activeClaims.delete(sessionId);
        } else {
            activeClaims.set(sessionId, remaining);
        }
    }
});

// Reset Race Condition challenge session
app.post('/api/laptop/reset', (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    // Do not reset while requests for this session are still running.
    if ((activeClaims.get(sessionId) || 0) > 0) {
        return res.status(409).json({
            success: false,
            message: 'Requests are still running. Try resetting after they finish.'
        });
    }

    laptopClaims.delete(sessionId);

    return res.json({
        success: true,
        message: 'Laptop claim counter reset for this challenge session.'
    });
});

// Secure Message page
app.get('/secure-message', (req, res) => {
    res.render('secure-message');
});

// IDOR challenge
app.get('/api/secure-message', (req, res) => {
    const userId = String(req.query.userId || '');

    const messages = {
        '101': {
            username: 'amit',
            title: 'Message for Amit',
            body: 'Mitron, report ka first draft ready hai. Meeting se pehle review kar lena.'
        },
        '102': {
            username: 'yogi',
            title: 'Message for Yogi',
            body: 'Yogi ji, event ke arrangements confirm hain. Final update ka intezar hai.'
        },
        '420': {
            username: 'gyanesh',
            title: 'Private message for Gyanesh',
            body: 'Gyanesh, sab jaan gaye... asli raaz yahin tha. Flag: ' + FLAG3
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

// Price tampering challenge
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

// Submit all flags
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

module.exports = app;

// Local development server
if (require.main === module && !process.env.VERCEL) {
    const PORT = process.env.PORT || 3000;

    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}
```
