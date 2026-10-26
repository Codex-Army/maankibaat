
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

// Intentionally vulnerable in-memory state for the isolated Race Condition CTF lab.
// For reliable multi-instance deployments, replace this Map with a shared datastore.
const laptopClaims = new Map();
const XSS_FLAG = 'MODI{Mann_Ki_Baat_XSS}';
const RACE_FLAG = 'MODI{Chor_Ke_Ghar_Mein_Chori}';

function auth(req, res, next) {
    const token = req.cookies && req.cookies.token;
    req.user = null;

    if (!token) return next();

    try {
        // JWT challenge: the signature MUST be valid. Participants must discover
        // the CTF secret and re-sign the modified role claim using HS256.
        req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    } catch (error) {
        // Invalid/expired signatures are not authenticated sessions.
        res.clearCookie('token', { path: '/' });
    }

    return next();
}

app.use(auth);

app.get('/', (req, res) => {
    res.render('index', {
        user: req.user || null
    });
});

app.post('/login', (req, res) => {

    const { username, password } = req.body;

    if(username === 'amit' && password === 'mitron@2026'){

        const token = jwt.sign({
            username,
            role:'user'
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

app.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    res.send(`
User-agent: *
Disallow: /modi
Disallow: /admin
`);
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

// XSS is intentionally implemented as a browser-local training exercise: each
// participant's feedback stays in their own browser and never affects other visitors.
app.get('/api/xss-flag', (req, res) => {
    res.json({ success: true, flag: XSS_FLAG });
});

// Deliberately vulnerable check-then-act logic for the Race Condition lab.
// Multiple concurrent requests can all pass the check before any increment occurs.

// Race Condition challenge state
const activeClaims = new Map();
const laptopClaims = new Map();

// Keep your existing RACE_FLAG declaration above this route.

app.post('/api/laptop/claim', async (req, res) => {
    const sessionId = String(req.body.sessionId || '');

    if (!/^[a-zA-Z0-9_-]{8,100}$/.test(sessionId)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid challenge session.'
        });
    }

    // Count requests overlapping in this Node.js process.
    const active = (activeClaims.get(sessionId) || 0) + 1;
    activeClaims.set(sessionId, active);

    // Capture the count before any request finishes.
    const reachedTwenty = active >= 20;

    try {
        await new Promise(resolve => setTimeout(resolve, 500));

        const current = laptopClaims.get(sessionId) || { claimed: 0 };
        current.claimed += 1;
        laptopClaims.set(sessionId, current);

        if (reachedTwenty) {
            return res.json({
                success: true,
                claimed: current.claimed,
                message: 'Race condition triggered!',
                flag: RACE_FLAG
            });
        }

        return res.json({
            success: true,
            claimed: current.claimed,
            message: 'Claim processed. 20 simultaneous requests are required.'
        });

    } finally {
        const remaining = (activeClaims.get(sessionId) || 1) - 1;

        if (remaining <= 0) {
            activeClaims.delete(sessionId);
        } else {
            activeClaims.set(sessionId, remaining);
        }
    }
});

// Intentional IDOR lab: object access is based on a caller-controlled userId.
// This deliberately vulnerable endpoint is for the local CTF challenge only.
app.get('/secure-message', (req, res) => {
    res.render('secure-message');
});

app.get('/api/secure-message', (req, res) => {
    const userId = String(req.query.userId || '');
    const messages = {
        '101': { username: 'amit', title: 'Message for Amit', body: 'Mitron, report ka first draft ready hai. Meeting se pehle review kar lena.' },
        '102': { username: 'yogi', title: 'Message for Yogi', body: 'Yogi ji, event ke arrangements confirm hain. Final update ka intezar hai.' },
        '420': { username: 'gyanesh', title: 'Private message for Gyanesh', body: 'Gyanesh, sab jaan gaye... asli raaz yahin tha. Flag: ' + FLAG3 }
    };

    const message = messages[userId];
    if (!message) {
        return res.status(404).json({ success: false, message: 'User/message not found. Check the request and userId.' });
    }

    // CTF flaw: no ownership/authorization check is performed for the requested userId.
    return res.json({ success: true, message });
});

app.post('/buy', (req, res) => {

    const price = Number(req.body.price);

    if(price === 0){
        return res.json({
            success:true,
            flag: FLAG1
        });
    }

    res.json({
        success:false,
        message:'Price too high'
    });
});

app.get('/admin', (req, res) => {
    // No valid JWT cookie means the visitor is not logged in.
    if (!req.user) {
        return res.redirect(302, '/');
    }

    // A valid user JWT is logged in, but does not grant admin access.
    // Keep this CTF role-check page so the challenge remains solvable.
    if (req.user.role !== 'admin') {
        return res.status(403).render('notadmin');
    }

    return res.render('admin', { flag: FLAG2 });
});

app.post('/submit-flags', (req, res) => {

    const { flag1, flag2, flag3, flag4, flag5 } = req.body;

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

    res.json({
        success:false,
        message:'Wrong Flags'
    });
});

module.exports = app;

// Vercel runs this as a serverless function. Only listen locally when started
// directly with `npm start` outside Vercel.
if (require.main === module && !process.env.VERCEL) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}
