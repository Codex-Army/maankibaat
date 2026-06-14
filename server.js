
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

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

function auth(req, res, next) {
    const token = req.cookies.token;

    if(token){
        try{
            req.user = jwt.verify(token, JWT_SECRET);
        }catch(e){}
    }

    next();
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

        res.cookie('token', token);

        return res.json({
            success:true,
            message:'Login Successful'
        });
    }

    res.json({
        success:false,
        message:'Wrong Credentials'
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

app.post('/buy', (req, res) => {

    const price = Number(req.body.price);

    if(price === 1){
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

    if(!req.user || req.user.role !== 'admin'){
        return res.render('notadmin');
    }

    res.render('admin', {
        flag: FLAG2
    });
});

app.post('/submit-flags', (req, res) => {

    const { flag1, flag2 } = req.body;

    if(flag1 === FLAG1 && flag2 === FLAG2){

        return res.json({
            success:true,
            reward:'MITRON-CTF-WINNER-2026'
        });
    }

    res.json({
        success:false,
        message:'Wrong Flags'
    });
});

module.exports = app;
const PORT = 3000;

app.listen(PORT, () => {
    console.log("Server running on http://localhost:3000");
});
