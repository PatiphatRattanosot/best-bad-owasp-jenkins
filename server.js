require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const axios = require('axios');
const morgan = require('morgan');
const { check, validationResult } = require('express-validator');
const sanitizeHtml = require('sanitize-html'); // สำหรับ XSS Best Practice

// Import models and middleware
const User = require('./models/User');
const { protect, authorize } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

// Connect to MongoDB
mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// EJS as view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Middleware
app.use(express.json()); // สำหรับ parsing application/json
app.use(express.urlencoded({ extended: true })); // สำหรับ parsing application/x-www-form-urlencoded
app.use(cookieParser()); // สำหรับ csurf

// A09:2021 – Security Logging and Monitoring Failures (Best Practice)
// ใช้ morgan สำหรับ HTTP request logging
app.use(morgan('combined')); // 'combined' format is good for production logging

// A05:2021 – Security Misconfiguration (Best Practice: Helmet for Security Headers)
// Helmet ช่วยตั้งค่า HTTP headers ต่างๆ เพื่อเพิ่มความปลอดภัย
// app.use(helmet());
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdn.tailwindcss.com"], // Allow Tailwind CSS CDN
            styleSrc: ["'self'", "https://cdn.tailwindcss.com", "'unsafe-inline'"], // Allow Tailwind CSS CDN and inline styles
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"], // If you use Google Fonts or similar
            objectSrc: ["'none'"],
            upgradeInsecureRequests: [],
        },
    },
}));
// สามารถตั้งค่าเฉพาะได้ เช่น
// app.use(helmet.xssFilter());
// app.use(helmet.frameguard({ action: 'deny' }));
// app.use(helmet.noSniff());
// app.use(helmet.hidePoweredBy());
// app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true })); // HSTS

// A07:2021 – Identification and Authentication Failures (Best Practice: Rate Limiting)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 นาที
    max: 5, // จำกัด 5 ครั้งต่อ IP ใน 15 นาที
    message: 'Too many login attempts from this IP, please try again after 15 minutes',
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// A07:2021 – Identification and Authentication Failures (Best Practice: Secure Session Management)
app.use(session({
    secret: process.env.SESSION_SECRET || 'supersecretkey_dev', // ควรอยู่ใน .env
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // ใช้ secure cookie ใน production (ต้องใช้ HTTPS)
        httpOnly: true, // ป้องกันการเข้าถึง cookie ผ่าน client-side script (XSS)
        maxAge: 1000 * 60 * 60 * 24 // 1 วัน
    }
}));

// A03/Other: CSRF (Best Practice: csurf)
app.use(csrf({ cookie: true }));

// Global CSRF token for all views
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});

// --- Routes ---

// Home Page
app.get('/', (req, res) => {
    res.render('index');
});

// --- A07:2021 – Identification and Authentication Failures ---

// Register Page
app.get('/register', (req, res) => {
    res.render('register');
});

// Register User (Bad Practice: Weak Password Policy / No Input Validation)
app.post('/register-bad', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        // Bad: ไม่มีการตรวจสอบความซับซ้อนของรหัสผ่าน
        // Bad: ไม่มีการตรวจสอบ email format
        const user = new User({ username, email, password, role: 'user' });
        await user.save();
        res.status(201).send('User registered (bad practice: weak password allowed)');
    } catch (error) {
        console.error(error);
        res.status(400).send('Registration failed (bad practice)');
    }
});

// Register User (Best Practice: Strong Password Policy / Input Validation)
app.post('/register-best', [
    check('username')
        .isLength({ min: 3 }).withMessage('Username must be at least 3 characters long')
        .isAlphanumeric().withMessage('Username must be alphanumeric'),
    check('email').isEmail().withMessage('Invalid email format'),
    check('password')
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
        .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])(?=.{8,})/)
        .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;
    try {
        const user = new User({ username, email, password, role: 'user' });
        await user.save();
        res.status(201).send('User registered successfully (best practice)');
    } catch (error) {
        console.error(error);
        res.status(400).send('Registration failed (best practice)');
    }
});

// Login Page
app.get('/login', (req, res) => {
    res.render('login');
});

// Login User (Bad Practice: No Rate Limiting)
app.post('/login-bad', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || !(await user.matchPassword(password))) {
            // Bad: ไม่มีการจำกัดจำนวนครั้งในการ Login Failed
            return res.status(401).send('Invalid credentials (bad practice)');
        }
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        res.redirect('/profile');
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error (bad practice)');
    }
});

// Login User (Best Practice: Rate Limiting)
app.post('/login-best', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || !(await user.matchPassword(password))) {
            return res.status(401).send('Invalid credentials (best practice)');
        }
        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        res.redirect('/profile');
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error (best practice)');
    }
});

// Logout
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login');
});

// --- A01:2021 – Broken Access Control ---

// User Profile Page (requires authentication)
app.get('/profile', protect, async (req, res) => {
    console.log(req.user)
    res.render('profile', { user: req.user });
});

// Get User by ID (Bad Practice: IDOR - Insecure Direct Object Reference)
app.get('/api/user-bad/:id', protect, async (req, res) => {
    // Bad: อนุญาตให้ผู้ใช้ดูข้อมูลโปรไฟล์ของ user ID ใดก็ได้โดยไม่มีการตรวจสอบสิทธิ์
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get User by ID (Best Practice: Proper Access Control)
app.get('/api/user-best/:id', protect, authorize('admin'), async (req, res) => {
    // Best: อนุญาตให้ดูข้อมูลโปรไฟล์ของ user ID อื่นได้เฉพาะ admin เท่านั้น
    // หรือถ้าเป็นผู้ใช้ทั่วไป ต้องเป็น ID ของตัวเองเท่านั้น
    if (req.user.role !== 'admin' && req.user._id.toString() !== req.params.id) {
        return res.status(403).json({ message: 'Access denied: You can only view your own profile.' });
    }
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Path Traversal (Bad Practice)
app.get('/download-bad', (req, res) => {
    const fileName = req.query.file; // ผู้ใช้ควบคุม filename ได้โดยตรง
    // Bad: ไม่มี Input Validation หรือ Path Normalization
    // ผู้โจมตีสามารถใช้ ../../etc/passwd เพื่อเข้าถึงไฟล์นอก directory ได้
    res.sendFile(path.join(__dirname, 'uploads', fileName));
});

// Path Traversal (Best Practice)
app.get('/download-best', (req, res) => {
    const fileName = req.query.file;
    if (!fileName) {
        return res.status(400).send('File name is required.');
    }

    const filePath = path.join(__dirname, 'uploads', fileName);
    // Best: ตรวจสอบว่าไฟล์ที่ร้องขออยู่ใน directory ที่อนุญาตเท่านั้น
    // path.resolve() ทำให้ได้ absolute path ที่ถูกต้อง
    // path.normalize() ลบ . และ .. ออก
    const normalizedPath = path.normalize(filePath);

    if (!normalizedPath.startsWith(path.join(__dirname, 'uploads'))) {
        return res.status(400).send('Invalid file path.');
    }

    res.sendFile(normalizedPath, (err) => {
        if (err) {
            console.error('Error sending file:', err);
            if (err.code === 'ENOENT') {
                return res.status(404).send('File not found.');
            }
            res.status(500).send('Error downloading file.');
        }
    });
});

// --- A03:2021 – Injection (SQL/NoSQL Injection) ---

// Search User (Bad Practice: NoSQL Injection Example for Mongoose)
app.get('/api/search-user-bad', async (req, res) => {
    const searchParam = req.query.username; // ผู้ใช้ส่ง {"$ne": null}
    // Bad: Mongoose/MongoDB Driver จะตีความ JSON string เป็น operator ได้
    // เช่น /api/search-user-bad?username={"$ne":null} จะดึงผู้ใช้ทั้งหมด
    try {
        const users = await User.find({ username: searchParam }).select('-password');
        res.json(users);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Search User (Best Practice: Input Sanitization for NoSQL)
app.get('/api/search-user-best', async (req, res) => {
    const searchParam = req.query.username;
    // Best: ตรวจสอบและ Sanitize input ก่อนนำไปใช้
    // สำหรับ NoSQL Injection, การใช้ `JSON.parse` หรือ `eval` กับ input โดยตรงเป็นสิ่งต้องห้าม
    // การใช้ Mongoose query builder โดยตรงจะช่วยป้องกันได้ส่วนใหญ่
    // แต่ถ้าต้องการป้องกัน "operator injection" ต้องตรวจสอบ input ก่อน
    if (typeof searchParam !== 'string') {
        return res.status(400).json({ message: 'Invalid search parameter.' });
    }
    try {
        // Mongoose โดยทั่วไปจะป้องกัน NoSQL injection ได้ดีอยู่แล้วเมื่อใช้ find()
        // แต่ถ้ามีการสร้าง query object จาก input โดยตรงต้องระมัดระวัง
        const users = await User.find({ username: new RegExp(`^${searchParam}`, 'i') }).select('-password'); // ใช้ RegExp เพื่อค้นหาแบบ case-insensitive
        res.json(users);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// --- A05:2021 – Security Misconfiguration ---

// Error Handling (Bad Practice: Verbose Error Messages)
app.get('/error-test-bad', (req, res, next) => {
    // Bad: จะแสดง stack trace เต็มรูปแบบเมื่อเกิดข้อผิดพลาด
    throw new Error('This is a test error for bad practice.');
});

// Error Handling (Best Practice: Custom Error Handler)
app.get('/error-test-best', (req, res, next) => {
    // Best: จะแสดงข้อความผิดพลาดทั่วไปและไม่เปิดเผยข้อมูลภายใน
    const err = new Error('This is a test error for best practice.');
    err.status = 500;
    next(err); // ส่ง error ไปยัง error handling middleware
});

// --- A08:2021 – Software and Data Integrity Failures ---

// File Upload (Bad Practice: No File Type/Size Validation)
const uploadBad = multer({ dest: 'uploads/' });
app.post('/upload-bad', uploadBad.single('file'), (req, res) => {
    // Bad: อนุญาตให้อัปโหลดไฟล์ประเภทใดก็ได้ ขนาดเท่าใดก็ได้
    // อาจนำไปสู่การอัปโหลด Shell หรือไฟล์ขนาดใหญ่เพื่อ DoS
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }
    res.send(`File uploaded (bad practice): ${req.file.originalname}`);
});

// File Upload (Best Practice: File Type/Size Validation)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const uploadBest = multer({
    storage: storage,
    limits: { fileSize: 1024 * 1024 * 5 }, // 5 MB limit
    fileFilter: (req, file, cb) => {
        // Best: ตรวจสอบ MIME type ของไฟล์
        if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png' || file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(new Error('Only JPEG, PNG, and PDF files are allowed!'), false);
        }
    }
});

app.post('/upload-best', uploadBest.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded or invalid file type/size.');
    }
    res.send(`File uploaded successfully (best practice): ${req.file.originalname}`);
});

// Insecure Deserialization (Bad Practice)
// สำหรับการสาธิตนี้ จะใช้ JSON.parse() ที่ปลอดภัย แต่ในสถานการณ์จริง
// ช่องโหว่นี้มักเกิดจากการใช้ไลบรารี deserialization ที่ไม่ปลอดภัย เช่น Node.js `vm` module
// หรือไลบรารีที่จัดการกับ serialized objects ที่ซับซ้อนโดยไม่มีการตรวจสอบ
app.post('/deserialize-bad', (req, res) => {
    const data = req.body.data; // สมมติว่ารับเป็น string ที่จะ eval
    try {
        // Bad: การใช้ eval() หรือไลบรารีที่ประมวลผลโค้ดจาก input โดยตรง
        // ใน ExpressJS โดยตรง การใช้ eval() เป็นสิ่งต้องห้าม
        // ตัวอย่างนี้จำลองแนวคิดของ deserialization ที่ไม่ปลอดภัย
        // หากผู้โจมตีส่งโค้ด JavaScript มาใน 'data' จะถูกรัน
        eval(data); // อันตรายมาก! DO NOT USE IN PRODUCTION!
        res.send('Deserialization attempted (bad practice). Check server console for effects.');
    } catch (e) {
        res.status(400).send('Error during deserialization (bad practice).');
    }
});

// Insecure Deserialization (Best Practice)
app.post('/deserialize-best', (req, res) => {
    const data = req.body.data;
    try {
        // Best: ใช้ JSON.parse() สำหรับข้อมูล JSON เท่านั้น
        // และไม่ควรประมวลผลโค้ดหรือ object ที่ซับซ้อนจาก input โดยตรง
        const parsedData = JSON.parse(data);
        res.json({ message: 'Data deserialized safely (best practice).', data: parsedData });
    } catch (e) {
        res.status(400).send('Invalid JSON data or safe deserialization failed.');
    }
});


// --- A10:2021 – Server-Side Request Forgery (SSRF) ---

// SSRF (Bad Practice)
app.get('/fetch-url-bad', async (req, res) => {
    const url = req.query.url; // ผู้ใช้ควบคุม URL ได้
    // Bad: ไม่มี Input Validation หรือ Whitelisting
    // ผู้โจมตีสามารถใช้ URL เช่น http://localhost/admin หรือ file:///etc/passwd
    // หรือ http://169.254.169.254/latest/meta-data/ (สำหรับ AWS EC2 metadata)
    try {
        const response = await axios.get(url);
        res.send(`Data from ${url}: <pre>${response.data}</pre>`);
    } catch (error) {
        console.error('SSRF Bad Practice Error:', error.message);
        res.status(500).send(`Error fetching URL (bad practice): ${error.message}`);
    }
});

// SSRF (Best Practice)
const ALLOWED_HOSTS = ['jsonplaceholder.typicode.com', 'example.com']; // Whitelist ของ hosts ที่อนุญาต
app.get('/fetch-url-best', async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) {
        return res.status(400).send('URL parameter is required.');
    }

    try {
        const parsedUrl = new URL(targetUrl); // ใช้ URL object เพื่อ parse URL
        // Best: ตรวจสอบ Hostname และ Protocol
        if (!ALLOWED_HOSTS.includes(parsedUrl.hostname)) {
            return res.status(400).send('Disallowed host.');
        }
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            return res.status(400).send('Disallowed protocol.');
        }
        // สามารถเพิ่มการตรวจสอบ Port หรือ Path ได้อีกถ้าจำเป็น

        const response = await axios.get(targetUrl);
        res.send(`Data from ${targetUrl}: <pre>${response.data}</pre>`);
    } catch (error) {
        console.error('SSRF Best Practice Error:', error.message);
        res.status(500).send(`Error fetching URL (best practice): ${error.message}`);
    }
});

// --- Other Critical Vulnerabilities ---

// XSS (Cross-Site Scripting) - Stored XSS
app.get('/comments', (req, res) => {
    // สมมติว่ามี comments เก็บอยู่ใน array (ใน production ควรเก็บใน DB)
    const comments = [
        { author: 'Alice', text: 'Hello, this is a normal comment.' },
        { author: 'Bob', text: '<script>alert("XSS Attack!");</script>' }, // Bad: Stored XSS payload
        { author: 'Charlie', text: 'Good day!' }
    ];
    res.render('comments', { comments });
});

// XSS (Cross-Site Scripting) - Reflected XSS
app.get('/search-xss', (req, res) => {
    const query = req.query.q || '';
    // Bad: แสดงผล input โดยไม่มีการ Escape HTML
    // ผู้โจมตีสามารถใช้ URL เช่น /search-xss?q=<script>alert('Reflected XSS!');</script>
    res.send(`<h1>Search Results for: ${query}</h1><p>No results found.</p>`);
});

// XSS (Best Practice: HTML Escaping / Sanitization)
app.get('/search-xss-best', (req, res) => {
    const query = req.query.q || '';
    // Best: ใช้ sanitize-html หรือ Template Engine ที่ Escape HTML อัตโนมัติ (EJS ทำให้อยู่แล้ว)
    // สำหรับการแสดงผลใน HTML โดยตรง EJS จะทำการ escape ให้โดยอัตโนมัติ
    // แต่ถ้าเป็นกรณีที่ต้องใส่ใน attribute หรือ JavaScript context ต้องระมัดระวังเป็นพิเศษ
    const sanitizedQuery = sanitizeHtml(query, {
        allowedTags: [], // ไม่อนุญาต tag ใดๆ
        allowedAttributes: {} // ไม่อนุญาต attribute ใดๆ
    });
    res.send(`<h1>Search Results for: ${sanitizedQuery}</h1><p>No results found.</p>`);
});


// CSRF (Cross-Site Request Forgery) - Bad Practice
app.get('/transfer-bad', (req, res) => {
    res.render('transfer', { csrfToken: '' }); // Bad: ไม่มี CSRF token
});

app.post('/transfer-money-bad', (req, res) => {
    const { amount, recipient } = req.body;
    // Bad: ไม่มี CSRF token ตรวจสอบ
    // ผู้โจมตีสามารถสร้างหน้าเว็บหลอกให้ผู้ใช้ส่ง request นี้ได้
    console.log(`Transferring ${amount} to ${recipient} (Bad Practice - No CSRF protection)`);
    res.send(`Transferred ${amount} to ${recipient} (Bad Practice - No CSRF protection).`);
});

// CSRF (Best Practice)
app.get('/transfer-best', (req, res) => {
    res.render('transfer', { csrfToken: req.csrfToken() }); // Best: มี CSRF token
});

app.post('/transfer-money-best', csrf(), (req, res) => {
    const { amount, recipient } = req.body;
    // Best: csurf middleware จะตรวจสอบ req.body._csrf token โดยอัตโนมัติ
    // หากไม่ถูกต้อง จะเกิด CSRF token mismatch error
    console.log(`Transferring ${amount} to ${recipient} (Best Practice - CSRF protected)`);
    res.send(`Transferred ${amount} to ${recipient} (Best Practice - CSRF protected).`);
});


// --- A04:2021 – Insecure Design ---
// Insecure Design เป็นเรื่องของการออกแบบระบบที่ไม่ปลอดภัยตั้งแต่แรก
// การสาธิตในโค้ดทำได้ยากโดยตรง แต่สามารถอธิบายได้ผ่านตัวอย่าง
// เช่น การไม่มี Role-Based Access Control (RBAC) ตั้งแต่แรก (ซึ่งถูกแก้ไขใน A01/A07 best practices)
// หรือการอนุญาตให้ API บางตัวเข้าถึงได้โดยไม่มีการตรวจสอบที่เพียงพอ
// ตัวอย่าง: API ที่ควรใช้ภายในเท่านั้นแต่เปิด public (covered by A01/A10 best practices)

// --- A06:2021 – Vulnerable and Outdated Components ---
// การสาธิตนี้จะทำได้โดยการใช้ dependencies ที่มีช่องโหว่ใน package.json
// และให้นักศึกษาลองรัน `npm audit`
// (ในตัวอย่างนี้ใช้ dependencies ที่อัปเดตแล้วเพื่อความปลอดภัย)

// --- Error Handling Middleware (Best Practice: Security Misconfiguration) ---
// ต้องอยู่ท้ายสุดของ middleware chain
app.use((err, req, res, next) => {
    console.error(err.stack); // บันทึก stack trace สำหรับการ debug ภายใน
    // A05:2021 – Security Misconfiguration (Best Practice: Custom Error Handling)
    // ไม่แสดง stack trace ให้ผู้ใช้เห็นใน production
    res.status(err.status || 500).send(process.env.NODE_ENV === 'development' ? err.stack : 'Something went wrong!');
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
    console.log(`Visit http://localhost:${PORT}`);
});