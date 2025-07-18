const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Middleware สำหรับตรวจสอบ JWT Token (Best Practice: Identification and Authentication Failures)
exports.protect = async (req, res, next) => {
    let token;
    // 1. Check for token in Authorization header (for API calls)
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }
    // 2. Check for token in cookies (for web routes after login)
    if (!token && req.cookies && req.cookies.token) {
        token = req.cookies.token;
    }

    if (!token) {
        // หากไม่มี token ให้แสดงหน้า login หรือข้อความ Unauthorized
        if (req.originalUrl.startsWith('/api')) {
            return res.status(401).json({ message: 'Not authorized, no token' });
        }
        return res.redirect('/login');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = await User.findById(decoded.id).select('-password');
        if (!req.user) {
            // หากไม่พบผู้ใช้ (อาจถูกลบไปแล้ว)
            if (req.originalUrl.startsWith('/api')) {
                return res.status(401).json({ message: 'Not authorized, user not found' });
            }
            return res.redirect('/login');
        }
        next();
    } catch (error) {
        console.error('Token verification failed:', error.message);
        // หาก token ไม่ถูกต้องหรือไม่หมดอายุ
        if (req.originalUrl.startsWith('/api')) {
            return res.status(401).json({ message: 'Not authorized, token failed' });
        }
        return res.redirect('/login');
    }
};

// Middleware สำหรับตรวจสอบบทบาท (Best Practice: Broken Access Control)
exports.authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            // หากผู้ใช้ไม่มีบทบาทที่ได้รับอนุญาต
            if (req.originalUrl.startsWith('/api')) {
                return res.status(403).json({ message: `User role ${req.user ? req.user.role : 'unknown'} is not authorized to access this route` });
            }
            return res.status(403).render('error', { message: 'Access Denied: You do not have permission to view this page.' });
        }
        next();
    };
};