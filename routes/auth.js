const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator'); // For input validation
const rateLimit = require('express-rate-limit'); // For rate limiting
const nodemailer = require('nodemailer');
const User = require('../models/User');
const auth = require('../middleware/auth');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Rate limiting for login and password reset requests
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 15 minutes
    max: 5, // max 5 login attempts per IP per window
    message: 'Too many login attempts from this IP, please try again after 5 minutes.'
});

const forgotPasswordLimiter = rateLimit({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 3, // max 3 requests per IP per hour
    message: 'Too many password reset requests from this IP, please try again in 30 minutes.'
});

// --- Register route with strong validation ---
router.post(
    '/register',
    [
        body('username', 'Username is required').not().isEmpty(),
        body('email', 'Please include a valid email').isEmail(),
        body('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { username, email, password } = req.body;
        try {
            let user = await User.findOne({ email });
            if (user) {
                return res.status(400).json({ msg: 'User already exists' });
            }
            user = new User({ username, email, password });
            await user.save();
            const payload = { user: { id: user.id } };
            const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
            // Send token in an HttpOnly cookie
            res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
            res.status(201).json({ msg: 'User registered successfully' });
        } catch (err) {
            res.status(500).send('Server error');
        }
    }
);

// --- Login route with rate limiting ---
router.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'The email or password you entered is incorrect' });
        }
        const isMatch = await user.matchPassword(password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'The email or password you entered is incorrect' });
        }
        const payload = { user: { id: user.id } };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        res.json({ msg: 'Logged in successfully' });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// --- Forgot password with rate limiting and secure token generation ---
router.post('/forgot-password', forgotPasswordLimiter, async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ msg: 'No user with that email' });
        }
        const resetToken = crypto.randomBytes(32).toString('hex'); // Stronger token
        user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        user.resetPasswordExpire = Date.now() + 1800000; // 30 minutes
        await user.save();
        // **Send email with the reset link**
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,    // Your Gmail address
                pass: process.env.EMAIL_PASS     // Your Gmail App Password
            }
        });

        const resetUrl = `http://localhost:4000/api/auth/reset-password/${resetToken}`;
        
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Password Reset Request',
            html: `
                <h3>Password Reset Request</h3>
                <p>Hello,</p>
                <p>You have requested to reset your password. Click the link below to proceed:</p>
                <a href="${resetUrl}">${resetUrl}</a>
                <p>This link will expire in 30 minutes.</p>
                <p>If you did not request this, please ignore this email.</p>
            `
        };

        await transporter.sendMail(mailOptions);
        
        res.json({ msg: 'Password reset link sent to your email' });
        
    } catch (err) {
        console.error('Email sending error:', err);
        res.status(500).send('Server error');
    }
});

// --- Logout route with server-side token blacklisting ---
router.post('/logout', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (user) {
            user.tokenBlacklist.push(req.token);
            await user.save();
        }
        res.clearCookie('token');
        res.json({ msg: 'Logged out successfully' });
    } catch (err) {
        res.status(500).send('Server error');
    }
});


module.exports = router;