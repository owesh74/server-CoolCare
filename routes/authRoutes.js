const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../models/User');

const router = express.Router();

// Middleware to protect routes with JWT
const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// Temporary OTP store
const otpStore = {};

// Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// @route   GET /auth/me
// @desc    Get user data if token is valid
router.get('/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json({ user });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /auth/signup
// @desc    Register a new user and send OTP
router.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        user = new User({
            name,
            email,
            password: hashedPassword,
        });
        await user.save();

        // Generate OTP and store it
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore[email] = { otp, timestamp: Date.now() };

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'CoolCare: OTP Verification',
            text: `Your OTP for CoolCare registration is: ${otp}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
                return res.status(500).json({ msg: 'Error sending OTP' });
            }
            res.status(200).json({ msg: 'OTP sent to your email. Please verify to complete signup.' });
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /auth/verify-otp
// @desc    Verify OTP and mark user as verified
router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const storedOtp = otpStore[email];
        if (!storedOtp || storedOtp.otp !== otp || (Date.now() - storedOtp.timestamp) > 300000) { // 5 mins validity
            return res.status(400).json({ msg: 'Invalid or expired OTP' });
        }

        await User.findOneAndUpdate({ email }, { verified: true });
        delete otpStore[email]; // Remove OTP from store
        res.json({ msg: 'Account verified successfully. You can now login.' });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /auth/login
// @desc    Login a user and return JWT
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        if (!user.verified) {
            return res.status(400).json({ msg: 'Please verify your account before logging in.' });
        }

        const payload = {
            user: {
                id: user.id,
                role: user.role
            },
        };

        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '1h' },
            (err, token) => {
                if (err) throw err;
                res.json({ token, user: { name: user.name, email: user.email, role: user.role } });
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

module.exports = router;