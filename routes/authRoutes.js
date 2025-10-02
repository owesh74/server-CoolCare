const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
// Nodemailer is only needed for the booking route, kept here for simplicity
const nodemailer = require('nodemailer'); 
const User = require('../models/User');

const router = express.Router();

// Middleware to protect routes with JWT (ONLY used for /me route)
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

// Helper function to generate JWT
const generateTokenAndRespond = (user, res) => {
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
            res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
        }
    );
};

// @route   GET /auth/me
// @desc    Get user data if token is valid (Kept for persistence check)
router.get('/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json({ user });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /auth/admin-pass-login
// @desc    Simplified Admin Login using only password
router.post('/admin-pass-login', async (req, res) => {
    const { password } = req.body;
    try {
        // Find the dedicated Admin user using the email from .env
        const adminUser = await User.findOne({ email: process.env.ADMIN_EMAIL, role: 'admin' });
        
        if (!adminUser) {
            return res.status(400).json({ msg: 'Admin account not set up.' });
        }

        // Compare the provided password hash with the stored hash
        const isMatch = await bcrypt.compare(password, adminUser.password);
        
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Password' });
        }

        // Login successful - generate token and send user info (including email)
        generateTokenAndRespond(adminUser, res);

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// REMOVED: All user signup, OTP, and password reset routes.

module.exports = router;