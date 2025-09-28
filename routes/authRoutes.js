const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../models/User');

const router = express.Router();

// Middleware for token validation (needed for /me and other protected routes)
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
            res.json({ token, user: { name: user.name, email: user.email, role: user.role } });
        }
    );
};

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
// @desc    Register a new user and send IMPROVED OTP message
router.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        user = new User({ name, email, password: hashedPassword });
        await user.save();

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore[email] = { otp, timestamp: Date.now(), purpose: 'signup' };

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'CoolCare: Account Verification OTP',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                    <h2 style="color: #1e40af;">Welcome to CoolCare, ${name}!</h2>
                    <p>Thank you for signing up. Please use the verification code below to activate your account:</p>
                    <h1 style="color: #10b981; font-size: 32px; text-align: center; margin: 20px 0; border: 2px dashed #10b981; padding: 10px;">${otp}</h1>
                    <p>This code is valid for 5 minutes.</p>
                    <p>If you did not request this, please ignore this email.</p>
                </div>
            `,
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
// @desc    Verify signup OTP and automatically log user in
router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const storedOtp = otpStore[email];
        // Ensure OTP is for signup and is valid
        if (!storedOtp || storedOtp.otp !== otp || storedOtp.purpose !== 'signup' || (Date.now() - storedOtp.timestamp) > 300000) {
            return res.status(400).json({ msg: 'Invalid or expired OTP' });
        }

        const user = await User.findOneAndUpdate({ email }, { verified: true }, { new: true });
        delete otpStore[email];

        if (user) {
            generateTokenAndRespond(user, res);
        } else {
             return res.status(404).json({ msg: 'User not found.' });
        }

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

        generateTokenAndRespond(user, res);

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


// --- NEW OTP RESET ROUTES ---

// @route   POST /auth/send-reset-otp
// @desc    Send OTP for password reset
router.post('/send-reset-otp', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ msg: 'User with that email does not exist.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        // Store purpose as 'reset'
        otpStore[email] = { otp, timestamp: Date.now(), purpose: 'reset' };

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'CoolCare: Password Reset Verification Code',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                    <h2 style="color: #ef4444;">Password Reset Request</h2>
                    <p>We received a request to reset your password. Use the code below:</p>
                    <h1 style="color: #f97316; font-size: 32px; text-align: center; margin: 20px 0; border: 2px dashed #f97316; padding: 10px;">${otp}</h1>
                    <p>This code is valid for 5 minutes. Do not share this code with anyone.</p>
                </div>
            `,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending reset OTP email:', error);
                return res.status(500).json({ msg: 'Error sending reset OTP email.' });
            }
            res.status(200).json({ msg: 'Password reset OTP sent to your email.' });
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /auth/verify-reset-otp
// @desc    Verify password reset OTP
router.post('/verify-reset-otp', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const storedOtp = otpStore[email];

        if (!storedOtp || storedOtp.otp !== otp || storedOtp.purpose !== 'reset' || (Date.now() - storedOtp.timestamp) > 300000) {
            return res.status(400).json({ msg: 'Invalid or expired OTP.' });
        }

        // OTP is valid. Frontend can now proceed to update password.
        // We do NOT delete the OTP here; we keep it for the final password update step for security.
        res.status(200).json({ msg: 'OTP verified successfully. You can now set a new password.' });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /auth/update-password
// @desc    Update password after successful OTP verification
router.post('/update-password', async (req, res) => {
    const { email, password } = req.body;

    // Check if a valid reset OTP exists in the store
    const storedOtp = otpStore[email];
    if (!storedOtp || storedOtp.purpose !== 'reset' || (Date.now() - storedOtp.timestamp) > 300000) {
        return res.status(400).json({ msg: 'Verification session expired. Please restart the process.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.findOneAndUpdate(
            { email },
            { password: hashedPassword },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ msg: 'User not found.' });
        }
        
        // Clear the OTP store after successful password update
        delete otpStore[email];
        
        res.status(200).json({ msg: 'Password has been successfully updated.' });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


module.exports = router;