const express = require('express');
const Booking = require('../models/Booking');
const User = require('../models/User');
const Service = require('../models/Service');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

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

// Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// @route   POST /api/bookings
// @desc    Create a new booking and send email notification
router.post('/', auth, async (req, res) => {
    const { serviceId, date, time, address, contactNumber } = req.body;
    try {
        const newBooking = new Booking({
            userId: req.user.id,
            serviceId,
            date,
            time,
            address,
            contactNumber,
        });
        const booking = await newBooking.save();

        // Fetch user and service details for email notification
        const user = await User.findById(req.user.id);
        const service = await Service.findById(serviceId);

        if (user && service) {
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: process.env.ADMIN_EMAIL,
                subject: 'New CoolCare Service Booking!',
                html: `
                    <h2>New Booking Details</h2>
                    <p><strong>Service:</strong> ${service.name}</p>
                    <p><strong>Date:</strong> ${new Date(date).toLocaleDateString()}</p>
                    <p><strong>Time:</strong> ${time}</p>
                    <p><strong>Address:</strong> ${address}</p>
                    <p><strong>User Name:</strong> ${user.name}</p>
                    <p><strong>User Email:</strong> ${user.email}</p>
                    <p><strong>Contact Number:</strong> ${contactNumber}</p>
                `,
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Error sending booking email:', error);
                } else {
                    console.log('Booking email sent:', info.response);
                }
            });
        }

        res.json(booking);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   GET /api/bookings/my
// @desc    Get all bookings for the logged-in user
router.get('/my', auth, async (req, res) => {
    try {
        const bookings = await Booking.find({ userId: req.user.id }).populate('serviceId', ['name', 'price']);
        res.json(bookings);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   GET /api/bookings/available-slots
// @desc    Check for booked slots on a specific date and service
router.get('/available-slots', async (req, res) => {
    const { serviceId, date } = req.query;
    if (!serviceId || !date) {
        return res.status(400).json({ msg: 'Service ID and date are required.' });
    }

    try {
        const bookings = await Booking.find({ serviceId, date }).select('time');
        const bookedTimes = bookings.map(booking => booking.time);
        res.json({ bookedTimes });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

module.exports = router;