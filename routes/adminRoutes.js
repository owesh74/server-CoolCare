const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Service = require('../models/Service');
const Booking = require('../models/Booking');

const router = express.Router();

// Middleware to protect admin routes
const adminAuth = async (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.user.id);
        if (user && user.role === 'admin') {
            req.user = user;
            next();
        } else {
            res.status(403).json({ msg: 'Access denied: not an admin' });
        }
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// @route   GET /api/admin/bookings
// @desc    Admin fetches all bookings
router.get('/bookings', adminAuth, async (req, res) => {
    try {
        const bookings = await Booking.find()
            .populate('userId', ['name', 'email'])
            .populate('serviceId', ['name', 'price']);
        res.json(bookings);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   PUT /api/admin/bookings/:id/status
// @desc    Admin updates booking status
router.put('/bookings/:id/status', adminAuth, async (req, res) => {
    const { status } = req.body;
    try {
        const booking = await Booking.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true }
        );
        if (!booking) {
            return res.status(404).json({ msg: 'Booking not found' });
        }
        res.json(booking);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   DELETE /api/admin/bookings/:id
// @desc    Admin deletes a booking
router.delete('/bookings/:id', adminAuth, async (req, res) => {
    try {
        const booking = await Booking.findByIdAndDelete(req.params.id);
        if (!booking) {
            return res.status(404).json({ msg: 'Booking not found' });
        }
        res.json({ msg: 'Booking removed successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   GET /api/admin/services
// @desc    Admin gets all services
router.get('/services', adminAuth, async (req, res) => {
    try {
        const services = await Service.find();
        res.json(services);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   POST /api/admin/services
// @desc    Admin creates a new service
router.post('/services', adminAuth, async (req, res) => {
    const { name, description, price, duration } = req.body;
    try {
        const newService = new Service({ name, description, price, duration });
        await newService.save();
        res.json(newService);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   PUT /api/admin/services/:id
// @desc    Admin updates a service
router.put('/services/:id', adminAuth, async (req, res) => {
    const { name, description, price, duration } = req.body;
    try {
        const service = await Service.findByIdAndUpdate(
            req.params.id,
            { name, description, price, duration },
            { new: true }
        );
        res.json(service);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// @route   DELETE /api/admin/services/:id
// @desc    Admin deletes a service
router.delete('/services/:id', adminAuth, async (req, res) => {
    try {
        await Service.findByIdAndDelete(req.params.id);
        res.json({ msg: 'Service removed' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

module.exports = router;