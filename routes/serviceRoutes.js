const express = require('express');
const Service = require('../models/Service');

const router = express.Router();

// @route   GET /api/services
// @desc    Get all available services
router.get('/', async (req, res) => {
    try {
        const services = await Service.find();
        res.json(services);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

module.exports = router;
