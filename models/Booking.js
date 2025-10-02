const mongoose = require('mongoose');

const BookingSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    serviceId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Service',
        required: true,
    },
    customerName: { // NEW FIELD ADDED
        type: String,
        required: true,
    },
    date: {
        type: String, // YYYY-MM-DD
        required: true,
    },
    time: {
        type: String, // HH:MM
        required: true,
    },
    address: {
        type: String,
        required: true,
    },
    contactNumber: {
        type: String,
        required: true,
    },
    status: {
        type: String,
        enum: ['Pending', 'Assigned', 'Completed'],
        default: 'Pending',
    },
}, { timestamps: true });

module.exports = mongoose.model('Booking', BookingSchema);