const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcryptjs');

// Load environment variables
dotenv.config();

// Import models
const User = require('./models/User');
const Service = require('./models/Service');
const Booking = require('./models/Booking');

// Import routes
const authRoutes = require('./routes/authRoutes');
const serviceRoutes = require('./routes/serviceRoutes');
const bookingRoutes = require('./routes/bookingRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json()); // For parsing application/json

// Database connection
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('MongoDB connected successfully.');
        await seedDatabase();
    } catch (err) {
        console.error('MongoDB connection error:', err.message);
        process.exit(1);
    }
};

// Seed initial data
const seedDatabase = async () => {
    try {
        const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASS, 10);
        // Admin user is always created/updated as verified and admin role
        await User.findOneAndUpdate(
            { email: process.env.ADMIN_EMAIL },
            { $set: { password: hashedPassword, role: 'admin', name: 'Admin User' } },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );
        console.log('Admin user seeded/updated successfully.');

        // Seed sample services
        const servicesCount = await Service.countDocuments();
        if (servicesCount === 0) {
            const services = [
                { name: 'AC Installation', description: 'Professional installation of new AC units.', price: 1500, duration: 180 },
                { name: 'AC Gas Filling', description: 'Recharging refrigerant gas for optimal cooling.', price: 800, duration: 90 },
                { name: 'AC Repair', description: 'Diagnosis and repair for all types of AC issues.', price: 1000, duration: 120 },
                { name: 'AC Servicing', description: 'Comprehensive cleaning and maintenance.', price: 500, duration: 60 }
            ];
            await Service.insertMany(services);
            console.log('Sample services seeded.');
        }

    } catch (err) {
        console.error('Database seeding error:', err.message);
    }
};

// Use routes
app.use('/auth', authRoutes);
app.use('/services', serviceRoutes);
app.use('/bookings', bookingRoutes);
app.use('/admin', adminRoutes);

app.get('/', (req, res) => {
    res.send('CoolCare Backend API is running.');
});

// Start server after DB connection
connectDB().then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});