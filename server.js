const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();


// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
const PORT = process.env.PORT ;
const MONGO_URI = process.env.MONGO_URI 
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.log(err));

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Register Route
app.post('/api/auth/signup', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully!' });
    } catch (err) {
        res.status(400).json({ error: 'Registration failed!' });
    }
});

// Login Route
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: 'User not found!' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials!' });

        const token = jwt.sign({ id: user._id }, "afjsohfoannana", { expiresIn: '1h' });
        res.status(200).json({ message: 'Login successful!', token });
    } catch (err) {
        res.status(500).json({ error: 'Login failed!' });
    }
});

// Protected Route 
app.get('/api/protected', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Unauthorized!' });

    jwt.verify(token, "afjsohfoannana", (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Invalid token!' });

        res.status(200).json({ message: 'Protected route accessed!', userId: decoded.id });
    });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));