require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mailgun = require('mailgun-js');
const twilio = require('twilio');

const app = express();

app.use(bodyParser.json());
app.use(cors());

// MongoDB connection using environment variable
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

// Twilio setup using environment variables
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Mailgun setup using environment variables
const mg = mailgun({ apiKey: process.env.MAILGUN_API_KEY, domain: process.env.MAILGUN_DOMAIN });

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    resetToken: String,
    resetTokenExpiry: Date,
});

const issueSchema = new mongoose.Schema({
    issue: { type: String, required: true },
    category: { type: String, required: true },
    assignee: { type: String, required: true },
    complainant: {
        phoneNumber: { type: String, required: true },
        email: { type: String, required: true },
    },
    status: { type: String, default: 'Pending' },
});

const User = mongoose.model('User', userSchema);
const Issue = mongoose.model('Issue', issueSchema);

const generateToken = (user) => {
    return jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization').replace('Bearer ', '');
    if (!token) {
        return res.status(401).send({ error: 'Unauthorized access' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).send({ error: 'Unauthorized access' });
    }
};

const sendNotification = async (trackingNumber, complainant) => {
    const message = `Your issue has been logged. Your tracking number is ${trackingNumber}.`;

    // Send SMS
    try {
        await twilioClient.messages.create({
            body: message,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: complainant.phoneNumber,
        });
        console.log('SMS sent successfully');
    } catch (error) {
        console.error('Error sending SMS:', error);
    }

    // Send Email
    try {
        const emailData = {
            from: 'noreply@yourdomain.com', // Replace with your Mailgun verified domain
            to: complainant.email,
            subject: 'Issue Logged - Tracking Number',
            text: message,
        };
        await mg.messages().send(emailData);
        console.log('Email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
    }
};

app.post('/api/users/register', async (req, res) => {
    const { username, password, email } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 8);
        const user = new User({ username, password: hashedPassword, email });
        await user.save();
        res.status(201).send({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).send({ message: 'Error registering user', error: err });
    }
});

app.post('/api/users/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).send({ error: 'Invalid username or password' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send({ error: 'Invalid username or password' });
        }
        const token = generateToken(user);
        res.send({ token });
    } catch (err) {
        res.status(500).send({ message: 'Error logging in', error: err });
    }
});

app.post('/api/users/reset-password', async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send({ error: 'Email not found' });
        }

        const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        user.resetToken = resetToken;
        user.resetTokenExpiry = Date.now() + 3600000; // 1 hour
        await user.save();

        const emailData = {
            from: 'noreply@yourdomain.com', // Replace with your Mailgun verified domain
            to: user.email,
            subject: 'Password Reset',
            text: `Please use the following link to reset your password: http://localhost:3000/update-password/${resetToken}`,
        };
        await mg.messages().send(emailData);

        res.status(200).send({ message: 'Password reset email sent' });
    } catch (err) {
        res.status(500).send({ message: 'Error sending password reset email', error: err });
    }
});

app.post('/api/users/update-password', async (req, res) => {
    const { token, newPassword } = req.body;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findOne({ _id: decoded.id, resetToken: token, resetTokenExpiry: { $gt: Date.now() } });

        if (!user) {
            return res.status(400).send({ error: 'Invalid or expired token' });
        }

        user.password = await bcrypt.hash(newPassword, 8);
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        await user.save();

        res.status(200).send({ message: 'Password updated successfully' });
    } catch (err) {
        res.status(500).send({ message: 'Error updating password', error: err });
    }
});

app.post('/api/issues', authMiddleware, async (req, res) => {
    const { issue, category, assignee, complainant } = req.body;
    try {
        const newIssue = new Issue({ issue, category, assignee, complainant });
        const savedIssue = await newIssue.save();

        const trackingNumber = savedIssue._id;

        await sendNotification(trackingNumber, complainant);

        res.status(200).send({ message: 'Issue logged successfully', trackingNumber });
    } catch (err) {
        console.error('Error logging issue:', err);
        res.status(500).send({ message: 'Error logging issue', error: err });
    }
});

app.get('/api/issues', authMiddleware, async (req, res) => {
    try {
        const issues = await Issue.find();
        console.log('Fetched Issues:', issues);
        res.status(200).json(issues);
    } catch (err) {
        console.error('Error fetching issues:', err);
        res.status(500).send({ message: 'Error fetching issues', error: err });
    }
});

app.get('/api/issues/stats', authMiddleware, async (req, res) => {
    try {
        const totalIssues = await Issue.countDocuments();
        const resolvedIssues = await Issue.countDocuments({ status: 'Resolved' });
        const pendingIssues = totalIssues - resolvedIssues;

        res.status(200).send({ totalIssues, resolvedIssues, pendingIssues });
    } catch (err) {
        console.error('Error fetching stats:', err);
        res.status(500).send({ message: 'Error fetching stats', error: err });
    }
});

app.put('/api/issues/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { issue, category, assignee, status } = req.body;
    try {
        await Issue.findByIdAndUpdate(id, { issue, category, assignee, status });
        res.status(200).send({ message: 'Issue updated successfully' });
    } catch (err) {
        console.error('Error updating issue:', err);
        res.status(500).send({ message: 'Error updating issue', error: err });
    }
});

app.delete('/api/issues/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    try {
        await Issue.findByIdAndDelete(id);
        res.status(200).send({ message: 'Issue deleted successfully' });
    } catch (err) {
        console.error('Error deleting issue:', err);
        res.status(500).send({ message: 'Error deleting issue', error: err });
    }
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
