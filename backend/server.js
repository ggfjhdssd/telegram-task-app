require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

// CORS - Frontend URL ကိုပဲ ခွင့်ပြုမယ်
app.use(cors({
    origin: process.env.FRONTEND_URL || '*',
    credentials: true
}));
app.use(express.json());

// ==================== MongoDB Schema ====================
const userSchema = new mongoose.Schema({
    userId: { type: Number, required: true, unique: true },
    username: String,
    coins: { type: Number, default: 1250 },
    dailyLastClaim: { type: Number, default: 0 },
    tasks: { type: Map, of: Number, default: {} }
});

const User = mongoose.model('User', userSchema);

// ==================== Telegram Validation ====================
const BOT_TOKEN = process.env.BOT_TOKEN;

function validateTelegramData(initData) {
    if (!initData || !BOT_TOKEN) return null;

    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    params.delete('hash');

    const dataCheckString = Array.from(params.entries())
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => `${key}=${value}`)
        .join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

    return calculatedHash === hash ? Object.fromEntries(params) : null;
}

// ==================== Auth Middleware ====================
async function authMiddleware(req, res, next) {
    const initData = req.headers['x-telegram-init-data'];
    if (!initData) {
        return res.status(401).json({ error: 'Missing init data' });
    }

    const userData = validateTelegramData(initData);
    if (!userData || !userData.user) {
        return res.status(403).json({ error: 'Invalid init data' });
    }

    const tgUser = JSON.parse(userData.user);
    req.tgUser = tgUser;
    next();
}

// ==================== Helper Functions ====================
async function getUser(userId, username) {
    let user = await User.findOne({ userId });
    if (!user) {
        user = new User({ userId, username: username || '' });
        await user.save();
    }
    return user;
}

// ==================== Routes ====================
app.get('/health', (req, res) => res.send('OK'));

app.get('/api/user', authMiddleware, async (req, res) => {
    try {
        const user = await getUser(req.tgUser.id, req.tgUser.username);
        res.json({
            userId: user.userId,
            username: user.username,
            coins: user.coins,
            dailyLastClaim: user.dailyLastClaim,
            tasks: Object.fromEntries(user.tasks)
        });
    } catch (err) {
        console.error('❌ /api/user error:', err.message);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/claim/daily', authMiddleware, async (req, res) => {
    try {
        const user = await getUser(req.tgUser.id, req.tgUser.username);
        const now = Date.now();
        const cooldown = 24 * 60 * 60 * 1000;

        if (now - user.dailyLastClaim < cooldown) {
            return res.status(400).json({ 
                error: 'Not ready', 
                remaining: cooldown - (now - user.dailyLastClaim) 
            });
        }

        user.coins += 15;
        user.dailyLastClaim = now;
        await user.save();

        res.json({ coins: user.coins, dailyLastClaim: user.dailyLastClaim });
    } catch (err) {
        console.error('❌ /api/claim/daily error:', err.message);
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/claim/task/:taskId', authMiddleware, async (req, res) => {
    try {
        const { taskId } = req.params;
        const user = await getUser(req.tgUser.id, req.tgUser.username);
        const now = Date.now();
        const cooldown = 2 * 60 * 60 * 1000;

        const lastClaim = user.tasks.get(taskId) || 0;
        if (now - lastClaim < cooldown) {
            return res.status(400).json({ 
                error: 'Not ready', 
                remaining: cooldown - (now - lastClaim) 
            });
        }

        user.coins += 30;
        user.tasks.set(taskId, now);
        await user.save();

        res.json({ coins: user.coins, tasks: Object.fromEntries(user.tasks) });
    } catch (err) {
        console.error('❌ /api/claim/task error:', err.message);
        res.status(500).json({ error: 'Database error' });
    }
});

// ==================== Start Server ====================
const PORT = process.env.PORT || 5000;

if (!process.env.MONGODB_URI) {
    console.error('❌ MONGODB_URI is not defined in environment variables');
    process.exit(1);
}

mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('✅ MongoDB connected successfully');
        app.listen(PORT, () => {
            console.log(`🚀 Server running on port ${PORT}`);
        });
    })
    .catch(err => {
        console.error('❌ MongoDB connection error:', err.message);
        process.exit(1);
    });
