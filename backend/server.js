// ============================================
// server.js - PayCoinAds Telegram WebApp Backend
// Environment variables required (set in Render):
//   BOT_TOKEN, ADMIN_ID, GROUP_ID, FRONTEND_URL,
//   MONGODB_URI, MIN_WITHDRAWAL, PORT (optional)
// ============================================

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
const TelegramBot = require('node-telegram-bot-api');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// ==================== Security & Middlewares ====================
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json({ limit: '10kb' }));

// Global rate limiter for API
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 150,
    message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', apiLimiter);

// Stricter limiter for claim endpoints
const claimLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 10,
    message: { error: 'Too many clicks. Please slow down.' }
});

// ==================== MongoDB Models ====================
const configSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    value: mongoose.Schema.Types.Mixed
});
const Config = mongoose.model('Config', configSchema);

const userSchema = new mongoose.Schema({
    userId: { type: Number, required: true, unique: true },
    username: String,
    photoUrl: { type: String, default: null },
    coins: { type: Number, default: 0 },
    dailyLastClaim: { type: Number, default: 0 },
    tasks: { type: Map, of: Number, default: {} },
    referredBy: { type: Number, default: null },
    referralCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    banned: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

const withdrawalSchema = new mongoose.Schema({
    userId: { type: Number, required: true },
    amount: { type: Number, required: true },
    method: { type: String, enum: ['kpay', 'wavepay', 'binance'], required: true },
    accountDetails: { type: String, required: true },
    status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 30 } // 30 days TTL
});
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// ==================== Default Configuration ====================
const DEFAULT_CONFIG = {
    REFERRAL_REWARD: 10,
    DAILY_REWARD: 15,
    TASK_REWARD: 30,
    MIN_WITHDRAWAL: parseInt(process.env.MIN_WITHDRAWAL) || 1000,
    TASK_COOLDOWN: 2 * 60 * 60 * 1000,      // 2 hours
    DAILY_COOLDOWN: 24 * 60 * 60 * 1000     // 24 hours
};

async function getConfig(key) {
    let cfg = await Config.findOne({ key });
    if (!cfg) {
        cfg = new Config({ key, value: DEFAULT_CONFIG[key] });
        await cfg.save();
    }
    return cfg.value;
}

async function setConfig(key, value) {
    await Config.updateOne({ key }, { value }, { upsert: true });
}

// Initialize config from environment variables (first run only)
async function initConfigFromEnv() {
    const envOverrides = {
        MIN_WITHDRAWAL: process.env.MIN_WITHDRAWAL,
    };
    for (const [key, envValue] of Object.entries(envOverrides)) {
        if (envValue !== undefined && DEFAULT_CONFIG.hasOwnProperty(key)) {
            const existing = await Config.findOne({ key });
            if (!existing) {
                const numValue = isNaN(envValue) ? envValue : parseInt(envValue);
                await setConfig(key, numValue);
                console.log(`✅ Initialized ${key} = ${numValue} from environment`);
            }
        }
    }
}

// ==================== Telegram Bot Setup ====================
const bot = new TelegramBot(process.env.BOT_TOKEN);
const ADMIN_ID = parseInt(process.env.ADMIN_ID);
const GROUP_ID = parseInt(process.env.GROUP_ID);

// Webhook URL: use env or construct from RENDER_EXTERNAL_URL (if on Render)
const WEBHOOK_URL = process.env.WEBHOOK_URL || (process.env.RENDER_EXTERNAL_URL ? `${process.env.RENDER_EXTERNAL_URL}/webhook` : null);
if (!WEBHOOK_URL) {
    console.error('❌ WEBHOOK_URL is not defined and could not be constructed from RENDER_EXTERNAL_URL. Set it manually (e.g., https://your-app.onrender.com/webhook).');
    process.exit(1);
}
bot.setWebHook(WEBHOOK_URL);

// Webhook endpoint for Telegram
app.post('/webhook', express.json(), (req, res) => {
    bot.processUpdate(req.body);
    res.sendStatus(200);
});

// ==================== Helper Functions ====================
function validateTelegramData(initData) {
    const BOT_TOKEN = process.env.BOT_TOKEN;
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

async function authMiddleware(req, res, next) {
    const initData = req.headers['x-telegram-init-data'];
    if (!initData) return res.status(401).json({ error: 'Missing init data' });
    const userData = validateTelegramData(initData);
    if (!userData || !userData.user) return res.status(403).json({ error: 'Invalid init data' });
    const tgUser = JSON.parse(userData.user);
    req.tgUser = tgUser;
    next();
}

async function getUser(userId, username) {
    let user = await User.findOne({ userId });
    if (!user) {
        user = new User({ userId, username: username || '' });
        await user.save();
    } else if (username && user.username !== username) {
        user.username = username;
        await user.save();
    }
    return user;
}

// ==================== Bot Commands ====================
function isAdmin(msg) {
    return msg.from.id === ADMIN_ID;
}

bot.onText(/\/start(?:\s+(.+))?/, async (msg, match) => {
    const chatId = msg.chat.id;
    const userId = msg.from.id;
    const username = msg.from.username || msg.from.first_name || 'User';
    const referralCode = match[1];

    let user = await User.findOne({ userId });
    if (!user) {
        user = new User({ userId, username });
        if (referralCode && !isNaN(referralCode) && parseInt(referralCode) !== userId) {
            const referrer = await User.findOne({ userId: parseInt(referralCode) });
            if (referrer && !referrer.banned) {
                user.referredBy = parseInt(referralCode);
                const reward = await getConfig('REFERRAL_REWARD');
                referrer.coins += reward;
                referrer.referralCount += 1;
                await referrer.save();
                await bot.sendMessage(referrer.userId, `🎉 မိတ်ဆွေအသစ် ဖိတ်ခေါ်မှုအတွက် ${reward} ဒင်္ဂါး ရရှိပါသည်။`);
            }
        }
        await user.save();
    }

    const webAppUrl = process.env.FRONTEND_URL;
    const welcomeMsg = `မင်္ဂလာပါ ${username}၊ PayCoinAds မှ ကြိုဆိုပါတယ်။ 🎉\n\nဂိမ်းဆော့ပြီး ပိုက်ဆံရှာရန် အောက်က Play Game ကိုနှိပ်ပါ။ 👇`;

    await bot.sendMessage(chatId, welcomeMsg, {
        reply_markup: {
            inline_keyboard: [[{ text: '🎮 Play Game', web_app: { url: webAppUrl } }]]
        }
    });
});

// Admin commands
bot.onText(/\/ban (\d+)/, async (msg, match) => {
    if (!isAdmin(msg)) return;
    const targetId = parseInt(match[1]);
    await User.updateOne({ userId: targetId }, { banned: true });
    bot.sendMessage(msg.chat.id, `User ${targetId} ကို Ban လိုက်ပါပြီ။`);
});

bot.onText(/\/unban (\d+)/, async (msg, match) => {
    if (!isAdmin(msg)) return;
    const targetId = parseInt(match[1]);
    await User.updateOne({ userId: targetId }, { banned: false });
    bot.sendMessage(msg.chat.id, `User ${targetId} ကို Unban လိုက်ပါပြီ။`);
});

bot.onText(/\/addcoin (\d+) (\d+)/, async (msg, match) => {
    if (!isAdmin(msg)) return;
    const targetId = parseInt(match[1]);
    const amount = parseInt(match[2]);
    await User.updateOne({ userId: targetId }, { $inc: { coins: amount } });
    bot.sendMessage(msg.chat.id, `User ${targetId} ကို ${amount} ဒင်္ဂါး ပေါင်းထည့်ပြီးပါပြီ။`);
});

bot.onText(/\/subcoin (\d+) (\d+)/, async (msg, match) => {
    if (!isAdmin(msg)) return;
    const targetId = parseInt(match[1]);
    const amount = parseInt(match[2]);
    await User.updateOne({ userId: targetId }, { $inc: { coins: -amount } });
    bot.sendMessage(msg.chat.id, `User ${targetId} ကို ${amount} ဒင်္ဂါး နုတ်ပြီးပါပြီ။`);
});

bot.onText(/\/userinfo (\d+)/, async (msg, match) => {
    if (!isAdmin(msg)) return;
    const targetId = parseInt(match[1]);
    const user = await User.findOne({ userId: targetId });
    if (!user) return bot.sendMessage(msg.chat.id, 'User not found');
    bot.sendMessage(msg.chat.id,
        `👤 User: ${user.username || 'No username'}\n` +
        `🆔 ID: ${user.userId}\n` +
        `🪙 Coins: ${user.coins}\n` +
        `👥 Referrals: ${user.referralCount}\n` +
        `📅 Joined: ${user.createdAt.toLocaleDateString()}\n` +
        `🚫 Banned: ${user.banned ? 'Yes' : 'No'}`
    );
});

bot.onText(/\/list (\d+)/, async (msg, match) => {
    if (!isAdmin(msg)) return;
    const page = parseInt(match[1]) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;
    const users = await User.find().skip(skip).limit(limit);
    let response = `📋 User list (page ${page}):\n`;
    users.forEach(u => {
        response += `${u.userId} - @${u.username || 'no username'} - ${u.coins} coins - ref: ${u.referralCount}\n`;
    });
    bot.sendMessage(msg.chat.id, response);
});

bot.onText(/\/set (\w+) (\w+)/, async (msg, match) => {
    if (!isAdmin(msg)) return;
    const key = match[1];
    let value = match[2];
    if (!isNaN(value)) value = parseInt(value);
    if (DEFAULT_CONFIG.hasOwnProperty(key)) {
        await setConfig(key, value);
        bot.sendMessage(msg.chat.id, `✅ ${key} ကို ${value} သို့ ပြောင်းလဲပြီးပါပြီ။`);
    } else {
        bot.sendMessage(msg.chat.id, `❌ မသိသော key: ${key}`);
    }
});

bot.onText(/\/get (\w+)/, async (msg, match) => {
    if (!isAdmin(msg)) return;
    const key = match[1];
    if (DEFAULT_CONFIG.hasOwnProperty(key)) {
        const value = await getConfig(key);
        bot.sendMessage(msg.chat.id, `${key} = ${value}`);
    } else {
        bot.sendMessage(msg.chat.id, `❌ မသိသော key: ${key}`);
    }
});

bot.onText(/\/approve (\w+)/, async (msg, match) => {
    if (!isAdmin(msg)) return;
    const withdrawalId = match[1];
    await Withdrawal.findByIdAndUpdate(withdrawalId, { status: 'completed' });
    bot.sendMessage(msg.chat.id, `Withdrawal ${withdrawalId} approved.`);
});

bot.onText(/\/reject (\w+)/, async (msg, match) => {
    if (!isAdmin(msg)) return;
    const withdrawalId = match[1];
    const withdrawal = await Withdrawal.findById(withdrawalId);
    if (withdrawal) {
        await User.updateOne({ userId: withdrawal.userId }, { $inc: { coins: withdrawal.amount } });
        await Withdrawal.findByIdAndUpdate(withdrawalId, { status: 'rejected' });
        bot.sendMessage(msg.chat.id, `Withdrawal ${withdrawalId} rejected and refunded.`);
    }
});

// ==================== API Routes ====================
app.get('/health', (req, res) => res.send('OK'));

app.get('/api/user', authMiddleware, async (req, res) => {
    try {
        const user = await getUser(req.tgUser.id, req.tgUser.username || req.tgUser.first_name);
        if (user.banned) {
            return res.status(403).json({ error: 'Your account is banned' });
        }

        try {
            const photos = await bot.getUserProfilePhotos(user.userId, { limit: 1 });
            if (photos.total_count > 0) {
                const fileId = photos.photos[0][0].file_id;
                const photoUrl = await bot.getFileLink(fileId);
                if (user.photoUrl !== photoUrl) {
                    user.photoUrl = photoUrl;
                    await user.save();
                }
            }
        } catch (e) {
            console.error('Error fetching profile photo:', e.message);
        }

        res.json({
            userId: user.userId,
            username: user.username,
            photoUrl: user.photoUrl,
            coins: user.coins,
            dailyLastClaim: user.dailyLastClaim,
            tasks: Object.fromEntries(user.tasks),
            referralCount: user.referralCount,
            createdAt: user.createdAt,
            banned: user.banned
        });
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/claim/daily', authMiddleware, claimLimiter, async (req, res) => {
    try {
        const user = await getUser(req.tgUser.id, req.tgUser.username);
        if (user.banned) return res.status(403).json({ error: 'Banned' });
        const now = Date.now();
        const cooldown = await getConfig('DAILY_COOLDOWN');
        if (now - user.dailyLastClaim < cooldown) {
            return res.status(400).json({ error: 'Not ready', remaining: cooldown - (now - user.dailyLastClaim) });
        }
        const reward = await getConfig('DAILY_REWARD');
        user.coins += reward;
        user.dailyLastClaim = now;
        await user.save();
        res.json({ coins: user.coins, dailyLastClaim: user.dailyLastClaim });
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/claim/task/:taskId', authMiddleware, claimLimiter, async (req, res) => {
    try {
        const { taskId } = req.params;
        const user = await getUser(req.tgUser.id, req.tgUser.username);
        if (user.banned) return res.status(403).json({ error: 'Banned' });
        const now = Date.now();
        const cooldown = await getConfig('TASK_COOLDOWN');
        const lastClaim = user.tasks.get(taskId) || 0;
        if (now - lastClaim < cooldown) {
            return res.status(400).json({ error: 'Not ready', remaining: cooldown - (now - lastClaim) });
        }
        const reward = await getConfig('TASK_REWARD');
        user.coins += reward;
        user.tasks.set(taskId, now);
        await user.save();
        res.json({ coins: user.coins, tasks: Object.fromEntries(user.tasks) });
    } catch (err) {
        res.status(500).json({ error: 'Database error' });
    }
});

app.post('/api/withdraw', authMiddleware, claimLimiter, async (req, res) => {
    try {
        const { method, accountDetails, accountName, amount } = req.body;
        if (!method || !accountDetails || !amount) {
            return res.status(400).json({ error: 'Missing fields' });
        }
        if (!['kpay', 'wavepay', 'binance'].includes(method)) {
            return res.status(400).json({ error: 'Invalid payment method' });
        }

        const withdrawalAmount = Number(amount);
        if (isNaN(withdrawalAmount) || withdrawalAmount <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        const minWithdraw = await getConfig('MIN_WITHDRAWAL');
        if (withdrawalAmount < minWithdraw) {
            return res.status(400).json({ error: `Minimum withdrawal is ${minWithdraw} coins` });
        }

        const user = await getUser(req.tgUser.id, req.tgUser.username);
        if (user.banned) return res.status(403).json({ error: 'Banned' });
        if (user.coins < withdrawalAmount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        user.coins -= withdrawalAmount;
        await user.save();

        const withdrawal = new Withdrawal({
            userId: user.userId,
            amount: withdrawalAmount,
            method,
            accountDetails: `${accountDetails} ${accountName ? `(${accountName})` : ''}`
        });
        await withdrawal.save();

        const message = `💸 Withdrawal Request\nUser: @${user.username || 'No username'} (${user.userId})\nAmount: ${withdrawalAmount} coins\nMethod: ${method}\nAccount: ${accountDetails} ${accountName ? `\nName: ${accountName}` : ''}\nTime: ${new Date().toLocaleString()}`;
        await bot.sendMessage(GROUP_ID, message);

        res.json({ success: true, remainingCoins: user.coins });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== Start Server ====================
const PORT = process.env.PORT || 5000;

if (!process.env.MONGODB_URI) {
    console.error('❌ MONGODB_URI is not defined');
    process.exit(1);
}

mongoose.connect(process.env.MONGODB_URI)
    .then(async () => {
        console.log('✅ MongoDB connected');
        await initConfigFromEnv();
        app.listen(PORT, () => {
            console.log(`🚀 Server running on port ${PORT}`);
            console.log(`🌍 Webhook URL: ${WEBHOOK_URL}`);
        });
    })
    .catch(err => {
        console.error('❌ MongoDB error:', err);
        process.exit(1);
    });
