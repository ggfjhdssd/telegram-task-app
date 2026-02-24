require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
const TelegramBot = require('node-telegram-bot-api');

const app = express();
app.use(cors({ origin: process.env.FRONTEND_URL || '*', credentials: true }));
app.use(express.json());

// ==================== MongoDB Models ====================

// Config Schema (for dynamic settings)
const configSchema = new mongoose.Schema({
    key: { type: String, unique: true },
    value: mongoose.Schema.Types.Mixed
});
const Config = mongoose.model('Config', configSchema);

// User Schema
const userSchema = new mongoose.Schema({
    userId: { type: Number, required: true, unique: true },
    username: String,
    coins: { type: Number, default: 0 },
    dailyLastClaim: { type: Number, default: 0 },
    tasks: { type: Map, of: Number, default: {} },
    referredBy: { type: Number, default: null },
    referralCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    banned: { type: Boolean, default: false }
});

// Withdrawal Schema (auto-delete after 30 days)
const withdrawalSchema = new mongoose.Schema({
    userId: { type: Number, required: true },
    amount: { type: Number, required: true },
    method: { type: String, enum: ['kpay', 'wavepay', 'binance'], required: true },
    accountDetails: { type: String, required: true },
    status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now, expires: 60 * 60 * 24 * 30 } // auto-delete after 30 days
});

const User = mongoose.model('User', userSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// ==================== Default Configs ====================
const DEFAULT_CONFIG = {
    REFERRAL_REWARD: 10,
    DAILY_REWARD: 15,
    TASK_REWARD: 30,
    MIN_WITHDRAWAL: 1000,
    TASK_COOLDOWN: 2 * 60 * 60 * 1000, // 2 hours in ms
    DAILY_COOLDOWN: 24 * 60 * 60 * 1000 // 24 hours in ms
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

// ==================== Telegram Bot Setup (Webhook) ====================
const bot = new TelegramBot(process.env.BOT_TOKEN);
const ADMIN_ID = parseInt(process.env.ADMIN_ID);
const GROUP_ID = parseInt(process.env.GROUP_ID);

// Set webhook on startup
bot.setWebHook(process.env.WEBHOOK_URL);

// Webhook endpoint
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
    }
    return user;
}

// ==================== Bot Commands ====================

// Helper: check admin
function isAdmin(msg) {
    return msg.from.id === ADMIN_ID;
}

// Start command with referral
bot.onText(/\/start(?:\s+(.+))?/, async (msg, match) => {
    const chatId = msg.chat.id;
    const userId = msg.from.id;
    const username = msg.from.username || 'user';
    const referralCode = match[1]; // should be a user ID

    let user = await User.findOne({ userId });
    if (!user) {
        user = new User({ userId, username });
        if (referralCode && !isNaN(referralCode)) {
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
    await bot.sendMessage(chatId, `မင်္ဂလာပါ! PayCoinAds သို့ ကြိုဆိုပါတယ်။`, {
        reply_markup: {
            inline_keyboard: [[{ text: '🎮 အက်ပ်ဖွင့်ရန်', web_app: { url: webAppUrl } }]]
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

// Admin config commands
bot.onText(/\/set (\w+) (\w+)/, async (msg, match) => {
    if (!isAdmin(msg)) return;
    const key = match[1];
    let value = match[2];
    // Handle numeric values
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

// Withdrawal approval (optional admin command)
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
        // Refund coins
        await User.updateOne({ userId: withdrawal.userId }, { $inc: { coins: withdrawal.amount } });
        await Withdrawal.findByIdAndUpdate(withdrawalId, { status: 'rejected' });
        bot.sendMessage(msg.chat.id, `Withdrawal ${withdrawalId} rejected and refunded.`);
    }
});

// ==================== API Routes ====================
app.get('/health', (req, res) => res.send('OK'));

app.get('/api/user', authMiddleware, async (req, res) => {
    try {
        const user = await getUser(req.tgUser.id, req.tgUser.username);
        if (user.banned) {
            return res.status(403).json({ error: 'Your account is banned' });
        }
        res.json({
            userId: user.userId,
            username: user.username,
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

app.post('/api/claim/daily', authMiddleware, async (req, res) => {
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

app.post('/api/claim/task/:taskId', authMiddleware, async (req, res) => {
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

app.post('/api/withdraw', authMiddleware, async (req, res) => {
    try {
        const { method, accountDetails, amount } = req.body;
        if (!method || !accountDetails || !amount) {
            return res.status(400).json({ error: 'Missing fields' });
        }
        if (!['kpay', 'wavepay', 'binance'].includes(method)) {
            return res.status(400).json({ error: 'Invalid payment method' });
        }
        const minWithdraw = await getConfig('MIN_WITHDRAWAL');
        if (amount < minWithdraw) {
            return res.status(400).json({ error: `Minimum withdrawal is ${minWithdraw} coins` });
        }

        const user = await getUser(req.tgUser.id, req.tgUser.username);
        if (user.banned) return res.status(403).json({ error: 'Banned' });
        if (user.coins < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        // Deduct coins
        user.coins -= amount;
        await user.save();

        // Create withdrawal record (auto-delete after 30 days)
        const withdrawal = new Withdrawal({
            userId: user.userId,
            amount,
            method,
            accountDetails
        });
        await withdrawal.save();

        // Send notification to admin group
        const message = `💸 Withdrawal Request\nUser: @${user.username || 'No username'} (${user.userId})\nAmount: ${amount} coins\nMethod: ${method}\nAccount: ${accountDetails}\nTime: ${new Date().toLocaleString()}`;
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
    .then(() => {
        console.log('✅ MongoDB connected');
        app.listen(PORT, () => {
            console.log(`🚀 Server running on port ${PORT}`);
            console.log(`🌍 Webhook URL: ${process.env.WEBHOOK_URL}`);
        });
    })
    .catch(err => {
        console.error('❌ MongoDB error:', err);
        process.exit(1);
    });
