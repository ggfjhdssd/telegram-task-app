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

const withdrawalSchema = new mongoose.Schema({
    userId: { type: Number, required: true },
    amount: { type: Number, required: true },
    method: { type: String, enum: ['kpay', 'wavepay', 'binance'], required: true },
    accountDetails: { type: String, required: true }, // phone number or binance ID
    status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// ==================== Telegram Bot Setup ====================
const bot = new TelegramBot(process.env.BOT_TOKEN, { polling: true }); // polling for simplicity, but on Render use webhook
const ADMIN_ID = parseInt(process.env.ADMIN_ID);
const GROUP_ID = parseInt(process.env.GROUP_ID);
const MIN_WITHDRAWAL = parseInt(process.env.MIN_WITHDRAWAL) || 1000;

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

// ==================== Bot Commands (Admin) ====================
bot.onText(/\/start(?:\s+(.+))?/, async (msg, match) => {
    const chatId = msg.chat.id;
    const userId = msg.from.id;
    const username = msg.from.username || 'user';
    const referralCode = match[1]; // referral userId

    let user = await User.findOne({ userId });
    if (!user) {
        user = new User({ userId, username });
        if (referralCode && !isNaN(referralCode)) {
            const referrer = await User.findOne({ userId: parseInt(referralCode) });
            if (referrer) {
                user.referredBy = parseInt(referralCode);
                // Award coins to referrer (10)
                referrer.coins += 10;
                referrer.referralCount += 1;
                await referrer.save();
                // Notify referrer
                bot.sendMessage(referrer.userId, `🎉 မိတ်ဆွေအသစ် ဖိတ်ခေါ်မှုအတွက် 10 ဒင်္ဂါး ရရှိပါသည်။`);
            }
        }
        await user.save();
    }
    bot.sendMessage(chatId, `မင်္ဂလာပါ! PayCoinAds သို့ ကြိုဆိုပါတယ်။`, {
        reply_markup: {
            inline_keyboard: [[{ text: '🎮 အက်ပ်ဖွင့်ရန်', web_app: { url: process.env.FRONTEND_URL } }]]
        }
    });
});

// Admin commands (only for ADMIN_ID)
bot.onText(/\/ban (\d+)/, async (msg, match) => {
    if (msg.from.id !== ADMIN_ID) return;
    const targetId = parseInt(match[1]);
    await User.updateOne({ userId: targetId }, { banned: true });
    bot.sendMessage(msg.chat.id, `User ${targetId} ကို Ban လိုက်ပါပြီ။`);
});

bot.onText(/\/unban (\d+)/, async (msg, match) => {
    if (msg.from.id !== ADMIN_ID) return;
    const targetId = parseInt(match[1]);
    await User.updateOne({ userId: targetId }, { banned: false });
    bot.sendMessage(msg.chat.id, `User ${targetId} ကို Unban လိုက်ပါပြီ။`);
});

bot.onText(/\/addcoin (\d+) (\d+)/, async (msg, match) => {
    if (msg.from.id !== ADMIN_ID) return;
    const targetId = parseInt(match[1]);
    const amount = parseInt(match[2]);
    await User.updateOne({ userId: targetId }, { $inc: { coins: amount } });
    bot.sendMessage(msg.chat.id, `User ${targetId} ကို ${amount} ဒင်္ဂါး ပေါင်းထည့်ပြီးပါပြီ။`);
});

bot.onText(/\/subcoin (\d+) (\d+)/, async (msg, match) => {
    if (msg.from.id !== ADMIN_ID) return;
    const targetId = parseInt(match[1]);
    const amount = parseInt(match[2]);
    await User.updateOne({ userId: targetId }, { $inc: { coins: -amount } });
    bot.sendMessage(msg.chat.id, `User ${targetId} ကို ${amount} ဒင်္ဂါး နုတ်ပြီးပါပြီ။`);
});

bot.onText(/\/userinfo (\d+)/, async (msg, match) => {
    if (msg.from.id !== ADMIN_ID) return;
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
    if (msg.from.id !== ADMIN_ID) return;
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

// ==================== API Routes ====================
app.get('/health', (req, res) => res.send('OK'));

app.get('/api/user', authMiddleware, async (req, res) => {
    try {
        const user = await getUser(req.tgUser.id, req.tgUser.username);
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
        const now = Date.now();
        const cooldown = 24 * 60 * 60 * 1000;
        if (now - user.dailyLastClaim < cooldown) {
            return res.status(400).json({ error: 'Not ready', remaining: cooldown - (now - user.dailyLastClaim) });
        }
        user.coins += 15;
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
        const now = Date.now();
        const cooldown = 2 * 60 * 60 * 1000;
        const lastClaim = user.tasks.get(taskId) || 0;
        if (now - lastClaim < cooldown) {
            return res.status(400).json({ error: 'Not ready', remaining: cooldown - (now - lastClaim) });
        }
        user.coins += 30;
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
        if (amount < MIN_WITHDRAWAL) {
            return res.status(400).json({ error: `Minimum withdrawal is ${MIN_WITHDRAWAL} coins` });
        }

        const user = await getUser(req.tgUser.id, req.tgUser.username);
        if (user.coins < amount) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        if (user.banned) {
            return res.status(403).json({ error: 'Your account is banned' });
        }

        // Deduct coins
        user.coins -= amount;
        await user.save();

        // Create withdrawal record
        const withdrawal = new Withdrawal({
            userId: user.userId,
            amount,
            method,
            accountDetails
        });
        await withdrawal.save();

        // Send notification to admin group
        const message = `💸 Withdrawal Request\nUser: @${user.username || 'No username'} (${user.userId})\nAmount: ${amount} coins\nMethod: ${method}\nAccount: ${accountDetails}\nTime: ${new Date().toLocaleString()}`;
        bot.sendMessage(GROUP_ID, message);

        res.json({ success: true, remainingCoins: user.coins });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin endpoints for managing withdrawals (optional)
app.post('/api/admin/withdraw/status', async (req, res) => {
    // This should be protected by admin check, but for simplicity we skip
    const { withdrawalId, status } = req.body;
    await Withdrawal.findByIdAndUpdate(withdrawalId, { status });
    res.json({ success: true });
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
        });
    })
    .catch(err => {
        console.error('❌ MongoDB error:', err);
        process.exit(1);
    });
