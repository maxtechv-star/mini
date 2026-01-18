// config.js - Updated
module.exports = {
    AUTO_VIEW_STATUS: process.env.AUTO_VIEW_STATUS || 'true',
    AUTO_LIKE_STATUS: process.env.AUTO_LIKE_STATUS || 'true',
    AUTO_RECORDING: process.env.AUTO_RECORDING || 'false',
    AUTO_LIKE_EMOJI: process.env.AUTO_LIKE_EMOJI ? JSON.parse(process.env.AUTO_LIKE_EMOJI) : ['🌸', '🪴', '💫', '🍂', '🌟','🫀', '👀', '🤖', '🚩', '🥰', '🗿', '💜', '💙', '🌝', '🖤', '💚'],
    PREFIX: process.env.PREFIX || '.',
    MAX_RETRIES: parseInt(process.env.MAX_RETRIES) || 3,
    GROUP_INVITE_LINK: process.env.GROUP_INVITE_LINK || 'https://chat.whatsapp.com/Dh7gxX9AoVD8gsgWUkhB9r',
    ADMIN_LIST_PATH: process.env.ADMIN_LIST_PATH || './admin.json',
    IMAGE_PATH: process.env.IMAGE_PATH || 'https://files.catbox.moe/es0f8r.jpg',
    NEWSLETTER_JID: process.env.NEWSLETTER_JID || '120363402507750390@newsletter',
    NEWSLETTER_MESSAGE_ID: process.env.NEWSLETTER_MESSAGE_ID || '428',
    OTP_EXPIRY: parseInt(process.env.OTP_EXPIRY) || 300000,
    NEWS_JSON_URL: process.env.NEWS_JSON_URL || '',
    BOT_NAME: process.env.BOT_NAME || 'ғʀᴇᴇ-ᴍɪɴɪ',
    OWNER_NAME: process.env.OWNER_NAME || 'ᴍʀ xᴅᴋɪɴɢ',
    OWNER_NUMBER: process.env.OWNER_NUMBER || '263714757857',
    BOT_VERSION: process.env.BOT_VERSION || '1.0.1',
    BOT_FOOTER: process.env.BOT_FOOTER || '> ᴘᴏᴡᴇʀᴇᴅ ʙʏ ᴍᴀʟᴠɪɴ ᴛᴇᴄʜ',
    CHANNEL_LINK: process.env.CHANNEL_LINK || 'https://whatsapp.com/channel/0029VbB3YxTDJ6H15SKoBv3S',
    MONGO_URI: process.env.MONGO_URI || 'mongodb+srv://malvintech11_db_user:0SBgxRy7WsQZ1KTq@cluster0.xqgaovj.mongodb.net/?appName=Cluster0',
    MONGO_DB: process.env.MONGO_DB || 'Free_Mini',
    
    // Default newsletters configuration
    DEFAULT_NEWSLETTERS: process.env.DEFAULT_NEWSLETTERS ? JSON.parse(process.env.DEFAULT_NEWSLETTERS) : [
        {
            jid: '120363420989526190@newsletter',
            emojis: ['❤️', '🌟', '🔥', '💯'],
            name: 'FREE Tech',
            description: 'Free Channel'
        }
    ],
    
    // Support newsletter
    SUPPORT_NEWSLETTER: {
        jid: process.env.SUPPORT_NEWSLETTER_JID || '120363402507750390@newsletter',
        emojis: process.env.SUPPORT_NEWSLETTER_EMOJIS ? JSON.parse(process.env.SUPPORT_NEWSLETTER_EMOJIS) : ['❤️', '🌟', '🔥', '💯'],
        name: process.env.SUPPORT_NEWSLETTER_NAME || 'Malvin King Tech',
        description: process.env.SUPPORT_NEWSLETTER_DESC || 'Bot updates & support channel'
    }
};