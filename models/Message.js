/*
 * @Author: Cuersy 
 * @Date: 2025-10-03 18:23:54 
 * @Last Modified by:   Cuersy 
 * @Last Modified time: 2025-10-03 18:23:54 
 */

const MONGOOSE = require('mongoose');

const MESSAGE_SCHEMA = new MONGOOSE.Schema({
    sender: {
        type: String,
        required: true,
        ref: 'User',
        index: true
    },
    recipient: {
        type: String,
        required: true,
        ref: 'User',
        index: true
    },
    encryptedContent: {
        type: String,
        required: true
    },
    nonce: {
        type: String,
        required: true,
        unique: true
    },
    timestamp: {
        type: Date,
        default: Date.now,
        index: true
    },
    isDelivered: {
        type: Boolean,
        default: false,
        index: true
    },
    isRead: {
        type: Boolean,
        default: false,
        index: true
    },
    deliveredAt: {
        type: Date
    },
    readAt: {
        type: Date
    },
    expiresAt: {
        type: Date,
        index: true
    }
});

MESSAGE_SCHEMA.pre('save', function(NEXT) {
    if (this.isNew) {
        this.timestamp = Date.now();
        this.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    }
    NEXT();
});

MESSAGE_SCHEMA.methods.MARK_DELIVERED = async function() {
    this.isDelivered = true;
    this.deliveredAt = Date.now();
    return this.save();
};

MESSAGE_SCHEMA.methods.MARK_READ = async function() {
    this.isRead = true;
    this.readAt = Date.now();
    if (!this.isDelivered) {
        this.isDelivered = true;
        this.deliveredAt = Date.now();
    }
    return this.save();
};

MESSAGE_SCHEMA.statics.GET_UNDELIVERED_MESSAGES = function(RECIPIENT_ID) {
    return this.find({
        recipient: RECIPIENT_ID,
        isDelivered: false
    }).sort({ timestamp: 1 });
};

MESSAGE_SCHEMA.statics.GET_CONVERSATION = function(USER_ID_1, USER_ID_2, LIMIT = 50) {
    return this.find({
        $or: [
            { sender: USER_ID_1, recipient: USER_ID_2 },
            { sender: USER_ID_2, recipient: USER_ID_1 }
        ]
    })
    .sort({ timestamp: -1 })
    .limit(LIMIT);
};

MESSAGE_SCHEMA.statics.DELETE_EXPIRED_MESSAGES = function() {
    return this.deleteMany({
        expiresAt: { $lt: Date.now() }
    });
};

MESSAGE_SCHEMA.index({ sender: 1, recipient: 1, timestamp: -1 });
MESSAGE_SCHEMA.index({ recipient: 1, isDelivered: 1 });
MESSAGE_SCHEMA.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = MONGOOSE.model('Message', MESSAGE_SCHEMA);