/*
 * @Author: Cuersy 
 * @Date: 2025-10-03 18:23:48 
 * @Last Modified by:   Cuersy 
 * @Last Modified time: 2025-10-03 18:23:48 
 */

const MONGOOSE = require('mongoose');

const USER_SCHEMA = new MONGOOSE.Schema({
    userId: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        index: true
    },
    publicKey: {
        type: String,
        required: true
    },
    lastSeen: {
        type: Date,
        default: Date.now
    },
    isOnline: {
        type: Boolean,
        default: false,
        index: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

USER_SCHEMA.pre('save', function(NEXT) {
    if (!this.userId) {
        this.userId = new MONGOOSE.Types.ObjectId().toString();
    }
    NEXT();
});

USER_SCHEMA.methods.SET_ONLINE = async function() {
    this.isOnline = true;
    this.lastSeen = Date.now();
    return this.save();
};

USER_SCHEMA.methods.SET_OFFLINE = async function() {
    this.isOnline = false;
    this.lastSeen = Date.now();
    return this.save();
};

USER_SCHEMA.statics.FIND_BY_USERNAME = function(USERNAME) {
    return this.findOne({ username: USERNAME });
};

USER_SCHEMA.statics.FIND_BY_USER_ID = function(USER_ID) {
    return this.findOne({ userId: USER_ID });
};

USER_SCHEMA.statics.GET_ONLINE_USERS = function() {
    return this.find({ isOnline: true });
};

module.exports = MONGOOSE.model('User', USER_SCHEMA);