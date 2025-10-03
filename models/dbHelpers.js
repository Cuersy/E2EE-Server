/*
 * @Author: Cuersy 
 * @Date: 2025-10-03 18:23:58 
 * @Last Modified by:   Cuersy 
 * @Last Modified time: 2025-10-03 18:23:58 
 */
const USER_MODEL = require('./User');
const MESSAGE_MODEL = require('./Message');

async function SAVE_MESSAGE_TO_DATABASE(SENDER, RECIPIENT, ENCRYPTED_CONTENT, NONCE) {
    try {
        const EXISTING_NONCE = await MESSAGE_MODEL.findOne({ nonce: NONCE });
        if (EXISTING_NONCE) {
            console.error('DUPLICATE_NONCE_DETECTED:', NONCE);
            return null;
        }

        const MESSAGE = await MESSAGE_MODEL.create({
            sender: SENDER,
            recipient: RECIPIENT,
            encryptedContent: ENCRYPTED_CONTENT,
            nonce: NONCE
        });
        
        console.log('MESSAGE_SAVED:', MESSAGE._id.toString());
        return MESSAGE;
    } catch (ERROR) {
        console.error('SAVE_MESSAGE_ERROR:', ERROR.message);
        return null;
    }
}

async function UPDATE_MESSAGE_STATUS(MESSAGE_ID, STATUS) {
    try {
        const MESSAGE = await MESSAGE_MODEL.findById(MESSAGE_ID);
        if (!MESSAGE) {
            console.error('MESSAGE_NOT_FOUND:', MESSAGE_ID);
            return false;
        }

        if (STATUS === 'delivered') {
            await MESSAGE.MARK_DELIVERED();
            console.log('MESSAGE_MARKED_DELIVERED:', MESSAGE_ID);
        } else if (STATUS === 'read') {
            await MESSAGE.MARK_READ();
            console.log('MESSAGE_MARKED_READ:', MESSAGE_ID);
        }
        
        return true;
    } catch (ERROR) {
        console.error('UPDATE_MESSAGE_STATUS_ERROR:', ERROR.message);
        return false;
    }
}

async function UPDATE_USER_STATUS(USER_ID, IS_ONLINE) {
    try {
        const USER = await USER_MODEL.findOne({ userId: USER_ID });
        if (!USER) {
            console.error('USER_NOT_FOUND:', USER_ID);
            return false;
        }

        if (IS_ONLINE) {
            await USER.SET_ONLINE();
        } else {
            await USER.SET_OFFLINE();
        }
        
        console.log('USER_STATUS_UPDATED:', USER_ID, 'ONLINE:', IS_ONLINE);
        return true;
    } catch (ERROR) {
        console.error('UPDATE_USER_STATUS_ERROR:', ERROR.message);
        return false;
    }
}

async function GET_USER_BY_ID(USER_ID) {
    try {
        return await USER_MODEL.FIND_BY_USER_ID(USER_ID);
    } catch (ERROR) {
        console.error('GET_USER_BY_ID_ERROR:', ERROR.message);
        return null;
    }
}

async function GET_USER_BY_USERNAME(USERNAME) {
    try {
        return await USER_MODEL.FIND_BY_USERNAME(USERNAME);
    } catch (ERROR) {
        console.error('GET_USER_BY_USERNAME_ERROR:', ERROR.message);
        return null;
    }
}

async function GET_UNDELIVERED_MESSAGES(RECIPIENT_ID) {
    try {
        return await MESSAGE_MODEL.GET_UNDELIVERED_MESSAGES(RECIPIENT_ID);
    } catch (ERROR) {
        console.error('GET_UNDELIVERED_MESSAGES_ERROR:', ERROR.message);
        return [];
    }
}

async function GET_CONVERSATION_HISTORY(USER_ID_1, USER_ID_2, LIMIT = 50) {
    try {
        return await MESSAGE_MODEL.GET_CONVERSATION(USER_ID_1, USER_ID_2, LIMIT);
    } catch (ERROR) {
        console.error('GET_CONVERSATION_HISTORY_ERROR:', ERROR.message);
        return [];
    }
}

async function DELETE_OLD_MESSAGES() {
    try {
        const RESULT = await MESSAGE_MODEL.DELETE_EXPIRED_MESSAGES();
        console.log('EXPIRED_MESSAGES_DELETED:', RESULT.deletedCount);
        return RESULT.deletedCount;
    } catch (ERROR) {
        console.error('DELETE_OLD_MESSAGES_ERROR:', ERROR.message);
        return 0;
    }
}

async function GET_ONLINE_USERS() {
    try {
        return await USER_MODEL.GET_ONLINE_USERS();
    } catch (ERROR) {
        console.error('GET_ONLINE_USERS_ERROR:', ERROR.message);
        return [];
    }
}

module.exports = {
    SAVE_MESSAGE_TO_DATABASE,
    UPDATE_MESSAGE_STATUS,
    UPDATE_USER_STATUS,
    GET_USER_BY_ID,
    GET_USER_BY_USERNAME,
    GET_UNDELIVERED_MESSAGES,
    GET_CONVERSATION_HISTORY,
    DELETE_OLD_MESSAGES,
    GET_ONLINE_USERS
};