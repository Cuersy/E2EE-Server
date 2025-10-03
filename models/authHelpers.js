/*
 * @Author: Cuersy 
 * @Date: 2025-10-03 18:24:04 
 * @Last Modified by:   Cuersy 
 * @Last Modified time: 2025-10-03 18:24:04 
 */

const USER_MODEL = require('./User');
const CRYPTO = require('crypto');

async function HANDLE_USER_AUTH(USERNAME, PUBLIC_KEY, USER_ID = null) {
    try {
        let USER;
        
        if (USER_ID) {
            USER = await USER_MODEL.findOne({ userId: USER_ID });
            
            if (USER) {
                USER.username = USERNAME;
                USER.publicKey = PUBLIC_KEY;
                USER.isOnline = true;
                USER.lastSeen = Date.now();
                await USER.save();
                
                console.log('EXISTING_USER_UPDATED:', USER.userId);
            } else {
                USER = await CREATE_NEW_USER(USERNAME, PUBLIC_KEY);
            }
        } else {
            USER = await USER_MODEL.FIND_BY_USERNAME(USERNAME);
            
            if (USER) {
                USER.publicKey = PUBLIC_KEY;
                USER.isOnline = true;
                USER.lastSeen = Date.now();
                await USER.save();
                
                console.log('USER_LOGGED_IN:', USER.userId);
            } else {
                USER = await CREATE_NEW_USER(USERNAME, PUBLIC_KEY);
            }
        }
        
        return USER;
    } catch (ERROR) {
        console.error('HANDLE_USER_AUTH_ERROR:', ERROR.message);
        throw ERROR;
    }
}

async function CREATE_NEW_USER(USERNAME, PUBLIC_KEY) {
    try {
        const USER_ID = GENERATE_USER_ID();
        
        const USER = await USER_MODEL.create({
            userId: USER_ID,
            username: USERNAME,
            publicKey: PUBLIC_KEY,
            isOnline: true
        });
        
        console.log('NEW_USER_CREATED:', USER.userId);
        return USER;
    } catch (ERROR) {
        if (ERROR.code === 11000) {
            if (ERROR.keyPattern.username) {
                throw new Error('USERNAME_ALREADY_EXISTS');
            }
            if (ERROR.keyPattern.userId) {
                return CREATE_NEW_USER(USERNAME, PUBLIC_KEY);
            }
        }
        
        console.error('CREATE_NEW_USER_ERROR:', ERROR.message);
        throw ERROR;
    }
}

function GENERATE_USER_ID() {
    return CRYPTO.randomBytes(16).toString('hex');
}

async function VERIFY_USER_CREDENTIALS(USERNAME, USER_ID) {
    try {
        const USER = await USER_MODEL.findOne({ 
            username: USERNAME,
            userId: USER_ID 
        });
        
        return USER !== null;
    } catch (ERROR) {
        console.error('VERIFY_USER_CREDENTIALS_ERROR:', ERROR.message);
        return false;
    }
}

async function UPDATE_USER_PUBLIC_KEY(USER_ID, NEW_PUBLIC_KEY) {
    try {
        const USER = await USER_MODEL.findOne({ userId: USER_ID });
        
        if (!USER) {
            console.error('USER_NOT_FOUND:', USER_ID);
            return null;
        }
        
        USER.publicKey = NEW_PUBLIC_KEY;
        await USER.save();
        
        console.log('PUBLIC_KEY_UPDATED:', USER_ID);
        return USER;
    } catch (ERROR) {
        console.error('UPDATE_USER_PUBLIC_KEY_ERROR:', ERROR.message);
        return null;
    }
}

async function DELETE_USER_ACCOUNT(USER_ID) {
    try {
        const RESULT = await USER_MODEL.deleteOne({ userId: USER_ID });
        
        if (RESULT.deletedCount > 0) {
            console.log('USER_DELETED:', USER_ID);
            return true;
        }
        
        return false;
    } catch (ERROR) {
        console.error('DELETE_USER_ACCOUNT_ERROR:', ERROR.message);
        return false;
    }
}

async function CHECK_USERNAME_AVAILABILITY(USERNAME) {
    try {
        const USER = await USER_MODEL.FIND_BY_USERNAME(USERNAME);
        return USER === null;
    } catch (ERROR) {
        console.error('CHECK_USERNAME_AVAILABILITY_ERROR:', ERROR.message);
        return false;
    }
}

module.exports = {
    HANDLE_USER_AUTH,
    CREATE_NEW_USER,
    GENERATE_USER_ID,
    VERIFY_USER_CREDENTIALS,
    UPDATE_USER_PUBLIC_KEY,
    DELETE_USER_ACCOUNT,
    CHECK_USERNAME_AVAILABILITY
};