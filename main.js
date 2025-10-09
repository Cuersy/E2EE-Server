/*
 * @Author: Cuersy 
 * @Date: 2025-10-09 21:56:17 
 * @Last Modified by:   Cuersy 
 * @Last Modified time: 2025-10-09 21:56:17 
 */
const WEBSOCKET_MODULE = require("ws");
const CRYPTO = require("crypto");
const MONGOOSE = require("mongoose");
require("dotenv").config();  
const { 
    SAVE_MESSAGE_TO_DATABASE, 
    UPDATE_MESSAGE_STATUS, 
    UPDATE_USER_STATUS,
    GET_UNDELIVERED_MESSAGES,
    GET_USER_BY_ID,
    DELETE_OLD_MESSAGES
} = require('./models/dbHelpers');
const { HANDLE_USER_AUTH } = require('./models/authHelpers');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/e2ee_chat';
const PORT = process.env.PORT || 8080;
const SESSION_TIMEOUT = 3600000;
const MESSAGE_TIMEOUT = 300000;
const MAX_NONCE_CACHE = 10000;
const MAX_MESSAGE_SIZE = 1048576;
const MAX_RECONNECT_ATTEMPTS = 5;
const HANDSHAKE_TIMEOUT = 30000;
const MAX_CONNECTIONS_PER_IP = 10;
const GLOBAL_RATE_LIMIT = 1000;
const GLOBAL_RATE_WINDOW = 60000;
const BRUTE_FORCE_THRESHOLD = 5;
const BRUTE_FORCE_WINDOW = 900000;
const MIN_KEY_SIZE = 4096;
const MAX_USERNAME_LENGTH = 32;
const MIN_USERNAME_LENGTH = 3;
const SESSION_ROTATION_INTERVAL = 1800000;
const CIPHER_SUITE = 'AES-256-GCM';
const HASH_ALGORITHM = 'sha512';
const SIGNATURE_ALGORITHM = 'RSA-SHA512';
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 32;
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

const CLIENT_SESSIONS = new Map();
const PENDING_MESSAGES = new Map();
const NONCE_CACHE = new Set();
const RATE_LIMIT_MAP = new Map();
const MESSAGE_ID_MAP = new Map();
const IP_CONNECTION_MAP = new Map();
const FAILED_AUTH_MAP = new Map();
const BLACKLIST_IPS = new Set();
const SESSION_ROTATION_MAP = new Map();
const SIGNATURE_CACHE = new Map();
const SUSPICIOUS_ACTIVITY_MAP = new Map();

let WSS = null;
let DB_CONNECTED = false;

const SECURITY_CONFIG = {
    ENFORCE_TLS: process.env.ENFORCE_TLS === 'true',
    REQUIRE_SIGNATURE: true,
    ENABLE_REPLAY_PROTECTION: true,
    ENABLE_TIMING_ATTACK_MITIGATION: true,
    ENABLE_DOS_PROTECTION: true,
    MAX_PACKET_RATE: 100,
    PACKET_RATE_WINDOW: 1000,
    ENABLE_HONEYPOT: true,
    LOG_SUSPICIOUS_ACTIVITY: true
};

function CONSTANT_TIME_COMPARE(A, B) {
    if (typeof A !== 'string' || typeof B !== 'string') {
        return false;
    }
    if (A.length !== B.length) {
        return false;
    }
    return CRYPTO.timingSafeEqual(Buffer.from(A), Buffer.from(B));
}

function SECURE_RANDOM_BYTES(LENGTH) {
    return CRYPTO.randomBytes(LENGTH);
}

function HASH_DATA(DATA, ALGORITHM = HASH_ALGORITHM) {
    return CRYPTO.createHash(ALGORITHM).update(DATA).digest('hex');
}

function HMAC_SIGN(DATA, KEY) {
    return CRYPTO.createHmac(HASH_ALGORITHM, KEY).update(DATA).digest('hex');
}

function VERIFY_HMAC(DATA, KEY, SIGNATURE) {
    const EXPECTED = HMAC_SIGN(DATA, KEY);
    return CONSTANT_TIME_COMPARE(EXPECTED, SIGNATURE);
}

function ENCRYPT_DATA(DATA, KEY) {
    const IV = SECURE_RANDOM_BYTES(IV_LENGTH);
    const CIPHER = CRYPTO.createCipheriv('aes-256-gcm', KEY, IV);
    let ENCRYPTED = CIPHER.update(JSON.stringify(DATA), 'utf8', 'hex');
    ENCRYPTED += CIPHER.final('hex');
    const AUTH_TAG = CIPHER.getAuthTag();
    return {
        ENCRYPTED: ENCRYPTED,
        IV: IV.toString('hex'),
        AUTH_TAG: AUTH_TAG.toString('hex')
    };
}

function DECRYPT_DATA(ENCRYPTED_PACKAGE, KEY) {
    const DECIPHER = CRYPTO.createDecipheriv(
        'aes-256-gcm',
        KEY,
        Buffer.from(ENCRYPTED_PACKAGE.IV, 'hex')
    );
    DECIPHER.setAuthTag(Buffer.from(ENCRYPTED_PACKAGE.AUTH_TAG, 'hex'));
    let DECRYPTED = DECIPHER.update(ENCRYPTED_PACKAGE.ENCRYPTED, 'hex', 'utf8');
    DECRYPTED += DECIPHER.final('utf8');
    return JSON.parse(DECRYPTED);
}

function DERIVE_KEY(PASSWORD, SALT) {
    return CRYPTO.pbkdf2Sync(PASSWORD, SALT, PBKDF2_ITERATIONS, 32, HASH_ALGORITHM);
}

function SIGN_DATA(DATA, PRIVATE_KEY) {
    const SIGN = CRYPTO.createSign(SIGNATURE_ALGORITHM);
    SIGN.update(JSON.stringify(DATA));
    SIGN.end();
    return SIGN.sign(PRIVATE_KEY, 'hex');
}

function VERIFY_SIGNATURE(DATA, PUBLIC_KEY, SIGNATURE) {
    try {
        const VERIFY = CRYPTO.createVerify(SIGNATURE_ALGORITHM);
        VERIFY.update(JSON.stringify(DATA));
        VERIFY.end();
        return VERIFY.verify(PUBLIC_KEY, SIGNATURE, 'hex');
    } catch (ERROR) {
        return false;
    }
}

function SANITIZE_INPUT(INPUT, MAX_LENGTH = 1000) {
    if (typeof INPUT !== 'string') {
        return '';
    }
    return INPUT.slice(0, MAX_LENGTH)
        .replace(/[<>\"'&]/g, '')
        .replace(/[\x00-\x1F\x7F]/g, '');
}

function VALIDATE_PUBLIC_KEY(KEY) {
    if (!KEY || typeof KEY !== 'string') return false;
    if (!KEY.includes('BEGIN PUBLIC KEY') || !KEY.includes('END PUBLIC KEY')) return false;
    if (KEY.length < 500 || KEY.length > 10000) return false;
    try {
        CRYPTO.createPublicKey(KEY);
        return true;
    } catch {
        return false;
    }
}

function VALIDATE_USERNAME(USERNAME) {
    if (!USERNAME || typeof USERNAME !== 'string') return false;
    if (USERNAME.length < MIN_USERNAME_LENGTH || USERNAME.length > MAX_USERNAME_LENGTH) return false;
    if (!/^[a-zA-Z0-9_-]+$/.test(USERNAME)) return false;
    const BLACKLIST = ['admin', 'root', 'system', 'null', 'undefined'];
    return !BLACKLIST.includes(USERNAME.toLowerCase());
}

function VALIDATE_USER_ID(USER_ID) {
    return typeof USER_ID === 'string' && /^[a-f0-9]{32}$/.test(USER_ID);
}

function VALIDATE_SESSION_ID(SESSION_ID) {
    return typeof SESSION_ID === 'string' && /^[a-f0-9]{64}$/.test(SESSION_ID);
}

function VALIDATE_NONCE(NONCE) {
    return typeof NONCE === 'string' && /^[a-f0-9]{32}$/.test(NONCE) && NONCE.length === 32;
}

function CHECK_IP_LIMIT(IP) {
    const CONNECTIONS = IP_CONNECTION_MAP.get(IP) || 0;
    return CONNECTIONS < MAX_CONNECTIONS_PER_IP;
}

function INCREMENT_IP_CONNECTIONS(IP) {
    const CURRENT = IP_CONNECTION_MAP.get(IP) || 0;
    IP_CONNECTION_MAP.set(IP, CURRENT + 1);
}

function DECREMENT_IP_CONNECTIONS(IP) {
    const CURRENT = IP_CONNECTION_MAP.get(IP) || 0;
    if (CURRENT > 0) {
        IP_CONNECTION_MAP.set(IP, CURRENT - 1);
    }
}

function IS_IP_BLACKLISTED(IP) {
    return BLACKLIST_IPS.has(IP);
}

function BLACKLIST_IP(IP, DURATION = 3600000) {
    BLACKLIST_IPS.add(IP);
    setTimeout(() => BLACKLIST_IPS.delete(IP), DURATION);
    LOG_SUSPICIOUS_ACTIVITY(IP, 'IP_BLACKLISTED', { DURATION });
}

function CHECK_BRUTE_FORCE(IDENTIFIER) {
    const NOW = Date.now();
    const ATTEMPTS = FAILED_AUTH_MAP.get(IDENTIFIER) || [];
    const RECENT = ATTEMPTS.filter(T => NOW - T < BRUTE_FORCE_WINDOW);
    return RECENT.length < BRUTE_FORCE_THRESHOLD;
}

function RECORD_FAILED_AUTH(IDENTIFIER) {
    const NOW = Date.now();
    const ATTEMPTS = FAILED_AUTH_MAP.get(IDENTIFIER) || [];
    ATTEMPTS.push(NOW);
    FAILED_AUTH_MAP.set(IDENTIFIER, ATTEMPTS);
    
    const RECENT = ATTEMPTS.filter(T => NOW - T < BRUTE_FORCE_WINDOW);
    if (RECENT.length >= BRUTE_FORCE_THRESHOLD) {
        return true;
    }
    return false;
}

function CHECK_RATE_LIMIT(SESSION_ID, LIMIT = 50, WINDOW = 60000) {
    const NOW = Date.now();
    const USER_REQUESTS = RATE_LIMIT_MAP.get(SESSION_ID) || [];
    const RECENT_REQUESTS = USER_REQUESTS.filter(TIME => NOW - TIME < WINDOW);
    
    if (RECENT_REQUESTS.length >= LIMIT) {
        LOG_SUSPICIOUS_ACTIVITY(SESSION_ID, 'RATE_LIMIT_EXCEEDED', { LIMIT, WINDOW });
        return false;
    }
    
    RECENT_REQUESTS.push(NOW);
    RATE_LIMIT_MAP.set(SESSION_ID, RECENT_REQUESTS);
    return true;
}

function CHECK_GLOBAL_RATE_LIMIT() {
    const NOW = Date.now();
    const ALL_REQUESTS = [];
    for (const REQUESTS of RATE_LIMIT_MAP.values()) {
        ALL_REQUESTS.push(...REQUESTS);
    }
    const RECENT = ALL_REQUESTS.filter(T => NOW - T < GLOBAL_RATE_WINDOW);
    return RECENT.length < GLOBAL_RATE_LIMIT;
}

function VALIDATE_MESSAGE_SIZE(DATA) {
    try {
        const SIZE = Buffer.byteLength(JSON.stringify(DATA));
        return SIZE <= MAX_MESSAGE_SIZE;
    } catch {
        return false;
    }
}

function LOG_SUSPICIOUS_ACTIVITY(IDENTIFIER, TYPE, DATA) {
    if (!SECURITY_CONFIG.LOG_SUSPICIOUS_ACTIVITY) return;
    
    const NOW = Date.now();
    const ACTIVITY = SUSPICIOUS_ACTIVITY_MAP.get(IDENTIFIER) || [];
    ACTIVITY.push({ TYPE, DATA, TIMESTAMP: NOW });
    SUSPICIOUS_ACTIVITY_MAP.set(IDENTIFIER, ACTIVITY);
    
    console.log('SUSPICIOUS_ACTIVITY:', IDENTIFIER, TYPE, JSON.stringify(DATA));
    
    const RECENT = ACTIVITY.filter(A => NOW - A.TIMESTAMP < 300000);
    if (RECENT.length > 20) {
        if (IDENTIFIER.includes('.')) {
            BLACKLIST_IP(IDENTIFIER);
        }
    }
}

async function CONNECT_DB() {
    try {
        MONGOOSE.set('strictQuery', false);
        
        await MONGOOSE.connect(MONGO_URI, {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });

        DB_CONNECTED = true;
        console.log('MongoDB OK');

        MONGOOSE.connection.on('error', (ERROR) => {
            console.error('MongoDB ERROR:', ERROR);
            DB_CONNECTED = false;
        });

        MONGOOSE.connection.on('disconnected', () => {
            console.log('MongoDB NOOK');
            DB_CONNECTED = false;
            ATTEMPT_RECONNECT();
        });

    } catch (ERROR) {
        console.error('MongoDB initial connection error:', ERROR);
        DB_CONNECTED = false;
        setTimeout(ATTEMPT_RECONNECT, 5000);
    }
}

async function ATTEMPT_RECONNECT() {
    let ATTEMPTS = 0;
    const RECONNECT_INTERVAL = setInterval(async () => {
        if (DB_CONNECTED || ATTEMPTS >= MAX_RECONNECT_ATTEMPTS) {
            clearInterval(RECONNECT_INTERVAL);
            if (!DB_CONNECTED) {
                console.error('Failed to reconnect to MongoDB after max attempts');
                process.exit(1);
            }
            return;
        }

        console.log(`Attempting to reconnect to MongoDB (${ATTEMPTS + 1}/${MAX_RECONNECT_ATTEMPTS})...`);
        ATTEMPTS++;

        try {
            await MONGOOSE.connect(MONGO_URI);
            DB_CONNECTED = true;
            console.log('MongoDB REOK');
            clearInterval(RECONNECT_INTERVAL);
        } catch (ERROR) {
            console.error('Reconnection attempt failed:', ERROR.message);
        }
    }, 5000);
}

class SECURE_SESSION {
    constructor() {
        this.PRIVATE_KEY = null;
        this.PUBLIC_KEY = null;
        this.CLIENT_PUBLIC_KEY = null;
        this.PEER_ID = null;
        this.SESSION_ID = SECURE_RANDOM_BYTES(32).toString("hex");
        this.CREATED_AT = Date.now();
        this.LAST_ACTIVITY = Date.now();
        this.MESSAGE_COUNTER = 0;
        this.USER_ID = null;
        this.USERNAME = null;
        this.IS_AUTHENTICATED = false;
        this.SESSION_KEY = SECURE_RANDOM_BYTES(32);
        this.SIGNATURE_NONCE = SECURE_RANDOM_BYTES(16).toString('hex');
        this.CHALLENGE_RESPONSE_HASH = null;
        this.PACKET_SEQUENCE = 0;
        this.EXPECTED_SEQUENCE = 0;
        this.INTEGRITY_FAILURES = 0;
        this.LAST_ROTATION = Date.now();
        this.CONNECTION_FINGERPRINT = null;
        this.GENERATE_KEY_PAIR();
    }

    GENERATE_KEY_PAIR() {
        try {
            const { publicKey, privateKey } = CRYPTO.generateKeyPairSync("rsa", {
                modulusLength: MIN_KEY_SIZE,
                publicKeyEncoding: { type: "spki", format: "pem" },
                privateKeyEncoding: { type: "pkcs8", format: "pem" }
            });
            this.PUBLIC_KEY = publicKey;
            this.PRIVATE_KEY = privateKey;
        } catch (ERROR) {
            console.error("KEY_GENERATION_ERROR:", ERROR.message);
            throw new Error("FAILED_TO_GENERATE_KEYS");
        }
    }

    SET_CLIENT_PUBLIC_KEY(PUBLIC_KEY, PEER_ID) {
        if (!VALIDATE_PUBLIC_KEY(PUBLIC_KEY)) {
            throw new Error("INVALID_PUBLIC_KEY");
        }
        if (!PEER_ID || typeof PEER_ID !== 'string' || PEER_ID.length > 100) {
            throw new Error("INVALID_PEER_ID");
        }
        this.CLIENT_PUBLIC_KEY = PUBLIC_KEY;
        this.PEER_ID = SANITIZE_INPUT(PEER_ID, 100);
    }

    async SET_USER_INFO(USERNAME, USER_ID = null) {
        try {
            if (!VALIDATE_USERNAME(USERNAME)) {
                throw new Error("INVALID_USERNAME");
            }

            if (USER_ID && !VALIDATE_USER_ID(USER_ID)) {
                throw new Error("INVALID_USER_ID_FORMAT");
            }

            const USER = await HANDLE_USER_AUTH(USERNAME, this.CLIENT_PUBLIC_KEY, USER_ID);
            
            if (!USER) {
                throw new Error("USER_CREATION_FAILED");
            }

            this.USER_ID = USER.userId;
            this.USERNAME = USER.username;
            this.IS_AUTHENTICATED = true;

            await UPDATE_USER_STATUS(USER.userId, true);
            return USER;
        } catch (ERROR) {
            console.error("SET_USER_INFO_ERROR:", ERROR.message);
            throw ERROR;
        }
    }

    UPDATE_ACTIVITY() {
        this.LAST_ACTIVITY = Date.now();
        this.PACKET_SEQUENCE++;
    }

    IS_EXPIRED() {
        return Date.now() - this.CREATED_AT > SESSION_TIMEOUT;
    }

    IS_INACTIVE() {
        return Date.now() - this.LAST_ACTIVITY > MESSAGE_TIMEOUT;
    }

    SHOULD_ROTATE() {
        return Date.now() - this.LAST_ROTATION > SESSION_ROTATION_INTERVAL;
    }

    ROTATE_SESSION_KEY() {
        this.SESSION_KEY = SECURE_RANDOM_BYTES(32);
        this.LAST_ROTATION = Date.now();
        this.SIGNATURE_NONCE = SECURE_RANDOM_BYTES(16).toString('hex');
        console.log('SESSION_KEY_ROTATED:', this.SESSION_ID.substring(0, 16));
    }

    VERIFY_SEQUENCE(SEQUENCE) {
        if (SEQUENCE <= this.EXPECTED_SEQUENCE) {
            this.INTEGRITY_FAILURES++;
            LOG_SUSPICIOUS_ACTIVITY(this.SESSION_ID, 'SEQUENCE_VIOLATION', { 
                EXPECTED: this.EXPECTED_SEQUENCE, 
                RECEIVED: SEQUENCE 
            });
            return false;
        }
        this.EXPECTED_SEQUENCE = SEQUENCE;
        return true;
    }

    CHECK_INTEGRITY() {
        if (this.INTEGRITY_FAILURES > 5) {
            LOG_SUSPICIOUS_ACTIVITY(this.SESSION_ID, 'MULTIPLE_INTEGRITY_FAILURES', {
                COUNT: this.INTEGRITY_FAILURES
            });
            return false;
        }
        return true;
    }
}

function VERIFY_USER_ID_FORMAT(USER_ID) {
    return VALIDATE_USER_ID(USER_ID);
}

async function SEND_SECURE_MESSAGE(WS, MESSAGE_TYPE, DATA, SENDER_SESSION = null, RECIPIENT_SESSION = null) {
    try {
        if (!WS || WS.readyState !== WEBSOCKET_MODULE.OPEN) {
            console.error("WEBSOCKET_NOT_OPEN");
            return false;
        }

        if (!MESSAGE_TYPE || typeof MESSAGE_TYPE !== 'string') {
            throw new Error("INVALID_MESSAGE_TYPE");
        }

        const SESSION = CLIENT_SESSIONS.get(WS);
        
        const MESSAGE = {
            TYPE: MESSAGE_TYPE,
            DATA: DATA || {},
            TIMESTAMP: Date.now(),
            NONCE: SECURE_RANDOM_BYTES(16).toString('hex')
        };

        if (SESSION && SESSION.IS_AUTHENTICATED) {
            MESSAGE.SEQUENCE = SESSION.PACKET_SEQUENCE;
            MESSAGE.SIGNATURE = SIGN_DATA(MESSAGE, SESSION.PRIVATE_KEY);
        }

        if (!VALIDATE_MESSAGE_SIZE(MESSAGE)) {
            throw new Error("MESSAGE_TOO_LARGE");
        }

        WS.send(JSON.stringify(MESSAGE));

        if (MESSAGE_TYPE === 'MESSAGE' && SENDER_SESSION && RECIPIENT_SESSION && DATA.ENCRYPTED_PACKAGE && DATA.NONCE) {
            const SAVED_MESSAGE = await SAVE_MESSAGE_TO_DATABASE(
                SENDER_SESSION.USER_ID,
                RECIPIENT_SESSION.USER_ID,
                DATA.ENCRYPTED_PACKAGE,
                DATA.NONCE
            );
            
            if (SAVED_MESSAGE && SAVED_MESSAGE._id) {
                MESSAGE_ID_MAP.set(DATA.NONCE, SAVED_MESSAGE._id.toString());
            }
        }

        return true;
    } catch (ERROR) {
        console.error("SEND_MESSAGE_ERROR:", ERROR.message);
        return false;
    }
}

function HANDLE_HANDSHAKE(WS) {
    try {
        const SESSION = new SECURE_SESSION();
        CLIENT_SESSIONS.set(WS, SESSION);
        
        const CHALLENGE = SECURE_RANDOM_BYTES(32).toString("base64");
        const CHALLENGE_HASH = HASH_DATA(CHALLENGE);
        SESSION.CHALLENGE_RESPONSE_HASH = CHALLENGE_HASH;
        PENDING_MESSAGES.set(SESSION.SESSION_ID, CHALLENGE);
        
        setTimeout(() => {
            if (PENDING_MESSAGES.has(SESSION.SESSION_ID)) {
                PENDING_MESSAGES.delete(SESSION.SESSION_ID);
                if (!SESSION.IS_AUTHENTICATED) {
                    LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'HANDSHAKE_TIMEOUT', {});
                    WS.close(1008, "HANDSHAKE_TIMEOUT");
                }
            }
        }, HANDSHAKE_TIMEOUT);

        SEND_SECURE_MESSAGE(WS, "HANDSHAKE", {
            PUBLIC_KEY: SESSION.PUBLIC_KEY,
            SESSION_ID: SESSION.SESSION_ID,
            CHALLENGE: CHALLENGE,
            SIGNATURE_NONCE: SESSION.SIGNATURE_NONCE,
            SERVER_INFO: {
                PROTOCOL_VERSION: "2.0",
                SUPPORTED_CIPHERS: [CIPHER_SUITE],
                KEY_SIZE: MIN_KEY_SIZE,
                MAX_MESSAGE_SIZE: MAX_MESSAGE_SIZE,
                REQUIRE_SIGNATURE: SECURITY_CONFIG.REQUIRE_SIGNATURE,
                REPLAY_PROTECTION: SECURITY_CONFIG.ENABLE_REPLAY_PROTECTION
            }
        });
    } catch (ERROR) {
        console.error("HANDSHAKE_ERROR:", ERROR.message);
        SAFE_CLOSE_SOCKET(WS, 1011, "HANDSHAKE_FAILED");
    }
}

async function HANDLE_HANDSHAKE_RESPONSE(WS, MSG) {
    const SESSION = CLIENT_SESSIONS.get(WS);
    
    if (!SESSION) {
        SAFE_CLOSE_SOCKET(WS, 1008, "NO_SESSION");
        return;
    }

    try {
        if (!CHECK_RATE_LIMIT(SESSION.SESSION_ID, 5, 10000)) {
            LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'HANDSHAKE_RATE_LIMIT', {});
            SAFE_CLOSE_SOCKET(WS, 1008, "RATE_LIMIT_EXCEEDED");
            return;
        }

        const CHALLENGE = PENDING_MESSAGES.get(SESSION.SESSION_ID);
        
        if (!CHALLENGE) {
            LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'NO_CHALLENGE', {});
            SAFE_CLOSE_SOCKET(WS, 1008, "NO_CHALLENGE");
            return;
        }

        if (!MSG.CHALLENGE_RESPONSE || !MSG.PEER_PUBLIC_KEY || !MSG.PEER_ID) {
            LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'INVALID_HANDSHAKE_RESPONSE', {});
            SAFE_CLOSE_SOCKET(WS, 1008, "INVALID_RESPONSE");
            return;
        }

        if (SECURITY_CONFIG.REQUIRE_SIGNATURE && MSG.SIGNATURE) {
            const VERIFY_DATA = {
                CHALLENGE_RESPONSE: MSG.CHALLENGE_RESPONSE,
                PEER_PUBLIC_KEY: MSG.PEER_PUBLIC_KEY,
                PEER_ID: MSG.PEER_ID
            };
            if (!VERIFY_SIGNATURE(VERIFY_DATA, MSG.PEER_PUBLIC_KEY, MSG.SIGNATURE)) {
                LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'INVALID_SIGNATURE', {});
                SAFE_CLOSE_SOCKET(WS, 1008, "SIGNATURE_VERIFICATION_FAILED");
                return;
            }
        }

        let DECRYPTED_CHALLENGE;
        try {
            DECRYPTED_CHALLENGE = CRYPTO.privateDecrypt(
                {
                    key: SESSION.PRIVATE_KEY,
                    padding: CRYPTO.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256"
                },
                Buffer.from(MSG.CHALLENGE_RESPONSE, "base64")
            );
        } catch (DECRYPT_ERROR) {
            LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'CHALLENGE_DECRYPT_FAILED', {});
            SAFE_CLOSE_SOCKET(WS, 1008, "CHALLENGE_FAILED");
            return;
        }

        if (DECRYPTED_CHALLENGE.toString("base64") !== CHALLENGE) {
            LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'CHALLENGE_MISMATCH', {});
            RECORD_FAILED_AUTH(SESSION.SESSION_ID);
            SAFE_CLOSE_SOCKET(WS, 1008, "CHALLENGE_FAILED");
            return;
        }

        SESSION.SET_CLIENT_PUBLIC_KEY(MSG.PEER_PUBLIC_KEY, MSG.PEER_ID);
        
        if (MSG.USERNAME) {
            try {
                if (!CHECK_BRUTE_FORCE(MSG.USERNAME)) {
                    LOG_SUSPICIOUS_ACTIVITY(MSG.USERNAME, 'BRUTE_FORCE_DETECTED', {});
                    SAFE_CLOSE_SOCKET(WS, 1008, "TOO_MANY_ATTEMPTS");
                    return;
                }
                
                await SESSION.SET_USER_INFO(MSG.USERNAME, MSG.USER_ID);
            } catch (AUTH_ERROR) {
                RECORD_FAILED_AUTH(MSG.USERNAME);
                SEND_SECURE_MESSAGE(WS, "ERROR", {
                    CODE: "AUTHENTICATION_FAILED",
                    MESSAGE: AUTH_ERROR.message
                });
                SAFE_CLOSE_SOCKET(WS, 1008, "AUTH_FAILED");
                return;
            }
        }

        PENDING_MESSAGES.delete(SESSION.SESSION_ID);
        SESSION.UPDATE_ACTIVITY();
        
        console.log("CLIENT_AUTHENTICATED:", SESSION.SESSION_ID.substring(0, 16), "USER:", SESSION.USERNAME || "ANONYMOUS");
        
        SEND_SECURE_MESSAGE(WS, "AUTHENTICATED", {
            SESSION_ID: SESSION.SESSION_ID,
            USER_ID: SESSION.USER_ID,
            USERNAME: SESSION.USERNAME,
            STATUS: "SUCCESS",
            SESSION_KEY_ROTATION: SESSION_ROTATION_INTERVAL
        });

        if (SESSION.USER_ID) {
            const OFFLINE_MESSAGES = await GET_UNDELIVERED_MESSAGES(SESSION.USER_ID);
            if (OFFLINE_MESSAGES && OFFLINE_MESSAGES.length > 0) {
                SEND_SECURE_MESSAGE(WS, "OFFLINE_MESSAGES_AVAILABLE", {
                    COUNT: OFFLINE_MESSAGES.length
                });
            }
        }

    } catch (ERROR) {
        console.error("AUTHENTICATION_ERROR:", ERROR.message);
        LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'AUTHENTICATION_ERROR', { ERROR: ERROR.message });
        SAFE_CLOSE_SOCKET(WS, 1008, "AUTHENTICATION_ERROR");
    }
}

async function HANDLE_MESSAGE(WS, MSG) {
    const SESSION = CLIENT_SESSIONS.get(WS);
    
    if (!SESSION) {
        SAFE_CLOSE_SOCKET(WS, 1008, "NO_SESSION");
        return;
    }

    try {
        SESSION.UPDATE_ACTIVITY();

        if (!SESSION.CHECK_INTEGRITY()) {
            LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'INTEGRITY_CHECK_FAILED', {});
            SAFE_CLOSE_SOCKET(WS, 1008, "INTEGRITY_VIOLATION");
            return;
        }

        if (!SESSION.IS_AUTHENTICATED || !SESSION.USER_ID) {
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "NOT_AUTHENTICATED",
                MESSAGE: "USER_AUTHENTICATION_REQUIRED"
            });
            return;
        }

        if (!CHECK_RATE_LIMIT(SESSION.SESSION_ID, 50, 60000)) {
            LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'MESSAGE_RATE_LIMIT', {});
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "RATE_LIMIT_EXCEEDED",
                MESSAGE: "TOO_MANY_MESSAGES"
            });
            return;
        }

        if (!CHECK_GLOBAL_RATE_LIMIT()) {
            LOG_SUSPICIOUS_ACTIVITY('GLOBAL', 'GLOBAL_RATE_LIMIT', {});
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "RATE_LIMIT_EXCEEDED",
                MESSAGE: "SERVER_OVERLOAD"
            });
            return;
        }

        if (!MSG.RECIPIENT_ID || !MSG.ENCRYPTED_PACKAGE) {
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "INVALID_MESSAGE",
                MESSAGE: "MISSING_REQUIRED_FIELDS"
            });
            return;
        }

        const RECIPIENT_ID = SANITIZE_INPUT(MSG.RECIPIENT_ID, 100);
        let RECIPIENT_WS = null;
        let RECIPIENT_SESSION = null;

        for (const [CLIENT_WS, CLIENT_SESSION] of CLIENT_SESSIONS.entries()) {
            if ((CLIENT_SESSION.SESSION_ID === RECIPIENT_ID || CLIENT_SESSION.USER_ID === RECIPIENT_ID) 
                && CLIENT_SESSION.IS_AUTHENTICATED) {
                RECIPIENT_WS = CLIENT_WS;
                RECIPIENT_SESSION = CLIENT_SESSION;
                break;
            }
        }

        const MESSAGE_ID = SECURE_RANDOM_BYTES(16).toString("hex");
        const NONCE = MSG.NONCE || MESSAGE_ID;

        if (!VALIDATE_NONCE(NONCE)) {
            LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'INVALID_NONCE', { NONCE });
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "INVALID_NONCE",
                MESSAGE: "NONCE_FORMAT_INVALID"
            });
            return;
        }

        if (SECURITY_CONFIG.ENABLE_REPLAY_PROTECTION && NONCE_CACHE.has(NONCE)) {
            LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'REPLAY_ATTACK', { NONCE });
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "DUPLICATE_MESSAGE",
                MESSAGE: "MESSAGE_ALREADY_RECEIVED"
            });
            return;
        }

        NONCE_CACHE.add(NONCE);

        if (!RECIPIENT_WS || RECIPIENT_WS.readyState !== WEBSOCKET_MODULE.OPEN) {
            if (DB_CONNECTED) {
                const SAVED_MESSAGE = await SAVE_MESSAGE_TO_DATABASE(
                    SESSION.USER_ID,
                    RECIPIENT_ID,
                    MSG.ENCRYPTED_PACKAGE,
                    NONCE
                );

                if (SAVED_MESSAGE && SAVED_MESSAGE._id) {
                    MESSAGE_ID_MAP.set(NONCE, SAVED_MESSAGE._id.toString());
                }

                SEND_SECURE_MESSAGE(WS, "MESSAGE_QUEUED", {
                    MESSAGE_ID: MESSAGE_ID,
                    NONCE: NONCE,
                    STATUS: "RECIPIENT_OFFLINE",
                    TIMESTAMP: Date.now()
                });
            } else {
                SEND_SECURE_MESSAGE(WS, "ERROR", {
                    CODE: "RECIPIENT_UNAVAILABLE",
                    MESSAGE: "TARGET_CLIENT_NOT_CONNECTED_AND_DB_UNAVAILABLE"
                });
            }
            return;
        }

        const FORWARDED_PACKAGE = {
            ENCRYPTED_PACKAGE: MSG.ENCRYPTED_PACKAGE,
            SENDER_ID: SESSION.SESSION_ID,
            SENDER_USER_ID: SESSION.USER_ID,
            SENDER_PUBLIC_KEY: SESSION.CLIENT_PUBLIC_KEY,
            SENDER_PEER_ID: SESSION.PEER_ID,
            MESSAGE_ID: MESSAGE_ID,
            NONCE: NONCE
        };

        const SENT = await SEND_SECURE_MESSAGE(
            RECIPIENT_WS, 
            "MESSAGE", 
            FORWARDED_PACKAGE, 
            SESSION, 
            RECIPIENT_SESSION
        );

        if (SENT) {
            SEND_SECURE_MESSAGE(WS, "DELIVERY_CONFIRMATION", {
                MESSAGE_ID: MESSAGE_ID,
                NONCE: NONCE,
                STATUS: "DELIVERED",
                TIMESTAMP: Date.now()
            });

            if (DB_CONNECTED && MESSAGE_ID_MAP.has(NONCE)) {
                const DB_MESSAGE_ID = MESSAGE_ID_MAP.get(NONCE);
                await UPDATE_MESSAGE_STATUS(DB_MESSAGE_ID, 'delivered');
            }

            SESSION.MESSAGE_COUNTER++;
            console.log("MESSAGE_FORWARDED:", SESSION.USERNAME, "->", RECIPIENT_SESSION.USERNAME);
        } else {
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "DELIVERY_FAILED",
                MESSAGE: "FAILED_TO_DELIVER_MESSAGE"
            });
        }

    } catch (ERROR) {
        console.error("MESSAGE_HANDLING_ERROR:", ERROR.message);
        LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'MESSAGE_HANDLING_ERROR', { ERROR: ERROR.message });
        SEND_SECURE_MESSAGE(WS, "ERROR", {
            CODE: "MESSAGE_PROCESSING_FAILED",
            MESSAGE: "INTERNAL_SERVER_ERROR"
        });
    }
}

async function HANDLE_ACKNOWLEDGMENT(WS, MSG) {
    const SESSION = CLIENT_SESSIONS.get(WS);
    
    if (!SESSION || !SESSION.IS_AUTHENTICATED) {
        return;
    }

    try {
        SESSION.UPDATE_ACTIVITY();

        if (!MSG.MESSAGE_ID && !MSG.NONCE) {
            return;
        }

        if (DB_CONNECTED) {
            let DB_MESSAGE_ID = MSG.MESSAGE_ID;
            
            if (MSG.NONCE && MESSAGE_ID_MAP.has(MSG.NONCE)) {
                DB_MESSAGE_ID = MESSAGE_ID_MAP.get(MSG.NONCE);
            }
            
            if (DB_MESSAGE_ID && MONGOOSE.Types.ObjectId.isValid(DB_MESSAGE_ID)) {
                await UPDATE_MESSAGE_STATUS(DB_MESSAGE_ID, MSG.STATUS || 'read');
            }
        }

        if (MSG.ORIGINAL_SENDER_ID) {
            const SENDER_ID = SANITIZE_INPUT(MSG.ORIGINAL_SENDER_ID, 100);
            for (const [CLIENT_WS, CLIENT_SESSION] of CLIENT_SESSIONS.entries()) {
                if ((CLIENT_SESSION.SESSION_ID === SENDER_ID || 
                     CLIENT_SESSION.USER_ID === SENDER_ID) && 
                    CLIENT_WS.readyState === WEBSOCKET_MODULE.OPEN) {
                    
                    SEND_SECURE_MESSAGE(CLIENT_WS, "READ_RECEIPT", {
                        MESSAGE_ID: MSG.MESSAGE_ID,
                        NONCE: MSG.NONCE,
                        READ_BY: SESSION.SESSION_ID,
                        READ_BY_USER_ID: SESSION.USER_ID,
                        TIMESTAMP: Date.now()
                    });
                    break;
                }
            }
        }
    } catch (ERROR) {
        console.error("ACKNOWLEDGMENT_ERROR:", ERROR.message);
    }
}

async function HANDLE_USER_REGISTER(WS, MSG) {
    const SESSION = CLIENT_SESSIONS.get(WS);
    
    if (!SESSION) {
        SAFE_CLOSE_SOCKET(WS, 1008, "NO_SESSION");
        return;
    }

    try {
        SESSION.UPDATE_ACTIVITY();

        if (!CHECK_RATE_LIMIT(SESSION.SESSION_ID, 3, 60000)) {
            LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'REGISTRATION_RATE_LIMIT', {});
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "RATE_LIMIT_EXCEEDED",
                MESSAGE: "TOO_MANY_REGISTRATION_ATTEMPTS"
            });
            return;
        }

        if (!MSG.USERNAME || !SESSION.CLIENT_PUBLIC_KEY) {
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "INVALID_REQUEST",
                MESSAGE: "MISSING_REQUIRED_FIELDS"
            });
            return;
        }

        if (!CHECK_BRUTE_FORCE(MSG.USERNAME)) {
            LOG_SUSPICIOUS_ACTIVITY(MSG.USERNAME, 'REGISTRATION_BRUTE_FORCE', {});
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "TOO_MANY_ATTEMPTS",
                MESSAGE: "PLEASE_TRY_AGAIN_LATER"
            });
            return;
        }

        const USER = await SESSION.SET_USER_INFO(MSG.USERNAME, MSG.USER_ID);
        
        SEND_SECURE_MESSAGE(WS, "USER_REGISTERED", {
            USER_ID: USER.userId,
            USERNAME: USER.username,
            STATUS: "SUCCESS"
        });

    } catch (ERROR) {
        console.error("USER_REGISTER_ERROR:", ERROR.message);
        RECORD_FAILED_AUTH(MSG.USERNAME || SESSION.SESSION_ID);
        
        let ERROR_MESSAGE = "REGISTRATION_FAILED";
        if (ERROR.message === "USERNAME_ALREADY_EXISTS") {
            ERROR_MESSAGE = "USERNAME_TAKEN";
        } else if (ERROR.message === "INVALID_USERNAME") {
            ERROR_MESSAGE = "INVALID_USERNAME_FORMAT";
        }

        SEND_SECURE_MESSAGE(WS, "ERROR", {
            CODE: "REGISTRATION_FAILED",
            MESSAGE: ERROR_MESSAGE
        });
    }
}

async function HANDLE_GET_OFFLINE_MESSAGES(WS, MSG) {
    const SESSION = CLIENT_SESSIONS.get(WS);
    
    if (!SESSION || !SESSION.IS_AUTHENTICATED || !SESSION.USER_ID) {
        SEND_SECURE_MESSAGE(WS, "ERROR", {
            CODE: "NOT_AUTHENTICATED",
            MESSAGE: "USER_AUTHENTICATION_REQUIRED"
        });
        return;
    }

    try {
        SESSION.UPDATE_ACTIVITY();

        if (!DB_CONNECTED) {
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "SERVICE_UNAVAILABLE",
                MESSAGE: "DATABASE_CONNECTION_UNAVAILABLE"
            });
            return;
        }

        const MESSAGES = await GET_UNDELIVERED_MESSAGES(SESSION.USER_ID);

        SEND_SECURE_MESSAGE(WS, "OFFLINE_MESSAGES", {
            COUNT: MESSAGES.length,
            MESSAGES: MESSAGES.map(MSG => {
                const DB_ID = MSG._id.toString();
                if (MSG.nonce) {
                    MESSAGE_ID_MAP.set(MSG.nonce, DB_ID);
                }
                
                return {
                    MESSAGE_ID: DB_ID,
                    SENDER_ID: MSG.sender,
                    ENCRYPTED_CONTENT: MSG.encryptedContent,
                    NONCE: MSG.nonce,
                    TIMESTAMP: MSG.timestamp
                };
            })
        });

        for (const MESSAGE of MESSAGES) {
            await MESSAGE.MARK_DELIVERED();
        }

        console.log("OFFLINE_MESSAGES_DELIVERED:", SESSION.USERNAME, "COUNT:", MESSAGES.length);

    } catch (ERROR) {
        console.error("GET_OFFLINE_MESSAGES_ERROR:", ERROR.message);
        SEND_SECURE_MESSAGE(WS, "ERROR", {
            CODE: "FETCH_MESSAGES_FAILED",
            MESSAGE: "FAILED_TO_RETRIEVE_MESSAGES"
        });
    }
}

async function HANDLE_HEARTBEAT(WS, MSG) {
    const SESSION = CLIENT_SESSIONS.get(WS);
    
    if (!SESSION) {
        return;
    }

    try {
        SESSION.UPDATE_ACTIVITY();
        
        if (SESSION.SHOULD_ROTATE()) {
            SESSION.ROTATE_SESSION_KEY();
            SEND_SECURE_MESSAGE(WS, "SESSION_KEY_ROTATED", {
                TIMESTAMP: Date.now(),
                NEW_NONCE: SESSION.SIGNATURE_NONCE
            });
        }
        
        SEND_SECURE_MESSAGE(WS, "HEARTBEAT_ACK", {
            TIMESTAMP: Date.now()
        });
    } catch (ERROR) {
        console.error("HEARTBEAT_ERROR:", ERROR.message);
    }
}

function SAFE_CLOSE_SOCKET(WS, CODE, REASON) {
    try {
        if (WS && WS.readyState === WEBSOCKET_MODULE.OPEN) {
            WS.close(CODE, REASON);
        }
    } catch (ERROR) {
        console.error("SAFE_CLOSE_ERROR:", ERROR.message);
    }
}

async function HANDLE_GET_USER_PUBLIC(WS, MSG) {
    const SESSION = CLIENT_SESSIONS.get(WS);
    if (!SESSION || !SESSION.IS_AUTHENTICATED) {
        SEND_SECURE_MESSAGE(WS, "ERROR", {
            CODE: "NOT_AUTHENTICATED",
            MESSAGE: "USER_AUTHENTICATION_REQUIRED"
        });
        return;
    }
    try {
        SESSION.UPDATE_ACTIVITY();
        
        if (!MSG.USER_ID) {
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "INVALID_REQUEST",
                MESSAGE: "MISSING_USER_ID"
            });
            return;
        }
        
        if (!VALIDATE_USER_ID(MSG.USER_ID)) {
            LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'INVALID_USER_ID_REQUEST', { USER_ID: MSG.USER_ID });
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "INVALID_REQUEST",
                MESSAGE: "INVALID_USER_ID_FORMAT"
            });
            return;
        }
        
        const USER = await GET_USER_BY_ID(MSG.USER_ID);
        if (!USER) {
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "USER_NOT_FOUND",
                MESSAGE: "NO_USER_WITH_GIVEN_ID"
            });
            return;
        }
        
        SEND_SECURE_MESSAGE(WS, "USER_PUBLIC_KEY", {
            USER_ID: USER.userId,
            USERNAME: USER.username,
            PUBLIC_KEY: USER.publicKey
        });
    } catch (ERROR) {
        console.error("GET_USER_PUBLIC_ERROR:", ERROR.message);
        SEND_SECURE_MESSAGE(WS, "ERROR", {
            CODE: "FETCH_PUBLIC_KEY_FAILED",
            MESSAGE: "FAILED_TO_RETRIEVE_PUBLIC_KEY"
        });     
    }
}

async function CLEANUP_SESSION(WS) {
    const SESSION = CLIENT_SESSIONS.get(WS);
    
    if (SESSION) {
        try {
            if (SESSION.USER_ID && DB_CONNECTED) {
                await UPDATE_USER_STATUS(SESSION.USER_ID, false);
            }
            
            CLIENT_SESSIONS.delete(WS);
            PENDING_MESSAGES.delete(SESSION.SESSION_ID);
            RATE_LIMIT_MAP.delete(SESSION.SESSION_ID);
            SESSION_ROTATION_MAP.delete(SESSION.SESSION_ID);
            SIGNATURE_CACHE.delete(SESSION.SESSION_ID);
            
            console.log("SESSION_CLEANED:", SESSION.SESSION_ID.substring(0, 16), "USER:", SESSION.USERNAME || "ANONYMOUS");
        } catch (ERROR) {
            console.error("CLEANUP_ERROR:", ERROR.message);
        }
    }
}

function INITIALIZE_WEBSOCKET_SERVER() {
    try {
        WSS = new WEBSOCKET_MODULE.Server({ 
            port: PORT,
            maxPayload: MAX_MESSAGE_SIZE,
            clientTracking: true,
            perMessageDeflate: false,
            verifyClient: (INFO, CALLBACK) => {
                const IP = INFO.req.socket.remoteAddress;
                
                if (IS_IP_BLACKLISTED(IP)) {
                    LOG_SUSPICIOUS_ACTIVITY(IP, 'BLACKLISTED_CONNECTION_ATTEMPT', {});
                    CALLBACK(false, 403, 'FORBIDDEN');
                    return;
                }
                
                if (!CHECK_IP_LIMIT(IP)) {
                    LOG_SUSPICIOUS_ACTIVITY(IP, 'IP_CONNECTION_LIMIT', {});
                    CALLBACK(false, 429, 'TOO_MANY_CONNECTIONS');
                    return;
                }
                
                CALLBACK(true);
            }
        });

        WSS.on("connection", (SOCKET, REQUEST) => {
            const IP = REQUEST.socket.remoteAddress;
            console.log("NEW_CONNECTION:", IP);
            INCREMENT_IP_CONNECTIONS(IP);

            SOCKET.on("message", async (RAW_MSG) => {
                try {
                    if (RAW_MSG.length > MAX_MESSAGE_SIZE) {
                        LOG_SUSPICIOUS_ACTIVITY(IP, 'OVERSIZED_MESSAGE', { SIZE: RAW_MSG.length });
                        SAFE_CLOSE_SOCKET(SOCKET, 1009, "MESSAGE_TOO_LARGE");
                        return;
                    }

                    const MSG = JSON.parse(RAW_MSG);
                    
                    if (!MSG.TYPE) {
                        throw new Error("MISSING_MESSAGE_TYPE");
                    }

                    const SESSION = CLIENT_SESSIONS.get(SOCKET);
                    
                    if (SESSION && SESSION.IS_AUTHENTICATED && SECURITY_CONFIG.REQUIRE_SIGNATURE) {
                        if (MSG.SIGNATURE && MSG.SEQUENCE) {
                            const VERIFY_DATA = {
                                TYPE: MSG.TYPE,
                                DATA: MSG.DATA,
                                TIMESTAMP: MSG.TIMESTAMP,
                                NONCE: MSG.NONCE
                            };
                            
                            if (!VERIFY_SIGNATURE(VERIFY_DATA, SESSION.CLIENT_PUBLIC_KEY, MSG.SIGNATURE)) {
                                LOG_SUSPICIOUS_ACTIVITY(SESSION.SESSION_ID, 'INVALID_MESSAGE_SIGNATURE', {});
                                SESSION.INTEGRITY_FAILURES++;
                                return;
                            }
                            
                            if (!SESSION.VERIFY_SEQUENCE(MSG.SEQUENCE)) {
                                return;
                            }
                        }
                    }

                    switch (MSG.TYPE) {
                        case "HANDSHAKE_REQUEST":
                            HANDLE_HANDSHAKE(SOCKET);
                            break;
                        case "HANDSHAKE_RESPONSE":
                            await HANDLE_HANDSHAKE_RESPONSE(SOCKET, MSG.DATA);
                            break;
                        case "MESSAGE":
                            await HANDLE_MESSAGE(SOCKET, MSG.DATA);
                            break;
                        case "ACKNOWLEDGMENT":
                            await HANDLE_ACKNOWLEDGMENT(SOCKET, MSG.DATA);
                            break;
                        case "USER_REGISTER":
                            await HANDLE_USER_REGISTER(SOCKET, MSG.DATA);
                            break;
                        case "GET_OFFLINE_MESSAGES":
                            await HANDLE_GET_OFFLINE_MESSAGES(SOCKET, MSG.DATA);
                            break;
                        case "HEARTBEAT":
                            await HANDLE_HEARTBEAT(SOCKET, MSG.DATA);
                            break;
                        case "GET_USER_PUBLIC":
                            await HANDLE_GET_USER_PUBLIC(SOCKET, MSG.DATA);
                            break;
                        default:
                            LOG_SUSPICIOUS_ACTIVITY(SESSION ? SESSION.SESSION_ID : IP, 'UNKNOWN_MESSAGE_TYPE', { TYPE: MSG.TYPE });
                            SEND_SECURE_MESSAGE(SOCKET, "ERROR", {
                                CODE: "UNKNOWN_MESSAGE_TYPE",
                                MESSAGE: "UNSUPPORTED_OPERATION"
                            });
                    }
                } catch (ERROR) {
                    console.error("MESSAGE_PROCESSING_ERROR:", ERROR.message);
                    LOG_SUSPICIOUS_ACTIVITY(IP, 'MESSAGE_PROCESSING_ERROR', { ERROR: ERROR.message });
                    SEND_SECURE_MESSAGE(SOCKET, "ERROR", {
                        CODE: "PROCESSING_ERROR",
                        MESSAGE: "INVALID_MESSAGE_FORMAT"
                    });
                }
            });

            SOCKET.on("close", async () => {
                DECREMENT_IP_CONNECTIONS(IP);
                await CLEANUP_SESSION(SOCKET);
            });

            SOCKET.on("error", async (ERROR) => {
                console.error("SOCKET_ERROR:", ERROR.message);
                DECREMENT_IP_CONNECTIONS(IP);
                await CLEANUP_SESSION(SOCKET);
            });
        });

        WSS.on("error", (ERROR) => {
            console.error("WSS_ERROR:", ERROR.message);
        });

        console.log("WEBSOCKET_SERVER_STARTED");
        console.log("PORT:", PORT);
        console.log("SECURITY_FEATURES_ENABLED");

    } catch (ERROR) {
        console.error("WSS_INITIALIZATION_ERROR:", ERROR.message);
        process.exit(1);
    }
}

setInterval(() => {
    const NOW = Date.now();
    for (const [WS, SESSION] of CLIENT_SESSIONS.entries()) {
        if (SESSION.IS_EXPIRED()) {
            console.log("SESSION_EXPIRED:", SESSION.SESSION_ID.substring(0, 16));
            SAFE_CLOSE_SOCKET(WS, 1000, "SESSION_EXPIRED");
            CLEANUP_SESSION(WS);
        } else if (SESSION.IS_INACTIVE()) {
            console.log("SESSION_INACTIVE:", SESSION.SESSION_ID.substring(0, 16));
            SAFE_CLOSE_SOCKET(WS, 1000, "INACTIVE_SESSION");
            CLEANUP_SESSION(WS);
        }
    }
}, 60000);

setInterval(() => {
    if (NONCE_CACHE.size > MAX_NONCE_CACHE) {
        NONCE_CACHE.clear();
        console.log("NONCE_CACHE_CLEARED");
    }
}, 300000);

setInterval(() => {
    const NOW = Date.now();
    for (const [SESSION_ID, REQUESTS] of RATE_LIMIT_MAP.entries()) {
        const RECENT = REQUESTS.filter(TIME => NOW - TIME < 60000);
        if (RECENT.length === 0) {
            RATE_LIMIT_MAP.delete(SESSION_ID);
        } else {
            RATE_LIMIT_MAP.set(SESSION_ID, RECENT);
        }
    }
}, 120000);

setInterval(() => {
    MESSAGE_ID_MAP.clear();
    console.log("MESSAGE_ID_MAP_CLEARED");
}, 1800000);

setInterval(() => {
    SIGNATURE_CACHE.clear();
    console.log("SIGNATURE_CACHE_CLEARED");
}, 1800000);

setInterval(() => {
    const NOW = Date.now();
    for (const [IDENTIFIER, ATTEMPTS] of FAILED_AUTH_MAP.entries()) {
        const RECENT = ATTEMPTS.filter(T => NOW - T < BRUTE_FORCE_WINDOW);
        if (RECENT.length === 0) {
            FAILED_AUTH_MAP.delete(IDENTIFIER);
        } else {
            FAILED_AUTH_MAP.set(IDENTIFIER, RECENT);
        }
    }
    console.log("FAILED_AUTH_CLEANUP");
}, 300000);

setInterval(() => {
    const NOW = Date.now();
    for (const [IDENTIFIER, ACTIVITIES] of SUSPICIOUS_ACTIVITY_MAP.entries()) {
        const RECENT = ACTIVITIES.filter(A => NOW - A.TIMESTAMP < 3600000);
        if (RECENT.length === 0) {
            SUSPICIOUS_ACTIVITY_MAP.delete(IDENTIFIER);
        } else {
            SUSPICIOUS_ACTIVITY_MAP.set(IDENTIFIER, RECENT);
        }
    }
    console.log("SUSPICIOUS_ACTIVITY_CLEANUP");
}, 600000);

if (DB_CONNECTED) {
    setInterval(async () => {
        try {
            const DELETED = await DELETE_OLD_MESSAGES();
            if (DELETED > 0) {
                console.log("OLD_MESSAGES_DELETED:", DELETED);
            }
        } catch (ERROR) {
            console.error("DELETE_OLD_MESSAGES_ERROR:", ERROR.message);
        }
    }, 86400000);
}

process.on('SIGINT', async () => {
    console.log('SHUTTING_DOWN_SERVER...');
    
    for (const [WS, SESSION] of CLIENT_SESSIONS.entries()) {
        SAFE_CLOSE_SOCKET(WS, 1001, "SERVER_SHUTDOWN");
    }
    
    if (WSS) {
        WSS.close(() => {
            console.log('WEBSOCKET_SERVER_CLOSED');
        });
    }
    
    if (DB_CONNECTED) {
        await MONGOOSE.connection.close();
        console.log('MONGODB_CONNECTION_CLOSED');
    }
    
    process.exit(0);
});

process.on('uncaughtException', (ERROR) => {
    console.error('UNCAUGHT_EXCEPTION:', ERROR);
});

process.on('unhandledRejection', (REASON, PROMISE) => {
    console.error('UNHANDLED_REJECTION:', REASON);
});

CONNECT_DB().then(() => {
    INITIALIZE_WEBSOCKET_SERVER();
}).catch((ERROR) => {
    console.error('STARTUP_ERROR:', ERROR);
    process.exit(1);
});