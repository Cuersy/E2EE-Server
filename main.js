/*
 * @Author: Cuersy 
 * @Date: 2025-10-03 18:23:22 
 * @Last Modified by: Cuersy
 * @Last Modified time: 2025-10-03 18:32:51
 */


const WEBSOCKET_MODULE = require("ws");
const CRYPTO = require("crypto");
const MONGOOSE = require("mongoose");

const { 
    SAVE_MESSAGE_TO_DATABASE, 
    UPDATE_MESSAGE_STATUS, 
    UPDATE_USER_STATUS,
    GET_UNDELIVERED_MESSAGES,
    GET_USER_BY_ID,
    DELETE_OLD_MESSAGES
} = require('./models/dbHelpers');
const { HANDLE_USER_AUTH } = require('./models/authHelpers');

const MONGO_URI = process.env.MONGO_URI || 'idk';
const PORT = process.env.PORT || 8080;
const SESSION_TIMEOUT = 3600000;
const MESSAGE_TIMEOUT = 300000;
const MAX_NONCE_CACHE = 10000;
const MAX_MESSAGE_SIZE = 1048576;
const MAX_RECONNECT_ATTEMPTS = 5;

const CLIENT_SESSIONS = new Map();
const PENDING_MESSAGES = new Map();
const NONCE_CACHE = new Set();
const RATE_LIMIT_MAP = new Map();
const MESSAGE_ID_MAP = new Map();

let WSS = null;
let DB_CONNECTED = false;

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
        this.SESSION_ID = CRYPTO.randomBytes(32).toString("hex");
        this.CREATED_AT = Date.now();
        this.LAST_ACTIVITY = Date.now();
        this.MESSAGE_COUNTER = 0;
        this.USER_ID = null;
        this.USERNAME = null;
        this.IS_AUTHENTICATED = false;
        this.GENERATE_KEY_PAIR();
    }

    GENERATE_KEY_PAIR() {
        try {
            const { publicKey, privateKey } = CRYPTO.generateKeyPairSync("rsa", {
                modulusLength: 4096,
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
        if (!PUBLIC_KEY || typeof PUBLIC_KEY !== 'string') {
            throw new Error("INVALID_PUBLIC_KEY");
        }
        if (!PEER_ID || typeof PEER_ID !== 'string') {
            throw new Error("INVALID_PEER_ID");
        }
        this.CLIENT_PUBLIC_KEY = PUBLIC_KEY;
        this.PEER_ID = PEER_ID;
    }

    async SET_USER_INFO(USERNAME, USER_ID = null) {
        try {
            if (!USERNAME || typeof USERNAME !== 'string' || USERNAME.length < 3 || USERNAME.length > 32) {
                throw new Error("INVALID_USERNAME");
            }

            if (USER_ID && !VERIFY_USER_ID_FORMAT(USER_ID)) {
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
    }

    IS_EXPIRED() {
        return Date.now() - this.CREATED_AT > SESSION_TIMEOUT;
    }

    IS_INACTIVE() {
        return Date.now() - this.LAST_ACTIVITY > MESSAGE_TIMEOUT;
    }
}

function VERIFY_USER_ID_FORMAT(USER_ID) {
    return typeof USER_ID === 'string' && /^[a-f0-9]{32}$/.test(USER_ID);
}

function CHECK_RATE_LIMIT(SESSION_ID, LIMIT = 50, WINDOW = 60000) {
    const NOW = Date.now();
    const USER_REQUESTS = RATE_LIMIT_MAP.get(SESSION_ID) || [];
    
    const RECENT_REQUESTS = USER_REQUESTS.filter(TIME => NOW - TIME < WINDOW);
    
    if (RECENT_REQUESTS.length >= LIMIT) {
        return false;
    }
    
    RECENT_REQUESTS.push(NOW);
    RATE_LIMIT_MAP.set(SESSION_ID, RECENT_REQUESTS);
    return true;
}

function VALIDATE_MESSAGE_SIZE(DATA) {
    try {
        const SIZE = Buffer.byteLength(JSON.stringify(DATA));
        return SIZE <= MAX_MESSAGE_SIZE;
    } catch (ERROR) {
        return false;
    }
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

        const MESSAGE = {
            TYPE: MESSAGE_TYPE,
            DATA: DATA || {},
            TIMESTAMP: Date.now()
        };

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
        
        const CHALLENGE = CRYPTO.randomBytes(32).toString("base64");
        PENDING_MESSAGES.set(SESSION.SESSION_ID, CHALLENGE);
        
        setTimeout(() => {
            if (PENDING_MESSAGES.has(SESSION.SESSION_ID)) {
                PENDING_MESSAGES.delete(SESSION.SESSION_ID);
                if (!SESSION.IS_AUTHENTICATED) {
                    WS.close(1008, "HANDSHAKE_TIMEOUT");
                }
            }
        }, 30000);

        SEND_SECURE_MESSAGE(WS, "HANDSHAKE", {
            PUBLIC_KEY: SESSION.PUBLIC_KEY,
            SESSION_ID: SESSION.SESSION_ID,
            CHALLENGE: CHALLENGE,
            SERVER_INFO: {
                PROTOCOL_VERSION: "2.0",
                SUPPORTED_CIPHERS: ["AES-256-GCM"],
                KEY_SIZE: 4096,
                MAX_MESSAGE_SIZE: MAX_MESSAGE_SIZE
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
            SAFE_CLOSE_SOCKET(WS, 1008, "RATE_LIMIT_EXCEEDED");
            return;
        }

        const CHALLENGE = PENDING_MESSAGES.get(SESSION.SESSION_ID);
        
        if (!CHALLENGE) {
            SAFE_CLOSE_SOCKET(WS, 1008, "NO_CHALLENGE");
            return;
        }

        if (!MSG.CHALLENGE_RESPONSE || !MSG.PEER_PUBLIC_KEY || !MSG.PEER_ID) {
            SAFE_CLOSE_SOCKET(WS, 1008, "INVALID_RESPONSE");
            return;
        }

        const DECRYPTED_CHALLENGE = CRYPTO.privateDecrypt(
            {
                key: SESSION.PRIVATE_KEY,
                padding: CRYPTO.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            },
            Buffer.from(MSG.CHALLENGE_RESPONSE, "base64")
        );

        if (DECRYPTED_CHALLENGE.toString("base64") !== CHALLENGE) {
            SAFE_CLOSE_SOCKET(WS, 1008, "CHALLENGE_FAILED");
            return;
        }

        SESSION.SET_CLIENT_PUBLIC_KEY(MSG.PEER_PUBLIC_KEY, MSG.PEER_ID);
        
        if (MSG.USERNAME) {
            try {
                await SESSION.SET_USER_INFO(MSG.USERNAME, MSG.USER_ID);
            } catch (AUTH_ERROR) {
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
            STATUS: "SUCCESS"
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

        if (!SESSION.IS_AUTHENTICATED || !SESSION.USER_ID) {
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "NOT_AUTHENTICATED",
                MESSAGE: "USER_AUTHENTICATION_REQUIRED"
            });
            return;
        }

        if (!CHECK_RATE_LIMIT(SESSION.SESSION_ID, 50, 60000)) {
            SEND_SECURE_MESSAGE(WS, "ERROR", {
                CODE: "RATE_LIMIT_EXCEEDED",
                MESSAGE: "TOO_MANY_MESSAGES"
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

        const RECIPIENT_ID = MSG.RECIPIENT_ID;
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

        const MESSAGE_ID = CRYPTO.randomBytes(16).toString("hex");
        const NONCE = MSG.NONCE || MESSAGE_ID;

        if (NONCE_CACHE.has(NONCE)) {
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
            for (const [CLIENT_WS, CLIENT_SESSION] of CLIENT_SESSIONS.entries()) {
                if ((CLIENT_SESSION.SESSION_ID === MSG.ORIGINAL_SENDER_ID || 
                     CLIENT_SESSION.USER_ID === MSG.ORIGINAL_SENDER_ID) && 
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

        const USER = await SESSION.SET_USER_INFO(MSG.USERNAME, MSG.USER_ID);
        
        SEND_SECURE_MESSAGE(WS, "USER_REGISTERED", {
            USER_ID: USER.userId,
            USERNAME: USER.username,
            STATUS: "SUCCESS"
        });

    } catch (ERROR) {
        console.error("USER_REGISTER_ERROR:", ERROR.message);
        
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
try{
    SESSION.UPDATE_ACTIVITY();
    if (!MSG.USER_ID) {
        SEND_SECURE_MESSAGE(WS, "ERROR", {
            CODE: "INVALID_REQUEST",
            MESSAGE: "MISSING_USER_ID"
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
}catch (ERROR) {
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
            clientTracking: true
        });

        WSS.on("connection", (SOCKET, REQUEST) => {
            console.log("NEW_CONNECTION:", REQUEST.socket.remoteAddress);

            SOCKET.on("message", async (RAW_MSG) => {
                try {
                    if (RAW_MSG.length > MAX_MESSAGE_SIZE) {
                        SAFE_CLOSE_SOCKET(SOCKET, 1009, "MESSAGE_TOO_LARGE");
                        return;
                    }

                    const MSG = JSON.parse(RAW_MSG);
                    
                    if (!MSG.TYPE) {
                        throw new Error("MISSING_MESSAGE_TYPE");
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
                            SEND_SECURE_MESSAGE(SOCKET, "ERROR", {
                                CODE: "UNKNOWN_MESSAGE_TYPE",
                                MESSAGE: "UNSUPPORTED_OPERATION"
                            });
                    }
                } catch (ERROR) {
                    console.error("MESSAGE_PROCESSING_ERROR:", ERROR.message);
                    SEND_SECURE_MESSAGE(SOCKET, "ERROR", {
                        CODE: "PROCESSING_ERROR",
                        MESSAGE: "INVALID_MESSAGE_FORMAT"
                    });
                }
            });

            SOCKET.on("close", async () => {
                await CLEANUP_SESSION(SOCKET);
            });

            SOCKET.on("error", async (ERROR) => {
                console.error("SOCKET_ERROR:", ERROR.message);
                await CLEANUP_SESSION(SOCKET);
            });
        });

        WSS.on("error", (ERROR) => {
            console.error("WSS_ERROR:", ERROR.message);
        });

        console.log("WEBSOCKET_SERVER_STARTED");
        console.log("PORT:", PORT);

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