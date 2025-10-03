const WEBSOCKET = require("ws");
const CRYPTO = require("crypto");
const READLINE = require("readline");

const SERVER_URL = "ws://localhost:8080";
const RECONNECT_INTERVAL = 5000;
const HEARTBEAT_INTERVAL = 30000;
const MESSAGE_TIMEOUT = 10000;

let WS = null;
let SESSION_ID = null;
let USER_ID = null;
let USERNAME = null;
let SERVER_PUBLIC_KEY = null;
let CLIENT_PRIVATE_KEY = null;
let CLIENT_PUBLIC_KEY = null;
let PEER_ID = null;
let IS_AUTHENTICATED = false;
let RECONNECT_ATTEMPTS = 0;
let MAX_RECONNECT_ATTEMPTS = 5;
let HEARTBEAT_TIMER = null;
let PENDING_MESSAGES = new Map();
let OFFLINE_MODE = false;

const RL = READLINE.createInterface({
    input: process.stdin,
    output: process.stdout
});

function GENERATE_KEY_PAIR() {
    try {
        const { publicKey, privateKey } = CRYPTO.generateKeyPairSync("rsa", {
            modulusLength: 4096,
            publicKeyEncoding: { type: "spki", format: "pem" },
            privateKeyEncoding: { type: "pkcs8", format: "pem" }
        });
        CLIENT_PUBLIC_KEY = publicKey;
        CLIENT_PRIVATE_KEY = privateKey;
        PEER_ID = CRYPTO.randomBytes(16).toString("hex");
        console.log("KEY_PAIR_GENERATED");
    } catch (ERROR) {
        console.error("KEY_GENERATION_ERROR:", ERROR.message);
        process.exit(1);
    }
}

function ENCRYPT_MESSAGE(MESSAGE, RECIPIENT_PUBLIC_KEY) {
    try {
        const ENCRYPTED = CRYPTO.publicEncrypt(
            {
                key: RECIPIENT_PUBLIC_KEY,
                padding: CRYPTO.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            },
            Buffer.from(MESSAGE)
        );
        return ENCRYPTED.toString("base64");
    } catch (ERROR) {
        console.error("ENCRYPTION_ERROR:", ERROR.message);
        return null;
    }
}

function DECRYPT_MESSAGE(ENCRYPTED_MESSAGE, PRIVATE_KEY) {
    try {
        const DECRYPTED = CRYPTO.privateDecrypt(
            {
                key: PRIVATE_KEY,
                padding: CRYPTO.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            },
            Buffer.from(ENCRYPTED_MESSAGE, "base64")
        );
        return DECRYPTED.toString("utf8");
    } catch (ERROR) {
        console.error("DECRYPTION_ERROR:", ERROR.message);
        return null;
    }
}

function SEND_MESSAGE(TYPE, DATA) {
    if (!WS || WS.readyState !== WEBSOCKET.OPEN) {
        console.error("WEBSOCKET_NOT_CONNECTED");
        return false;
    }

    try {
        const MESSAGE = {
            TYPE: TYPE,
            DATA: DATA || {},
            TIMESTAMP: Date.now()
        };
        WS.send(JSON.stringify(MESSAGE));
        return true;
    } catch (ERROR) {
        console.error("SEND_ERROR:", ERROR.message);
        return false;
    }
}

function HANDLE_HANDSHAKE(MSG) {
    try {
        SERVER_PUBLIC_KEY = MSG.PUBLIC_KEY;
        SESSION_ID = MSG.SESSION_ID;
        
        console.log("HANDSHAKE_RECEIVED");
        console.log("SESSION_ID:", SESSION_ID.substring(0, 16));
        console.log("PROTOCOL_VERSION:", MSG.SERVER_INFO.PROTOCOL_VERSION);

        const CHALLENGE_RESPONSE = ENCRYPT_MESSAGE(MSG.CHALLENGE, SERVER_PUBLIC_KEY);
        
        if (!CHALLENGE_RESPONSE) {
            console.error("CHALLENGE_ENCRYPTION_FAILED");
            return;
        }

        SEND_MESSAGE("HANDSHAKE_RESPONSE", {
            CHALLENGE_RESPONSE: CHALLENGE_RESPONSE,
            PEER_PUBLIC_KEY: CLIENT_PUBLIC_KEY,
            PEER_ID: PEER_ID,
            USERNAME: USERNAME,
            USER_ID: USER_ID
        });

    } catch (ERROR) {
        console.error("HANDSHAKE_ERROR:", ERROR.message);
    }
}

function HANDLE_AUTHENTICATED(MSG) {
    IS_AUTHENTICATED = true;
    SESSION_ID = MSG.SESSION_ID;
    USER_ID = MSG.USER_ID;
    USERNAME = MSG.USERNAME;
    
    console.log("AUTHENTICATED_SUCCESSFULLY");
    console.log("USER_ID:", USER_ID);
    console.log("USERNAME:", USERNAME);
    
    START_HEARTBEAT();
    
    SEND_MESSAGE("GET_OFFLINE_MESSAGES", {});
    
    SHOW_MENU();
}

function HANDLE_MESSAGE(MSG) {
    try {
        const DECRYPTED = DECRYPT_MESSAGE(MSG.ENCRYPTED_PACKAGE, CLIENT_PRIVATE_KEY);
        
        if (!DECRYPTED) {
            console.error("MESSAGE_DECRYPTION_FAILED");
            return;
        }

        console.log("\n");
        console.log("NEW_MESSAGE_FROM:", MSG.SENDER_USER_ID || MSG.SENDER_ID);
        console.log("MESSAGE:", DECRYPTED);
        console.log("TIMESTAMP:", new Date(MSG.TIMESTAMP || Date.now()).toISOString());
        console.log("\n");

        SEND_MESSAGE("ACKNOWLEDGMENT", {
            MESSAGE_ID: MSG.MESSAGE_ID,
            NONCE: MSG.NONCE,
            STATUS: "read",
            ORIGINAL_SENDER_ID: MSG.SENDER_USER_ID || MSG.SENDER_ID
        });

        SHOW_PROMPT();

    } catch (ERROR) {
        console.error("MESSAGE_HANDLING_ERROR:", ERROR.message);
    }
}

function HANDLE_DELIVERY_CONFIRMATION(MSG) {
    console.log("MESSAGE_DELIVERED");
    console.log("MESSAGE_ID:", MSG.MESSAGE_ID);
    console.log("STATUS:", MSG.STATUS);
    
    if (PENDING_MESSAGES.has(MSG.NONCE)) {
        PENDING_MESSAGES.delete(MSG.NONCE);
    }
}

function HANDLE_MESSAGE_QUEUED(MSG) {
    console.log("MESSAGE_QUEUED");
    console.log("MESSAGE_ID:", MSG.MESSAGE_ID);
    console.log("STATUS:", MSG.STATUS);
    
    if (PENDING_MESSAGES.has(MSG.NONCE)) {
        PENDING_MESSAGES.delete(MSG.NONCE);
    }
}

function HANDLE_READ_RECEIPT(MSG) {
    console.log("\n");
    console.log("MESSAGE_READ_BY:", MSG.READ_BY_USER_ID || MSG.READ_BY);
    console.log("MESSAGE_ID:", MSG.MESSAGE_ID);
    console.log("\n");
    SHOW_PROMPT();
}

function HANDLE_OFFLINE_MESSAGES_AVAILABLE(MSG) {
    console.log("OFFLINE_MESSAGES_AVAILABLE:", MSG.COUNT);
}

function HANDLE_OFFLINE_MESSAGES(MSG) {
    console.log("\n");
    console.log("OFFLINE_MESSAGES_RECEIVED:", MSG.COUNT);
    
    if (MSG.MESSAGES && MSG.MESSAGES.length > 0) {
        MSG.MESSAGES.forEach((MESSAGE, INDEX) => {
            const DECRYPTED = DECRYPT_MESSAGE(MESSAGE.ENCRYPTED_CONTENT, CLIENT_PRIVATE_KEY);
            
            if (DECRYPTED) {
                console.log("\n");
                console.log("MESSAGE", INDEX + 1);
                console.log("FROM:", MESSAGE.SENDER_ID);
                console.log("MESSAGE:", DECRYPTED);
                console.log("TIMESTAMP:", new Date(MESSAGE.TIMESTAMP).toISOString());
                
                SEND_MESSAGE("ACKNOWLEDGMENT", {
                    MESSAGE_ID: MESSAGE.MESSAGE_ID,
                    NONCE: MESSAGE.NONCE,
                    STATUS: "read",
                    ORIGINAL_SENDER_ID: MESSAGE.SENDER_ID
                });
            }
        });
    }
    console.log("\n");
}

function HANDLE_USER_REGISTERED(MSG) {
    USER_ID = MSG.USER_ID;
    USERNAME = MSG.USERNAME;
    
    console.log("USER_REGISTERED_SUCCESSFULLY");
    console.log("USER_ID:", USER_ID);
    console.log("USERNAME:", USERNAME);
}

function HANDLE_USER_PUBLIC_KEY(MSG) {
    console.log("\n");
    console.log("USER_PUBLIC_KEY_RETRIEVED");
    console.log("USER_ID:", MSG.USER_ID);
    console.log("USERNAME:", MSG.USERNAME);
    console.log("\n");
    
    RL.question("ENTER_MESSAGE: ", (MESSAGE_TEXT) => {
        if (MESSAGE_TEXT && MESSAGE_TEXT.trim().length > 0) {
            SEND_ENCRYPTED_MESSAGE(MSG.USER_ID, MESSAGE_TEXT.trim(), MSG.PUBLIC_KEY);
        }
        SHOW_MENU();
    });
}

function HANDLE_ERROR(MSG) {
    console.error("SERVER_ERROR");
    console.error("CODE:", MSG.CODE);
    console.error("MESSAGE:", MSG.MESSAGE);
}

function HANDLE_HEARTBEAT_ACK(MSG) {
    console.log("HEARTBEAT_ACK_RECEIVED");
}

function START_HEARTBEAT() {
    if (HEARTBEAT_TIMER) {
        clearInterval(HEARTBEAT_TIMER);
    }
    
    HEARTBEAT_TIMER = setInterval(() => {
        if (IS_AUTHENTICATED) {
            SEND_MESSAGE("HEARTBEAT", {});
        }
    }, HEARTBEAT_INTERVAL);
}

function STOP_HEARTBEAT() {
    if (HEARTBEAT_TIMER) {
        clearInterval(HEARTBEAT_TIMER);
        HEARTBEAT_TIMER = null;
    }
}

function SEND_ENCRYPTED_MESSAGE(RECIPIENT_ID, MESSAGE_TEXT, RECIPIENT_PUBLIC_KEY) {
    if (!RECIPIENT_PUBLIC_KEY) {
        console.error("NO_RECIPIENT_PUBLIC_KEY");
        console.log("FETCHING_PUBLIC_KEY");
        
        SEND_MESSAGE("GET_USER_PUBLIC", {
            USER_ID: RECIPIENT_ID
        });
        return;
    }

    try {
        const ENCRYPTED = ENCRYPT_MESSAGE(MESSAGE_TEXT, RECIPIENT_PUBLIC_KEY);
        
        if (!ENCRYPTED) {
            console.error("ENCRYPTION_FAILED");
            return;
        }

        const NONCE = CRYPTO.randomBytes(16).toString("hex");
        
        PENDING_MESSAGES.set(NONCE, {
            RECIPIENT_ID: RECIPIENT_ID,
            MESSAGE: MESSAGE_TEXT,
            TIMESTAMP: Date.now()
        });

        SEND_MESSAGE("MESSAGE", {
            RECIPIENT_ID: RECIPIENT_ID,
            ENCRYPTED_PACKAGE: ENCRYPTED,
            NONCE: NONCE
        });

        console.log("MESSAGE_SENT");
        console.log("NONCE:", NONCE);

        setTimeout(() => {
            if (PENDING_MESSAGES.has(NONCE)) {
                console.log("MESSAGE_TIMEOUT:", NONCE);
                PENDING_MESSAGES.delete(NONCE);
            }
        }, MESSAGE_TIMEOUT);

    } catch (ERROR) {
        console.error("SEND_ENCRYPTED_MESSAGE_ERROR:", ERROR.message);
    }
}

function SHOW_MENU() {
    console.log("\n");
    console.log("1_SEND_MESSAGE");
    console.log("2_GET_OFFLINE_MESSAGES");
    console.log("3_REGISTER_NEW_USER");
    console.log("4_GET_USER_PUBLIC_KEY");
    console.log("5_SHOW_STATUS");
    console.log("6_EXIT");
    console.log("\n");
    
    SHOW_PROMPT();
}

function SHOW_PROMPT() {
    RL.question("SELECT_OPTION: ", HANDLE_MENU_SELECTION);
}

function HANDLE_MENU_SELECTION(OPTION) {
    switch (OPTION.trim()) {
        case "1":
            RL.question("RECIPIENT_USER_ID: ", (RECIPIENT_ID) => {
                if (RECIPIENT_ID && RECIPIENT_ID.trim().length > 0) {
                    SEND_MESSAGE("GET_USER_PUBLIC", {
                        USER_ID: RECIPIENT_ID.trim()
                    });
                } else {
                    console.log("INVALID_RECIPIENT_ID");
                    SHOW_MENU();
                }
            });
            break;
            
        case "2":
            SEND_MESSAGE("GET_OFFLINE_MESSAGES", {});
            SHOW_MENU();
            break;
            
        case "3":
            RL.question("NEW_USERNAME: ", (NEW_USERNAME) => {
                if (NEW_USERNAME && NEW_USERNAME.trim().length >= 3) {
                    SEND_MESSAGE("USER_REGISTER", {
                        USERNAME: NEW_USERNAME.trim()
                    });
                    setTimeout(() => SHOW_MENU(), 1000);
                } else {
                    console.log("INVALID_USERNAME");
                    SHOW_MENU();
                }
            });
            break;
            
        case "4":
            RL.question("USER_ID: ", (TARGET_USER_ID) => {
                if (TARGET_USER_ID && TARGET_USER_ID.trim().length > 0) {
                    SEND_MESSAGE("GET_USER_PUBLIC", {
                        USER_ID: TARGET_USER_ID.trim()
                    });
                    setTimeout(() => SHOW_MENU(), 1000);
                } else {
                    console.log("INVALID_USER_ID");
                    SHOW_MENU();
                }
            });
            break;
            
        case "5":
            console.log("\n");
            console.log("CLIENT_STATUS");
            console.log("AUTHENTICATED:", IS_AUTHENTICATED);
            console.log("USERNAME:", USERNAME || "NOT_SET");
            console.log("USER_ID:", USER_ID || "NOT_SET");
            console.log("SESSION_ID:", SESSION_ID ? SESSION_ID.substring(0, 16) : "NOT_SET");
            console.log("PEER_ID:", PEER_ID);
            console.log("PENDING_MESSAGES:", PENDING_MESSAGES.size);
            console.log("\n");
            SHOW_MENU();
            break;
            
        case "6":
            console.log("DISCONNECTING");
            DISCONNECT();
            process.exit(0);
            break;
            
        default:
            console.log("INVALID_OPTION");
            SHOW_MENU();
    }
}

function CONNECT() {
    try {
        console.log("CONNECTING_TO_SERVER:", SERVER_URL);
        
        WS = new WEBSOCKET(SERVER_URL);

        WS.on("open", () => {
            console.log("CONNECTED_TO_SERVER");
            RECONNECT_ATTEMPTS = 0;
            
            SEND_MESSAGE("HANDSHAKE_REQUEST", {});
        });

        WS.on("message", (RAW_DATA) => {
            try {
                const MSG = JSON.parse(RAW_DATA);
                
                if (!MSG.TYPE) {
                    console.error("INVALID_MESSAGE_FORMAT");
                    return;
                }

                switch (MSG.TYPE) {
                    case "HANDSHAKE":
                        HANDLE_HANDSHAKE(MSG.DATA);
                        break;
                    case "AUTHENTICATED":
                        HANDLE_AUTHENTICATED(MSG.DATA);
                        break;
                    case "MESSAGE":
                        HANDLE_MESSAGE(MSG.DATA);
                        break;
                    case "DELIVERY_CONFIRMATION":
                        HANDLE_DELIVERY_CONFIRMATION(MSG.DATA);
                        break;
                    case "MESSAGE_QUEUED":
                        HANDLE_MESSAGE_QUEUED(MSG.DATA);
                        break;
                    case "READ_RECEIPT":
                        HANDLE_READ_RECEIPT(MSG.DATA);
                        break;
                    case "OFFLINE_MESSAGES_AVAILABLE":
                        HANDLE_OFFLINE_MESSAGES_AVAILABLE(MSG.DATA);
                        break;
                    case "OFFLINE_MESSAGES":
                        HANDLE_OFFLINE_MESSAGES(MSG.DATA);
                        break;
                    case "USER_REGISTERED":
                        HANDLE_USER_REGISTERED(MSG.DATA);
                        break;
                    case "USER_PUBLIC_KEY":
                        HANDLE_USER_PUBLIC_KEY(MSG.DATA);
                        break;
                    case "ERROR":
                        HANDLE_ERROR(MSG.DATA);
                        break;
                    case "HEARTBEAT_ACK":
                        HANDLE_HEARTBEAT_ACK(MSG.DATA);
                        break;
                    default:
                        console.log("UNKNOWN_MESSAGE_TYPE:", MSG.TYPE);
                }
            } catch (ERROR) {
                console.error("MESSAGE_PARSE_ERROR:", ERROR.message);
            }
        });

        WS.on("close", (CODE, REASON) => {
            console.log("CONNECTION_CLOSED");
            console.log("CODE:", CODE);
            console.log("REASON:", REASON.toString());
            
            IS_AUTHENTICATED = false;
            STOP_HEARTBEAT();
            
            if (RECONNECT_ATTEMPTS < MAX_RECONNECT_ATTEMPTS) {
                console.log("RECONNECTING_IN", RECONNECT_INTERVAL / 1000, "SECONDS");
                setTimeout(() => {
                    RECONNECT_ATTEMPTS++;
                    CONNECT();
                }, RECONNECT_INTERVAL);
            } else {
                console.log("MAX_RECONNECT_ATTEMPTS_REACHED");
                process.exit(1);
            }
        });

        WS.on("error", (ERROR) => {
            console.error("WEBSOCKET_ERROR:", ERROR.message);
        });

    } catch (ERROR) {
        console.error("CONNECTION_ERROR:", ERROR.message);
    }
}

function DISCONNECT() {
    STOP_HEARTBEAT();
    
    if (WS && WS.readyState === WEBSOCKET.OPEN) {
        WS.close(1000, "CLIENT_DISCONNECT");
    }
    
    IS_AUTHENTICATED = false;
    SESSION_ID = null;
}

function INITIALIZE() {
    console.log("E2EE_CHAT_CLIENT");
    console.log("INITIALIZING");
    
    GENERATE_KEY_PAIR();
    
    RL.question("ENTER_USERNAME: ", (INPUT_USERNAME) => {
        if (INPUT_USERNAME && INPUT_USERNAME.trim().length >= 3) {
            USERNAME = INPUT_USERNAME.trim();
            
            RL.question("ENTER_USER_ID_OR_LEAVE_EMPTY: ", (INPUT_USER_ID) => {
                if (INPUT_USER_ID && INPUT_USER_ID.trim().length > 0) {
                    USER_ID = INPUT_USER_ID.trim();
                }
                
                CONNECT();
            });
        } else {
            console.error("INVALID_USERNAME");
            process.exit(1);
        }
    });
}

process.on("SIGINT", () => {
    console.log("\n");
    console.log("SHUTTING_DOWN");
    DISCONNECT();
    RL.close();
    process.exit(0);
});

process.on("uncaughtException", (ERROR) => {
    console.error("UNCAUGHT_EXCEPTION:", ERROR.message);
});

process.on("unhandledRejection", (REASON) => {
    console.error("UNHANDLED_REJECTION:", REASON);
});

INITIALIZE();