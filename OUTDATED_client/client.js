/*
 * @Author: Cuersy 
 * @Date: 2025-10-03 18:23:37 
 * @Last Modified by:   Cuersy 
 * @Last Modified time: 2025-10-03 18:23:37 
 */

// THIS CLIENT OUTDATED, PLEASE USE THE NEW CLIENT IN THE 'new_client' FOLDER


const WEBSOCKET = require("ws");
const CRYPTO = require("crypto");
const READLINE = require("readline");
const FS = require("fs");

class SECURE_CLIENT {
    constructor(SERVER_URL) {
        this.WS = null;
        this.SERVER_URL = SERVER_URL;
        this.PRIVATE_KEY = null;
        this.PUBLIC_KEY = null;
        this.SESSION_ID = null;
        this.PEER_SESSIONS = new Map();
        this.MESSAGE_QUEUE = [];
        this.AUTHENTICATED = false;
        this.generateKeyPair();
    }

    generateKeyPair() {
        const { publicKey, privateKey } = CRYPTO.generateKeyPairSync("rsa", {
            modulusLength: 4096,
            publicKeyEncoding: { type: "spki", format: "pem" },
            privateKeyEncoding: { type: "pkcs8", format: "pem" }
        });
        this.PUBLIC_KEY = publicKey;
        this.PRIVATE_KEY = privateKey;
        this.PEER_ID = CRYPTO.createHash("sha256").update(this.PUBLIC_KEY).digest("hex").substring(0, 16);
    }

    connect() {
        return new Promise((RESOLVE, REJECT) => {
            this.WS = new WEBSOCKET(this.SERVER_URL);

            this.WS.on("open", () => {
                console.log("CONNECTED_TO_SERVER");
                this.requestHandshake();
            });

            this.WS.on("message", (RAW_DATA) => {
                try {
                    const MSG = JSON.parse(RAW_DATA);
                    this.handleMessage(MSG);
                    if (this.AUTHENTICATED && !RESOLVE.called) {
                        RESOLVE.called = true;
                        RESOLVE();
                    }
                } catch (ERROR) {
                    console.error("MESSAGE_PARSE_ERROR:", ERROR.message);
                }
            });

            this.WS.on("error", (ERROR) => {
                console.error("CONNECTION_ERROR:", ERROR.message);
                REJECT(ERROR);
            });

            this.WS.on("close", () => {
                console.log("CONNECTION_CLOSED");
                this.AUTHENTICATED = false;
            });

            setTimeout(() => {
                if (!this.AUTHENTICATED) {
                    REJECT(new Error("CONNECTION_TIMEOUT"));
                }
            }, 10000);
        });
    }

    requestHandshake() {
        this.sendMessage("HANDSHAKE_REQUEST", {});
    }

    handleMessage(MSG) {
        switch (MSG.TYPE) {
            case "HANDSHAKE":
                this.handleHandshake(MSG.DATA);
                break;
            case "AUTHENTICATED":
                this.handleAuthenticated(MSG.DATA);
                break;
            case "MESSAGE":
                this.handleIncomingMessage(MSG.DATA);
                break;
            case "DELIVERY_CONFIRMATION":
                this.handleDeliveryConfirmation(MSG.DATA);
                break;
            case "READ_RECEIPT":
                this.handleReadReceipt(MSG.DATA);
                break;
            case "ERROR":
                this.handleError(MSG.DATA);
                break;
        }
    }

    handleHandshake(DATA) {
        console.log("HANDSHAKE_RECEIVED");
        this.SESSION_ID = DATA.SESSION_ID;
        this.SERVER_PUBLIC_KEY = DATA.PUBLIC_KEY;

        try {
            const CHALLENGE_RESPONSE = CRYPTO.publicEncrypt(
                {
                    key: this.SERVER_PUBLIC_KEY,
                    padding: CRYPTO.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: "sha256"
                },
                Buffer.from(DATA.CHALLENGE, "base64")
            );

            this.sendMessage("HANDSHAKE_RESPONSE", {
                CHALLENGE_RESPONSE: CHALLENGE_RESPONSE.toString("base64"),
                PEER_PUBLIC_KEY: this.PUBLIC_KEY,
                PEER_ID: this.PEER_ID
            });
        } catch (ERROR) {
            console.error("HANDSHAKE_ERROR:", ERROR.message);
        }
    }

    handleAuthenticated(DATA) {
        console.log("AUTHENTICATION_SUCCESS");
        console.log("SESSION_ID:", DATA.SESSION_ID);
        console.log("YOUR_PEER_ID:", this.PEER_ID);
        this.AUTHENTICATED = true;
        this.saveKeysToFile();
        this.processMessageQueue();
    }

    saveKeysToFile() {
        const KEY_DATA = {
            SESSION_ID: this.SESSION_ID,
            PEER_ID: this.PEER_ID,
            PUBLIC_KEY: this.PUBLIC_KEY,
            PRIVATE_KEY: this.PRIVATE_KEY
        };
        
        try {
            FS.writeFileSync(`client_${this.SESSION_ID.substring(0, 8)}.json`, JSON.stringify(KEY_DATA, null, 2));
            console.log(`KEYS_SAVED_TO: client_${this.SESSION_ID.substring(0, 8)}.json`);
        } catch (ERROR) {
            console.error("FAILED_TO_SAVE_KEYS:", ERROR.message);
        }
    }

    encryptMessage(PLAINTEXT, RECIPIENT_PUBLIC_KEY) {
        const AES_KEY = CRYPTO.randomBytes(32);
        const IV = CRYPTO.randomBytes(16);
        const CIPHER = CRYPTO.createCipheriv("aes-256-gcm", AES_KEY, IV);
        
        let ENCRYPTED = CIPHER.update(PLAINTEXT, "utf8", "base64");
        ENCRYPTED += CIPHER.final("base64");
        const AUTH_TAG = CIPHER.getAuthTag();

        const ENCRYPTED_AES_KEY = CRYPTO.publicEncrypt(
            {
                key: RECIPIENT_PUBLIC_KEY,
                padding: CRYPTO.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            },
            AES_KEY
        );

        const TIMESTAMP = Date.now();
        const NONCE = CRYPTO.randomBytes(16);
        const SIGNATURE = this.signData(Buffer.concat([
            Buffer.from(ENCRYPTED, "base64"),
            AUTH_TAG,
            IV,
            NONCE,
            Buffer.from(TIMESTAMP.toString())
        ]));

        return {
            ENCRYPTED_DATA: ENCRYPTED,
            ENCRYPTED_KEY: ENCRYPTED_AES_KEY.toString("base64"),
            IV: IV.toString("base64"),
            AUTH_TAG: AUTH_TAG.toString("base64"),
            NONCE: NONCE.toString("base64"),
            TIMESTAMP: TIMESTAMP,
            SIGNATURE: SIGNATURE
        };
    }

    decryptMessage(ENCRYPTED_PACKAGE, SENDER_PUBLIC_KEY) {
        const SIGNATURE_DATA = Buffer.concat([
            Buffer.from(ENCRYPTED_PACKAGE.ENCRYPTED_DATA, "base64"),
            Buffer.from(ENCRYPTED_PACKAGE.AUTH_TAG, "base64"),
            Buffer.from(ENCRYPTED_PACKAGE.IV, "base64"),
            Buffer.from(ENCRYPTED_PACKAGE.NONCE, "base64"),
            Buffer.from(ENCRYPTED_PACKAGE.TIMESTAMP.toString())
        ]);

        if (!this.verifySignature(SIGNATURE_DATA, ENCRYPTED_PACKAGE.SIGNATURE, SENDER_PUBLIC_KEY)) {
            throw new Error("SIGNATURE_VERIFICATION_FAILED");
        }

        const ENCRYPTED_AES_KEY = Buffer.from(ENCRYPTED_PACKAGE.ENCRYPTED_KEY, "base64");
        const AES_KEY = CRYPTO.privateDecrypt(
            {
                key: this.PRIVATE_KEY,
                padding: CRYPTO.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256"
            },
            ENCRYPTED_AES_KEY
        );

        const IV = Buffer.from(ENCRYPTED_PACKAGE.IV, "base64");
        const AUTH_TAG = Buffer.from(ENCRYPTED_PACKAGE.AUTH_TAG, "base64");
        const DECIPHER = CRYPTO.createDecipheriv("aes-256-gcm", AES_KEY, IV);
        DECIPHER.setAuthTag(AUTH_TAG);

        let DECRYPTED = DECIPHER.update(ENCRYPTED_PACKAGE.ENCRYPTED_DATA, "base64", "utf8");
        DECRYPTED += DECIPHER.final("utf8");

        return DECRYPTED;
    }

    signData(DATA) {
        const SIGN = CRYPTO.createSign("SHA256");
        SIGN.update(DATA);
        SIGN.end();
        return SIGN.sign(this.PRIVATE_KEY, "base64");
    }

    verifySignature(DATA, SIGNATURE, PUBLIC_KEY) {
        const VERIFY = CRYPTO.createVerify("SHA256");
        VERIFY.update(DATA);
        VERIFY.end();
        return VERIFY.verify(PUBLIC_KEY, SIGNATURE, "base64");
    }

    sendSecureMessage(RECIPIENT_ID, MESSAGE_TEXT) {
        if (!this.AUTHENTICATED) {
            console.log("NOT_AUTHENTICATED_YET");
            this.MESSAGE_QUEUE.push({ RECIPIENT_ID, MESSAGE_TEXT });
            return;
        }

        const PEER_DATA = this.PEER_SESSIONS.get(RECIPIENT_ID);
        if (!PEER_DATA) {
            console.log("RECIPIENT_NOT_FOUND_PLEASE_ADD_PEER_FIRST");
            console.log("USE: add <SESSION_ID>");
            return;
        }

        try {
            const ENCRYPTED_PACKAGE = this.encryptMessage(MESSAGE_TEXT, PEER_DATA.PUBLIC_KEY);
            
            this.sendMessage("MESSAGE", {
                RECIPIENT_ID: RECIPIENT_ID,
                ENCRYPTED_PACKAGE: ENCRYPTED_PACKAGE,
                PEER_ID: this.PEER_ID
            });

            console.log("MESSAGE_SENT_TO:", RECIPIENT_ID);
        } catch (ERROR) {
            console.error("ENCRYPTION_ERROR:", ERROR.message);
            console.error("DETAILS:", ERROR.stack);
        }
    }

    handleIncomingMessage(DATA) {
        try {
            const DECRYPTED_MESSAGE = this.decryptMessage(DATA.ENCRYPTED_PACKAGE, DATA.SENDER_PUBLIC_KEY);
            
            console.log("\n========================================");
            console.log("NEW_MESSAGE_FROM:", DATA.SENDER_ID);
            console.log("MESSAGE:", DECRYPTED_MESSAGE);
            console.log("TIMESTAMP:", new Date(DATA.ENCRYPTED_PACKAGE.TIMESTAMP).toLocaleString());
            console.log("========================================\n");

            if (!this.PEER_SESSIONS.has(DATA.SENDER_ID)) {
                this.addPeer(DATA.SENDER_ID, DATA.SENDER_PUBLIC_KEY);
                console.log("SENDER_AUTOMATICALLY_ADDED_TO_PEERS");
            }

            this.sendMessage("ACKNOWLEDGMENT", {
                MESSAGE_ID: DATA.MESSAGE_ID,
                ORIGINAL_SENDER_ID: DATA.SENDER_ID,
                STATUS: "READ"
            });
        } catch (ERROR) {
            console.error("DECRYPTION_ERROR:", ERROR.message);
        }
    }

    handleDeliveryConfirmation(DATA) {
        console.log("✓ MESSAGE_DELIVERED:", DATA.MESSAGE_ID.substring(0, 8));
    }

    handleReadReceipt(DATA) {
        console.log("✓✓ MESSAGE_READ_BY:", DATA.READ_BY.substring(0, 8));
    }

    handleError(DATA) {
        console.error("❌ SERVER_ERROR:", DATA.CODE);
        console.error("MESSAGE:", DATA.MESSAGE);
    }

    addPeer(PEER_SESSION_ID, PEER_PUBLIC_KEY) {
        if (!PEER_PUBLIC_KEY || typeof PEER_PUBLIC_KEY !== 'string') {
            console.log("ERROR: INVALID_PUBLIC_KEY");
            return;
        }

        if (!PEER_PUBLIC_KEY.includes("BEGIN PUBLIC KEY")) {
            console.log("ERROR: PUBLIC_KEY_MUST_BE_IN_PEM_FORMAT");
            return;
        }

        this.PEER_SESSIONS.set(PEER_SESSION_ID, {
            PUBLIC_KEY: PEER_PUBLIC_KEY,
            ADDED_AT: Date.now()
        });
        console.log("✓ PEER_ADDED:", PEER_SESSION_ID.substring(0, 16));
    }

    listPeers() {
        console.log("\n========================================");
        console.log("CONNECTED_PEERS:");
        if (this.PEER_SESSIONS.size === 0) {
            console.log("NO_PEERS_CONNECTED");
        } else {
            for (const [PEER_ID, PEER_DATA] of this.PEER_SESSIONS.entries()) {
                console.log(`- ${PEER_ID.substring(0, 16)}... (ADDED: ${new Date(PEER_DATA.ADDED_AT).toLocaleString()})`);
            }
        }
        console.log("========================================\n");
    }

    exportPublicKey() {
        const FILE_NAME = `public_key_${this.SESSION_ID.substring(0, 8)}.pem`;
        try {
            FS.writeFileSync(FILE_NAME, this.PUBLIC_KEY);
            console.log(`PUBLIC_KEY_EXPORTED_TO: ${FILE_NAME}`);
        } catch (ERROR) {
            console.error("FAILED_TO_EXPORT_KEY:", ERROR.message);
        }
    }

    sendMessage(TYPE, DATA) {
        if (this.WS && this.WS.readyState === WEBSOCKET.OPEN) {
            this.WS.send(JSON.stringify({
                TYPE: TYPE,
                DATA: DATA,
                TIMESTAMP: Date.now()
            }));
        }
    }

    processMessageQueue() {
        while (this.MESSAGE_QUEUE.length > 0) {
            const QUEUED_MSG = this.MESSAGE_QUEUE.shift();
            this.sendSecureMessage(QUEUED_MSG.RECIPIENT_ID, QUEUED_MSG.MESSAGE_TEXT);
        }
    }

    disconnect() {
        if (this.WS) {
            this.WS.close();
        }
    }
}

const RL = READLINE.createInterface({
    input: process.stdin,
    output: process.stdout
});

let WAITING_FOR_KEY = false;
let TEMP_SESSION_ID = null;
let KEY_BUFFER = "";

async function main() {
    const SERVER_URL = process.argv[2] || "ws://localhost:8080";
    const CLIENT = new SECURE_CLIENT(SERVER_URL);

    console.log("CONNECTING_TO_SERVER...");
    
    try {
        await CLIENT.connect();
        console.log("\n✓ CONNECTED_AND_AUTHENTICATED");
        console.log("\n📋 AVAILABLE_COMMANDS:");
        console.log("  add <SESSION_ID>         - ADD_PEER (will prompt for public key)");
        console.log("  send <SESSION_ID> <MSG>  - SEND_MESSAGE");
        console.log("  list                     - LIST_PEERS");
        console.log("  myid                     - SHOW_YOUR_INFO");
        console.log("  export                   - EXPORT_YOUR_PUBLIC_KEY");
        console.log("  exit                     - DISCONNECT\n");

        const PROMPT_USER = () => {
            if (WAITING_FOR_KEY) {
                RL.question("", (INPUT) => {
                    INPUT = INPUT.trim();
                    
                    if (INPUT === "END" || INPUT === "") {
                        if (KEY_BUFFER.length > 0) {
                            CLIENT.addPeer(TEMP_SESSION_ID, KEY_BUFFER);
                            KEY_BUFFER = "";
                            TEMP_SESSION_ID = null;
                            WAITING_FOR_KEY = false;
                        } else {
                            console.log("ERROR: NO_KEY_PROVIDED");
                            WAITING_FOR_KEY = false;
                        }
                        PROMPT_USER();
                    } else {
                        KEY_BUFFER += INPUT + "\n";
                        PROMPT_USER();
                    }
                });
                return;
            }

            RL.question("COMMAND: ", async (INPUT) => {
                const PARTS = INPUT.trim().split(" ");
                const COMMAND = PARTS[0].toLowerCase();

                switch (COMMAND) {
                    case "add":
                        if (PARTS.length >= 2) {
                            TEMP_SESSION_ID = PARTS[1];
                            console.log("\nPASTE_PUBLIC_KEY (press Enter on empty line when done):");
                            WAITING_FOR_KEY = true;
                            KEY_BUFFER = "";
                        } else {
                            console.log("USAGE: add <SESSION_ID>");
                        }
                        break;

                    case "send":
                        if (PARTS.length >= 3) {
                            const RECIPIENT_ID = PARTS[1];
                            const MESSAGE = PARTS.slice(2).join(" ");
                            CLIENT.sendSecureMessage(RECIPIENT_ID, MESSAGE);
                        } else {
                            console.log("USAGE: send <SESSION_ID> <MESSAGE>");
                        }
                        break;

                    case "list":
                        CLIENT.listPeers();
                        break;

                    case "myid":
                        console.log("\n========================================");
                        console.log("YOUR_SESSION_ID:", CLIENT.SESSION_ID);
                        console.log("YOUR_PEER_ID:", CLIENT.PEER_ID);
                        console.log("\nYOUR_PUBLIC_KEY:");
                        console.log(CLIENT.PUBLIC_KEY);
                        console.log("========================================\n");
                        break;

                    case "export":
                        CLIENT.exportPublicKey();
                        break;

                    case "exit":
                        console.log("DISCONNECTING...");
                        CLIENT.disconnect();
                        RL.close();
                        process.exit(0);
                        return;

                    default:
                        console.log("UNKNOWN_COMMAND");
                }

                PROMPT_USER();
            });
        };

        PROMPT_USER();
    } catch (ERROR) {
        console.error("CONNECTION_FAILED:", ERROR.message);
        process.exit(1);
    }
}

main();