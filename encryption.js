/*
 * @Author: Cuersy 
 * @Date: 2025-10-03 18:23:29 
 * @Last Modified by:   Cuersy 
 * @Last Modified time: 2025-10-03 18:23:29 
 */

const crypto = require("crypto");


class Encryption {
  constructor() {
    this.publicKey = null;
    this.privateKey = null;
  }
  genkey() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    return { publicKey, privateKey };
  }
  getPublicKey() {
    return this.publicKey;
  }
  encrypt(message) {
    const encrypted = crypto.publicEncrypt(
      {
        key: this.publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      Buffer.from(message)
    );
    return encrypted;
  }
  decrypt(encryptedstring) {
    const decrypted = crypto.privateDecrypt(
      {
        key: this.privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256"
      },
      encryptedstring
    );
    return decrypted.toString();
  }
};

export default Encryption;