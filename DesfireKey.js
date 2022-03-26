"use strict";

const crypto = require("crypto");

const {DESFIRE_COMMANDS, DESFIRE_STATUS, DESFIRE_CONSTANTS} = require("./desfire_consts.js");

class Key {
    constructor(keyId, key) {
        if (Array.isArray(key)) {
            key = Buffer.from(key);
        }
        if (!Buffer.isBuffer(key)) {
            throw new Error("expected key to be a buffer or array");
        }
        this.key = key;
        this.keyId = keyId;
        this.keySize = key.length;
        this.blockSize = 8;

        this.random_a = null;
        this.random_b = null;

        this.sessionKey = null;
        this.sessionIv = null;
        
        this.cmac1 = null;
        this.cmac2 = null;
    }
    
    rotateLeft(buffer) {
        return Buffer.concat([buffer.slice(1, buffer.length), buffer.slice(0, 1)]);
    }
    
    rotateRight(buffer) {
        return Buffer.concat([buffer.slice(buffer.length - 1, buffer.length), buffer.slice(0, buffer.length - 1)]);
    }
    
    bitShiftLeft(buffer) {
        for (let index = 0; index < buffer.length - 1; index++) {
            buffer[index] = (buffer[index] << 1) | (buffer[index + 1] >> 7);
        }
        buffer[buffer.length - 1] = buffer[buffer.length - 1] << 1;
    }
    
    generateCmacSubKeys() {
        let R = (this.blockSize == 8) ? 0x1B : 0x87;
        let data = Buffer.from(new Array(this.blockSize).fill(0));
        this.sessionIv = Buffer.alloc(this.blockSize).fill(0);
        data = this.encryptCBC(data);
        this.cmac1 = Buffer.alloc(this.blockSize);
        data.copy(this.cmac1);
        this.bitShiftLeft(this.cmac1);
        if (data[0] & 0x80) {
            this.cmac1[this.cmac1.length - 1] ^= R;
        }
        this.cmac2 = Buffer.alloc(this.blockSize);
        data.copy(this.cmac2);
        this.bitShiftLeft(this.cmac2);
        if (this.cmac1[0] & 0x80) {
            this.cmac2[this.cmac2.length - 1] ^= R;
        }
    }
    
    decryptCBC(data) {
        let result = this.decrypt(data, this.sessionIv);
        this.sessionIv = data.slice(-1 * this.blockSize);
        return result;
    }
    
    encryptCBC(data) {
        let result = this.encrypt(data, this.sessionIv);
        this.sessionIv = result.slice(-1 * this.blockSize);
        return result;
    }
    
    decrypt() {
        throw new Error("not implemented");
    }
    
    encrypt() {
        throw new Error("not implemented");
    }
    
    async authenticate() {
        throw new Error("not implemented");
    }
}

class KeyDes extends Key {
    constructor(keyId, key) {
        super(keyId, key);
        if (this.keySize !== 16) {
            throw new Error("invalid key length");
        }
        this.blockSize = 8;
    }
    
    decrypt(data, iv = Buffer.alloc(8).fill(0)) {
        const decipher = crypto.createDecipheriv("DES-EDE-CBC", this.key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }

    encrypt(data, iv = Buffer.alloc(8).fill(0)) {
        const decipher = crypto.createCipheriv("DES-EDE-CBC", this.key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
    
    async authenticate(card) {
        let [data, resultCode] = await card.executeTransaction(card.wrap(DESFIRE_COMMANDS["AuthenticateLegacy"], [this.keyId]));
        if (resultCode !== DESFIRE_STATUS["MoreFrames"]) {
            throw new Error("failed to authenticate");
        }
        const random_b_encrypted = data; // encrypted random_b from reader
        this.random_b = this.decrypt(random_b_encrypted);     
        const random_b_rotated = this.rotateLeft(this.random_b);
        this.random_a = crypto.randomBytes(this.random_b.length);
        const ciphertext = this.encrypt(Buffer.concat([this.random_a, random_b_rotated]));
        [data, resultCode] = await card.executeTransaction(card.wrap(DESFIRE_COMMANDS["AdditionalFrame"], ciphertext));
        if (resultCode !== DESFIRE_STATUS["Success"]) {
            throw new Error("failed to set up random_a");
        }
        const random_a2_encrypted_rotated = data;
        const random_a2_rotated = this.decrypt(random_a2_encrypted_rotated); // decrypt to get rotated value of random_a2
        const random_a2 =this.rotateRight(random_a2_rotated);
        if (!this.random_a.equals(random_a2)) { // compare decrypted random_a2 response from reader with our random_a if it equals authentication process was successful
            throw new Error("failed to match random_a random bytes");
        }
        
        this.sessionKey = Buffer.concat([this.random_a.slice(0,4), this.random_b.slice(0,4)]);
        this.sessionIv = Buffer.alloc(8).fill(0);
        this.generateCmacSubKeys();
    }
}

class KeyAes extends Key {
    constructor(keyId, key) {
        super(keyId, key);
        if (this.keySize !== 16) {
            throw new Error("invalid key length");
        }
        this.blockSize = 16;
    }
    
    decrypt(data, iv = Buffer.alloc(16).fill(0)) {
        const decipher = crypto.createDecipheriv("AES-128-CBC", this.key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
    
    encrypt(data, iv = Buffer.alloc(16).fill(0)) {
        const decipher = crypto.createCipheriv("AES-128-CBC", this.key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
    
    async authenticate(card) {
        let [data, resultCode] = await card.executeTransaction(card.wrap(DESFIRE_COMMANDS["Ev1AuthenticateAes"], [this.keyId]));
        if (resultCode !== DESFIRE_STATUS["MoreFrames"]) {
            throw new Error("failed to authenticate");
        }
        const random_b_encrypted = data; // encrypted random_b from reader
        this.random_b = this.decrypt(random_b_encrypted);
        const random_b_rotated = this.rotateLeft(this.random_b);
        this.random_a = crypto.randomBytes(this.random_b.length);
        const ciphertext = this.encrypt(Buffer.concat([this.random_a, random_b_rotated]), random_b_encrypted);
        [data, resultCode] = await card.executeTransaction(card.wrap(DESFIRE_COMMANDS["AdditionalFrame"], ciphertext));
        if (resultCode !== DESFIRE_STATUS["Success"]) {
            throw new Error("failed to set up random_a");
        }
        const random_a_encrypted_rotated = data; // encrypted random a from reader
        const random_a_rotated = this.decrypt(random_a_encrypted_rotated, ciphertext.slice(-16)); // decrypt to get rotated value of random_a2
        const random_a2 = this.rotateRight(random_a_rotated);
        if (!this.random_a.equals(random_a2)) { // compare decrypted random_a2 response from reader with our random_a if it equals authentication process was successful
            throw new Error("failed to match random_a random bytes");
        }
        
        this.sessionKey = Buffer.concat([this.random_a.slice(0,4), this.random_b.slice(0,4), this.random_a.slice(12, 16), this.random_b.slice(12, 16)]);
        this.sessionIv = Buffer.alloc(16).fill(0);
        this.generateCmacSubKeys();
    }
    
    /*
     *         this.sessionKey = Buffer.concat([random_a.slice(0,4), random_b.slice(0,4), random_a.slice(12, 16), random_b.slice(12, 16)]);
        this.iv = Buffer.alloc(16).fill(0);
        this.keyType = "aes";
        this.keyId = keyId;
        this.blockSize = 16;
        */
}

module.exports = {
    KeyDes: KeyDes,
    KeyAes: KeyAes
};
