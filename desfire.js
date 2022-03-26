"use strict";

const crypto = require("crypto");
const crc32 = require("buffer-crc32");

const {DESFIRE_COMMANDS, DESFIRE_STATUS, DESFIRE_CONSTANTS} = require("./desfire_consts.js");
const { KeyDes, KeyAes } = require("./DesfireKey.js");

function writeUint24LE(buffer, value, position = 0) {
    let tempBuffer = Buffer.alloc(4);
    tempBuffer.writeUint32LE(value);
    tempBuffer.copy(buffer, position, 0, 3);
}

class DesfireCardVersion {
    constructor(buffer) {
        if (buffer.length != 28) {
            throw new Error("Expected exactly 28 bytes");
        }
        this.vendorId             = buffer.readUint8(0);
        this.hardwareType         = buffer.readUint8(1);
        this.hardwareSubType      = buffer.readUint8(2);
        this.hardwareMajorVersion = buffer.readUint8(3);
        this.HardwareMinorVersion = buffer.readUint8(4);
        this.hardwareStorageSize  = buffer.readUint8(5);
        this.hardwareProtocol     = buffer.readUint8(6);
        this.softwareVendorId     = buffer.readUint8(7);
        this.softwareType         = buffer.readUint8(8);
        this.softwareSubType      = buffer.readUint8(9);
        this.softwareMajorVersion = buffer.readUint8(10);
        this.softwareMinorVersion = buffer.readUint8(11);
        this.softwareStorageSize  = buffer.readUint8(12);
        this.softwareProtocol     = buffer.readUint8(13);
        this.uid                  = buffer.slice(14,21).toJSON().data;;
        this.batchNumber          = buffer.slice(21,26).toJSON().data;;
        this.productionWeek       = buffer.readUint8(26);
        this.productionYear       = buffer.readUint8(27);
    }
    
    print() {
        console.log("Hardware version: " + this.hardwareMajorVersion + "." + this.HardwareMinorVersion);
        console.log("Software version: " + this.softwareMajorVersion + "." + this.softwareMinorVersion);
        console.log("Storage capacity: " + (1 << (this.hardwareStorageSize / 2)));
        console.log("Production date:  week " + this.productionWeek.toString(16) + " of 20" + ((this.productionYear < 0x10) ? "0" : "") + this.productionYear.toString(16));
        let batchNumberStringArray = [];
        for (let index = 0; index < this.batchNumber.length; index++) {
            batchNumberStringArray.push(((this.batchNumber[index] < 0x10) ? "0" : "") + this.batchNumber[index].toString(16));
        }
        console.log("Batch number:     " + batchNumberStringArray.join(""));
        let uidStringArray = [];
        for (let index = 0; index < this.uid.length; index++) {
            uidStringArray.push(((this.uid[index] < 0x10) ? "0" : "") + this.uid[index].toString(16));
        }
        console.log("Unique ID:        " + uidStringArray.join(""));
        
    }
}

class DesfireKeySettings {
    constructor(buffer = Buffer.from([0x0F, 0x00])) {
        let settings = buffer.readUint8(0);
        this.allowChangeMk              = Boolean(settings & 0x01);
        this.allowListingWithoutMk      = Boolean(settings & 0x02);
        this.allowCreateDeleteWithoutMk = Boolean(settings & 0x04);
        this.allowChangeConfiguration   = Boolean(settings & 0x08);
        this.allowChangeWithKey         = (settings & 0xF0) >> 4; // 0x0 is master key, 0xE is target key, 0xF is frozen
        this.keyCount = buffer.readUint8(1) & 0x0F;
        let _keyType = buffer.readUint8(1) & 0xF0;
        this.keyType = "invalid";
        if (_keyType === 0x00) {
            this.keyType = "des";
        } else if (_keyType == 0x40) {
            this.keyType = "3des";
        } else if (_keyType == 0x80) {
            this.keyType = "aes";
        }
    }
    
    getBuffer() {
        let _keyType = null;
        if (this.keyType === "des") {
            _keyType = 0x00;
        } else if (this.keyType === "3des") {
            _keyType = 0x40;
        } else if (this.keyType === "aes") {
            _keyType = 0x80;
        } else {
            throw new Error("key type invalid");
        }
        let settings = (this.allowChangeWithKey << 4) | (this.allowChangeMk ? 1 : 0) | (this.allowListingWithoutMk ? 2 : 0) | (this.allowCreateDeleteWithoutMk ? 4 : 0) | (this.allowChangeConfiguration ? 8 : 0);
        return Buffer.from([settings, this.keyCount + _keyType]);
    }
}

class DesfireCard {
    constructor(reader, card) {
        this._reader = reader;
        this._card = card;

        this.default_des_key = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        this.default_aes_key = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        this.key = null;
    }
   
    async executeTransactionRaw(cmd, responseMaxLength = 40) {
        return this._reader.transmit(Buffer.from(cmd), responseMaxLength);
    };
    
    async executeTransaction(cmd, responseMaxLength = 40) {
        let raw = await this._reader.transmit(Buffer.from(cmd), responseMaxLength);
        let resultCode = raw.slice(-1)[0];
        let data = raw.slice(0, -2);
        return [data, resultCode];
    }
    
    async calculateCmac(input) {
        let buffer = Buffer.from(input);
        if (buffer.length % this.key.blockSize) {
            buffer = Buffer.concat([buffer, Buffer.from([0x80])]);
            buffer = Buffer.concat([buffer, Buffer.from(new Array(buffer.length % this.key.blockSize).fill(0))]);
            //console.log("Padded CMAC input", buffer);
            for (let index = 0; index < this.key.blockSize; index++) {
                buffer[buffer.length - this.key.blockSize + index] ^= this.key.cmac2[index];
            }
            //console.log("After XOR", buffer);
        } else {
            //console.log("Unpadded CMAC input", buffer);
            for (let index = 0; index < this.key.blockSize; index++) {
                buffer[buffer.length - this.key.blockSize + index] ^= this.key.cmac1[index];
            }
            //console.log("After XOR", buffer);
        }
        buffer = this.key.encryptCBC(buffer.slice(-1 * this.key.blockSize));
        let result = Buffer.alloc(this.key.sessionIv.length);
        this.key.sessionIv.copy(result);
        return result;
    }
    
    async executeTransactionMac(cmd, responseMaxLength = 40) {
        let cmac = await this.calculateCmac(cmd);
        console.log("Calculated CMAC:", cmac);
        return this.executeTransaction(cmd, responseMaxLength);
    }
    
    wrap(cmd, dataIn) {
        if (dataIn.length > 0) {
            return [0x90, cmd, 0x00, 0x00, dataIn.length, ...dataIn, 0x00];
        } else {
            return [0x90, cmd, 0x00, 0x00, 0x00];
        }
    }

    async authenticateDes(keyId, key) {
        this.key = new KeyDes(keyId, key);
        await this.key.authenticate(this);
    }
    
    async authenticateAes(keyId, key) {
        this.key = new KeyAes(keyId, key);
        await this.key.authenticate(this);
    }
    
    async readFileData(aFileId, aOffset, aLength) {
        let parameters = Buffer.alloc(7);
        parameters.writeUint8(aFileId, 0);
        writeUint24LE(parameters, aOffset, 1);
        writeUint24LE(parameters, aLength, 4);
        console.log(parameters);
        let [data, resultCode] = await this.executeTransaction(this.wrap(DESFIRE_COMMANDS["ReadData"], parameters), 0xFF);

        if (resultCode !== DESFIRE_STATUS["Success"]) {
            throw new Error("read file failed (0x" + resultCode.toString(16) + ")");
        }
        
        let content = data.slice(0,aLength);
        let cmac = data.slice(aLength);
        
        let calcCmac = await this.calculateCmac(Buffer.concat([content, Buffer.from([0])]));
                
        console.log("File contents", content);
        console.log("RX CMAC", cmac);
        console.log("CA CMAC", calcCmac.slice(0,8));
        // CMAC check doesn't work yet.
    };
    
    decryptAes(key, data, iv = Buffer.alloc(16).fill(0)) {
        const decipher = crypto.createDecipheriv("AES-128-CBC", key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }

    async decryptResponse(ciphertext) {
        let plaintext = this.decryptAes(this.sessionKey, ciphertext, this.iv);
        if (this.keyType === "aes") {
            this.iv = ciphertext.slice(-16);
        }
        return plaintext;
    }
    
    async readCardUid() {
        // Not functional yet!
        const result = await this.executeTransactionRaw(this.wrap(DESFIRE_COMMANDS["Ev1GetCardUid"], []), 255);
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("read file failed");
        }
        return this.decryptResponse(result.slice(0, result.length - 2));
    };
    
    async formatCard() {
        const result = await this.executeTransactionRaw(this.wrap(DESFIRE_COMMANDS["FormatPicc"], []));
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("format failed");
        }
    };
    
    async getFreeMemory() {
        const result = await this.executeTransactionRaw(this.wrap(DESFIRE_COMMANDS["Ev1FreeMem"], []));
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("get free memory failed");
        }
        return Buffer.concat([result.slice(0,3), Buffer.from([0x00])]).readUint32LE();
    };
    
    async getKeyVersion(keyNo) {
        const result = await this.executeTransactionRaw(this.wrap(DESFIRE_COMMANDS["GetKeyVersion"], [keyNo]));
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("get key version failed");
        }
        return result.readUint8(0);
    }
    
    async getKeySettings() {
        const result = await this.executeTransactionRaw(this.wrap(DESFIRE_COMMANDS["GetKeySettings"], []));
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("get key settings failed");
        }
        return new DesfireKeySettings(result.slice(0,-2));
    }
    
    async changeKeySettings(newSettings) {
        throw new Error("not implemented");
    }
    
    async getCardVersion() {
        let result = await this.executeTransactionRaw(this.wrap(DESFIRE_COMMANDS["GetVersion"], []));
        let data = Buffer.from(result.slice(0,result.length-2));
        while (result.slice(-1)[0] === DESFIRE_STATUS["MoreFrames"]) {
            result = await this.executeTransactionRaw(this.wrap(DESFIRE_COMMANDS["AdditionalFrame"], []));
            data = Buffer.concat([data, result.slice(0,result.length-2)]);
        }
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("failed to get card version");
        }
        return new DesfireCardVersion(data);
    };
    
    async getApplicationsIds() {
        let result = await this.executeTransactionRaw(this.wrap(DESFIRE_COMMANDS["GetApplicationIdentifiers"], []));
        let appsRaw = Buffer.from(result.slice(0,result.length-2));
        while (result.slice(-1)[0] === DESFIRE_STATUS["MoreFrames"]) {
            result = await this.executeTransactionRaw(this.wrap(DESFIRE_COMMANDS["AdditionalFrame"], []));
            appsRaw = Buffer.concat([appsRaw, result.slice(0,result.length-2)]);
        }
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("failed to list application ids");
        }
        let appsArray = appsRaw.toJSON().data;
        let apps = [];
        for (let index = 0; index < appsArray.length; index += 3) {
            apps.push(appsArray.slice(index, index+3));
        }
        return apps;
    }
    
    getKeyByValue(object, value) {
        return Object.keys(object).find(key => object[key] === value);
    }
    
    async createApplication(aAppId, aSettings, aKeyCount, aKeyType) {
        console.log("> Create application ", aAppId.toString(16));
        let parameters = Buffer.alloc(5);
        writeUint24LE(parameters, aAppId, 0);
        parameters.writeUint8(aSettings, 3);
        parameters.writeUint8(aKeyCount | aKeyType, 4);
        console.log("  Parameters:", parameters);
        let [data, returnCode] = await this.executeTransaction(this.wrap(DESFIRE_COMMANDS["CreateApplication"], parameters));
        /*console.log("Return code:", this.getKeyByValue(DESFIRE_STATUS, returnCode));
        console.log("Data:       ", data);*/
        if (returnCode !== DESFIRE_STATUS["Success"]) {
            throw new Error("create application failed (" + this.getKeyByValue(DESFIRE_STATUS, returnCode) + ")");
        }
    }
    
    async selectApplication(appId) {
        if (typeof appId === "number") {
            let newAppId = Buffer.from([0,0,0,0]);
            newAppId.writeUint32LE(appId);
            appId = newAppId.slice(0,3);
        }
        const result = await this.executeTransactionRaw(this.wrap(DESFIRE_COMMANDS["SelectApplication"], appId));
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("failed to select app");
        }
    }
}

module.exports = {DesfireCard: DesfireCard, DesfireKeySettings: DesfireKeySettings};
