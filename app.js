"use strict";

const crypto = require("crypto");
const crc32 = require("buffer-crc32");
const { NFC, CONNECT_MODE_DIRECT } = require("nfc-pcsc");
const { DESFIRE_COMMANDS, DESFIRE_STATUS } = require("./desfire.js");

const nfc = new NFC();

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

        this.default_des_key         = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        this.default_aes_key         = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        this.sessionKey = null;
        this.iv = null;
        this.keyType = null;
        this.keyId = null;
        
        setTimeout(this.run.bind(this), 0);
    }
    
    decryptDes(key, data, iv = Buffer.alloc(8).fill(0)) {
        const decipher = crypto.createDecipheriv("DES-EDE-CBC", key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }

    encryptDes(key, data, iv = Buffer.alloc(8).fill(0)) {
        const decipher = crypto.createCipheriv("DES-EDE-CBC", key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }

    decryptAes(key, data, iv = Buffer.alloc(16).fill(0)) {
        const decipher = crypto.createDecipheriv("AES-128-CBC", key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
    
    encryptAes(key, data, iv = Buffer.alloc(16).fill(0)) {
        const decipher = crypto.createCipheriv("AES-128-CBC", key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
    
    async send(cmd, info = "unknown", responseMaxLength = 40) {
        const buff = Buffer.from(cmd);
        //console.log(this._reader.name + " " + info + ": sending ", buff);
        const data = await this._reader.transmit(buff, responseMaxLength);
        //console.log(this._reader.name + " " + info + ": received ", data);
        return data;
    };
    
    wrap(cmd, dataIn) {
        if (dataIn.length > 0) {
            return [0x90, cmd, 0x00, 0x00, dataIn.length, ...dataIn, 0x00];
        } else {
            return [0x90, cmd, 0x00, 0x00, 0x00];
        }
    }
    
    async authenticateDes(keyId, key) {
        // 2: [0x0a] Authenticate(keyId) [2bytes]
        // DataIn: keyId (1 byte)
        const res1 = await this.send(this.wrap(DESFIRE_COMMANDS["AuthenticateLegacy"], [keyId]), "authenticate des");
        if (res1.slice(-1)[0] !== DESFIRE_STATUS["MoreFrames"]) {
            throw new Error("failed to authenticate");
        }

        // encrypted RndB from reader
        // cut out status code (last 2 bytes)
        const ecRndB = res1.slice(0, -2);

        // decrypt it
        const RndB = this.decryptDes(key, ecRndB);

        // rotate RndB
        const RndBp = Buffer.concat([RndB.slice(1, RndB.length), RndB.slice(0, 1)]);

        // generate a 8 byte Random Number A
        const RndA = crypto.randomBytes(RndB.length);

        // concat RndA and RndBp
        const msg = this.encryptDes(key, Buffer.concat([RndA, RndBp]));

        // send it back to the reader
        const res2 = await this.send(this.wrap(DESFIRE_COMMANDS["AdditionalFrame"], msg), "set up RndA");
        if (res2.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("failed to set up RndA");
        }

        // encrypted RndAp from reader
        // cut out status code (last 2 bytes)
        const ecRndAp = res2.slice(0, -2);

        // decrypt to get rotated value of RndA2
        const RndAp = this.decryptDes(key, ecRndAp);

        // rotate
        const RndA2 = Buffer.concat([RndAp.slice(RndAp.length - 1, RndAp.length), RndAp.slice(0, RndAp.length - 1)]);

        // compare decrypted RndA2 response from reader with our RndA
        // if it equals authentication process was successful
        if (!RndA.equals(RndA2)) {
            throw new Error("failed to match RndA random bytes");
        }

        return { RndA, RndB };
    }
    
    async authenticateAes(keyId, key) {
        // 2: [0x0a] Authenticate(keyId) [2bytes]
        // DataIn: keyId (1 byte)
        const res1 = await this.send(this.wrap(DESFIRE_COMMANDS["Ev1AuthenticateAes"], [keyId]), "authenticate aes");
        if (res1.slice(-1)[0] !== DESFIRE_STATUS["MoreFrames"]) {
            throw new Error("failed to authenticate");
        }

        // encrypted RndB from reader
        // cut out status code (last 2 bytes)
        const ecRndB = res1.slice(0, -2);

        // decrypt it
        const RndB = this.decryptAes(key, ecRndB);

        // rotate RndB
        const RndBp = Buffer.concat([RndB.slice(1, RndB.length), RndB.slice(0, 1)]);

        // generate a 8 byte Random Number A
        const RndA = crypto.randomBytes(RndB.length);

        // concat RndA and RndBp
        const ciphertext = this.encryptAes(key, Buffer.concat([RndA, RndBp]), ecRndB);

        // send it back to the reader
        const res2 = await this.send(this.wrap(DESFIRE_COMMANDS["AdditionalFrame"], ciphertext), "set up RndA");
        if (res2.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("failed to set up RndA");
        }

        // encrypted RndAp from reader
        // cut out status code (last 2 bytes)
        const ecRndAp = res2.slice(0, -2);

        // decrypt to get rotated value of RndA2
        const RndAp = this.decryptAes(key, ecRndAp, ciphertext.slice(-16));

        // rotate
        const RndA2 = Buffer.concat([RndAp.slice(RndAp.length - 1, RndAp.length), RndAp.slice(0, RndAp.length - 1)]);

        // compare decrypted RndA2 response from reader with our RndA
        // if it equals authentication process was successful
        if (!RndA.equals(RndA2)) {
            throw new Error("failed to match RndA random bytes");
        }
        
        this.sessionKey = Buffer.concat([RndA.slice(0,4), RndB.slice(0,4), RndA.slice(12, 16), RndB.slice(12, 16)]);
        this.iv = Buffer.alloc(16).fill(0);
        this.keyType = "aes";
        this.keyId = keyId;
    }
    
    async readData(fileId) {
        // 3: [0xBD] ReadData(FileNo,Offset,Length) [8bytes] - Reads data from Standard Data Files or Backup Data Files
        const res = await this.send(this.wrap(DESFIRE_COMMANDS["ReadData"], [fileId, 0,0,0, 16,0,0]), "read file", 255);
        // something went wrong
        if (res.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("read file failed");
        }
        console.log("File contents", res); // Contains garbage at the end
    };

    async decryptResponse(ciphertext) {
        let plaintext = this.decryptAes(this.sessionKey, ciphertext, this.iv);
        if (this.keyType === "aes") {
            this.iv = ciphertext.slice(-16);
        }
        return plaintext;
    }
    
    async readCardUid() {
        // Not functional yet!
        const result = await this.send(this.wrap(DESFIRE_COMMANDS["Ev1GetCardUid"], []), "read card uid", 255);
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("read file failed");
        }
        return this.decryptResponse(result.slice(0, result.length - 2));
    };
    
    async formatCard() {
        const result = await this.send(this.wrap(DESFIRE_COMMANDS["FormatPicc"], []), "format", 255);
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("format failed");
        }
    };
    
    async getFreeMemory() {
        const result = await this.send(this.wrap(DESFIRE_COMMANDS["Ev1FreeMem"], []), "get free", 255);
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("get free memory failed");
        }
        return Buffer.concat([result.slice(0,3), Buffer.from([0x00])]).readUint32LE();
    };
    
    async getKeyVersion(keyNo) {
        const result = await this.send(this.wrap(DESFIRE_COMMANDS["GetKeyVersion"], [keyNo]), "get key version", 255);
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("get key version failed");
        }
        return result.readUint8(0);
    }
    
    async getKeySettings() {
        const result = await this.send(this.wrap(DESFIRE_COMMANDS["GetKeySettings"], []), "get key settings", 255);
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("get key settings failed");
        }
        return new DesfireKeySettings(result.slice(0,-2));
    }
    
    async changeKeySettings(newSettings) {
        throw new Error("not implemented");
    }
    
    async getCardVersion() {
        let result = await this.send(this.wrap(DESFIRE_COMMANDS["GetVersion"], []), "get version", 255);
        let data = Buffer.from(result.slice(0,result.length-2));
        while (result.slice(-1)[0] === DESFIRE_STATUS["MoreFrames"]) {
            result = await this.send(this.wrap(DESFIRE_COMMANDS["AdditionalFrame"], []), "get version (continued)");
            data = Buffer.concat([data, result.slice(0,result.length-2)]);
        }
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("failed to get card version");
        }
        return new DesfireCardVersion(data);
    };
    
    async getApplicationsIds() {
        let result = await this.send(this.wrap(DESFIRE_COMMANDS["GetApplicationIdentifiers"], []), "get application ids");
        let appsRaw = Buffer.from(result.slice(0,result.length-2));
        while (result.slice(-1)[0] === DESFIRE_STATUS["MoreFrames"]) {
            result = await this.send(this.wrap(DESFIRE_COMMANDS["AdditionalFrame"], []), "get application ids (continued)");
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
    
    async createApplication(appId, keySettings, keyCount, keyType) {
        // Not functional yet!
        if (typeof appId === "number") {
            let newAppId = Buffer.from([0,0,0,0]);
            newAppId.writeUint32LE(appId);
            appId = newAppId.slice(0,3);
        }
        const result = await this.send(this.wrap(DESFIRE_COMMANDS["createApplication"], [appId, keySettings.getBuffer(), keyCount | keyType]), "create application", 255);
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            console.log(result);
            throw new Error("create application failed");
        }
    }
    
    async selectApplication(appId) {
        if (typeof appId === "number") {
            let newAppId = Buffer.from([0,0,0,0]);
            newAppId.writeUint32LE(appId);
            appId = newAppId.slice(0,3);
        }
        const result = await this.send(this.wrap(DESFIRE_COMMANDS["SelectApplication"], appId), "select app");
        if (result.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("failed to select app");
        }
    }
    
    async run() {
        try {
            await this.selectApplication(0x000000); // Select PICC
            console.log(await this.getKeySettings());
            let desSession = await this.authenticateDes(0x00, this.default_des_key); // Authenticate using default key
            let version = await this.getCardVersion();
            version.print();
            console.log("Free memory:     ", await this.getFreeMemory(), "bytes");
            let applications = await this.getApplicationsIds();
            let applicationsString = "";
            for (let index = 0; index < applications.length; index++) {
                let appId = Buffer.concat([Buffer.from(applications[index]), Buffer.from([0x00])]).readUint32LE();
                applicationsString += appId.toString(16).padStart(6,"0") + " ";
            }
            console.log("Applications:    ", applicationsString);
            /*await this.selectApplication(0x001984); // Select TkkrLab
            await this.authenticateAes(0x00, this.default_aes_key);
            console.log(await this.getKeySettings());*/
            
            let keySettings = new DesfireKeySettings();
            this.createApplication(0x001234, keySettings, 1, 0x80);
            
            //let realUid = await this.readCardUid();
            //console.log("Real UID:", realUid);
            //await this.readData(0);
        } catch (error) {
            console.error("Desfire error", error);
        }
    }
}

class NfcReader {
    constructor(reader, onEnd) {
        this.desfireEv2Atr = Buffer.from([0x3b, 0x81, 0x80, 0x01, 0x80, 0x80]);
        this.desfireEv1Atr = Buffer.from([0x3b, 0x81, 0x80, 0x01, 0x8f, 0x8f]);
        this._reader = reader;
        this._onEnd = onEnd;
        this._reader.autoProcessing = false;
        this._reader.on("end", () => {
            if (typeof this._onEnd === "function") {
                this._onEnd(this, reader.name);
            }
        });
        this._reader.on("card", this._onCard.bind(this));
        this._reader.on("card.off", this._onCardRemoved.bind(this));
        reader.on("error", (err) => {
            console.error(this._reader.name + " error:", err);
        });
        
        this.card = null;
    };

    async _onCard(card) {
        if ((Buffer.compare(card.atr, this.desfireEv1Atr) === 0) || (Buffer.compare(card.atr, this.desfireEv2Atr) === 0)) {
            this.card = new DesfireCard(this._reader, card);
            //console.log(this._reader.name + ": Desfire card attached");
        } else {
            console.log(this._reader.name + ": unsupported card attached", card.atr);
        }
    }
    
    async _onCardRemoved(card) {
        this.card = null;
        console.log(this._reader.name + ": card removed");
    }
}

let readers = {};

function onReaderEnd(nfcReader, name) {
    console.log("Reader removed:", name);
    delete readers[name];
}

nfc.on("reader", async reader => {
    if (reader.name in readers) {
        console.error("Error: reader attached but already registered", reader.name);
    }
    readers[reader.name] = new NfcReader(reader, onReaderEnd);
    console.log("Reader attached:", reader.name);
});

nfc.on("error", err => {
    console.error("NFC error", err);
});
