"use strict";

const crypto = require("crypto");

function writeUint24LE(buffer, value, position = 0) {
    let tempBuffer = Buffer.alloc(4);
    tempBuffer.writeUint32LE(value);
    tempBuffer.copy(buffer, position, 0, 3);
}

class DesfireBase {
    constructor() {
        this.constants = {
            NotAuthenticated: 255,
            MaxFrameSize: 60, // The maximum total length of a packet that is transfered to / from the card

            commands: {
                // Security related commands
                AuthenticateLegacy: 0x0A,
                ChangeKeySettings: 0x54,
                GetKeySettings: 0x45,
                ChangeKey: 0xC4,
                GetKeyVersion: 0x64,

                // PICC level commands
                CreateApplication: 0xCA,
                DeleteApplication: 0xDA,
                GetApplicationIdentifiers: 0x6A,
                SelectApplication: 0x5A,
                FormatPicc: 0xFC,
                GetVersion: 0x60,

                // Application level commands
                GetFileIdentifiers: 0x6F,
                GetFileSettings: 0xF5,
                ChangeFileSettings: 0x5F,
                CreateStandardDataFile: 0xCD,
                CreateBackupDataFile: 0xCB,
                CreateValueFile: 0xCC,
                CreateLinearRecordFile: 0xC1,
                CreateCyclicRecordFile: 0xC0,
                DeleteFile: 0xDF,

                // Data manipulation commands
                ReadData: 0xBD,
                WriteData: 0x3D,
                GetValue: 0x6C,
                Credit: 0x0C,
                Debit: 0xDC,
                LimitedCredit: 0x1C,
                WriteRecord: 0x3B,
                ReadRecords: 0xBB,
                ClearRecordFile: 0xEB,
                CommitTransaction: 0xC7,
                AbortTransaction: 0xA7,

                // Other
                AdditionalFrame: 0xAF, // data did not fit into a frame, another frame will follow

                // Desfire EV1 instructions
                Ev1AuthenticateIso: 0x1A,
                Ev1AuthenticateAes: 0xAA,
                Ev1FreeMem: 0x6E,
                Ev1GetDfNames: 0x6D,
                Ev1GetCardUid: 0x51,
                Ev1GetIsoFileIdentifiers: 0x61,
                Ev1SetConfiguration: 0x5C,

                // ISO7816 instructions
                ISO7816ExternalAuthenticate: 0x82,
                ISO7816InternalAuthenticate: 0x88,
                ISO7816AppendRecord: 0xE2,
                ISO7816GetChallenge: 0x84,
                ISO7816ReadRecords: 0xB2,
                ISO7816SelectFile: 0xA4,
                ISO7816ReadBinary: 0xB0,
                ISO7816UpdateBinary: 0xD6
            },
            
            status: {
                success: 0x00,
                noChanges: 0x0C,
                outOfMemory: 0x0E,
                illegalCommand: 0x1C,
                integrityError: 0x1E,
                keyDoesNotExist: 0x40,
                wrongCommandLen: 0x7E,
                permissionDenied: 0x9D,
                incorrectParam: 0x9E,
                appNotFound: 0xA0,
                appIntegrityError: 0xA1,
                authentError: 0xAE,
                moreFrames: 0xAF, // data did not fit into a frame, another frame will follow
                limitExceeded: 0xBE,
                cardIntegrityError: 0xC1,
                commandAborted: 0xCA,
                cardDisabled: 0xCD,
                invalidApp: 0xCE,
                duplicateAidFiles: 0xDE,
                eepromError: 0xEE,
                fileNotFound: 0xF0,
                fileIntegrityError: 0xF1
            },

            keySettings: {
                // Bits 0-3
                allowChangeMk: 0x01, // If this bit is set, the MK can be changed, otherwise it is frozen.
                listingWithoutMk: 0x02, // Picc key: If this bit is set, GetApplicationIDs, GetKeySettings do not require MK authentication, App  key: If this bit is set, GetFileIDs, GetFileSettings, GetKeySettings do not require MK authentication.
                createDeleteWithoutMk: 0x04, // Picc key: If this bit is set, CreateApplication does not require MK authentication, App  key: If this bit is set, CreateFile, DeleteFile do not require MK authentication.
                configurationChangeable: 0x08, // If this bit is set, the configuration settings of the MK can be changed, otherwise they are frozen.
                
                // Bits 4-7 (not used for the PICC master key)
                changeKeyWithMk: 0x00, // A key change requires MK authentication
                changeKeyWithKey1: 0x10, // A key change requires authentication with key 1
                changeKeyWithKey2: 0x20, // A key change requires authentication with key 2
                changeKeyWithKey3: 0x30, // A key change requires authentication with key 3
                changeKeyWithKey4: 0x40, // A key change requires authentication with key 4 
                changeKeyWithKey5: 0x50, // A key change requires authentication with key 5
                changeKeyWithKey6: 0x60, // A key change requires authentication with key 6
                changeKeyWithKey7: 0x70, // A key change requires authentication with key 7
                changeKeyWithKey8: 0x80, // A key change requires authentication with key 8
                changeKeyWithKey9: 0x90, // A key change requires authentication with key 9
                changeKeyWithKeyA: 0xA0, // A key change requires authentication with key 10
                changeKeyWithKeyB: 0xB0, // A key change requires authentication with key 11
                changeKeyWithKeyC: 0xC0, // A key change requires authentication with key 12
                changeKeyWithKeyD: 0xD0, // A key change requires authentication with key 13
                changeKeyWithTargetedKey: 0xE0, // A key change requires authentication with the same key that is to be changed
                changeKeyFrozen: 0xF0, // All keys are frozen

                factoryDefault: 0x0F
            },
            
            keyType: {
                des: 0x00,
                tripleDes: 0x40,
                aes: 0x80
            }
        };
    }
};

class DesfireKey extends DesfireBase {
    constructor(keyId, key) {
        super();
        if (Array.isArray(key)) {
            key = Buffer.from(key);
        }
        if (!Buffer.isBuffer(key)) {
            throw new Error("expected key to be a buffer or array");
        }
        this.authenticationKey = key;
        this.authenticationkeyIdentifier = keyId;

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
    
    clearIv(session) {
        if (session) {
            this.sessionIv = Buffer.alloc(this.blockSize).fill(0);
        } else {
            this.authenticationIv = Buffer.alloc(this.blockSize).fill(0);
        }
    }

    generateCmacSubKeys() {
        this.clearIv(true);
        let R = (this.blockSize == 8) ? 0x1B : 0x87;
        let data = Buffer.alloc(this.blockSize).fill(0);
        this.cmac1 = Buffer.alloc(this.blockSize);
        this.cmac2 = Buffer.alloc(this.blockSize);

        data = this.encrypt(data, true);

        data.copy(this.cmac1);
        this.bitShiftLeft(this.cmac1);
        if (data[0] & 0x80) {
            this.cmac1[this.cmac1.length - 1] ^= R;
        }

        this.cmac1.copy(this.cmac2);
        this.bitShiftLeft(this.cmac2);
        if (this.cmac1[0] & 0x80) {
            this.cmac2[this.cmac2.length - 1] ^= R;
        }

        this.clearIv(true);
    }

    decrypt(data, session) {
        throw new Error("not implemented");
    }
    
    encrypt(data, session) {
        throw new Error("not implemented");
    }
    
    async authenticate() {
        throw new Error("not implemented");
    }
}

class DesfireKeyDes extends DesfireKey {
    constructor(keyId, key) {
        super(keyId, key);
        if (this.keySize !== 16) {
            throw new Error("invalid key length");
        }
        this.blockSize = 8;
    }
    
    decrypt(data, session) {
        const decipher = crypto.createDecipheriv("DES-EDE-CBC", session ? this.sessionKey : this.authenticationKey, Buffer.alloc(8).fill(0));
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }

    encrypt(data, session) {
        const decipher = crypto.createCipheriv("DES-EDE-CBC", session ? this.sessionKey : this.authenticationKey, Buffer.alloc(8).fill(0));
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
    
    async authenticate(card) {
        this.clearIv(false);
        let [data, returnCode] = await card.executeTransaction(card.wrap(this.constants.commands["AuthenticateLegacy"], [this.keyId]));
        if (returnCode !== this.constants.status.moreFrames) {
            throw new Error("failed to authenticate");
        }
        const random_b_encrypted = data; // encrypted random_b from reader
        this.random_b = this.decrypt(random_b_encrypted, false);
        const random_b_rotated = this.rotateLeft(this.random_b);
        this.random_a = crypto.randomBytes(this.random_b.length);
        const ciphertext = this.encrypt(Buffer.concat([this.random_a, random_b_rotated]), false);
        [data, returnCode] = await card.executeTransaction(card.wrap(this.constants.commands["AdditionalFrame"], ciphertext));
        if (returnCode !== this.constants.status.success) {
            throw new Error("failed to set up random_a");
        }
        const random_a2_encrypted_rotated = data;
        const random_a2_rotated = this.decrypt(random_a2_encrypted_rotated, false); // decrypt to get rotated value of random_a2
        const random_a2 =this.rotateRight(random_a2_rotated);
        if (!this.random_a.equals(random_a2)) { // compare decrypted random_a2 response from reader with our random_a if it equals authentication process was successful
            throw new Error("failed to match random_a random bytes");
        }
        
        this.sessionKey = Buffer.concat([this.random_a.slice(0,4), this.random_b.slice(0,4), this.random_a.slice(0,4), this.random_b.slice(0,4)]);
        this.clearIv(true);
        this.generateCmacSubKeys();
    }
}

class DesfireKeyAes extends DesfireKey {
    constructor(keyId, key) {
        super(keyId, key);
        if (this.keySize !== 16) {
            throw new Error("invalid key length");
        }
        this.blockSize = 16;
    }

    decrypt(data, session) {
        //if (session) console.log("AES D");
        const decipher = crypto.createDecipheriv("AES-128-CBC", session ? this.sessionKey : this.authenticationKey, session ? this.sessionIv : this.authenticationIv);
        decipher.setAutoPadding(false);
        let result = Buffer.concat([decipher.update(data), decipher.final()]);
        if (session) {
            this.sessionIv = data.slice(-1 * this.blockSize);
        } else {
            this.authenticationIv = data.slice(-1 * this.blockSize);
        }
        return result;
    }
    
    encrypt(data, session) {
        //if (session) console.log("AES E", this.sessionIv);
        const cipher = crypto.createCipheriv("AES-128-CBC", session ? this.sessionKey : this.authenticationKey, session ? this.sessionIv : this.authenticationIv);
        cipher.setAutoPadding(false);
        let result = Buffer.concat([cipher.update(data), cipher.final()]);
        if (session) {
            this.sessionIv = result.slice(-1 * this.blockSize);
        } else {
            this.authenticationIv = result.slice(-1 * this.blockSize);
        }
        return result;
    }
    
    async authenticate(card) {
        this.clearIv(false);
        let [data, returnCode] = await card.executeTransaction(card.wrap(this.constants.commands["Ev1AuthenticateAes"], [this.keyId]));
        if (returnCode !== this.constants.status.moreFrames) {
            throw new Error("failed to authenticate");
        }
        const random_b_encrypted = data; // encrypted random_b from reader
        this.random_b = this.decrypt(random_b_encrypted, false);
        const random_b_rotated = this.rotateLeft(this.random_b);
        this.random_a = crypto.randomBytes(this.random_b.length);
        const ciphertext = this.encrypt(Buffer.concat([this.random_a, random_b_rotated]), false);
        [data, returnCode] = await card.executeTransaction(card.wrap(this.constants.commands["AdditionalFrame"], ciphertext));
        if (returnCode !== this.constants.status.success) {
            throw new Error("failed to set up random_a");
        }
        const random_a_encrypted_rotated = data; // encrypted random a from reader
        const random_a_rotated = this.decrypt(random_a_encrypted_rotated, false); // decrypt to get rotated value of random_a2
        const random_a2 = this.rotateRight(random_a_rotated);
        if (!this.random_a.equals(random_a2)) { // compare decrypted random_a2 response from reader with our random_a if it equals authentication process was successful
            throw new Error("failed to match random_a random bytes");
        }
        
        this.sessionKey = Buffer.concat([this.random_a.slice(0,4), this.random_b.slice(0,4), this.random_a.slice(12, 16), this.random_b.slice(12, 16)]);
        this.clearIv(true);
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

class DesfireCardVersion extends DesfireBase {
    constructor(buffer) {
        super();
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
        //super();
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

class DesfireCard extends DesfireBase {
    constructor(reader, card) {
        super();
        this._reader = reader;
        this._card = card;

        this.default_des_key = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        this.default_3des_key = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        this.default_aes_key = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        this.key = null;
    }

    // Helper functions

    getKeyByValue(object, value) {
        return Object.keys(object).find(key => object[key] === value);
    }

    async executeTransactionRaw(packet, responseMaxLength = 40) {
        console.log("OLD TRANSACTION RAW");
        return this._reader.transmit(Buffer.from(packet), responseMaxLength);
    };

    async executeTransaction(packet, responseMaxLength = 40) {
        console.log("OLD TRANSACTION");
        let raw = await this._reader.transmit(Buffer.from(packet), responseMaxLength);
        let returnCode = raw.slice(-1)[0];
        let data = raw.slice(0, -2);
        return [data, returnCode];
    }
    
    async communicate(cmd, data, encrypted = False, useCmac = False) {
        console.log("Communicate: ", cmd.toString(16), data);
        if ((encrypted || useCmac) && (this.key === null)) {
            throw Error("Not authenticated");
        }
        
        if (useCmac) {
            let txData = Buffer.from([cmd, ...data]);
            let txCmac = await this.calculateCmac(txData);
            //console.log("TX CMAC", txData, " = ", txCmac);
        }

        let packet = this.wrap(cmd, data);
        
        let raw = await this._reader.transmit(Buffer.from(packet), 40);
        
        //console.log("Raw response: ", raw, "#", raw.length);
        
        if (raw[raw.length - 2] !== 0x91) {
            throw Error("Invalid response");
        }

        let returnCode = raw.slice(-1)[0];
        raw = raw.slice(0,-2);
        
        if (useCmac) {
            let cmac = raw.slice(-8);
            raw = raw.slice(0, -8);
            //console.log("Response: Status ", returnCode, "CMAC: ", cmac, " Data: ", raw, "#", raw.length);
            let inputForCmacCalc = new Buffer.alloc(raw.length + 1);
            raw.copy(inputForCmacCalc);
            inputForCmacCalc[raw.length] = returnCode;
            let calccmac = await this.calculateCmac(inputForCmacCalc);
            //console.log("RX CMAC", inputForCmacCalc, " = ", calccmac.slice(0,8));
            if (Buffer.compare(cmac, calccmac.slice(0,8)) !== 0) {
               throw Error("Invalid cmac");
            }
        } else {
            //console.log("Response: Status ", returnCode, " Data: ", raw, "#", raw.length);
        }

        return [raw, returnCode];
    }
    
    crc(data) {
        let poly = 0xEDB88320;
        let crc = 0xFFFFFFFF;
        for (let n = 0; n < data.length; n++) {
            crc ^= data[n];
            for (let b = 0; b < 8; b++) {
                if (crc & 1) {
                    crc = (crc >>> 1) ^ poly;
                } else {
                    crc = (crc >>> 1);
                }
            }
        }
        
        return crc >>> 0;
    }

    async calculateCmac(input) {
        let buffer = Buffer.from(input);
        let paddingLength = (buffer.length < this.key.blockSize) ? (this.key.blockSize - buffer.length) : ((this.key.blockSize - (buffer.length % this.key.blockSize)) % this.key.blockSize);
        if (paddingLength > 0) {
            paddingLength -= 1;
            buffer = Buffer.concat([buffer, Buffer.from([0x80])]);
            buffer = Buffer.concat([buffer, Buffer.from(new Array(paddingLength).fill(0))]);
            for (let index = 0; index < this.key.blockSize; index++) {
                buffer[buffer.length - this.key.blockSize + index] ^= this.key.cmac2[index];
            }
        } else {
            for (let index = 0; index < this.key.blockSize; index++) {
                buffer[buffer.length - this.key.blockSize + index] ^= this.key.cmac1[index];
            }
        }
        buffer = await this.key.encrypt(buffer, true);
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

    decryptAes(key, data, iv = Buffer.alloc(16).fill(0)) {
        const decipher = crypto.createDecipheriv("AES-128-CBC", key, iv);
        decipher.setAutoPadding(false);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }

    // Security related commands

    async authenticateLegacy(keyId, key) {
        this.key = new DesfireKeyDes(keyId, key);
        await this.key.authenticate(this);
    }

    async changeKeySettings(newSettings) {
        throw new Error("not implemented");
    }

    async getKeySettings() {
        let [data, returnCode] = await this.communicate(this.constants.commands.GetKeySettings, [], false, (this.key !== null));
        if (returnCode !== this.constants.status.success) {
            throw new Error("get key settings failed");
        }
        return new DesfireKeySettings(data);
    }

    async getKeyVersion(keyNo) {
        let [data, returnCode] = await this.communicate(this.constants.commands.GetKeyVersion, [keyNo], false, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("get key version failed");
        }
        return data.readUint8(0);
    }

    // PICC level commands

    async createApplication(aAppId, aSettings, aKeyCount, aKeyType) {
        if (typeof aAppId !== "number" || aAppId < 0 || aAppId >= Math.pow(2, 8 * 3)) { // 3 bytes
            throw Error("Application identifier needs to be a positive number of at most three bytes");
        }
        let parameters = Buffer.alloc(5);
        writeUint24LE(parameters, aAppId, 0);
        parameters.writeUint8(aSettings, 3);
        parameters.writeUint8(aKeyCount | aKeyType, 4);
        console.log(parameters, aKeyCount, aKeyType);
        let [data, returnCode] = await this.executeTransaction(this.wrap(this.constants.commands["CreateApplication"], parameters));
        if (returnCode !== this.constants.status.success) {
            throw new Error("Create application failed (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }

    async deleteApplication(aAppId) {
        if (typeof aAppId !== "number" || aAppId < 0 || aAppId >= Math.pow(2, 8 * 3)) { // 3 bytes
            throw Error("Application identifier needs to be a positive number of at most three bytes");
        }
        let parameters = Buffer.alloc(3);
        writeUint24LE(parameters, aAppId, 0);
        let [data, returnCode] = await this.executeTransaction(this.wrap(this.constants.commands.DeleteApplication, parameters));
        if (returnCode !== this.constants.status.success) {
            throw new Error("Delete application failed (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
    }

    async getApplicationIdentifiers() {
        let result = await this.executeTransactionRaw(this.wrap(this.constants.commands["GetApplicationIdentifiers"], []));
        let appsRaw = Buffer.from(result.slice(0,result.length-2));
        while (result.slice(-1)[0] === this.constants.status.moreFrames) {
            result = await this.executeTransactionRaw(this.wrap(this.constants.commands["AdditionalFrame"], []));
            appsRaw = Buffer.concat([appsRaw, result.slice(0,result.length-2)]);
        }
        if (result.slice(-1)[0] !== this.constants.status.success) {
            throw new Error("failed to list application ids");
        }
        let appsArray = appsRaw.toJSON().data;
        let apps = [];
        for (let index = 0; index < appsArray.length; index += 3) {
            apps.push(appsArray.slice(index, index+3));
        }
        return apps;
    }

    async selectApplication(appId) {
        if (typeof appId === "number") {
            let newAppId = Buffer.from([0,0,0,0]);
            newAppId.writeUint32LE(appId);
            appId = newAppId.slice(0,3);
        }
        const result = await this._reader.transmit(Buffer.from(this.wrap(this.constants.commands["SelectApplication"], appId)), 40);
        if (result.slice(-1)[0] !== this.constants.status.success) {
            throw new Error("failed to select app");
        }
        this.key = null;
    }

    async formatPicc() {
        const result = await this.executeTransactionRaw(this.wrap(this.constants.commands["FormatPicc"], []));
        if (result.slice(-1)[0] !== this.constants.status.success) {
            throw new Error("format failed");
        }
    }

    async getVersion() {
        let result = await this.executeTransactionRaw(this.wrap(this.constants.commands["GetVersion"], []));
        let data = Buffer.from(result.slice(0,result.length-2));
        while (result.slice(-1)[0] === this.constants.status.moreFrames) {
            result = await this.executeTransactionRaw(this.wrap(this.constants.commands["AdditionalFrame"], []));
            data = Buffer.concat([data, result.slice(0,result.length-2)]);
        }
        if (result.slice(-1)[0] !== this.constants.status.success) {
            throw new Error("failed to get card version");
        }
        return new DesfireCardVersion(data);
    };

    // Application level commands

    async getFileIdentifiers() {
        let [data, returnCode] = await this.communicate(
            this.constants.commands.GetFileIdentifiers, [], false, true);
        if (returnCode !== this.constants.status.success) {
            throw new Error("Failed to get file identifiers (" + this.getKeyByValue(this.constants.status, returnCode) + ")");
        }
        return data;
    }

    async getFileSettings() {
        throw new Error("Not implemented");
    }

    async changeFileSettings() {
        throw new Error("Not implemented");
    }

    async createStandardDataFile() {
        throw new Error("Not implemented");
    }

    async createBackupDataFile() {
        throw new Error("Not implemented");
    }

    async createValueFile() {
        throw new Error("Not implemented");
    }

    async createLinearRecordFile() {
        throw new Error("Not implemented");
    }

    async createCyclicRecordFile() {
        throw new Error("Not implemented");
    }

    async deleteFile() {
        throw new Error("Not implemented");
    }

    // Data manipulation commands

    async readData(aFileId, aOffset, aLength) {
        let parameters = Buffer.alloc(7);
        parameters.writeUint8(aFileId, 0);
        writeUint24LE(parameters, aOffset, 1);
        writeUint24LE(parameters, aLength, 4);
        console.log(parameters);
        let [data, returnCode] = await this.executeTransaction(this.wrap(this.constants.commands["ReadData"], parameters), 0xFF);

        if (returnCode !== this.constants.status.success) {
            throw new Error("read file failed (0x" + returnCode.toString(16) + ")");
        }

        let content = data.slice(0,aLength);
        let cmac = data.slice(aLength);

        let calcCmac = await this.calculateCmac(Buffer.concat([content, Buffer.from([0])]));

        console.log("File contents", content);
        console.log("RX CMAC", cmac);
        console.log("CA CMAC", calcCmac.slice(0,8));
        // CMAC check doesn't work yet.
    };

    async writeData() {
        throw new Error("Not implemented");
    }

    async getValue() {
        throw new Error("Not implemented");
    }

    async credit() {
        throw new Error("Not implemented");
    }

    async debit() {
        throw new Error("Not implemented");
    }

    async limitedCredit() {
        throw new Error("Not implemented");
    }

    async writeRecord() {
        throw new Error("Not implemented");
    }

    async readRecords() {
        throw new Error("Not implemented");
    }

    async clearRecordFile() {
        throw new Error("Not implemented");
    }

    async commitTransaction() {
        throw new Error("Not implemented");
    }

    async abortTransaction() {
        throw new Error("Not implemented");
    }

    // Desfire EV1 instructions

    async ev1AuthenticateIso(keyId, key) {
        throw new Error("Not implemented");
    }

    async ev1AuthenticateAes(keyId, key) {
        this.key = new DesfireKeyAes(keyId, key);
        await this.key.authenticate(this);
    }

    async ev1FreeMem() {
        const result = await this.executeTransactionRaw(this.wrap(this.constants.commands["Ev1FreeMem"], []));
        if (result.slice(-1)[0] !== this.constants.status.success) {
            throw new Error("get free memory failed");
        }
        return Buffer.concat([result.slice(0,3), Buffer.from([0x00])]).readUint32LE();
    };

    async ev1GetDfNames() {
        throw new Error("Not implemented");
    }
    
    async ev1GetCardUid() {
        // Not functional yet!
        /*const result = await this.executeTransactionRaw(this.wrap(this.constants.commands["Ev1GetCardUid"], []), 255);
        if (result.slice(-1)[0] !== this.constants.status.success) {
            throw new Error("read file failed");
        }
        return this.decryptResponse(result.slice(0, result.length - 2));*/
    };

    async ev1GetIsoFileIdentifiers() {
        throw new Error("Not implemented");
    }

    async ev1SetConfiguration() {
        throw new Error("Not implemented");
    }
    
    test(keyId, key) {
        this.key = new DesfireKeyAes(keyId, key);
        this.key.sessionKey = key;
        this.key.clearIv(true);
    }
}

module.exports = {DesfireCard: DesfireCard, DesfireKeySettings: DesfireKeySettings};
