"use strict";

const crypto = require("crypto");
const { NFC, CONNECT_MODE_DIRECT } = require("nfc-pcsc");
const { DESFIRE_COMMANDS, DESFIRE_STATUS } = require("./desfire.js");

const nfc = new NFC();

class DesfireCard {
    constructor(reader, card) {
        this._reader = reader;
        this._card = card;

        this.default_des_key = Buffer.from("00000000000000000000000000000000", "hex");
        
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
    
    async send(cmd, info = "unknown", responseMaxLength = 40) {
        const buff = Buffer.from(cmd);
        console.log(this._reader.name + " " + info + ": sending ", buff);
        const data = await this._reader.transmit(buff, responseMaxLength);
        console.log(this._reader.name + " " + info + ": received ", data);
        return data;
    };
    
    wrap(cmd, dataIn) {
        if (dataIn.length > 0) {
            return [0x90, cmd, 0x00, 0x00, dataIn.length, ...dataIn, 0x00];
        } else {
            return [0x90, cmd, 0x00, 0x00, 0x00];
        }
    }
    
    async selectApplication(appId) {
        // 1: [0x5A] SelectApplication(appId) [4 bytes] - Selects one specific application for further access
        // DataIn: appId (3 bytes)
        const res = await this.send(this.wrap(DESFIRE_COMMANDS["SelectApplication"], appId), "select app");

        // something went wrong
        if (res.slice(-1)[0] !== DESFIRE_STATUS["Success"]) {
            throw new Error("failed to select app");
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
        const RndBp = Buffer.concat([RndB.slice(1, 8), RndB.slice(0, 1)]);

        // generate a 8 byte Random Number A
        const RndA = crypto.randomBytes(8);

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
        const RndA2 = Buffer.concat([RndAp.slice(7, 8), RndAp.slice(0, 7)]);

        // compare decrypted RndA2 response from reader with our RndA
        // if it equals authentication process was successful
        if (!RndA.equals(RndA2)) {
            throw new Error("failed to match RndA random bytes");
        }

        return { RndA, RndB };
    }
    
    async listApplicationsIds() {
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
    
    async run() {
        try {
            await this.selectApplication([0x00, 0x00, 0x00]); // Select PICC
			await this.authenticateDes(0x00, this.default_des_key); // Authenticate using default key
            let applications = await this.listApplicationsIds();
            console.log(applications);
        } catch (error) {
            console.error("Desfire error", error);
        }
    }
}

class NfcReader {
    constructor(reader, onEnd) {
        this.desfireAtr = Buffer.from([0x3b, 0x81, 0x80, 0x01, 0x80, 0x80]);
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
        if (Buffer.compare(card.atr, this.desfireAtr) === 0) {
            this.card = new DesfireCard(this._reader, card);
            console.log(this._reader.name + ": Desfire card attached");
        } else {
            console.log(this._reader.name + ": unsupported card attached");
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
