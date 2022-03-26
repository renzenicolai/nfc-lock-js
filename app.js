"use strict";

const { NFC, CONNECT_MODE_DIRECT } = require("nfc-pcsc");
const { DesfireCard, DesfireKeySettings } = require("./desfire.js");

const nfc = new NFC();

async function exampleFunction(desfire) {
    try {
        console.log(" > Select PICC application");
        await desfire.selectApplication(0x000000); // Select PICC
        //console.log(await desfire.getKeySettings());
        console.log(" > Authenticate to PICC application with default DES key");
        await desfire.authenticateDes(0x00, desfire.default_des_key); // Authenticate using default key
        
        console.log("Session key:  ", desfire.key.sessionKey);
        console.log("CMAC subkeys: ", desfire.key.cmac1, desfire.key.cmac2);
        
        let version = await desfire.getCardVersion();
        version.print();
        console.log("Free memory:     ", await desfire.getFreeMemory(), "bytes");
        let applications = await desfire.getApplicationsIds();
        let applicationsString = "";
        for (let index = 0; index < applications.length; index++) {
            let appId = Buffer.concat([Buffer.from(applications[index]), Buffer.from([0x00])]).readUint32LE();
            applicationsString += appId.toString(16).padStart(6,"0") + " ";
        }
        console.log("Applications:    ", applicationsString);
        
        //let keySettings = new DesfireKeySettings();
        //desfire.createApplication(0x001234, 0x0F, 1, 0x80);
        
        console.log(" > Select 1984 application");
        await desfire.selectApplication(0x001984); // Select TkkrLab
        console.log(" > Authenticate to 1984 application with default AES key");
        await desfire.authenticateAes(0x00, desfire.default_aes_key);
        //console.log(await desfire.getKeySettings());
        
        //let realUid = await desfire.readCardUid();
        //console.log("Real UID:", realUid);
        console.log(" > Read file data");
        await desfire.readFileData(0, 0, 8);
        //await desfire.formatCard();
        //console.log("Done, card formatted!");
    } catch (error) {
        console.error("Desfire error", error);
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
            console.log(this._reader.name + ": Desfire card attached");
            exampleFunction(this.card);
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
