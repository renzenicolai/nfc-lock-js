"use strict";

const { NFC, CONNECT_MODE_DIRECT } = require("@aapeli/nfc-pcsc");
const { DesfireCard, DesfireKeySettings } = require("./desfire.js");
const Atr = require("./parseAtr.js");

const nfc = new NFC();

async function handleDesfireCard(desfire) {
    try {
        console.log(" > Select PICC application");
        await desfire.selectApplication(0x000000); // Select PICC
        console.log(" > Authenticate to PICC application with default DES key");
        await desfire.authenticateLegacy(0x00, desfire.default_des_key); // Authenticate using default key
        console.log(" > Format card");
        await desfire.formatPicc();
        console.log(" > Create application");
        desfire.createApplication(1234, desfire.constants.keySettings.factoryDefault, 2, desfire.constants.keyType.aes);
        console.log(" > Read list of applications");
        let applications = await desfire.getApplicationIdentifiers();
        let applicationsString = "";
        for (let index = 0; index < applications.length; index++) {
            let appId = Buffer.concat([Buffer.from(applications[index]), Buffer.from([0x00])]).readUint32LE();
            applicationsString += appId + " ";
        }
        console.log("Applications: ", applicationsString);
        
        console.log(" > Select 1234 application");
        await desfire.selectApplication(1234); 

        console.log(" > Authenticate to 1234 application with default AES key");
        await desfire.ev1AuthenticateAes(0, desfire.default_aes_key);

        /*console.log(" > Get file identifiers");
        let files = await desfire.getFileIdentifiers();
        console.log("Files: ", files);*/
        
        let keyVersion = await desfire.getKeyVersion(0);
        console.log("Key version:", keyVersion);
        
        /*console.log(" > Delete application");
        desfire.deleteApplication(1234);
        console.log(" > Read list of applications");
        applications = await desfire.getApplicationIdentifiers();
        applicationsString = "";
        for (let index = 0; index < applications.length; index++) {
            let appId = Buffer.concat([Buffer.from(applications[index]), Buffer.from([0x00])]).readUint32LE();
            applicationsString += appId.toString(16).padStart(6,"0") + " ";
        }
        console.log("Applications: ", applicationsString);*/
/*
        console.log("Session key:  ", desfire.key.sessionKey);
        console.log("CMAC subkeys: ", desfire.key.cmac1, desfire.key.cmac2);
        
        let version = await desfire.getVersion();
        version.print();
        console.log("Free memory:     ", await desfire.ev1FreeMem(), "bytes");
        let applications = await desfire.getApplicationIdentifiers();
        let applicationsString = "";
        for (let index = 0; index < applications.length; index++) {
            let appId = Buffer.concat([Buffer.from(applications[index]), Buffer.from([0x00])]).readUint32LE();
            applicationsString += appId.toString(16).padStart(6,"0") + " ";
        }
        console.log("Applications:    ", applicationsString);
        
        let keySettings = new DesfireKeySettings();
        desfire.createApplication(0x001234, 0x0F, 1, 0x80);*/
        
        /*console.log(" > Select 1984 application");
        await desfire.selectApplication(0x001984); // Select TkkrLab
        console.log(" > Authenticate to 1984 application with default AES key");
        await desfire.ev1AuthenticateAes(0x00, desfire.default_aes_key);
        //console.log(await desfire.getKeySettings());
        
        //let realUid = await desfire.readCardUid();
        //console.log("Real UID:", realUid);
        console.log(" > Read file data");
        await desfire.readData(0, 0, 8);
        //await desfire.formatPicc();
        //console.log("Done, card formatted!");*/
    } catch (error) {
        console.error("Desfire error", error);
    }
}

class NfcReader {
    constructor(reader, onEnd) {
        this.androidAtr    = Buffer.from([0x3b, 0x80, 0x80, 0x01, 0x01]);
        this.tlvAtr        = Buffer.from([0x3b, 0x8d, 0x80, 0x01, 0x80]);
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
            if (err.message.startsWith("Not found response. Tag not compatible with AID")) {
                console.log(this._reader.name + ": Card is not compatible with this application.");
            } else {
                console.error(this._reader.name + " error:", err);
            }
        });
        
        this.card = null;
        this.cardPresent = false;
    };

    async _onCard(card) {
        let cardWasPresent = this.cardPresent;
        this.cardPresent = true;
        let atr = new Atr(card.atr);
        if (!cardWasPresent) {
            if (atr.isDesfire()) {
                this.card = new DesfireCard(this._reader, card);
                console.log(this._reader.name + ": Desfire card attached");
                handleDesfireCard(this.card);
                
                /*console.log("\n\n\n\n\nEMPTY MESSAGE\n\n");
                
                this.card.test(0, Buffer.from([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C]));
                this.card.key.generateCmacSubKeys();
                
                console.log("OUT  ", await this.card.calculateCmac(Buffer.from([])));
                
                console.log("\n\n\n\n\n16 BYTE MESSAGE\n\n");
                
                this.card.key.generateCmacSubKeys();
                console.log("OUT  ", await this.card.calculateCmac(Buffer.from([0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A])));
                
                console.log("\n\n\n\n\n40 BYTE MESSAGE\n\n");
                
                this.card.key.generateCmacSubKeys();
                console.log("OUT  ", await this.card.calculateCmac(Buffer.from([0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11])));*/
                
                /*console.log("CRC: ", this.card.crc(Buffer.from([0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80])).toString(16));*/

            /*} else if (Buffer.compare(card.atr, this.androidAtr) === 0) {
                console.log(this._reader.name + ": Android phone attached");
            } else if (Buffer.compare(card.atr.slice(0,this.tlvAtr.length), this.tlvAtr) === 0) {
                // Compact TLV data object
                console.log(this._reader.name + ": Card with compact TLV attached");
                for (let i = this.tlvAtr.length; i < card.atr.length;) {
                    let tagType = (card.atr[i] & 0xF0) >> 4;
                    let tagLength = card.atr[i] & 0xF;
                    let tagValue = card.atr.slice(i + 1, i + 1, tagLength);
                    console.log(this._reader.name + "    type " + tagType.toString(16) + ", length " + tagLength + " value ", tagValue);
                    i += tagLength;
                    if (tagLength == 0) break;
                }*/
            } else {
                //this._reader.aid = 'A000000527210101'; // Yubico OATH
                this._reader.aid = 'D2760000850101'; // NDEF
                this._reader.handleTag(); // This executes the card event again!
            }
        } else {
            // Library has handled the tag
            if (typeof card.uid === "string") {
                console.log("Card with UID " + card.uid + " found: ", card);
            } else {
                console.log("Card found:", card);
            }
        }
    }
    
    async _onCardRemoved(card) {
        this.card = null;
        this.cardPresent = false;
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
