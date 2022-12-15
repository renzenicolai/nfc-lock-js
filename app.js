"use strict";

const { NFC, CONNECT_MODE_DIRECT } = require("@aapeli/nfc-pcsc");
const { DesfireCard, DesfireKeySettings } = require("./desfire.js");
const Atr = require("./parseAtr.js");

const nfc = new NFC();

async function handleDesfireCard(desfire) {
    try {
        console.log(" > Select PICC application");
        await desfire.selectApplication(0x000000); // Select PICC
        //console.log(await desfire.getKeySettings());
        console.log(" > Authenticate to PICC application with default DES key");
        await desfire.authenticateLegacy(0x00, desfire.default_des_key); // Authenticate using default key
        
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
        
        //let keySettings = new DesfireKeySettings();
        //desfire.createApplication(0x001234, 0x0F, 1, 0x80);
        
        console.log(" > Select 1984 application");
        await desfire.selectApplication(0x001984); // Select TkkrLab
        console.log(" > Authenticate to 1984 application with default AES key");
        await desfire.ev1AuthenticateAes(0x00, desfire.default_aes_key);
        //console.log(await desfire.getKeySettings());
        
        //let realUid = await desfire.readCardUid();
        //console.log("Real UID:", realUid);
        console.log(" > Read file data");
        await desfire.readData(0, 0, 8);
        //await desfire.formatPicc();
        //console.log("Done, card formatted!");
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
                this._reader.aid = 'F222222222';
                this._reader.handleTag(); // This executes the card event again!
            }
        } else {
            // Library has handled the tag
            if (typeof card.uid === "string") {
                console.log("Card with UID " + card.uid + " found");
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
