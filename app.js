"use strict";

const { NFC, CONNECT_MODE_DIRECT } = require("@aapeli/nfc-pcsc");
const { DesfireCard, DesfireKeySettings } = require("./desfire.js");
const Atr = require("./parseAtr.js");

const nfc = new NFC();

async function handleDesfireCard(desfire) {
    try {

        // This block of code functions as a test for some of the library functions

        console.log(" > Select PICC application");
        await desfire.selectApplication(0x000000); // Select PICC

        console.log(" > Authenticate to PICC application with default DES key");
        await desfire.authenticateLegacy(0x00, desfire.default_des_key); // Authenticate using default key

        console.log(" > Get card version");
        let version = await desfire.getVersion();
        version.print();

        console.log(" > DES Get card UID");
        let uid = await desfire.ev1GetCardUid();
        console.log("Card UID: ", uid);

        console.log(" > Format card");
        await desfire.formatPicc();

        console.log(" > Create application");
        desfire.createApplication(1234, desfire.constants.keySettings.factoryDefault, 2, desfire.constants.keyType.aes);

        console.log(" > Read list of applications");
        let applications = await desfire.getApplicationIdentifiers();
        console.log("Applications: ", applications);
        
        console.log(" > Select 1234 application");
        await desfire.selectApplication(1234); 

        console.log(" > Authenticate to 1234 application with default AES key");
        await desfire.ev1AuthenticateAes(0, desfire.default_aes_key);

        console.log(" > AES Get card UID");
        uid = await desfire.ev1GetCardUid();
        console.log("Card UID: ", uid);

        console.log(" > AES Get card UID");
        uid = await desfire.ev1GetCardUid();
        console.log("Card UID: ", uid);

        console.log(" > AES Get card UID");
        uid = await desfire.ev1GetCardUid();
        console.log("Card UID: ", uid);

        console.log(" > Get key settings");
        console.log(await desfire.getKeySettings());

        console.log(" > Get key version");
        let keyVersion = await desfire.getKeyVersion(0);
        console.log("Key version:", keyVersion);

        console.log(" > Get card UID");
        uid = await desfire.ev1GetCardUid();
        console.log("Card UID: ", uid);

        console.log(" > Get card UID");
        uid = await desfire.ev1GetCardUid();
        console.log("Card UID: ", uid);

        console.log(" > Get card UID");
        uid = await desfire.ev1GetCardUid();
        console.log("Card UID: ", uid);

        console.log(" > Create file (plain)");
        await desfire.createStandardDataFile(0, false, false, 0, 0, 0, 0, 32);

        console.log(" > Write data to file (plain)");
        await desfire.writeData(0, Buffer.from("Hello plain text", "utf-8"), false, false, 0);

        console.log(" > Read data from file (plain)");
        let fileContents = await desfire.readData(0, false, false, 0, 16);
        console.log("File contents:", fileContents);

        console.log(" > Create file (CMAC)");
        await desfire.createStandardDataFile(1, true, false, 0, 0, 0, 0, 32);

        /*console.log(" > Write data to file (CMAC)");
        await desfire.writeData(1, Buffer.from("Hello CMAC", "utf-8"), true, false, 0);

        console.log(" > Read data from file (CMAC)");
        let fileContents = await desfire.readData(0, false, false, 0, 16);
        console.log("File contents:", fileContents);*/

        console.log(" > Get file identifiers");
        let files = await desfire.getFileIdentifiers();
        console.log("Files: ", files);

        console.log(" > Get card UID");
        uid = await desfire.ev1GetCardUid();
        console.log("Card UID: ", uid);
        
        console.log(" > Delete application");
        desfire.deleteApplication(1234);

        console.log(" > Read list of applications");
        applications = await desfire.getApplicationIdentifiers();
        console.log("Applications: ", applications);

        console.log(" > Get free memory");
        let freeMemory = await desfire.ev1FreeMem();
        console.log("Free memory: ", freeMemory, "bytes");
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
