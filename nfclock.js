"use strict";

const crypto = require('crypto');
const { NFC, CONNECT_MODE_DIRECT } = require("@aapeli/nfc-pcsc");
const { DesfireCard, DesfireKeySettings } = require("@nicolaielectronics/desfire.js");
const Atr = require("./parseAtr.js");

class NfcReader {
    constructor(reader, onEnd, checkCard) {
        this.androidAtr    = Buffer.from([0x3b, 0x80, 0x80, 0x01, 0x01]);
        this.tlvAtr        = Buffer.from([0x3b, 0x8d, 0x80, 0x01, 0x80]);
        this._reader = reader;
        this._onEnd = onEnd;
        this._checkCard = checkCard;
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
                await this.card.getUid();
                console.log(this._reader.name + ": Desfire card " + this.card.uid + " attached");
                this._checkCard(this.card);
            } else {
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

class NfcLock {
    constructor(configuration, database, hardware, mqtt, programmer=false) {
        this.configuration = configuration;
        this.database = database;
        this.hardware = hardware;
        this.mqtt = mqtt;
        this.nfc = new NFC();

        this.readers = {};

        this.nfc.on("reader", async (reader) => {
            if (reader.name in this.readers) {
                console.error("Error: reader attached but already registered", reader.name);
            }
            this.readers[reader.name] = new NfcReader(reader, this._onReaderEnd.bind(this), programmer ? this.programCard.bind(this) : this.checkCard.bind(this));
            console.log("Reader attached:", reader.name);
            if (this.mqtt) {
                this.mqtt.publish({
                    type: "reader_attached",
                    name: reader.name
                });
            }
        });
        
        this.nfc.on("error", (err) => {
            console.error("NFC error", err);
            if (this.mqtt) {
                this.mqtt.publish({
                    type: "nfc_error",
                    reason: err
                });
            }
        });
    }

    async checkCard(desfire) {
        try {
            let database = this.database.get();
            if (!(desfire.uid in database)) {
                console.error("UID not found in database");
                if (this.mqtt) {
                    this.mqtt.publish({
                        type: "denied",
                        reason: "identifier not in database",
                    });
                }
                return;
            }
    
            let data = Buffer.from(database[desfire.uid]['secret'], 'hex');
            let key = data.slice(0,16);
            let secret = data.slice(16,32);
    
            await desfire.selectApplication(0x0591);
            await desfire.ev1AuthenticateAes(0, key);
            let secretOnCard = await desfire.readDataEncrypted(1, 0, 16);
    
            if (Buffer.compare(secret, secretOnCard) !== 0) {
                console.error("Secret on card is invalid");
                if (this.mqtt) {
                    this.mqtt.publish({
                        type: "denied",
                        reason: "invalid secret",
                        owner: database[desfire.uid]['owner'],
                        name: database[desfire.uid]['name'],
                    });
                }
                return;
            }
            
            console.log("Found valid Desfire key, owner is '" + database[desfire.uid]['owner'] + "'. Opening door...");
            this.hardware.openDoor();
            if (this.mqtt) {
                this.mqtt.publish({
                    type: "access",
                    reason: "valid key",
                    owner: database[desfire.uid]['owner'],
                    name: database[desfire.uid]['name'],
                });
            }
    
            //let nameOnCard = await desfire.readDataEncrypted(2, 0, 16);
            //console.log("Card is verified!", nameOnCard.toString('ascii'));
        } catch (error) {
            console.error("Failed to authenticate card", error);
            if (this.mqtt) {
                this.mqtt.publish({
                    type: "denied",
                    reason: "error",
                    error: error
                });
            }
        }
    }

    async programCard(desfire) {
        try {
            let key = crypto.randomBytes(16);
            let secret = crypto.randomBytes(16);

            // Format
            await desfire.selectApplication(0x000000); // Select PICC
            await desfire.authenticateLegacy(0x00, desfire.default_des_key); // Authenticate using default key
            await desfire.formatPicc();

            // Program
            await desfire.selectApplication(0x000000); // Select PICC
            await desfire.authenticateLegacy(0x00, desfire.default_des_key); // Authenticate using default key

            let uid = (await desfire.ev1GetCardUid()).toString('hex');
            if (desfire.uid !== uid) {
                console.log("Randomized UID mode detected, this card can not be used");
                mainWindow.webContents.send('nfc-card-error', {
                    reader: this._reader.name,
                    uid: desfire.uid,
                    error: "Randomized UID mode detected, this card can not be used"
                });
                return;
            }

            // Create application, change key and authenticate
            await desfire.createApplication(0x0591, desfire.constants.keySettings.factoryDefault, 1, desfire.constants.keyType.AES);
            await desfire.selectApplication(0x0591);
            await desfire.ev1AuthenticateAes(0, desfire.default_aes_key);
            await desfire.changeKeyAes(42, 0, key);
            await desfire.ev1AuthenticateAes(0, key);

            // Create file, write secret and read back secret for verification
            await desfire.createStandardDataFile(1, false, true, 0, 0, 0, 0, 16);
            await desfire.writeDataEncrypted(1, secret, 0);
            let fileContents = await desfire.readDataEncrypted(1, 0, 16);
            if (Buffer.compare(secret, fileContents) !== 0) {
                console.log("Failed to verify secret file contents");
                mainWindow.webContents.send('nfc-card-error', {
                    reader: this._reader.name,
                    uid: desfire.uid,
                    error: "Failed to verify secret file contents"
                });
                return;
            }

            console.log("UID: " + desfire.uid + ", data: " + key.toString('hex') + secret.toString('hex'));

            let database = this.database.get();
            database[desfire.uid] = {
                "secret": key.toString('hex') + secret.toString('hex'),
                "owner": "unnamed",
                "name": "Unnamed"
            };
            this.database.store();

        } catch (error) {
            console.log("Error:", error.message);
        }
    }
    
    _onReaderEnd(nfcReader, name) {
        console.log("Reader removed:", name);
        delete this.readers[name];
        if (this.mqtt) {
            this.mqtt.publish({
                type: "reader_detached",
                name: name
            });
        }
    }
}

module.exports = NfcLock;
