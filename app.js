"use strict";

const fs = require('fs');
const { NFC, CONNECT_MODE_DIRECT } = require("@aapeli/nfc-pcsc");
const { DesfireCard, DesfireKeySettings } = require("@nicolaielectronics/desfire.js");
const Gpio = require('onoff').Gpio;
const sleep = require('sleep-promise');
const Atr = require("./parseAtr.js");

const nfc = new NFC();

let database = JSON.parse(fs.readFileSync('nfc.json'));

/* Raspberry Pi GPIO */

var gpio_solenoid = new Gpio(25, 'out');
var gpio_sense_powersupply = new Gpio(23, 'in');
var gpio_sense_door_closed = new Gpio(24, 'in');

gpio_solenoid.writeSync(0); // initialise it low (upon boot will be floating unless pulled down)

async function openDoor() {
    gpio_solenoid.writeSync(1); // open lock
    await sleep(2000); // Wait 2000 ms
    gpio_solenoid.writeSync(0); // close lock
}

function sensorLoop() {
    let powersupply_ok = gpio_sense_powersupply.readSync();
    if (!powersupply_ok) {
        console.log("Solenoid powersupply failure!");
    } else {
        let door_closed = gpio_sense_door_closed.readSync();
        if (!door_closed) {
            console.log("Door sensor indicates that the door is open!");
        }
    }
}

setInterval(sensorLoop, 2000);

/* NFC reader */

async function checkCard(desfire) {
    try {
        if (!(desfire.uid in database)) {
            console.error("UID not found in database");
            return;
        }

        let data = Buffer.from(database[desfire.uid]['secret'], 'hex');
        let key = data.slice(0,16);
        let secret = data.slice(16,32);

        await desfire.selectApplication(0x1984); 
        await desfire.ev1AuthenticateAes(0, key);
        let secretOnCard = await desfire.readDataEncrypted(1, 0, 16);

        if (Buffer.compare(secret, secretOnCard) !== 0) {
            console.error("Secret on card is invalid");
            return;
        }
        
        console.log("Found valid Desfire key, owner is '", database[desfire.uid]['owner'], "'. Opening door...");
        openDoor();

        //let nameOnCard = await desfire.readDataEncrypted(2, 0, 16);
        //console.log("Card is verified!", nameOnCard.toString('ascii'));
    } catch (error) {
        console.error("Failed to authenticate card", error);
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
                await this.card.getUid();
                console.log(this._reader.name + ": Desfire card " + this.card.uid + " attached");
                checkCard(this.card);
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
