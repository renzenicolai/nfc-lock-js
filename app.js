"use strict";

const Configuration = require("nicolai-configuration");
const Hardware = require("./hardware.js");
const NfcLock = require("./nfclock.js");
const Spacecore = require("./spacecore.js");
const Database = require("./database.js");
const Mqtt = require("./mqtt.js");

const configuration = new Configuration("configuration.json");
let database = new Database(configuration);
let mqtt = new Mqtt(configuration);
let spacecore = new Spacecore(configuration, database);


async function handle_power_change(power) {
    if (power) {
        console.error("Solenoid power lost!");
    } else {
        console.log("Solenoid power OK");
    }
    mqtt.publish({
        type: "power",
        state: power
    });
}

async function handle_state_change(state) {
    if (state) {
        console.error("Door OPEN");
    } else {
        console.log("Door CLOSED");
    }
    mqtt.publish({
        type: "state",
        state: state
    });
}

const hardware = new Hardware(configuration, handle_power_change, handle_state_change);
let nfclock = new NfcLock(configuration, database, hardware, mqtt);
