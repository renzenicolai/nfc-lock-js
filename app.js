"use strict";

const Configuration = require("nicolai-configuration");
const Hardware = require("./hardware.js");
const NfcLock = require("./nfclock.js");
const Spacecore = require("./spacecore.js");
const Database = require("./database.js");
const Mqtt = require("./mqtt.js");

const configuration = new Configuration("configuration.json");
const hardware = new Hardware(configuration, null, null);

let database = new Database(configuration);
let mqtt = new Mqtt(configuration);
let spacecore = new Spacecore(configuration, database);
let nfclock = new NfcLock(configuration, database, hardware, mqtt);