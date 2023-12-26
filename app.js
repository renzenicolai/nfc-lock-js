"use strict";

const Configuration = require("nicolai-configuration");
const Hardware = require("./hardware.js");
const NfcLock = require("./nfclock.js");
const Spacecore = require("./spacecore.js");
const Database = require("./database.js");

const configuration = new Configuration("configuration.json");
const hardware = new Hardware(configuration, null, null);

let database = new Database(configuration);
let nfclock = new NfcLock(configuration, database, hardware);
let spacecore = new Spacecore(configuration, database);
