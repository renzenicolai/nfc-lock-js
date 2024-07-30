"use strict";

const Configuration = require("nicolai-configuration");
const NfcLock = require("./nfclock.js");
const Database = require("./database.js");

const configuration = new Configuration("configuration.json");
let database = new Database(configuration);

let nfclock = new NfcLock(configuration, database, null, null, true);


