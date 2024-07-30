"use strict";

const fs = require('fs');

class Database {
    constructor(configuration) {
        this.configuration = configuration;
        this.filename = configuration.get("database");
        this.database = {};

        this.load();
    }

    load() {
        try {
            this.database = JSON.parse(fs.readFileSync(this.filename));
            console.log("Database loaded from disk, " + Object.keys(this.database).length + " keys in database");
        } catch (error) {
            console.error("Warning: failed to load database from disk");
        }
    }

    store() {
        try {
            fs.writeFileSync(this.filename, JSON.stringify(this.database, null, 2));
        } catch (error) {
            console.error("Warning: failed to store database to disk", error);
        }
    }

    get() {
        return this.database;
    }

    set(database) {
        this.database = database;
    }
}

module.exports = Database;
