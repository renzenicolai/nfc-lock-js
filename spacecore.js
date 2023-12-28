"use strict";

const ApiClient = require("./apiclient.js");

class Spacecore {
    constructor(configuration, database) {
        this.configuration = configuration;
        this.database = database;
        this.server = configuration.get("spacecore", "server");
        this.apiClient = new ApiClient(
            this._onOpen.bind(this),
            this._onClose.bind(this),
            this._onError.bind(this),
            this._onSession.bind(this),
            this.server
        );
        this.interval = this.configuration.get("spacecore", "interval") || 10000;
        this.session = null;
        this.loopTimer = null;
        this.username = this.configuration.get("spacecore", "username") || "lock";
        this.password = this.configuration.get("spacecore", "password");

        if (this.server !== null) {
            this.apiClient.connect();
            this.loopTimer = setTimeout(this._loop.bind(this), this.interval);
        } else {
            console.error("Warning: no Spacecore server configured, database synchronization disabled");
        }
    }

    async _onOpen() {
        console.log("Connected to Spacecore server");
        await this._loop();
    }

    async _onClose() {
        console.log("Disconnected from Spacecore server");
        this.session = null;
    }

    async _onError(source, ...args) {
        console.log("Error while communicating with server:", source, args);
        this.session = null;
    }
    
    async _onSession(session) {
        this.session = session;
    }

    async _loop() {
        try {
            clearTimeout(this.loopTimer);
            if (this.session !== null) {
                await this.apiClient.requestPromise("ping");
                if (this.session.user === null) {
                    // Not authenticated
                    if (this.session.permissions.indexOf("user/authenticate") >= 0) {
                        // Authenticate
                        try {
                            let result = await this.apiClient.requestPromise(
                                "user/authenticate",
                                {
                                    user_name: this.username,
                                    password: this.password
                                }
                            );
                            console.log("Authenticated to Spacecore as user '" + result.user_name + "'");
                        } catch (error) {
                            console.error("Warning: Failed to authenticate to Spacecore server", error);
                        }
                    } else {
                        console.error("Warning: Spacecore server has no authentication method available");
                    }
                }

                try {
                    let result = await this.apiClient.requestPromise(
                        "person/list", null
                    );
                    await this._createDatabase(result);
                } catch (error) {
                    console.error("Warning: Failed to query list of persons from Spacecore server", error);
                }
            } else {
                this.apiClient.connect();
            }
        } catch (error) {
            console.error("Error: Spacecore synchronization failed", error);
        }
        clearTimeout(this.loopTimer);
        this.loopTimer = setTimeout(this._loop.bind(this), this.interval);
    }
    
    async _createDatabase(persons) {
        let database = {};
        for (let index = 0; index < persons.length; index++) {
            let person = persons[index];
            let nickname = person.nick_name;
            let name = person.first_name + ((person.last_name.length > 0) ? (" " + person.last_name) : "");
            let tokens = person.tokens;

            if (tokens.length < 1) {
                //console.log("Person '" + name + "' has no key assigned");
            } else {
                for (let tokenIndex = 0; tokenIndex < tokens.length; tokenIndex++) {
                    let token = tokens[tokenIndex];
                    if (token.enabled) {
                        if (token.type.name === "DesFire card for doorlock") {
                            let uid = token.public;
                            let secret = token.private;
                            if (uid in database) {
                                console.log("Person '" + name + "' has key " + uid + " assigned, which is also assigned to " + database[uid].owner);
                            }
                            database[uid] = {
                                secret: secret,
                                owner: nickname,
                                name: name
                            };
                        } else {
                            //console.log("Person '" + name + "' has a key of type " + token.type.name + " which has been ignored");
                        }
                    } else {
                        //console.log("Person '" + name + "' has a disabled key which has been ignored");
                    }
                }
            }
        }
        this.database.set(database);
        this.database.store();
        //console.log("Database synchronized with Spacecore, " + Object.keys(database).length + " keys in database");
    }
}

module.exports = Spacecore;
