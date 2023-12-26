"use strict";

const mqtt = require("mqtt");

class Mqtt {
    constructor(configuration) {
        this.configuration = configuration;
        this.server = configuration.get("mqtt", "server");
        this.topic = configuration.get("mqtt", "topic");
        this.client = null;

        if (this.server !== null && this.topic !== null) {
            this._connect();
        } else {
            console.error("Warning: MQTT not configured");
        }
    }

    async _connect() {
        try {
            this.client = await mqtt.connectAsync(this.server);

            console.log("Connected to MQTT server");
            this.publish({
                type: "connected"
            });
        } catch (error) {
            console.error("Error: failed to connect to MQTT", error);
        }
    }

    async publish(information) {
        try {
            if (this.topic !== null && this.client) {
                await this.client.publishAsync(this.topic, JSON.stringify(information));
            }
        } catch (error) {
            console.error("Error: failed to publish to MQTT", error);
        }
    }
}

module.exports = Mqtt;