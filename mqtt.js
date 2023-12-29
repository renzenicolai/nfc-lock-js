"use strict";

const mqtt = require("mqtt");

class Mqtt {
    constructor(configuration) {
        this.configuration = configuration;
        this.server = configuration.get("mqtt", "server");
        this.topic = configuration.get("mqtt", "topic");
        this.reconnectPeriod = configuration.get("mqtt", "reconnectPeriod") || 2000;
        this.connectTimeout = configuration.get("mqtt", "connectTimeout") || 30000;
        this.client = null;

        if (this.server !== null && this.topic !== null) {
            this._connect();
        } else {
            console.error("Warning: MQTT not configured");
        }
    }

    async _connect() {
        try {
            this.client = await mqtt.connect(this.server, {
                reconnectPeriod: this.reconnectPeriod,
                connectTimeout: this.connectTimeout
            });

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
                await this.client.publish(this.topic, JSON.stringify(information));
            }
        } catch (error) {
            console.error("Error: failed to publish to MQTT", error);
        }
    }
}

module.exports = Mqtt;
