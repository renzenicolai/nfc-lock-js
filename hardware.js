"use strict";

const Gpio = require('onoff').Gpio;
const sleep = require('sleep-promise');

class Hardware {
    constructor(configuration, power_callback, state_callback) {
        this.configuration = configuration;
        this.power_callback = power_callback;
        this.state_callback = state_callback;

        this.duration = configuration.get("hardware", "duration");
        if (this.duration == null) {
            throw new Error("Error: no duration configured");
        }

        this.gpio_number_solenoid = configuration.get("hardware", "gpio", "solenoid");
        this.gpio_handle_solenoid = null;
        if (this.gpio_number_solenoid != null) {
            this.gpio_handle_solenoid = new Gpio(this.gpio_number_solenoid, "out");
            this.gpio_handle_solenoid.writeSync(0); // This sets the direction of the GPIO to output
        } else {
            console.error("Warning: no GPIO configured for solenoid output");
        }

        this.gpio_number_sensor_power = configuration.get("hardware", "gpio", "sensor_power");
        this.gpio_handle_sensor_power = null;
        if (this.gpio_number_sensor_power != null) {
            this.gpio_handle_sensor_power = new Gpio(this.gpio_number_sensor_power, "in");
        } else {
            console.error("Warning: no GPIO configured for power sensor input");
        }

        this.previous_power = true;

        this.gpio_number_sensor_state = configuration.get("hardware", "gpio", "sensor_state");
        this.gpio_handle_sensor_state = null;
        if (this.gpio_number_sensor_state != null) {
            this.gpio_handle_sensor_state = new Gpio(this.gpio_number_sensor_state, "in");
        } else {
            console.error("Warning: no GPIO configured for state sensor input");
        }

        this.previous_state = true;

        this.sensor_interval = configuration.get("hardware", "interval");
        if (typeof this.sensor_interval !== "number") {
            throw new Error("Error: no interval configured for sensor poll loop");
        }
        this.sensor_interval_pointer = setInterval(this._sensorLoop.bind(this), this.sensor_interval);
    }

    async openDoor() {
        if (this.gpio_handle_solenoid !== null) {
            this.gpio_handle_solenoid.writeSync(1);
            await sleep(this.duration);
            this.gpio_handle_solenoid.writeSync(0);
        } else {
            console.log("Warning: no solenoid gpio available to open the door");
        }
    }

    _sensorLoop() {
        if (this.gpio_handle_sensor_power !== null) {
            let power = this.gpio_handle_sensor_power.readSync();
            if (power !== this.previous_power) {
                this.previous_power = power;
                if (typeof this.power_callback === "function") {
                    this.power_callback(power);
                }
            }
        }

        if (this.gpio_handle_sensor_state !== null) {
            let state = this.gpio_handle_sensor_state.readSync();
            if (state !== this.previous_state) {
                if (typeof this.state_callback === "function") {
                    this.state_callback(power);
                }
            }
        }
    }
}

module.exports = Hardware;
