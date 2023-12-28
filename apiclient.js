"use strict";

const WebSocket = require('ws');

class ApiClient {
    constructor(onOpen = null, onClose = null, onError = null, onSession = null, server = window.location.protocol.replace("http","ws") + "//" + window.location.host + "/api/") {
        this.server = server;
        this.connected = false;
        this.isConnecting = false;
        this._wsCallbacks = {};
        this._wsTimeouts = {};
        this._wsPushCallbacks = {};
        this.socket = null;
        this.onOpen = onOpen;
        this.onError = onError;
        this.onClose = onClose;
        this.onSession = onSession;
        this.connectTimeout = null;
        this.pingTimeout = null;
        this.pingRequestTimeout = null;
        this.token = null;
        this.session = null;
    }

    connect() {
        if ((this.isConnecting === false) && (this.connected === false)) {
            this.isConnecting = true;
            if (this.socket !== null) {
                this.socket.close();
            }
            this.socket = new WebSocket(this.server);
            this.socket.onmessage = this._handleResponse.bind(this);
            this.socket.onerror = this._handleWsError.bind(this);
            this.socket.onclose = this._handleClose.bind(this);
            this.socket.onopen = this._handleOpen.bind(this);
            this.connectTimeout = setTimeout(this._onConnectTimeout.bind(this), 10000);
        }
    }

    _onConnectTimeout() {
        this.isConnecting = false;
        if (this.connected === false) {
            console.log("Websocket connect timeout");
            this.connect();
        } else {
            console.log("Websocket connect timeout while connected?!");
        }
    }

    _handleOpen() {
        this.isConnecting = false;
        this.connected = true;
        clearTimeout(this.connectTimeout);
        clearTimeout(this.pingRequestTimeout);
        this.pingRequestTimeout = setTimeout(this._ping.bind(this), 1);
        if (typeof this.onOpen === "function") {
            this.onOpen();
        } else {
            console.log("API websocket connected");
        }
    }

    _handleWsError(event) {
        this._handleError("Connection error", true, event);
    }

    _handleError(source, restart, ...args) {
        if (typeof this.onError === "function") {
            this.onError(source, ...args);
        } else {
            console.log("API error ("+source+")", ...args);
        }
        if ((this.socket !== null) && restart) {
            this.socket.close();
        }
    }

    _handleClose() {
        this.session = null;
        this.connected = false;
        this.socket = null;
        clearTimeout(this.pingRequestTimeout);
        clearTimeout(this.pingTimeout);
        for (let index in this._wsTimeouts) {
            clearTimeout(this._wsTimeouts[index]);
            delete this._wsTimeouts[index];
        }
        for (let index in this._wsCallbacks) {
            delete this._wsCallbacks[index];
        }
        if (typeof this.onClose === "function") {
            this.onClose();
        } else {
            console.log("API websocket disconnected");
        }
    }

    _ping() {
        if (this.connected) {
            clearTimeout(this.pingTimeout);
            clearTimeout(this.pingRequestTimeout);
            this.pingTimeout = setTimeout(this._onPingTimeout.bind(this), 10000);
            if (this.token !== null) {
                this.request("session/state", null, this._onSessionStateResponse.bind(this));
            } else {
                this.request("session/create", null, this._onSessionCreateResponse.bind(this)); // Create new session
            }
        }
    }
    
    logout(callback = null) {
        if (this.connected) {
            this.request("session/destroy", null, callback);
            this.token = null;
            this.session = null;
            if (typeof this.onSession === "function") {
                this.onSession(null);
            }
            this._ping();
        }
    }

    _onSessionCreateResponse(result, error) {
        clearTimeout(this.pingTimeout);
        clearTimeout(this.pingRequestTimeout);
        this.pingRequestTimeout = setTimeout(this._ping.bind(this), 1);
        if (result) {
            this.token = result;
            this.session = null;
            if (typeof this.onSession === "function") {
                this.onSession(null);
            }
        }
        if (error) {
            console.log("Failed to create session:", error);
        }
    }
    
    _onSessionStateResponse(result, error) {
        clearTimeout(this.pingTimeout);
        clearTimeout(this.pingRequestTimeout);
        this.pingRequestTimeout = setTimeout(this._ping.bind(this), 2000);
        if (error) {
            this.token = null; // Session is invalid
            this.session = null;
            if ((this.session) && (typeof this.onSession === "function")) {
                this.onSession(null);
            }
        }
        if (result) {
            this.session = result;
            if (typeof this.onSession === "function") {
                this.onSession(result);
            }
        }
    }

    _onPingTimeout() {
        console.log("Ping timeout");
        if (this.socket !== null) {
            this.socket.close();
        }
    }

    _handleResponse(event) {
        try {
            var message = JSON.parse(event.data);
            if (typeof message === "string") {
                message = {result: null, err: message};
            } else {
                if (typeof message.result === "undefined") message.result = null;
                if (typeof message.error === "undefined") message.error = null;
            }
            if ((typeof message.pushMessage === "boolean") && (message.pushMessage)) {
                if (message.subject in this._wsPushCallbacks) {
                    let callbacks = this._wsPushCallbacks[message.subject];
                    for (let index = 0; index < callbacks.length; index++) {
                        callbacks[index](message.message);
                    }
                } else {
                    console.error("Push message ignored, no callback available", message);
                }
            } else {
                if (typeof message.id !== "undefined") {
                    if (typeof this._wsCallbacks[message.id]==="function") {
                        clearTimeout(this._wsTimeouts[message.id]);
                        this._wsCallbacks[message.id](message.result, message.error);
                        delete this._wsCallbacks[message.id];
                        delete this._wsTimeouts[message.id];
                    } else {
                        console.error("Response ignored, no callback available", message);
                    }
                } else {
                    this._handleError("no identifier in response", false, message);
                }
            }
        } catch(err) {
            try {
                var message = JSON.parse(event.data);
                if (typeof this._wsCallbacks[message.id]==="function") {
                    clearTimeout(this._wsTimeouts[message.id]);
                    delete this._wsCallbacks[message.id];
                    delete this._wsTimeouts[message.id];
                }
            } catch (_) {}
            this._handleError("exception while handling event response", false, err);
        }
    }

    pushSubscribe(subject, callback, requestCallback = null) {
        if (requestCallback === null) {
            // eslint-disable-next-line no-unused-vars
            requestCallback = (result, error) => {};
        }
        this.request("session/push/subscribe", subject, requestCallback);
        if (!(subject in this._wsPushCallbacks)) {
            this._wsPushCallbacks[subject] = [];
        }
        if (this._wsPushCallbacks[subject].indexOf(callback) < 0) {
            this._wsPushCallbacks[subject].push(callback);
        }
    }

    pushUnsubscribe(subject, callback, requestCallback = null) {
        if (requestCallback === null) {
            // eslint-disable-next-line no-unused-vars
            requestCallback = (result, error) => {};
        }
        if (!(subject in this._wsPushCallbacks)) {
            // The subject is not present in the list of callbacks
            this.request("session/push/unsubscribe", subject, requestCallback);
            return;
        }
        this._wsPushCallbacks[subject] = this._wsPushCallbacks[subject].filter(e => e !== callback);
        if (this._wsPushCallbacks[subject].length < 1) {
            // Only unsubscribe after the last subscribed callback is removed
            delete this._wsPushCallbacks[subject];
            this.request("session/push/unsubscribe", subject, requestCallback);
        } else {
            // Else act like the client has unsubscribed, but keep the subscription for the other callbacks
            requestCallback(true, null);
        }
    }

    pushDebug() {
        for (let subject in this._wsPushCallbacks) {
            let callbacks = this._wsPushCallbacks[subject];
            console.log("Subject '" + subject + "': " + callbacks.length + " callbacks", callbacks);
        }
    }

    generateUid() {
        return (Date.now().toString(36) + Math.random().toString(36).substr(2, 5)).toUpperCase();
    }

    request(method="ping", params=null, callback=null, timeout=8000) {
        if (this.socket === null) throw "Failed to execute request, no connection with server.";
        var uid = this.generateUid();
        var message = JSON.stringify({
            jsonrpc: "2.0",
            id: uid,
            method: method,
            params: params,
            token: this.token
        });
        if (typeof callback === "function") {
            this._wsCallbacks[uid] = callback.bind(this);
            this._wsTimeouts[uid] = setTimeout(this._onRequestTimeout.bind(this, uid), timeout);
        }
        this.socket.send(message);
        return uid;
    }

    requestPromise(method = "ping", params = null, timeout = 8000) {
        return new Promise((resolve, reject) => {
            this.request(method, params, (result, error) => {
                if (error !== null) {
                    reject(error);
                } else {
                    resolve(result);
                }
            }, timeout);
        });
    }

    _onRequestTimeout(uid) {
        this._wsCallbacks[uid](null, "timeout");
        delete this._wsCallbacks[uid];
    }

    _mergeArrays(...arrays) {
        let jointArray = [];
    
        arrays.forEach(array => {
            jointArray = [...jointArray, ...array];
        });
        const uniqueArray = jointArray.reduce((newArray, item) => {
            if (newArray.includes(item)) {
                return newArray;
            } else {
                return [...newArray, item];
            }
        }, []);
        return uniqueArray;
    }

    getPermissions() {
        let permissions = [];
        if (this.session) {
            permissions = permissions.concat(this.session.permissions);
            if (this.session.user) {
                permissions = this._mergeArrays(permissions, this.session.user.permissions);
                for (let groupIndex = 0; groupIndex < this.session.user.groups.length; groupIndex++) {
                    let group = this.session.user.groups[groupIndex];
                    permissions = this._mergeArrays(permissions, group.permissions);
                }
            }
        }
        return permissions;
    }
}

module.exports = ApiClient;
