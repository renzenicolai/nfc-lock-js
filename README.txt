# NFC lock app

This app verifies Desfire NFC tags through a pcsc smartcard reader on a Rasperry Pi.
If a key is valid, it will pull up a GPIO pin, i.e. to power a solenoid through suitable electronics

## Prerequisites

- Packages:
  - node
  - pcscd
  - libpcsclite-dev
- GPIO access:
  - Add the user running the app to group 'gpio'

## Steps to start

1. Install Node dependencies

`npm install`

2. Start the app

`node app.js`

3. See if reader is detected

If a reader is detected it will say so on the console. If no reader is detected
within a few seconds, unplug and replug it.


