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


## Using a UART connected PN532 reader

```
sudo apt install nodejs npm screen libnfc-dev libnfc-bin git autoconf automake libtool pcscd libpcsclite-dev

git clone "https://github.com/nfc-tools/ifdnfc.git"
cd ifdnfc/
autoreconf -vis
./configure --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib
make
sudo make install
```

In `/etc/nfc/libnfc.conf`:

```
device.name = "IFD-NFC"
device.connstring = "pn532_uart:/dev/ttyUSB0"
```

In `/etc/reader.conf.d/ifdnfc`:

```
FRIENDLYNAME      "IFD-NFC"
LIBPATH           /usr/lib/libifdnfc.so
CHANNELID         0
```

The service file `ifdnfc.service` can be used to automatically start the service using systemd. Copy this file to `/etc/systemd/system/ifdnfc.service` then run `sudo systemctl enable --now ifdnfc` to start. Be sure to change the username in the service file to something that suits your system.

Also enable pcscd with `sudo systemctl enable --now pcscd`
