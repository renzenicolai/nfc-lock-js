"use strict";

let commands = {
    "mcNotAuthenticated": 255,
    "mcMaxFrameSize": 60, // The maximum total length of a packet that is transfered to / from the card

    // Desfire legacy instructions
    "AuthenticateLegacy": 0x0A,
    "ChangeKeySettings": 0x54,
    "GetKeySettings": 0x45,
    "ChangeKey": 0xC4,
    "GetKeyVersion": 0x64,
    "CreateApplication": 0xCA,
    "DeleteApplication": 0xDA,
    "GetApplicationIdentifiers": 0x6A,
    "SelectApplication": 0x5A,
    "FormatPicc": 0xFC,
    "GetVersion": 0x60,
    "GetFileIdentifiers": 0x6F,
    "GetFileSettings": 0xF5,
    "ChangeFileSettings": 0x5F,
    "CreateStandardDataFile": 0xCD,
    "CreateBackupDataFile": 0xCB,
    "CreateValueFile": 0xCC,
    "CreateLinearRecordFile": 0xC1,
    "CreateCyclicRecordFile": 0xC0,
    "DeleteFile": 0xDF,
    "ReadData": 0xBD,
    "WriteData": 0x3D,
    "GetValue": 0x6C,
    "Credit": 0x0C,
    "Debit": 0xDC,
    "LimitedCredit": 0x1C,
    "WriteRecord": 0x3B,
    "ReadRecords": 0xBB,
    "ClearRecordFile": 0xEB,
    "CommitTransaction": 0xC7,
    "AbortTransaction": 0xA7,
    "AdditionalFrame": 0xAF, // data did not fit into a frame, another frame will follow

     // Desfire EV1 instructions
    "Ev1AuthenticateIso": 0x1A,
    "Ev1AuthenticateAes": 0xAA,
    "Ev1FreeMem": 0x6E,
    "Ev1GetDfNames": 0x6D,
    "Ev1GetCardUid": 0x51,
    "Ev1GetIsoFileIdentifiers": 0x61,
    "Ev1SetConfiguration": 0x5C,

    // ISO7816 instructions
    "ISO7816ExternalAuthenticate": 0x82,
    "ISO7816InternalAuthenticate": 0x88,
    "ISO7816AppendRecord": 0xE2,
    "ISO7816GetChallenge": 0x84,
    "ISO7816ReadRecords": 0xB2,
    "ISO7816SelectFile": 0xA4,
    "ISO7816ReadBinary": 0xB0,
    "ISO7816UpdateBinary": 0xD6
};

module.exports = {DESFIRE_COMMANDS: commands};
