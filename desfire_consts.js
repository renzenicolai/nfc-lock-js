"use strict";

const DESFIRE_CONSTANTS = {
    "NotAuthenticated": 255,
    "MaxFrameSize": 60, // The maximum total length of a packet that is transfered to / from the card
};

const DESFIRE_COMMANDS = {
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

const DESFIRE_STATUS = {
    "Success": 0x00,
    "NoChanges": 0x0C,
    "OutOfMemory": 0x0E,
    "IllegalCommand": 0x1C,
    "IntegrityError": 0x1E,
    "KeyDoesNotExist": 0x40,
    "WrongCommandLen": 0x7E,
    "PermissionDenied": 0x9D,
    "IncorrectParam": 0x9E,
    "AppNotFound": 0xA0,
    "AppIntegrityError": 0xA1,
    "AuthentError": 0xAE,
    "MoreFrames": 0xAF, // data did not fit into a frame, another frame will follow
    "LimitExceeded": 0xBE,
    "CardIntegrityError": 0xC1,
    "CommandAborted": 0xCA,
    "CardDisabled": 0xCD,
    "InvalidApp": 0xCE,
    "DuplicateAidFiles": 0xDE,
    "EepromError": 0xEE,
    "FileNotFound": 0xF0,
    "FileIntegrityError": 0xF1
};

module.exports = {DESFIRE_COMMANDS: DESFIRE_COMMANDS, DESFIRE_STATUS: DESFIRE_STATUS, DESFIRE_CONSTANTS: DESFIRE_CONSTANTS};
