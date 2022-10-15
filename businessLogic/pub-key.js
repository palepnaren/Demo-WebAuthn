const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const { Certificate } = require('@fidm/x509');
const iso_3166_1 = require('iso-3166-1');
const { Fido2Lib } = require('fido2-lib');
const store = require('store2');
const base64ToBuffer = require('base64-arraybuffer');
const optionGeneratorFn = (extName, type, value) => value;
const resultParserFn = () => { };
const resultValidatorFn = () => { };
Fido2Lib.addExtension("appid", optionGeneratorFn, resultParserFn, resultValidatorFn);

exports.initPubKey = function (user, callback) {

    makeCredRequest().attestationOptions().then(options => {
        var regOpts = options;
        var bufChallenge = Buffer.from(regOpts.challenge, 'base64');
        regOpts.challenge = bufChallenge.toString('base64');
        var bufId = Buffer.from(crypto.randomBytes(32), 'base64');
        console.log("bufId inside initPubKey: "+bufId.toString('base64'));
        regOpts.user = {
            id: bufId.toString('base64'),
            name: user.username,
            displayName: user.name
        }
        regOpts.authenticatorAttachment = "cross-platform";
        regOpts.pubKeyCredParams = [{
            type: "public-key", alg: -257
        },
        { type: "public-key", alg: -7 }]
        return callback(regOpts);
    });

}

exports.getPublicKey = function (res, _challenge, callback) {

    let attestationBuffer = base64ToBuffer.decode(res.response.attestationObject);
    let ctapMakeCredResp = cbor.decodeAllSync(attestationBuffer)[0];
    let authDataStructure = parseMakeCredAuthData(ctapMakeCredResp.authData);
    let _fido2 = store('fido2');
    let fido2 = new Fido2Lib(_fido2);

    res.id = base64ToBuffer.decode(res.id);
    res.rawId = base64ToBuffer.decode(res.rawId);
    console.log("res.id inside getPubKey: "+res.id);
    console.log("res.rawId inside getPubKey: "+res.rawId);
    console.log("authDataStructure.credID inside getPubKey: "+authDataStructure.credID);
    const attestationExpectations = {
        challenge: _challenge,
        origin: "http://localhost:3000",
        factor: "either"
    };
    fido2.attestationResult(res, attestationExpectations).then(res => {
        console.log(res);
        callback({ data: res, credId: authDataStructure.credID });
    });

}

exports.getServerAssertion = function (authenticators, id, _challenge, callback) {
    console.log("id inside getServerAssertion: "+id);
    let _fido2 = store('fido2');
    let fido2 = new Fido2Lib(_fido2);
    fido2.assertionOptions({extensionOptions:{appid: "http://localhost:3000"}}).then(res => {
        console.log("getServerAssertion");
        console.log(res)
        var bufChallenge = Buffer.from(_challenge, 'base64');
        res.challenge = bufChallenge.toString('base64');
        res.allowCredentials = [{
            type: 'public-key',
            id: id,
            // transports: ['internal', "usb", "nfc", "ble"]
            transports : ["usb","internal"]
        }]
        res.rpId = "localhost";
        res.timeout = 300000;
        res.userVerification = "required";
        return callback(res);
    })

}

exports.valiate = function (res, key, _challenge, callback) {

    let _fido2 = store('fido2');
    let fido2 = new Fido2Lib(_fido2);
    res.id = base64ToBuffer.decode(res.id);
    res.rawId = base64ToBuffer.decode(res.rawId);
    const assertionExpectations = {
        // Remove the following comment if allowCredentials has been added into authnOptions so the credential received will be validate against allowCredentials array.
        allowCredentials: [{
            id: res.rawId,
            type: "public-key",
            // transports: ["internal", "usb", "nfc", "ble"]
            transports: ["usb","internal"]
        }],
        challenge: _challenge,
        origin: "http://localhost:3000",
        factor: "either",
        publicKey: key,
        prevCounter: 0,
        userHandle: res.response.userHandle
    };

    fido2.assertionResult(res, assertionExpectations).then(res => {
        return callback(res);
    }).catch(error => {
        return callback(error);
    })
}


var makeCredRequest = function () {

    var fido2 = new Fido2Lib({
        rpId: "localhost",
        rpName: "Naren Webauthn example",
        rpIcon: "http://localhost:3000",
        challengeSize: 128,
        cryptoParams: [-7, -257],
        attestation: "direct",
        authenticatorAttachment: "cross-platform",
        authenticatorRequireResidentKey: false,
        authenticatorUserVerification: "required",
        timeout: 300000,
    })

    fido2.enableExtension("appid");

    store('fido2', fido2);

    return fido2;

}

var parseMakeCredAuthData = (buffer) => {
    let rpIdHash = buffer.slice(0, 32); buffer = buffer.slice(32);
    let flagsBuf = buffer.slice(0, 1); buffer = buffer.slice(1);
    let flags = flagsBuf[0];
    let counterBuf = buffer.slice(0, 4); buffer = buffer.slice(4);
    let counter = counterBuf.readUInt32BE(0);
    let aaguid = buffer.slice(0, 16); buffer = buffer.slice(16);
    let credIDLenBuf = buffer.slice(0, 2); buffer = buffer.slice(2);
    let credIDLen = credIDLenBuf.readUInt16BE(0);
    let credID = buffer.slice(0, credIDLen); buffer = buffer.slice(credIDLen);
    let COSEPublicKey = buffer;

    return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey }
}

