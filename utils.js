const blake2 = require('blake2');
const nanoBase32 = require('./base32')

function Base32Encode(data) {
    return nanoBase32.encode(new Uint8Array(data));
}

function encodeAddress(publicKey,prefix = "nano") {
    const account = Base32Encode(publicKey);
    const checksum = Base32Encode(blake2.createHash('blake2b', {
        digestLength: 5
    }).update(publicKey).digest().reverse());
    return `${prefix}_${account}${checksum}`
}

module.exports = {encodeAddress}