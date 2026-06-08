'use strict';

const wasm = require('./smime_wasm.js');

const CIPHERS = ['AES-CBC', 'AES-GCM'];
const RSA_KEY_TRANSPORTS = ['PKCS#1 v1.5', 'OAEP'];

function toBytes(plaintext) {
    if (plaintext == null) return new Uint8Array(0);
    if (Buffer.isBuffer(plaintext)) return new Uint8Array(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);
    if (plaintext instanceof Uint8Array) return plaintext;
    throw new TypeError('plaintext must be a Buffer or Uint8Array');
}

const SMIMEEncryptor = {
    CIPHERS,
    RSA_KEY_TRANSPORTS,
    // PKCS#1 v1.5 key transport is compiled into the wasm blob, so it is always available.
    pkcs1v15Available: true,

    // Encrypt with AES-256-GCM (CMS AuthEnvelopedData). Returns a Buffer, or false if no
    // recipient certificate had a usable key.
    async encryptGCM(certs, plaintext, options) {
        const pkcs1v15 = (options && options.keyTransport) === 'PKCS#1 v1.5';
        const out = wasm.encrypt_gcm(certs, toBytes(plaintext), pkcs1v15);
        return out == null ? false : Buffer.from(out);
    },

    // Encrypt with AES-256-CBC (CMS EnvelopedData). Returns a Buffer, or false if no
    // recipient certificate had a usable key.
    async encryptCBC(certs, plaintext, options) {
        const pkcs1v15 = (options && options.keyTransport) === 'PKCS#1 v1.5';
        const out = wasm.encrypt_cbc(certs, toBytes(plaintext), pkcs1v15);
        return out == null ? false : Buffer.from(out);
    },

    // Validate a recipient certificate's public key (RSA 2048-4096, or EC P-256/384/521).
    // Throws on an unsupported key.
    validateCertKey(pem) {
        wasm.validate_cert_key(pem);
    },
};

module.exports = SMIMEEncryptor;
module.exports.SMIMEEncryptor = SMIMEEncryptor;
