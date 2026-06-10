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

    // Encrypt with AES-256-GCM (CMS AuthEnvelopedData). Returns a Buffer, or false if
    // certs is empty. Throws if any recipient certificate has an unsupported key.
    async encryptGCM(certs, plaintext, options) {
        const keyTransport = (options && options.keyTransport) || 'OAEP';
        if (!RSA_KEY_TRANSPORTS.includes(keyTransport)) {
            throw new TypeError(`unsupported keyTransport: ${keyTransport}`);
        }
        if (!certs || certs.length === 0) return false;
        return Buffer.from(wasm.encrypt_gcm(certs, toBytes(plaintext), keyTransport === 'PKCS#1 v1.5'));
    },

    // Encrypt with AES-256-CBC (CMS EnvelopedData). Returns a Buffer, or false if
    // certs is empty. Throws if any recipient certificate has an unsupported key.
    async encryptCBC(certs, plaintext, options) {
        const keyTransport = (options && options.keyTransport) || 'OAEP';
        if (!RSA_KEY_TRANSPORTS.includes(keyTransport)) {
            throw new TypeError(`unsupported keyTransport: ${keyTransport}`);
        }
        if (!certs || certs.length === 0) return false;
        return Buffer.from(wasm.encrypt_cbc(certs, toBytes(plaintext), keyTransport === 'PKCS#1 v1.5'));
    },

    // Validate a recipient certificate's public key (RSA 2048-4096, EC P-256/384/521, or X25519).
    // Throws on an unsupported key.
    validateCertKey(pem) {
        wasm.validate_cert_key(pem);
    },
};

module.exports = SMIMEEncryptor;
module.exports.SMIMEEncryptor = SMIMEEncryptor;
