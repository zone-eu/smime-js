/*eslint no-unused-expressions: 0, prefer-arrow-callback: 0, no-console:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const crypto = require('crypto');
const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const SMIMEEncryptor = require('../lib/smime');

const { validateCertKey } = SMIMEEncryptor;

describe('SMIMEEncryptor', function () {
    this.timeout(60000); // eslint-disable-line no-invalid-this

    let tmpDir;
    let certs = [];
    let keys = {};

    // EC key+cert pairs keyed by curve name
    let ecKeys = {};
    let ecCerts = {};

    // Additional RSA sizes
    let rsaKeys = {};
    let rsaCerts = {};

    before(function () {
        // Probe PKCS#1 v1.5 availability
        try {
            let { publicKey: probeKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
            let probeCt = crypto.publicEncrypt({ key: probeKey, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from('smime-probe'));
            SMIMEEncryptor.pkcs1v15Available = probeCt && probeCt.length > 0;
        } catch (err) {
            // not available
        }

        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'smime-test-'));

        // Generate 3 self-signed RSA 2048 certs
        for (let i = 0; i < 3; i++) {
            let keyPath = path.join(tmpDir, `key${i}.pem`);
            let certPath = path.join(tmpDir, `cert${i}.pem`);
            execSync(`openssl req -x509 -newkey rsa:2048 -keyout ${keyPath} -out ${certPath} -days 1 -nodes -subj "/CN=user${i}@test.ee" 2>/dev/null`);
            certs.push(fs.readFileSync(certPath, 'utf8').trim());
            keys[i] = keyPath;
        }

        // Generate RSA certs at different sizes
        for (let bits of [2048, 3072, 4096]) {
            let keyPath = path.join(tmpDir, `rsa${bits}.key.pem`);
            let certPath = path.join(tmpDir, `rsa${bits}.cert.pem`);
            execSync(
                `openssl req -x509 -newkey rsa:${bits} -keyout ${keyPath} -out ${certPath} -days 1 -nodes -subj "/CN=rsa${bits}@test.ee" 2>/dev/null`
            );
            rsaKeys[bits] = keyPath;
            rsaCerts[bits] = fs.readFileSync(certPath, 'utf8').trim();
        }

        // Generate EC certs for P-256, P-384, P-521
        let curves = { 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' };
        for (let [label, curve] of Object.entries(curves)) {
            let keyPath = path.join(tmpDir, `ec-${label}.key.pem`);
            let certPath = path.join(tmpDir, `ec-${label}.cert.pem`);
            execSync(
                `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:${curve} -keyout ${keyPath} -out ${certPath} -days 1 -nodes -subj "/CN=ec-${label}@test.ee" 2>/dev/null`
            );
            ecKeys[label] = keyPath;
            ecCerts[label] = fs.readFileSync(certPath, 'utf8').trim();
        }
    });

    after(function () {
        if (tmpDir) {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        }
    });

    // Helper to decrypt DER via openssl CLI
    function decryptDer(derBuf, keyPath, certPath) {
        let derPath = path.join(tmpDir, `decrypt-${Date.now()}-${Math.random().toString(36).slice(2)}.der`);
        fs.writeFileSync(derPath, derBuf);
        return execSync(`openssl cms -decrypt -inform DER -in ${derPath} -inkey ${keyPath} -recip ${certPath}`).toString();
    }

    // --- Encrypt/decrypt with openssl ---

    describe('encryptGCM', function () {
        it('should encrypt with one RSA certificate and openssl can decrypt', async function () {
            let plaintext = Buffer.from('Hello, this is a test message.');
            let result = await SMIMEEncryptor.encryptGCM([certs[0]], plaintext);
            expect(result).to.be.an.instanceOf(Buffer);

            let decrypted = decryptDer(result, keys[0], path.join(tmpDir, 'cert0.pem'));
            expect(decrypted).to.equal('Hello, this is a test message.');
        });

        it('should encrypt with multiple RSA certificates and each can decrypt', async function () {
            let plaintext = Buffer.from('Multi-recipient test.');
            let result = await SMIMEEncryptor.encryptGCM([certs[0], certs[1], certs[2]], plaintext);
            expect(result).to.be.an.instanceOf(Buffer);

            for (let i = 0; i < 3; i++) {
                let decrypted = decryptDer(result, keys[i], path.join(tmpDir, `cert${i}.pem`));
                expect(decrypted).to.equal('Multi-recipient test.');
            }
        });

        it('should return false for invalid certificates', async function () {
            let result = await SMIMEEncryptor.encryptGCM(['not-a-cert'], Buffer.from('test'));
            expect(result).to.be.false;
        });

        it('should return false for empty cert array', async function () {
            let result = await SMIMEEncryptor.encryptGCM([], Buffer.from('test'));
            expect(result).to.be.false;
        });

        it('should skip invalid certs and encrypt with valid ones', async function () {
            let plaintext = Buffer.from('Mixed certs test.');
            let result = await SMIMEEncryptor.encryptGCM(['garbage', certs[0], 'also-bad'], plaintext);
            expect(result).to.be.an.instanceOf(Buffer);

            let decrypted = decryptDer(result, keys[0], path.join(tmpDir, 'cert0.pem'));
            expect(decrypted).to.equal('Mixed certs test.');
        });
    });

    describe('encryptCBC', function () {
        it('should encrypt with one RSA certificate and openssl can decrypt', async function () {
            let plaintext = Buffer.from('CBC encryption test.');
            let result = await SMIMEEncryptor.encryptCBC([certs[0]], plaintext);
            expect(result).to.be.an.instanceOf(Buffer);

            let decrypted = decryptDer(result, keys[0], path.join(tmpDir, 'cert0.pem'));
            expect(decrypted).to.equal('CBC encryption test.');
        });

        it('should encrypt with multiple RSA certificates and each can decrypt', async function () {
            let plaintext = Buffer.from('CBC multi-recipient.');
            let result = await SMIMEEncryptor.encryptCBC([certs[0], certs[1], certs[2]], plaintext);
            expect(result).to.be.an.instanceOf(Buffer);

            for (let i = 0; i < 3; i++) {
                let decrypted = decryptDer(result, keys[i], path.join(tmpDir, `cert${i}.pem`));
                expect(decrypted).to.equal('CBC multi-recipient.');
            }
        });

        it('should return false for invalid certificates', async function () {
            let result = await SMIMEEncryptor.encryptCBC(['not-a-cert'], Buffer.from('test'));
            expect(result).to.be.false;
        });
    });

    // --- EC key variants ---

    for (let curve of ['P-256', 'P-384', 'P-521']) {
        it(`GCM: should encrypt and decrypt with EC ${curve} certificate`, async function () {
            let plaintext = Buffer.from(`EC ${curve} GCM test.`);
            let result = await SMIMEEncryptor.encryptGCM([ecCerts[curve]], plaintext);
            expect(result).to.be.an.instanceOf(Buffer);

            let decrypted = decryptDer(result, ecKeys[curve], path.join(tmpDir, `ec-${curve}.cert.pem`));
            expect(decrypted).to.equal(`EC ${curve} GCM test.`);
        });

        it(`CBC: should encrypt and decrypt with EC ${curve} certificate`, async function () {
            let plaintext = Buffer.from(`EC ${curve} CBC test.`);
            let result = await SMIMEEncryptor.encryptCBC([ecCerts[curve]], plaintext);
            expect(result).to.be.an.instanceOf(Buffer);

            let decrypted = decryptDer(result, ecKeys[curve], path.join(tmpDir, `ec-${curve}.cert.pem`));
            expect(decrypted).to.equal(`EC ${curve} CBC test.`);
        });
    }

    // --- RSA size variants ---

    for (let bits of [2048, 3072, 4096]) {
        it(`GCM: should encrypt and decrypt with RSA ${bits} certificate`, async function () {
            let plaintext = Buffer.from(`RSA ${bits} GCM test.`);
            let result = await SMIMEEncryptor.encryptGCM([rsaCerts[bits]], plaintext);
            expect(result).to.be.an.instanceOf(Buffer);

            let decrypted = decryptDer(result, rsaKeys[bits], path.join(tmpDir, `rsa${bits}.cert.pem`));
            expect(decrypted).to.equal(`RSA ${bits} GCM test.`);
        });

        it(`CBC: should encrypt and decrypt with RSA ${bits} certificate`, async function () {
            let plaintext = Buffer.from(`RSA ${bits} CBC test.`);
            let result = await SMIMEEncryptor.encryptCBC([rsaCerts[bits]], plaintext);
            expect(result).to.be.an.instanceOf(Buffer);

            let decrypted = decryptDer(result, rsaKeys[bits], path.join(tmpDir, `rsa${bits}.cert.pem`));
            expect(decrypted).to.equal(`RSA ${bits} CBC test.`);
        });
    }

    // --- Mixed RSA + EC recipients ---

    it('GCM: should encrypt for mixed RSA + EC P-256 recipients and both can decrypt', async function () {
        let plaintext = Buffer.from('Mixed RSA+EC GCM test.');
        let result = await SMIMEEncryptor.encryptGCM([certs[0], ecCerts['P-256']], plaintext);
        expect(result).to.be.an.instanceOf(Buffer);

        let dec1 = decryptDer(result, keys[0], path.join(tmpDir, 'cert0.pem'));
        expect(dec1).to.equal('Mixed RSA+EC GCM test.');

        let dec2 = decryptDer(result, ecKeys['P-256'], path.join(tmpDir, 'ec-P-256.cert.pem'));
        expect(dec2).to.equal('Mixed RSA+EC GCM test.');
    });

    it('CBC: should encrypt for mixed RSA + EC P-256 recipients and both can decrypt', async function () {
        let plaintext = Buffer.from('Mixed RSA+EC CBC test.');
        let result = await SMIMEEncryptor.encryptCBC([certs[0], ecCerts['P-256']], plaintext);
        expect(result).to.be.an.instanceOf(Buffer);

        let dec1 = decryptDer(result, keys[0], path.join(tmpDir, 'cert0.pem'));
        expect(dec1).to.equal('Mixed RSA+EC CBC test.');

        let dec2 = decryptDer(result, ecKeys['P-256'], path.join(tmpDir, 'ec-P-256.cert.pem'));
        expect(dec2).to.equal('Mixed RSA+EC CBC test.');
    });

    // --- PKCS#1 v1.5 vs OAEP key transport ---

    it('PKCS#1 v1.5: should encrypt with CBC + PKCS#1 v1.5 and decrypt', async function () {
        let plaintext = Buffer.from('PKCS1 CBC test.');
        let result = await SMIMEEncryptor.encryptCBC([certs[0]], plaintext, { keyTransport: 'PKCS#1 v1.5' });
        expect(result).to.be.an.instanceOf(Buffer);

        let decrypted = decryptDer(result, keys[0], path.join(tmpDir, 'cert0.pem'));
        expect(decrypted).to.equal('PKCS1 CBC test.');

        // Verify PKCS#1 v1.5 key transport OID via asn1parse
        let derPath = path.join(tmpDir, 'pkcs1_cbc_check.der');
        fs.writeFileSync(derPath, result);
        let asn1Output = execSync(`openssl asn1parse -inform DER -in ${derPath}`).toString();
        expect(asn1Output).to.include('rsaEncryption');
        expect(asn1Output).to.not.include('rsaesOaep');
    });

    it('OAEP: should encrypt with CBC + OAEP and decrypt', async function () {
        let plaintext = Buffer.from('OAEP CBC test.');
        let result = await SMIMEEncryptor.encryptCBC([certs[0]], plaintext, { keyTransport: 'OAEP' });
        expect(result).to.be.an.instanceOf(Buffer);

        let decrypted = decryptDer(result, keys[0], path.join(tmpDir, 'cert0.pem'));
        expect(decrypted).to.equal('OAEP CBC test.');

        let derPath = path.join(tmpDir, 'oaep_cbc_check.der');
        fs.writeFileSync(derPath, result);
        let asn1Output = execSync(`openssl asn1parse -inform DER -in ${derPath}`).toString();
        expect(asn1Output).to.include('rsaesOaep');
    });

    it('PKCS#1 v1.5: should encrypt with GCM + PKCS#1 v1.5 and decrypt', async function () {
        let plaintext = Buffer.from('PKCS1 GCM test.');
        let result = await SMIMEEncryptor.encryptGCM([certs[0]], plaintext, { keyTransport: 'PKCS#1 v1.5' });
        expect(result).to.be.an.instanceOf(Buffer);

        let decrypted = decryptDer(result, keys[0], path.join(tmpDir, 'cert0.pem'));
        expect(decrypted).to.equal('PKCS1 GCM test.');
    });

    it('OAEP: should encrypt with GCM + OAEP and decrypt', async function () {
        let plaintext = Buffer.from('OAEP GCM test.');
        let result = await SMIMEEncryptor.encryptGCM([certs[0]], plaintext, { keyTransport: 'OAEP' });
        expect(result).to.be.an.instanceOf(Buffer);

        let decrypted = decryptDer(result, keys[0], path.join(tmpDir, 'cert0.pem'));
        expect(decrypted).to.equal('OAEP GCM test.');
    });

    // --- Certificate key validation ---

    describe('Certificate key validation', function () {
        it('should accept RSA 2048 certificate', function () {
            expect(() => validateCertKey(certs[0])).to.not.throw();
        });

        it('should accept RSA 3072 certificate', function () {
            expect(() => validateCertKey(rsaCerts[3072])).to.not.throw();
        });

        it('should accept RSA 4096 certificate', function () {
            expect(() => validateCertKey(rsaCerts[4096])).to.not.throw();
        });

        it('should accept EC P-256 certificate', function () {
            expect(() => validateCertKey(ecCerts['P-256'])).to.not.throw();
        });

        it('should accept EC P-384 certificate', function () {
            expect(() => validateCertKey(ecCerts['P-384'])).to.not.throw();
        });

        it('should accept EC P-521 certificate', function () {
            expect(() => validateCertKey(ecCerts['P-521'])).to.not.throw();
        });

        it('should reject RSA 1024 certificate (too small)', function () {
            let keyPath = path.join(tmpDir, 'rsa1024.key.pem');
            let certPath = path.join(tmpDir, 'rsa1024.cert.pem');
            execSync(`openssl req -x509 -newkey rsa:1024 -keyout ${keyPath} -out ${certPath} -days 1 -nodes -subj "/CN=rsa1024@test.ee" 2>/dev/null`);
            let certPem = fs.readFileSync(certPath, 'utf8').trim();

            expect(() => validateCertKey(certPem)).to.throw('RSA key too small');
        });

        it('should reject RSA 4104 certificate (too big)', function () {
            let keyPath = path.join(tmpDir, 'rsa4104.key.pem');
            let certPath = path.join(tmpDir, 'rsa4104.cert.pem');
            execSync(`openssl req -x509 -newkey rsa:4104 -keyout ${keyPath} -out ${certPath} -days 1 -nodes -subj "/CN=rsa4104@test.ee" 2>/dev/null`);
            let certPem = fs.readFileSync(certPath, 'utf8').trim();

            expect(() => validateCertKey(certPem)).to.throw('RSA key too large');
        });

        it('should reject unsupported EC curve (secp256k1)', function () {
            let keyPath = path.join(tmpDir, 'secp256k1.key.pem');
            let certPath = path.join(tmpDir, 'secp256k1.cert.pem');
            execSync(
                `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp256k1 -keyout ${keyPath} -out ${certPath} -days 1 -nodes -subj "/CN=secp256k1@test.ee" 2>/dev/null`
            );
            let certPem = fs.readFileSync(certPath, 'utf8').trim();

            expect(() => validateCertKey(certPem)).to.throw('unsupported EC curve');
        });
    });

    // --- Key material zeroing ---

    describe('Key material zeroing', function () {
        it('should zero the CEK after successful GCM encryption', async function () {
            let capturedCek;
            let origRandomBytes = crypto.randomBytes;
            crypto.randomBytes = function (size) {
                let buf = origRandomBytes.call(crypto, size);
                if (size === 32 && !capturedCek) {
                    capturedCek = buf;
                }
                return buf;
            };
            try {
                let result = await SMIMEEncryptor.encryptGCM([certs[0]], Buffer.from('test'), { keyTransport: 'OAEP' });
                expect(result).to.be.an.instanceOf(Buffer);
                expect(capturedCek).to.exist;
                expect(Buffer.alloc(32).equals(capturedCek)).to.be.true; // all zeros
            } finally {
                crypto.randomBytes = origRandomBytes;
            }
        });

        it('should zero the ECDH shared secret after successful GCM encryption with EC cert', async function () {
            let capturedSharedSecret;
            let origDiffieHellman = crypto.diffieHellman;
            crypto.diffieHellman = function (opts) {
                let buf = origDiffieHellman.call(crypto, opts);
                if (!capturedSharedSecret) {
                    capturedSharedSecret = buf;
                }
                return buf;
            };
            try {
                let result = await SMIMEEncryptor.encryptGCM([ecCerts['P-256']], Buffer.from('test'), { keyTransport: 'OAEP' });
                expect(result).to.be.an.instanceOf(Buffer);
                expect(capturedSharedSecret).to.exist;
                expect(capturedSharedSecret.every(b => b === 0)).to.be.true; // all zeros
            } finally {
                crypto.diffieHellman = origDiffieHellman;
            }
        });

        it('should zero the CEK even when encryption throws', async function () {
            let capturedCek;
            let origRandomBytes = crypto.randomBytes;
            let origCreateCipheriv = crypto.createCipheriv;
            crypto.randomBytes = function (size) {
                let buf = origRandomBytes.call(crypto, size);
                if (size === 32 && !capturedCek) {
                    capturedCek = buf;
                }
                return buf;
            };
            crypto.createCipheriv = function () {
                throw new Error('injected cipher error');
            };
            try {
                let threw = false;
                try {
                    await SMIMEEncryptor.encryptGCM([certs[0]], Buffer.from('test'), { keyTransport: 'OAEP' });
                } catch (err) {
                    threw = true;
                    expect(err.message).to.equal('injected cipher error');
                }
                expect(threw).to.be.true;
                expect(capturedCek).to.exist;
                expect(Buffer.alloc(32).equals(capturedCek)).to.be.true; // zeroed despite error
            } finally {
                crypto.randomBytes = origRandomBytes;
                crypto.createCipheriv = origCreateCipheriv;
            }
        });

        it('should zero the ECDH shared secret even when key wrapping throws', async function () {
            let capturedSharedSecret;
            let origDiffieHellman = crypto.diffieHellman;
            let origWrapKey = crypto.webcrypto.subtle.wrapKey;
            crypto.diffieHellman = function (opts) {
                let buf = origDiffieHellman.call(crypto, opts);
                if (!capturedSharedSecret) {
                    capturedSharedSecret = buf;
                }
                return buf;
            };
            crypto.webcrypto.subtle.wrapKey = async function () {
                throw new Error('injected wrapKey error');
            };
            try {
                let threw = false;
                try {
                    await SMIMEEncryptor.encryptGCM([ecCerts['P-256']], Buffer.from('test'), { keyTransport: 'OAEP' });
                } catch (err) {
                    threw = true;
                    expect(err.message).to.equal('injected wrapKey error');
                }
                expect(threw).to.be.true;
                expect(capturedSharedSecret).to.exist;
                expect(capturedSharedSecret.every(b => b === 0)).to.be.true; // zeroed despite error
            } finally {
                crypto.diffieHellman = origDiffieHellman;
                crypto.webcrypto.subtle.wrapKey = origWrapKey;
            }
        });
    });
});
