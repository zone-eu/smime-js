/*eslint no-unused-expressions: 0, prefer-arrow-callback: 0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const SMIMEEncryptor = require('../lib/smime');

const { validateCertKey } = SMIMEEncryptor;

const KEYS = path.resolve(__dirname, '..', '..', 'tests', 'keys');
const readCert = name => fs.readFileSync(path.join(KEYS, name), 'utf8').trim();

const rsaCert = readCert('test_rsa.pem');
const edCert = readCert('test_ed25519.pem');
const EC = {
    'P-256': { cert: readCert('test_p256.pem'), key: 'test_p256.key' },
    'P-384': { cert: readCert('test_p384.pem'), key: 'test_p384.key' },
    'P-521': { cert: readCert('test_p521.pem'), key: 'test_p521.key' }
};
const rsaKey = path.join(KEYS, 'test_rsa.key');
const rsaCertPath = path.join(KEYS, 'test_rsa.pem');

describe('SMIMEEncryptor (WASM blob)', function () {
    this.timeout(60000); // eslint-disable-line no-invalid-this

    let tmpDir;
    let counter = 0;

    before(function () {
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'smime-wasm-test-'));
    });

    after(function () {
        if (tmpDir) {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        }
    });

    // Decrypt a CMS DER blob via the openssl CLI and return the recovered content.
    function decryptDer(derBuf, keyFile, certFile) {
        let derPath = path.join(tmpDir, `dec-${counter++}.der`);
        fs.writeFileSync(derPath, derBuf);
        return execSync(`openssl cms -decrypt -inform DER -in ${derPath} -inkey ${keyFile} -recip ${certFile}`).toString();
    }

    function asn1(derBuf) {
        let derPath = path.join(tmpDir, `asn1-${counter++}.der`);
        fs.writeFileSync(derPath, derBuf);
        return execSync(`openssl asn1parse -inform DER -in ${derPath}`).toString();
    }

    // chai-as-promised isn't a dependency, so assert rejection by hand.
    async function rejects(promise, re) {
        let err;
        try {
            await promise;
        } catch (e) {
            err = e;
        }
        expect(err, 'expected the promise to reject').to.be.an('error');
        if (re) expect(err.message).to.match(re);
    }

    describe('encryptGCM', function () {
        it('encrypts to an RSA recipient and openssl decrypts it', async function () {
            let result = await SMIMEEncryptor.encryptGCM([rsaCert], Buffer.from('Hello, GCM.'));
            expect(result).to.be.an.instanceOf(Buffer);
            expect(decryptDer(result, rsaKey, rsaCertPath)).to.equal('Hello, GCM.');
        });

        it('throws on a malformed certificate PEM', async function () {
            await rejects(SMIMEEncryptor.encryptGCM(['not-a-cert'], Buffer.from('x')), /certificate/i);
        });

        it('returns false for an empty cert array', async function () {
            expect(await SMIMEEncryptor.encryptGCM([], Buffer.from('x'))).to.be.false;
        });

        it('throws when any recipient has an unsupported key', async function () {
            await rejects(SMIMEEncryptor.encryptGCM([edCert, rsaCert], Buffer.from('x')), /unsupported recipient key type/i);
        });
    });

    describe('encryptCBC', function () {
        it('encrypts to an RSA recipient and openssl decrypts it', async function () {
            let result = await SMIMEEncryptor.encryptCBC([rsaCert], Buffer.from('Hello, CBC.'));
            expect(result).to.be.an.instanceOf(Buffer);
            expect(decryptDer(result, rsaKey, rsaCertPath)).to.equal('Hello, CBC.');
        });
    });

    for (let [curve, { key }] of Object.entries(EC)) {
        let certFile = path.join(KEYS, `test_${curve.replace('P-', 'p')}.pem`);
        let keyFile = path.join(KEYS, key);

        it(`GCM: encrypts to and decrypts from an EC ${curve} recipient`, async function () {
            let result = await SMIMEEncryptor.encryptGCM([EC[curve].cert], Buffer.from(`EC ${curve} GCM.`));
            expect(result).to.be.an.instanceOf(Buffer);
            expect(decryptDer(result, keyFile, certFile)).to.equal(`EC ${curve} GCM.`);
        });

        it(`CBC: encrypts to and decrypts from an EC ${curve} recipient`, async function () {
            let result = await SMIMEEncryptor.encryptCBC([EC[curve].cert], Buffer.from(`EC ${curve} CBC.`));
            expect(result).to.be.an.instanceOf(Buffer);
            expect(decryptDer(result, keyFile, certFile)).to.equal(`EC ${curve} CBC.`);
        });
    }

    // openssl 3.5 cannot decrypt X25519 KARI ("no matching recipient"), so assert the
    // RFC 8418 structure instead; the encrypt->decrypt roundtrip is covered in Rust tests.
    it('encrypts to an X25519 recipient per RFC 8418 (HKDF-SHA256 + AES-256 wrap)', async function () {
        let result = await SMIMEEncryptor.encryptGCM([readCert('test_x25519.pem')], Buffer.from('X25519.'));
        expect(result).to.be.an.instanceOf(Buffer);
        let parsed = asn1(result);
        expect(parsed).to.include('1.2.840.113549.1.9.16.3.19'); // dhSinglePass-stdDH-hkdf-sha256-scheme
        expect(parsed).to.include('X25519');
        expect(parsed).to.include('aes256-wrap');
    });

    it('encrypts for mixed RSA + EC P-256 recipients and both decrypt', async function () {
        let result = await SMIMEEncryptor.encryptGCM([rsaCert, EC['P-256'].cert], Buffer.from('Mixed RSA+EC.'));
        expect(result).to.be.an.instanceOf(Buffer);
        expect(decryptDer(result, rsaKey, rsaCertPath)).to.equal('Mixed RSA+EC.');
        expect(decryptDer(result, path.join(KEYS, EC['P-256'].key), path.join(KEYS, 'test_p256.pem'))).to.equal('Mixed RSA+EC.');
    });

    describe('RSA key transport', function () {
        it('PKCS#1 v1.5: decrypts and carries the rsaEncryption OID', async function () {
            let result = await SMIMEEncryptor.encryptCBC([rsaCert], Buffer.from('PKCS1.'), { keyTransport: 'PKCS#1 v1.5' });
            expect(result).to.be.an.instanceOf(Buffer);
            expect(decryptDer(result, rsaKey, rsaCertPath)).to.equal('PKCS1.');
            let parsed = asn1(result);
            expect(parsed).to.include('rsaEncryption');
            expect(parsed).to.not.include('rsaesOaep');
        });

        it('OAEP (default): decrypts and carries the rsaesOaep OID', async function () {
            let result = await SMIMEEncryptor.encryptCBC([rsaCert], Buffer.from('OAEP.'));
            expect(result).to.be.an.instanceOf(Buffer);
            expect(decryptDer(result, rsaKey, rsaCertPath)).to.equal('OAEP.');
            expect(asn1(result)).to.include('rsaesOaep');
        });

        it('rejects an unknown keyTransport value', async function () {
            await rejects(SMIMEEncryptor.encryptCBC([rsaCert], Buffer.from('x'), { keyTransport: 'oaep' }), /unsupported keyTransport: oaep/);
            await rejects(SMIMEEncryptor.encryptGCM([rsaCert], Buffer.from('x'), { keyTransport: 'pkcs1' }), /unsupported keyTransport: pkcs1/);
        });
    });

    describe('validateCertKey', function () {
        it('accepts the supported RSA, EC and X25519 certificates', function () {
            expect(() => validateCertKey(rsaCert)).to.not.throw();
            for (let { cert } of Object.values(EC)) {
                expect(() => validateCertKey(cert)).to.not.throw();
            }
            expect(() => validateCertKey(readCert('test_x25519.pem'))).to.not.throw();
        });

        it('rejects an Ed25519 signing key', function () {
            expect(() => validateCertKey(edCert)).to.throw(/unsupported recipient key type: Ed25519/i);
        });
    });
});
