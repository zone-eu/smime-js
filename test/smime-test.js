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

        it('skips unsupported recipients and encrypts with the supported one', async function () {
            let result = await SMIMEEncryptor.encryptGCM([edCert, rsaCert], Buffer.from('Skip.'));
            expect(result).to.be.an.instanceOf(Buffer);
            expect(decryptDer(result, rsaKey, rsaCertPath)).to.equal('Skip.');
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
    });

    describe('validateCertKey', function () {
        it('accepts the supported RSA and EC certificates', function () {
            expect(() => validateCertKey(rsaCert)).to.not.throw();
            for (let { cert } of Object.values(EC)) {
                expect(() => validateCertKey(cert)).to.not.throw();
            }
        });

        it('rejects an unsupported key type', function () {
            expect(() => validateCertKey(edCert)).to.throw(/unsupported/i);
        });
    });
});
