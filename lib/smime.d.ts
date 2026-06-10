// Type definitions for @zone-eu/smime-js
export type RsaKeyTransport = 'PKCS#1 v1.5' | 'OAEP';

export interface EncryptOptions {
    /** RSA key transport. Defaults to OAEP; any other value throws a TypeError. */
    keyTransport?: RsaKeyTransport;
}

export interface SMIMEEncryptorType {
    readonly CIPHERS: readonly ['AES-CBC', 'AES-GCM'];
    readonly RSA_KEY_TRANSPORTS: readonly ['PKCS#1 v1.5', 'OAEP'];
    readonly pkcs1v15Available: true;

    /** Encrypt with AES-256-GCM (CMS AuthEnvelopedData). Resolves to a Buffer, or false if no valid recipients. */
    encryptGCM(certs: string[], plaintext: Buffer | Uint8Array, options?: EncryptOptions): Promise<Buffer | false>;

    /** Encrypt with AES-256-CBC (CMS EnvelopedData). Resolves to a Buffer, or false if no valid recipients. */
    encryptCBC(certs: string[], plaintext: Buffer | Uint8Array, options?: EncryptOptions): Promise<Buffer | false>;

    /** Validate a recipient certificate's public key (RSA 2048-4096, or EC P-256/384/521). Throws if unsupported. */
    validateCertKey(pem: string): void;
}

export declare const SMIMEEncryptor: SMIMEEncryptorType;
export default SMIMEEncryptor;
