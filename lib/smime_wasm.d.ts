/* tslint:disable */
/* eslint-disable */

export interface SmimeError {
    id: string;
    args: Map<string, string>;
}


/**
 * Checks related to the cryptographic signature and its representation
 */
export interface SignatureChecks {
    /**
     * Signature is valid over signed data (message digest)
     */
    signature_matches_signed_data: boolean;
    /**
     * Message digest matches content
     */
    message_digest_matches_content: boolean;
    /**
     * Other non-critical notes or warnings
     */
    other_notes?: SmimeError[];
    /**
     * Which type of RFC 9788 Header Protection is used
     */
    rfc9788_hp?: string;
    /**
     * If the signature uses RFC 9788
     */
    rfc9788: boolean;
    /**
     * Email addresses in signer certificate
     */
    certificate_emails?: string[];
    /**
     * Names in signer certificate
     */
    certificate_names?: string[];
}

/**
 * Debug information about the validation process
 */
export interface ValidationDetails {
    /**
     * Which trust store was used to validate the certificate.
     */
    trust_store_used: string;
    /**
     * If the certificate itself is valid
     */
    certificate_trusted_valid: boolean;
    /**
     * Certificate of this signer
     */
    certificate: string;
    /**
     * If the certificate has been revoked (currently not implemented)
     */
    revocation_status?: string;
    /**
     * If all the SCTs are valid (trust unknown)
     */
    scts_valid?: boolean;
    /**
     * Other non-critical notes or warnings
     */
    other_notes?: SmimeError[];
    /**
     * Checks done with the signature itself
     */
    checks: SignatureChecks;
}

/**
 * Information about a single CMS RecipientInfo
 */
export interface RecipientInfoSummary {
    /**
     * Issuer distinguished name
     */
    issuer: string;
    /**
     * Serial number (hex)
     */
    serial_number: string;
    /**
     * Key encryption algorithm, RFC name (e.g. \"RSAES-PKCS1-v1_5\", \"RSAES-OAEP\")
     */
    key_encryption_algorithm: string;
}

/**
 * Information about the encryption layer of the message
 */
export interface EncryptionInfo {
    /**
     * Content encryption cipher without key size (e.g. \"AES-CBC\", \"3DES-CBC\", \"RC2-CBC\")
     */
    cipher: string;
    /**
     * Key size (e.g. \"128-bit\", \"192-bit\", \"256-bit\")
     */
    key_size: string;
    /**
     * All recipients listed in the EnvelopedData
     */
    recipients: RecipientInfoSummary[];
}

/**
 * Result of one specific signer/signature
 * There may be more than one signature
 */
export interface SignerValidation {
    /**
     * Final result of the validation
     * Composite of certificate trust, checks done on the certificate and signature
     */
    signature_valid: boolean;
    /**
     * The chain of certificates to a trusted root, as fingerprints
     */
    chain?: string[];
    /**
     * Detailed information about the validation process
     */
    validation_details: ValidationDetails;
    /**
     * Signing time from the PKCS#7 structure
     */
    signing_time?: string;
}

/**
 * The complete signature result
 */
export interface SmimeValidationResult {
    /**
     * Which signing system was used to sign the message
     */
    signing_system: SigningSystem;
    /**
     * Who were the signers and if their signatures were valid
     */
    signers: SignerValidation[];
    /**
     * Errors that occurred during validation
     */
    failures?: SmimeError[];
    /**
     * Content that was actually signed
     */
    signed_content?: number[];
    /**
     * Sender address that can be displayed to the user
     */
    from_address: string | undefined;
    /**
     * Sender comment/name that can be displayed to the user
     */
    from_comment?: string;
    /**
     * Date of the message
     */
    date?: string;
    /**
     * Encryption layer information (populated when EnvelopedData is encountered)
     */
    encryption_info?: EncryptionInfo;
}


/**
 * Which signing system was used to sign the message
 */
export enum SigningSystem {
    /**
     * Signature is multipart/signed and S/MIME
     */
    MultipartSignedSMIME = 0,
    /**
     * Signature is application/pkcs7-mime (CMS, S/MIME)
     */
    MIMEPartSMIME = 1,
    /**
     * Signature is multipart/signed and PGP
     */
    MultipartSignedPGP = 2,
    /**
     * Signature is application/pgp (PGP)
     */
    MIMEPartPGP = 3,
    /**
     * Unknown or missing
     */
    Other = 4,
}

export enum TrustStore {
    /**
     * Builtin trust store (Mozilla S/MIME trust store)
     */
    Builtin = 0,
    /**
     * Debug certificates
     */
    Debug = 1,
}

/**
 * Encrypt to recipients using AES-256-CBC (CMS EnvelopedData).
 * Returns DER ContentInfo bytes, or `undefined` if no recipient cert had a usable key.
 */
export function encrypt_cbc(certs_pem: string[], plaintext: Uint8Array, pkcs1v15: boolean): Uint8Array | undefined;

/**
 * Encrypt to recipients using AES-256-GCM (CMS AuthEnvelopedData).
 * Returns DER ContentInfo bytes, or `undefined` if no recipient cert had a usable key.
 */
export function encrypt_gcm(certs_pem: string[], plaintext: Uint8Array, pkcs1v15: boolean): Uint8Array | undefined;

/**
 * Validate a recipient certificate's public key (RSA 2048-4096, or EC P-256/384/521).
 * Throws if the key is unsupported.
 */
export function validate_cert_key(cert_pem: string): void;

export function verify_smime_from_eml(eml_text: string): SmimeValidationResult;
