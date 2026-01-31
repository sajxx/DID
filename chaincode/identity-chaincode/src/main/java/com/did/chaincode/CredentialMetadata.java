package com.did.chaincode;

import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

import java.util.Objects;

/**
 * CredentialMetadata - On-chain representation of a Verifiable Credential
 * 
 * IMPORTANT: This class stores ONLY metadata and hashes, never the actual credential data.
 * The actual credential content (name, DOB, etc.) is stored off-chain in the holder's wallet.
 * 
 * This design ensures:
 * 1. Privacy: Sensitive data never touches the blockchain
 * 2. Compliance: GDPR right-to-be-forgotten compatible (raw data can be deleted locally)
 * 3. Verifiability: Hash allows integrity verification without exposing data
 */
@DataType
public class CredentialMetadata {

    /**
     * Unique identifier for the credential
     * Format: cred:<uuid>
     */
    @Property
    private String credentialId;

    /**
     * DID of the entity that issued this credential
     * Must be a registered and active identity
     */
    @Property
    private String issuerDid;

    /**
     * DID of the entity holding this credential
     */
    @Property
    private String holderDid;

    /**
     * SHA-256 hash of the complete credential data
     * Used for integrity verification
     * 
     * The credential data that was hashed typically includes:
     * - All claim attributes
     * - Issuer signature
     * - Issuance date
     * - Schema reference
     */
    @Property
    private String credentialHash;

    /**
     * Hash of the credential schema
     * Allows verifiers to know the credential structure
     */
    @Property
    private String schemaHash;

    /**
     * Credential expiration date in ISO 8601 format
     * null means no expiration
     */
    @Property
    private String expirationDate;

    /**
     * Current status of the credential
     * Values: VALID, REVOKED, EXPIRED, SUSPENDED
     */
    @Property
    private String status;

    /**
     * Timestamp when credential was issued
     */
    @Property
    private String issuedAt;

    /**
     * Reason for revocation (if revoked)
     */
    @Property
    private String revocationReason;

    /**
     * Timestamp when credential was revoked
     */
    @Property
    private String revokedAt;

    // Default constructor
    public CredentialMetadata() {
    }

    // Getters and Setters
    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public String getIssuerDid() {
        return issuerDid;
    }

    public void setIssuerDid(String issuerDid) {
        this.issuerDid = issuerDid;
    }

    public String getHolderDid() {
        return holderDid;
    }

    public void setHolderDid(String holderDid) {
        this.holderDid = holderDid;
    }

    public String getCredentialHash() {
        return credentialHash;
    }

    public void setCredentialHash(String credentialHash) {
        this.credentialHash = credentialHash;
    }

    public String getSchemaHash() {
        return schemaHash;
    }

    public void setSchemaHash(String schemaHash) {
        this.schemaHash = schemaHash;
    }

    public String getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(String expirationDate) {
        this.expirationDate = expirationDate;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(String issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }

    public String getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(String revokedAt) {
        this.revokedAt = revokedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CredentialMetadata that = (CredentialMetadata) o;
        return Objects.equals(credentialId, that.credentialId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(credentialId);
    }

    @Override
    public String toString() {
        return "CredentialMetadata{" +
                "credentialId='" + credentialId + '\'' +
                ", issuerDid='" + issuerDid + '\'' +
                ", holderDid='" + holderDid + '\'' +
                ", status='" + status + '\'' +
                ", issuedAt='" + issuedAt + '\'' +
                '}';
    }
}
