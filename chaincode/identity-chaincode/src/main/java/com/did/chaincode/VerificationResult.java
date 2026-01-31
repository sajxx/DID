package com.did.chaincode;

import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

/**
 * VerificationResult - Response object for credential verification
 * 
 * Contains the result of verifying a credential against the blockchain,
 * including validity status, issuer information, and any error reasons.
 */
@DataType
public class VerificationResult {

    /**
     * The credential ID that was verified
     */
    @Property
    private String credentialId;

    /**
     * Whether the credential is valid
     */
    @Property
    private boolean valid;

    /**
     * Human-readable explanation of the result
     */
    @Property
    private String reason;

    /**
     * DID of the credential issuer
     */
    @Property
    private String issuerDid;

    /**
     * DID of the credential holder
     */
    @Property
    private String holderDid;

    /**
     * When the credential was issued
     */
    @Property
    private String issuedAt;

    /**
     * When the credential expires
     */
    @Property
    private String expirationDate;

    /**
     * When the credential was revoked (if applicable)
     */
    @Property
    private String revokedAt;

    /**
     * Timestamp of this verification
     */
    @Property
    private String verifiedAt;

    // Default constructor
    public VerificationResult() {
    }

    // Getters and Setters
    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
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

    public String getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(String issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(String expirationDate) {
        this.expirationDate = expirationDate;
    }

    public String getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(String revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getVerifiedAt() {
        return verifiedAt;
    }

    public void setVerifiedAt(String verifiedAt) {
        this.verifiedAt = verifiedAt;
    }

    @Override
    public String toString() {
        return "VerificationResult{" +
                "credentialId='" + credentialId + '\'' +
                ", valid=" + valid +
                ", reason='" + reason + '\'' +
                ", verifiedAt='" + verifiedAt + '\'' +
                '}';
    }
}
