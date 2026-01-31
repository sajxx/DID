package com.did.chaincode;

import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

import java.util.Objects;

/**
 * Identity - Data model for Decentralized Identity stored on the ledger
 * 
 * This class represents a DID document stored on the Hyperledger Fabric ledger.
 * Only hashed/minimal data is stored for privacy preservation.
 * 
 * Key Design Decisions:
 * - publicKeyHash: Store only the hash of the public key, not the key itself
 * - metadata: Flexible JSON field for additional non-sensitive attributes
 * - status: Lifecycle management (ACTIVE, SUSPENDED, DEACTIVATED)
 */
@DataType
public class Identity {

    /**
     * The Decentralized Identifier (DID)
     * Format: did:fabric:<hash-of-public-key>
     * This serves as the unique identifier for the identity
     */
    @Property
    private String did;

    /**
     * SHA-256 hash of the user's public key
     * Used for verification without exposing the actual key
     */
    @Property
    private String publicKeyHash;

    /**
     * Optional metadata as JSON string
     * Can include: key algorithm, creation method, etc.
     */
    @Property
    private String metadata;

    /**
     * Identity status for lifecycle management
     * Values: ACTIVE, SUSPENDED, DEACTIVATED
     */
    @Property
    private String status;

    /**
     * Timestamp when identity was created
     */
    @Property
    private String createdAt;

    /**
     * Timestamp of last update
     */
    @Property
    private String updatedAt;

    // Default constructor required for JSON deserialization
    public Identity() {
    }

    // Getters and Setters
    public String getDid() {
        return did;
    }

    public void setDid(String did) {
        this.did = did;
    }

    public String getPublicKeyHash() {
        return publicKeyHash;
    }

    public void setPublicKeyHash(String publicKeyHash) {
        this.publicKeyHash = publicKeyHash;
    }

    public String getMetadata() {
        return metadata;
    }

    public void setMetadata(String metadata) {
        this.metadata = metadata;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Identity identity = (Identity) o;
        return Objects.equals(did, identity.did);
    }

    @Override
    public int hashCode() {
        return Objects.hash(did);
    }

    @Override
    public String toString() {
        return "Identity{" +
                "did='" + did + '\'' +
                ", publicKeyHash='" + publicKeyHash + '\'' +
                ", status='" + status + '\'' +
                ", createdAt='" + createdAt + '\'' +
                '}';
    }
}
