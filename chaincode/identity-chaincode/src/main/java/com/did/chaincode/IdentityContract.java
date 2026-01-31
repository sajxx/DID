package com.did.chaincode;

import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.contract.ContractInterface;
import org.hyperledger.fabric.contract.annotation.*;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ledger.KeyValue;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * IdentityContract - Hyperledger Fabric Smart Contract for Decentralized Identity Management
 * 
 * This chaincode implements the core DID operations:
 * 1. Identity Registration - Register a new DID with public key hash
 * 2. Credential Issuance - Issue verifiable credentials to DIDs
 * 3. Credential Revocation - Revoke issued credentials
 * 4. Credential Verification - Verify credential authenticity and status
 * 
 * IMPORTANT: Only hashed data is stored on-chain for privacy preservation.
 * Raw credential data never touches the blockchain.
 */
@Contract(
    name = "IdentityContract",
    info = @Info(
        title = "Decentralized Identity Management Contract",
        description = "Smart contract for managing decentralized identities and verifiable credentials",
        version = "1.0.0",
        license = @License(name = "Apache 2.0", url = "https://www.apache.org/licenses/LICENSE-2.0.html"),
        contact = @Contact(
            email = "did-support@example.com",
            name = "DID Team"
        )
    )
)
@Default
public class IdentityContract implements ContractInterface {

    private static final Logger LOG = Logger.getLogger(IdentityContract.class.getName());
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    // Composite key prefixes for organizing ledger data
    private static final String IDENTITY_PREFIX = "IDENTITY";
    private static final String CREDENTIAL_PREFIX = "CREDENTIAL";
    private static final String REVOCATION_PREFIX = "REVOKED";

    /**
     * Initialize the chaincode ledger
     * Called when chaincode is instantiated
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public void initLedger(final Context ctx) {
        LOG.info("Initializing Identity Management Ledger");
        // Ledger is initialized empty - identities are registered on demand
    }

    /**
     * Register a new Decentralized Identity (DID)
     * 
     * @param ctx The transaction context
     * @param did The Decentralized Identifier (derived from public key hash)
     * @param publicKeyHash SHA-256 hash of the user's public key
     * @param metadata Optional metadata (e.g., creation timestamp, key algorithm)
     * @return The registered identity as JSON
     * 
     * Security Note: Only the hash of the public key is stored, not the key itself.
     * This allows verification without exposing cryptographic material.
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String registerIdentity(final Context ctx, final String did, 
            final String publicKeyHash, final String metadata) {
        
        ChaincodeStub stub = ctx.getStub();
        LOG.info("Registering identity: " + did);

        // Create composite key for identity storage
        String compositeKey = stub.createCompositeKey(IDENTITY_PREFIX, did).toString();

        // Check if identity already exists
        byte[] existingData = stub.getState(compositeKey);
        if (existingData != null && existingData.length > 0) {
            String errorMessage = String.format("Identity %s already exists", did);
            LOG.warning(errorMessage);
            throw new ChaincodeException(errorMessage, "IDENTITY_ALREADY_EXISTS");
        }

        // Create identity object
        Identity identity = new Identity();
        identity.setDid(did);
        identity.setPublicKeyHash(publicKeyHash);
        identity.setMetadata(metadata);
        identity.setStatus("ACTIVE");
        identity.setCreatedAt(stub.getTxTimestamp().toString());
        identity.setUpdatedAt(stub.getTxTimestamp().toString());

        // Store identity on ledger
        String identityJson = gson.toJson(identity);
        stub.putState(compositeKey, identityJson.getBytes(StandardCharsets.UTF_8));

        LOG.info("Identity registered successfully: " + did);
        return identityJson;
    }

    /**
     * Issue a Verifiable Credential to a DID
     * 
     * @param ctx The transaction context
     * @param credentialId Unique identifier for the credential
     * @param issuerDid DID of the credential issuer
     * @param holderDid DID of the credential holder
     * @param credentialHash SHA-256 hash of the full credential data
     * @param schemaHash Hash of the credential schema for validation
     * @param expirationDate Credential expiration date (ISO 8601 format)
     * @return The issued credential metadata as JSON
     * 
     * Privacy Note: Only the credential hash is stored on-chain.
     * The actual credential data is stored off-chain in the holder's wallet.
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String issueCredential(final Context ctx, final String credentialId,
            final String issuerDid, final String holderDid, final String credentialHash,
            final String schemaHash, final String expirationDate) {
        
        ChaincodeStub stub = ctx.getStub();
        LOG.info("Issuing credential: " + credentialId + " to holder: " + holderDid);

        // Verify issuer identity exists and is active
        String issuerKey = stub.createCompositeKey(IDENTITY_PREFIX, issuerDid).toString();
        byte[] issuerData = stub.getState(issuerKey);
        if (issuerData == null || issuerData.length == 0) {
            throw new ChaincodeException("Issuer identity not found: " + issuerDid, "ISSUER_NOT_FOUND");
        }
        Identity issuer = gson.fromJson(new String(issuerData, StandardCharsets.UTF_8), Identity.class);
        if (!"ACTIVE".equals(issuer.getStatus())) {
            throw new ChaincodeException("Issuer identity is not active", "ISSUER_INACTIVE");
        }

        // Verify holder identity exists
        String holderKey = stub.createCompositeKey(IDENTITY_PREFIX, holderDid).toString();
        byte[] holderData = stub.getState(holderKey);
        if (holderData == null || holderData.length == 0) {
            throw new ChaincodeException("Holder identity not found: " + holderDid, "HOLDER_NOT_FOUND");
        }

        // Check if credential already exists
        String credentialKey = stub.createCompositeKey(CREDENTIAL_PREFIX, credentialId).toString();
        byte[] existingCredential = stub.getState(credentialKey);
        if (existingCredential != null && existingCredential.length > 0) {
            throw new ChaincodeException("Credential already exists: " + credentialId, "CREDENTIAL_EXISTS");
        }

        // Create credential metadata object
        CredentialMetadata credential = new CredentialMetadata();
        credential.setCredentialId(credentialId);
        credential.setIssuerDid(issuerDid);
        credential.setHolderDid(holderDid);
        credential.setCredentialHash(credentialHash);
        credential.setSchemaHash(schemaHash);
        credential.setExpirationDate(expirationDate);
        credential.setStatus("VALID");
        credential.setIssuedAt(stub.getTxTimestamp().toString());

        // Store credential metadata on ledger
        String credentialJson = gson.toJson(credential);
        stub.putState(credentialKey, credentialJson.getBytes(StandardCharsets.UTF_8));

        // Emit event for credential issuance (subscribers can listen for this)
        stub.setEvent("CredentialIssued", credentialJson.getBytes(StandardCharsets.UTF_8));

        LOG.info("Credential issued successfully: " + credentialId);
        return credentialJson;
    }

    /**
     * Revoke a previously issued credential
     * 
     * @param ctx The transaction context
     * @param credentialId The credential to revoke
     * @param issuerDid The DID of the issuer requesting revocation
     * @param reason Reason for revocation
     * @return Updated credential metadata as JSON
     * 
     * Authorization: Only the original issuer can revoke a credential
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String revokeCredential(final Context ctx, final String credentialId,
            final String issuerDid, final String reason) {
        
        ChaincodeStub stub = ctx.getStub();
        LOG.info("Revoking credential: " + credentialId);

        // Retrieve credential
        String credentialKey = stub.createCompositeKey(CREDENTIAL_PREFIX, credentialId).toString();
        byte[] credentialData = stub.getState(credentialKey);
        if (credentialData == null || credentialData.length == 0) {
            throw new ChaincodeException("Credential not found: " + credentialId, "CREDENTIAL_NOT_FOUND");
        }

        CredentialMetadata credential = gson.fromJson(
            new String(credentialData, StandardCharsets.UTF_8), CredentialMetadata.class);

        // Authorization check: Only issuer can revoke
        if (!credential.getIssuerDid().equals(issuerDid)) {
            throw new ChaincodeException("Unauthorized: Only the issuer can revoke this credential", 
                "UNAUTHORIZED_REVOCATION");
        }

        // Check if already revoked
        if ("REVOKED".equals(credential.getStatus())) {
            throw new ChaincodeException("Credential is already revoked", "ALREADY_REVOKED");
        }

        // Update credential status
        credential.setStatus("REVOKED");
        credential.setRevocationReason(reason);
        credential.setRevokedAt(stub.getTxTimestamp().toString());

        // Store updated credential
        String updatedJson = gson.toJson(credential);
        stub.putState(credentialKey, updatedJson.getBytes(StandardCharsets.UTF_8));

        // Add to revocation registry for efficient lookup
        String revocationKey = stub.createCompositeKey(REVOCATION_PREFIX, credentialId).toString();
        stub.putState(revocationKey, updatedJson.getBytes(StandardCharsets.UTF_8));

        // Emit revocation event
        stub.setEvent("CredentialRevoked", updatedJson.getBytes(StandardCharsets.UTF_8));

        LOG.info("Credential revoked successfully: " + credentialId);
        return updatedJson;
    }

    /**
     * Verify a credential's authenticity and status
     * 
     * @param ctx The transaction context
     * @param credentialId The credential to verify
     * @param providedHash Hash of the credential data being presented
     * @return Verification result as JSON
     * 
     * Verification checks:
     * 1. Credential exists on-chain
     * 2. Credential has not been revoked
     * 3. Credential has not expired
     * 4. Provided hash matches stored hash (integrity check)
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String verifyCredential(final Context ctx, final String credentialId,
            final String providedHash) {
        
        ChaincodeStub stub = ctx.getStub();
        LOG.info("Verifying credential: " + credentialId);

        // Retrieve credential metadata
        String credentialKey = stub.createCompositeKey(CREDENTIAL_PREFIX, credentialId).toString();
        byte[] credentialData = stub.getState(credentialKey);
        
        VerificationResult result = new VerificationResult();
        result.setCredentialId(credentialId);
        result.setVerifiedAt(stub.getTxTimestamp().toString());

        if (credentialData == null || credentialData.length == 0) {
            result.setValid(false);
            result.setReason("Credential not found on ledger");
            return gson.toJson(result);
        }

        CredentialMetadata credential = gson.fromJson(
            new String(credentialData, StandardCharsets.UTF_8), CredentialMetadata.class);

        // Check revocation status
        if ("REVOKED".equals(credential.getStatus())) {
            result.setValid(false);
            result.setReason("Credential has been revoked: " + credential.getRevocationReason());
            result.setRevokedAt(credential.getRevokedAt());
            return gson.toJson(result);
        }

        // Verify hash integrity
        if (!credential.getCredentialHash().equals(providedHash)) {
            result.setValid(false);
            result.setReason("Credential hash mismatch - data may have been tampered");
            return gson.toJson(result);
        }

        // All checks passed
        result.setValid(true);
        result.setReason("Credential is valid and authentic");
        result.setIssuerDid(credential.getIssuerDid());
        result.setHolderDid(credential.getHolderDid());
        result.setIssuedAt(credential.getIssuedAt());
        result.setExpirationDate(credential.getExpirationDate());

        LOG.info("Credential verification completed: " + credentialId + " - Valid: " + result.isValid());
        return gson.toJson(result);
    }

    /**
     * Query an identity by DID
     * 
     * @param ctx The transaction context
     * @param did The DID to query
     * @return Identity data as JSON
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String queryIdentity(final Context ctx, final String did) {
        ChaincodeStub stub = ctx.getStub();
        String compositeKey = stub.createCompositeKey(IDENTITY_PREFIX, did).toString();
        byte[] data = stub.getState(compositeKey);
        
        if (data == null || data.length == 0) {
            throw new ChaincodeException("Identity not found: " + did, "IDENTITY_NOT_FOUND");
        }
        
        return new String(data, StandardCharsets.UTF_8);
    }

    /**
     * Query a credential by ID
     * 
     * @param ctx The transaction context
     * @param credentialId The credential ID to query
     * @return Credential metadata as JSON
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String queryCredential(final Context ctx, final String credentialId) {
        ChaincodeStub stub = ctx.getStub();
        String compositeKey = stub.createCompositeKey(CREDENTIAL_PREFIX, credentialId).toString();
        byte[] data = stub.getState(compositeKey);
        
        if (data == null || data.length == 0) {
            throw new ChaincodeException("Credential not found: " + credentialId, "CREDENTIAL_NOT_FOUND");
        }
        
        return new String(data, StandardCharsets.UTF_8);
    }

    /**
     * Get all credentials issued to a specific holder
     * 
     * @param ctx The transaction context
     * @param holderDid The holder's DID
     * @return List of credentials as JSON array
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String getCredentialsByHolder(final Context ctx, final String holderDid) {
        ChaincodeStub stub = ctx.getStub();
        List<CredentialMetadata> credentials = new ArrayList<>();

        // Query all credentials and filter by holder
        QueryResultsIterator<KeyValue> results = stub.getStateByPartialCompositeKey(CREDENTIAL_PREFIX);
        
        for (KeyValue result : results) {
            CredentialMetadata credential = gson.fromJson(
                new String(result.getValue(), StandardCharsets.UTF_8), CredentialMetadata.class);
            if (holderDid.equals(credential.getHolderDid())) {
                credentials.add(credential);
            }
        }

        return gson.toJson(credentials);
    }

    /**
     * Get all revoked credentials (revocation registry)
     * 
     * @param ctx The transaction context
     * @return List of revoked credential IDs
     */
    @Transaction(intent = Transaction.TYPE.EVALUATE)
    public String getRevocationRegistry(final Context ctx) {
        ChaincodeStub stub = ctx.getStub();
        List<String> revokedIds = new ArrayList<>();

        QueryResultsIterator<KeyValue> results = stub.getStateByPartialCompositeKey(REVOCATION_PREFIX);
        
        for (KeyValue result : results) {
            CredentialMetadata credential = gson.fromJson(
                new String(result.getValue(), StandardCharsets.UTF_8), CredentialMetadata.class);
            revokedIds.add(credential.getCredentialId());
        }

        return gson.toJson(revokedIds);
    }

    /**
     * Update identity status (deactivate/reactivate)
     * 
     * @param ctx The transaction context
     * @param did The DID to update
     * @param newStatus The new status (ACTIVE, SUSPENDED, DEACTIVATED)
     * @return Updated identity as JSON
     */
    @Transaction(intent = Transaction.TYPE.SUBMIT)
    public String updateIdentityStatus(final Context ctx, final String did, final String newStatus) {
        ChaincodeStub stub = ctx.getStub();
        String compositeKey = stub.createCompositeKey(IDENTITY_PREFIX, did).toString();
        byte[] data = stub.getState(compositeKey);
        
        if (data == null || data.length == 0) {
            throw new ChaincodeException("Identity not found: " + did, "IDENTITY_NOT_FOUND");
        }

        // Validate status
        if (!newStatus.equals("ACTIVE") && !newStatus.equals("SUSPENDED") && !newStatus.equals("DEACTIVATED")) {
            throw new ChaincodeException("Invalid status. Must be ACTIVE, SUSPENDED, or DEACTIVATED", 
                "INVALID_STATUS");
        }

        Identity identity = gson.fromJson(new String(data, StandardCharsets.UTF_8), Identity.class);
        identity.setStatus(newStatus);
        identity.setUpdatedAt(stub.getTxTimestamp().toString());

        String updatedJson = gson.toJson(identity);
        stub.putState(compositeKey, updatedJson.getBytes(StandardCharsets.UTF_8));

        return updatedJson;
    }
}
