#!/bin/bash
# ============================================================
# DID System - Network & Chaincode Setup Script (Fabric 2.5+)
# Uses genesis block approach for channel creation (no system channel)
# Builds and deploys chaincode as external service (CCaaS)
# ============================================================

set -euo pipefail

# ----------------------------
# Colors
# ----------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ----------------------------
# UI helpers
# ----------------------------
print_step()    { echo -e "${BLUE}==>${NC} $1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}!${NC} $1"; }
print_error()   { echo -e "${RED}✗${NC} $1"; }

# ----------------------------
# Globals
# ----------------------------
CHANNEL_NAME="did-channel"
CC_NAME="identity-chaincode"
CC_LABEL="identity-chaincode_1.0"
CC_VERSION="1.0"
CC_SEQUENCE="1"

PROJECT_ROOT="$(pwd)"
NETWORK_DIR="${PROJECT_ROOT}/network"
CONFIG_DIR="${PROJECT_ROOT}/network-config"
CHAINCODE_DIR="${PROJECT_ROOT}/chaincode/identity-chaincode"

echo "============================================================"
echo "  DID System - Network & Chaincode Setup (Fabric 2.5+)"
echo "============================================================"
echo ""

# ----------------------------
# Sanity check: run from root
# ----------------------------
if [ ! -d "chaincode" ]; then
    print_error "Directory 'chaincode' not found."
    print_error "Please run this script from the project root directory."
    exit 1
fi

if [ ! -d "network-config" ]; then
    print_error "Directory 'network-config' not found."
    print_error "This folder should contain: crypto-config.yaml, configtx.yaml, docker-compose.yml"
    exit 1
fi

if [ ! -d "network" ]; then
    print_step "'network' directory not found. Creating it..."
    mkdir -p "network"
    print_success "Created 'network' directory."
fi

# ----------------------------
# Step 1: Prerequisites
# ----------------------------
print_step "Checking prerequisites..."

missing_deps=0

# Gradle (Chaincode build)
if ! command -v gradle &> /dev/null; then
    print_error "Gradle not found. Required for chaincode build (build.gradle detected)"
    print_error "Install with SDKMAN: sdk install gradle"
    missing_deps=1
else
    print_success "Gradle: $(gradle --version | head -n 1)"
fi

# Docker
if ! command -v docker &> /dev/null; then
    print_error "Docker not found. Please install Docker"
    missing_deps=1
else
    print_success "Docker: $(docker --version)"
fi

# Docker compose
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker compose"
    print_success "Docker Compose: docker compose"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_CMD="docker-compose"
    print_success "Docker Compose: docker-compose"
else
    print_error "Docker Compose not found"
    missing_deps=1
fi

# Docker daemon running
if ! docker info &>/dev/null; then
    print_error "Docker daemon is not running"
    missing_deps=1
else
    print_success "Docker daemon running"
fi

if [ $missing_deps -eq 1 ]; then
    print_error "Please install missing dependencies and try again"
    exit 1
fi

echo ""

# ----------------------------
# Step 2: Setup Fabric network
# ----------------------------
print_step "Setting up Hyperledger Fabric network..."
cd "${NETWORK_DIR}"

# Download Fabric binaries if needed
if [ ! -d "bin" ]; then
    print_warning "Downloading Fabric binaries (Fabric 2.5.9)..."
    curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh | bash -s -- binary 2.5.9
    print_success "Fabric binaries downloaded"
fi

# Stop old network (if running)
if docker ps --format '{{.Names}}' | grep -qE "peer0\.org1\.did\.com|orderer\.did\.com|cli"; then
    print_warning "Existing Fabric containers detected. Stopping network..."
    ${DOCKER_COMPOSE_CMD} down -v || true
fi

# Clean artifacts (sudo avoids Permission denied)
print_step "Cleaning up old artifacts..."
sudo rm -rf crypto-config channel-artifacts organizations system-genesis-block 2>/dev/null || true
mkdir -p channel-artifacts

# Copy config files from network-config
print_step "Copying configuration files from network-config/..."
cp "${CONFIG_DIR}/crypto-config.yaml" .
cp "${CONFIG_DIR}/configtx.yaml" .
cp "${CONFIG_DIR}/docker-compose.yml" .
cp "${CONFIG_DIR}/connection-org1.json" .
print_success "Configuration files copied"

# Generate crypto materials
print_step "Generating cryptographic materials..."
./bin/cryptogen generate --config=./crypto-config.yaml --output="crypto-config"
print_success "Crypto materials generated"

# Generate application channel genesis block (no system channel)
print_step "Generating application channel genesis block..."
export FABRIC_CFG_PATH="${PWD}"

./bin/configtxgen -profile DIDChannel \
  -outputBlock ./channel-artifacts/${CHANNEL_NAME}.block \
  -channelID ${CHANNEL_NAME}

print_success "Channel genesis block generated: channel-artifacts/${CHANNEL_NAME}.block"

# Start containers
print_step "Starting Fabric network containers..."
${DOCKER_COMPOSE_CMD} up -d

# Wait
print_step "Waiting for containers to initialize (30 seconds)..."
sleep 30

# Verify containers
if ! docker ps --format '{{.Names}}' | grep -q "peer0.org1.did.com"; then
    print_error "peer0.org1.did.com is not running"
    print_error "Check logs: ${DOCKER_COMPOSE_CMD} logs -f"
    exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q "orderer.did.com"; then
    print_error "orderer.did.com is not running"
    print_error "Check logs: ${DOCKER_COMPOSE_CMD} logs -f"
    exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q "cli"; then
    print_error "cli container is not running"
    print_error "Check logs: ${DOCKER_COMPOSE_CMD} logs -f"
    exit 1
fi

print_success "Fabric network containers started"

# Join orderer via osnadmin
print_step "Joining orderer to channel (osnadmin)..."

docker exec cli osnadmin channel join \
  --channelID ${CHANNEL_NAME} \
  --config-block /opt/gopath/src/github.com/hyperledger/fabric/peer/channel-artifacts/${CHANNEL_NAME}.block \
  -o orderer.did.com:7053 \
  --ca-file /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/did.com/orderers/orderer.did.com/msp/tlscacerts/tlsca.did.com-cert.pem \
  --client-cert /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/did.com/orderers/orderer.did.com/tls/server.crt \
  --client-key /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/did.com/orderers/orderer.did.com/tls/server.key \
  2>&1 | grep -v "already exists" || true

print_success "Orderer joined to channel"
sleep 5

# Join peers
print_step "Joining peers to channel..."

docker exec cli peer channel join \
  -b /opt/gopath/src/github.com/hyperledger/fabric/peer/channel-artifacts/${CHANNEL_NAME}.block
print_success "peer0.org1 joined channel"

docker exec \
  -e CORE_PEER_ADDRESS=peer0.org2.did.com:9051 \
  -e CORE_PEER_LOCALMSPID=Org2MSP \
  -e CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.did.com/peers/peer0.org2.did.com/tls/ca.crt \
  -e CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.did.com/users/Admin@org2.did.com/msp \
  cli peer channel join \
  -b /opt/gopath/src/github.com/hyperledger/fabric/peer/channel-artifacts/${CHANNEL_NAME}.block
print_success "peer0.org2 joined channel"

# Skip anchor peers due to genesis-block channel creation mismatch
print_warning "Skipping anchor peer updates (genesis-block channel creation causes version mismatch)."

# Verify channel
print_step "Verifying channel setup..."
CHANNEL_LIST="$(docker exec cli peer channel list 2>&1 || true)"
if echo "$CHANNEL_LIST" | grep -q "${CHANNEL_NAME}"; then
    print_success "Channel verification passed"
else
    print_error "Channel not found in peer channel list"
    echo "$CHANNEL_LIST"
    exit 1
fi

echo ""

# ----------------------------
# Step 3: Build chaincode (Gradle)
# ----------------------------
print_step "Building chaincode..."
cd "${CHAINCODE_DIR}"

if [ -f "build.gradle" ]; then
    print_success "Chaincode build file detected: build.gradle"
else
    print_error "build.gradle not found in chaincode directory: ${CHAINCODE_DIR}"
    exit 1
fi

# Generate Gradle wrapper if missing (best practice)
if [ ! -f "./gradlew" ]; then
    print_warning "Gradle wrapper not found. Generating wrapper using system Gradle..."
    gradle wrapper
    chmod +x ./gradlew
    print_success "Gradle wrapper generated (gradlew)"
fi

print_step "Running chaincode build: ./gradlew clean build shadowJar"
./gradlew clean build shadowJar

# Validate output jar produced by shadowJar config:
# shadowJar config sets jar name to build/libs/chaincode.jar
if [ ! -f "build/libs/chaincode.jar" ]; then
    print_error "Expected chaincode JAR not found: build/libs/chaincode.jar"
    print_warning "Available jars:"
    ls -la build/libs || true
    exit 1
fi

print_success "Chaincode built successfully: build/libs/chaincode.jar"

echo ""

# ----------------------------
# Step 4: Deploy chaincode (CCaaS mode)
# ----------------------------
print_step "Deploying chaincode using CCaaS (Chaincode as a Service)..."
cd "${NETWORK_DIR}"

ORDERER_CA_PATH="/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/ordererOrganizations/did.com/orderers/orderer.did.com/msp/tlscacerts/tlsca.did.com-cert.pem"

# Build the chaincode Docker image for CCaaS
print_step "Building chaincode Docker image..."
cd "${CHAINCODE_DIR}"
docker build -t did-chaincode:1.0 .
print_success "Chaincode Docker image built: did-chaincode:1.0"

cd "${NETWORK_DIR}"

# Create CCaaS package (metadata.json + connection.json in tar.gz)
print_step "Creating CCaaS chaincode package..."
CCAAS_PKG_DIR="${CHAINCODE_DIR}/ccaas-pkg"
rm -rf "${CCAAS_PKG_DIR}"
mkdir -p "${CCAAS_PKG_DIR}"

# Create connection.json for CCaaS
cat > "${CCAAS_PKG_DIR}/connection.json" << 'EOF'
{
  "address": "chaincode.did.com:9999",
  "dial_timeout": "10s",
  "tls_required": false
}
EOF

# Create metadata.json for CCaaS
cat > "${CCAAS_PKG_DIR}/metadata.json" << 'EOF'
{
  "type": "ccaas",
  "label": "identity-chaincode_1.0"
}
EOF

# Package the CCaaS chaincode
cd "${CCAAS_PKG_DIR}"
tar cfz code.tar.gz connection.json
tar cfz "${CC_NAME}-ccaas.tar.gz" code.tar.gz metadata.json
cp "${CC_NAME}-ccaas.tar.gz" "${NETWORK_DIR}/"
cd "${NETWORK_DIR}"

print_step "Installing CCaaS chaincode on peer0.org1..."
docker exec cli peer lifecycle chaincode install /opt/gopath/src/github.com/hyperledger/fabric/peer/channel-artifacts/${CC_NAME}-ccaas.tar.gz 2>&1 || {
    # Copy package to cli container
    docker cp "${CC_NAME}-ccaas.tar.gz" cli:/opt/gopath/src/github.com/hyperledger/fabric/peer/
    docker exec cli peer lifecycle chaincode install ${CC_NAME}-ccaas.tar.gz
}

print_step "Installing CCaaS chaincode on peer0.org2..."
docker exec \
  -e CORE_PEER_ADDRESS=peer0.org2.did.com:9051 \
  -e CORE_PEER_LOCALMSPID=Org2MSP \
  -e CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.did.com/peers/peer0.org2.did.com/tls/ca.crt \
  -e CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.did.com/users/Admin@org2.did.com/msp \
  cli peer lifecycle chaincode install ${CC_NAME}-ccaas.tar.gz

print_success "CCaaS chaincode installed on both peers"

print_step "Querying installed chaincode package ID..."
PACKAGE_ID="$(
  docker exec cli peer lifecycle chaincode queryinstalled 2>&1 \
    | grep "${CC_LABEL}" \
    | sed -n 's/^.*Package ID: \([^,]*\),.*/\1/p' \
    | head -1
)"

if [ -z "${PACKAGE_ID}" ]; then
    print_error "Failed to extract chaincode package ID"
    docker exec cli peer lifecycle chaincode queryinstalled
    exit 1
fi

print_success "Package ID: ${PACKAGE_ID}"

# Start the chaincode container with the correct CHAINCODE_ID
print_step "Starting chaincode container with Package ID..."
export CHAINCODE_CCID="${PACKAGE_ID}"

# Stop old chaincode container if running
docker stop chaincode.did.com 2>/dev/null || true
docker rm chaincode.did.com 2>/dev/null || true

# Start chaincode container with correct ID
docker run -d \
  --name chaincode.did.com \
  --network did-network \
  -e CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999 \
  -e CHAINCODE_ID="${PACKAGE_ID}" \
  -e CORE_CHAINCODE_ID_NAME="${PACKAGE_ID}" \
  -p 9999:9999 \
  did-chaincode:1.0

print_success "Chaincode container started"
sleep 5

print_step "Approving chaincode for Org1..."
docker exec cli peer lifecycle chaincode approveformyorg \
  -o orderer.did.com:7050 \
  --channelID ${CHANNEL_NAME} \
  --name ${CC_NAME} \
  --version ${CC_VERSION} \
  --package-id "${PACKAGE_ID}" \
  --sequence ${CC_SEQUENCE} \
  --tls \
  --cafile "${ORDERER_CA_PATH}"

print_step "Approving chaincode for Org2..."
docker exec \
  -e CORE_PEER_ADDRESS=peer0.org2.did.com:9051 \
  -e CORE_PEER_LOCALMSPID=Org2MSP \
  -e CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.did.com/peers/peer0.org2.did.com/tls/ca.crt \
  -e CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.did.com/users/Admin@org2.did.com/msp \
  cli peer lifecycle chaincode approveformyorg \
  -o orderer.did.com:7050 \
  --channelID ${CHANNEL_NAME} \
  --name ${CC_NAME} \
  --version ${CC_VERSION} \
  --package-id "${PACKAGE_ID}" \
  --sequence ${CC_SEQUENCE} \
  --tls \
  --cafile "${ORDERER_CA_PATH}"

print_success "Chaincode approved by both orgs"

print_step "Committing chaincode..."
docker exec cli peer lifecycle chaincode commit \
  -o orderer.did.com:7050 \
  --channelID ${CHANNEL_NAME} \
  --name ${CC_NAME} \
  --version ${CC_VERSION} \
  --sequence ${CC_SEQUENCE} \
  --tls \
  --cafile "${ORDERER_CA_PATH}" \
  --peerAddresses peer0.org1.did.com:7051 \
  --tlsRootCertFiles /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org1.did.com/peers/peer0.org1.did.com/tls/ca.crt \
  --peerAddresses peer0.org2.did.com:9051 \
  --tlsRootCertFiles /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.did.com/peers/peer0.org2.did.com/tls/ca.crt

print_success "Chaincode committed to channel"

echo ""

# ----------------------------
# Step 5: Test chaincode
# ----------------------------
print_step "Testing chaincode deployment..."
sleep 5

docker exec cli peer chaincode invoke \
  -o orderer.did.com:7050 \
  --tls \
  --cafile "${ORDERER_CA_PATH}" \
  -C ${CHANNEL_NAME} \
  -n ${CC_NAME} \
  --peerAddresses peer0.org1.did.com:7051 \
  --tlsRootCertFiles /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org1.did.com/peers/peer0.org1.did.com/tls/ca.crt \
  --peerAddresses peer0.org2.did.com:9051 \
  --tlsRootCertFiles /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/peerOrganizations/org2.did.com/peers/peer0.org2.did.com/tls/ca.crt \
  -c '{"function":"registerIdentity","Args":["did:fabric:test123","testPublicKey123","Test User"]}'

sleep 3

QUERY_RESULT="$(docker exec cli peer chaincode query \
  -C ${CHANNEL_NAME} \
  -n ${CC_NAME} \
  -c '{"function":"queryIdentity","Args":["did:fabric:test123"]}' \
  2>/dev/null || true)"

if echo "$QUERY_RESULT" | grep -q "did:fabric:test123"; then
    print_success "Chaincode test successful"
else
    print_warning "Chaincode query did not return expected result."
    print_warning "Raw output:"
    echo "$QUERY_RESULT"
fi

echo ""

# ----------------------------
# Summary
# ----------------------------
echo "============================================================"
echo -e "${GREEN}✓ Setup Complete!${NC}"
echo "============================================================"
echo ""
echo "Network and Chaincode setup completed successfully!"
echo ""
echo "Network status:"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "did.com|cli|NAMES" || true
echo ""
echo "Useful commands:"
echo "  - View logs:      ${DOCKER_COMPOSE_CMD} logs -f"
echo "  - Stop network:   cd network && ${DOCKER_COMPOSE_CMD} down"
echo "  - Clean all:      cd network && ${DOCKER_COMPOSE_CMD} down -v && sudo rm -rf crypto-config channel-artifacts"
echo ""
echo "============================================================"
