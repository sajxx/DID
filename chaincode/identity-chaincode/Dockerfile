# Dockerfile for Chaincode as a Service (CCaaS)
FROM eclipse-temurin:11-jre-jammy

# Create chaincode directory
WORKDIR /chaincode

# Copy the pre-built chaincode JAR
COPY build/libs/chaincode.jar /chaincode/chaincode.jar

# Set environment variables for chaincode
ENV CHAINCODE_SERVER_ADDRESS=0.0.0.0:9999
ENV CORE_CHAINCODE_ID_NAME=identity-chaincode_1.0:placeholder

# Expose the chaincode port
EXPOSE 9999

# Run the chaincode
CMD ["java", "-jar", "/chaincode/chaincode.jar"]
