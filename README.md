 # Secure Kafka Cluster on Minikube with mTLS

 This `README.md` provides a comprehensive guide to deploying a secure Kafka cluster on Minikube using Confluent Platform Docker images, with a strong focus on Mutual TLS (mTLS) for all internal and external communication. It details the step-by-step process, highlights common pitfalls and errors encountered during the setup, and offers solutions and best practices to avoid them.

 ## Table of Contents
 1.  Introduction
 2.  Prerequisites
 3.  Cluster Setup Steps
     *   Minikube Initialization
     *   Cert-Manager Installation
     *   Kubernetes Namespace & RBAC
     *   Certificate Authority (CA) Setup
     *   Leaf Certificate Issuance
     *   Secrets & ConfigMaps Deployment
     *   Zookeeper & Kafka StatefulSets Deployment
 4.  Detailed SSL/TLS Configuration Guide
     *   Certificate Management with cert-manager
     *   Keystore & Truststore Generation (initContainers)
     *   Kubernetes Secrets for Passwords
     *   Kafka & Zookeeper Configuration (`server.properties`, `zookeeper.properties`)
     *   Confluent `dub` Entrypoint & Environment Variables
     *   Readiness & Liveness Probes for mTLS
 5.  Troubleshooting Common Errors & Solutions
 6.  Visual Explanations (Diagrams)
 7.  Verification
 8.  Further Steps

 ## 1. Introduction

 This guide walks you through deploying a highly available Kafka cluster secured with mTLS on Minikube. We leverage `cert-manager` for automated certificate management and Confluent Platform Docker images for Zookeeper and Kafka. The focus is on correctly configuring SSL/TLS, which is often the most challenging aspect of secure Kafka deployments.

 ## 2. Prerequisites

 Before you begin, ensure you have the following tools installed:
 *   **Minikube:** A local Kubernetes cluster.
 *   **kubectl:** The Kubernetes command-line tool.
 *   **Docker:** Required if using the `docker` driver for Minikube.
 *   **`openssl`:** For certificate operations (usually pre-installed).
 *   **`keytool`:** Part of the Java Development Kit (JDK), used for Java keystore operations.

 Ensure your user is part of the `docker` group if you are using the Docker driver for Minikube. The `setup_minikube_kafka.sh` script includes checks and instructions for this.

 ## 3. Cluster Setup Steps

 The `setup_minikube_kafka.sh` script automates most of the initial setup.

 ### 3.1 Minikube Initialization
 The script starts or ensures Minikube is running with specified CPU, memory, and disk size.

 ### 3.2 Cert-Manager Installation
 `cert-manager` is installed manually, as it's crucial for automated certificate issuance.

 ### 3.3 Kubernetes Namespace & RBAC
 A dedicated namespace (`kafka-cluster`) is created, along with necessary ServiceAccounts, Roles, and RoleBindings for the Kafka components.

 ### 3.4 Certificate Authority (CA) Setup
 `cert-manager` is used to create a self-signed Root CA and an Intermediate CA, which will sign all subsequent Kafka and Zookeeper certificates.

 ### 3.5 Leaf Certificate Issuance
 Server certificates for Zookeeper and Kafka are issued by the Intermediate CA. These certificates are used for mTLS between brokers, and between brokers and Zookeeper.

 ### 3.6 Secrets & ConfigMaps Deployment
 Kubernetes Secrets are created to store sensitive passwords for keystores and truststores. ConfigMaps are used to define base configurations for Zookeeper and Kafka.

 ### 3.7 Zookeeper & Kafka StatefulSets Deployment
 Finally, the Zookeeper and Kafka StatefulSets are deployed. These include `initContainers` for dynamic keystore/truststore generation and main containers configured for secure operation.

 ## 4. Detailed SSL/TLS Configuration Guide

 This section elaborates on the critical SSL/TLS configuration aspects, highlighting the interplay between different Kubernetes resources and the Confluent Docker images.

 ### 4.1 Certificate Management with cert-manager

 `cert-manager` automates the lifecycle of X.509 certificates.
 *   **Root CA:** A `Certificate` resource with `isCA: true` and a `selfSigned` `Issuer` creates the root certificate and key, stored in `root-ca-secret`.
 *   **Intermediate CA:** Another `Certificate` with `isCA: true` and an `Issuer` referencing the `root-ca-secret` creates the intermediate certificate, stored in `intermediate-ca-secret`.
 *   **Leaf Certificates:** `Certificate` resources for Zookeeper (`zookeeper-tls`) and Kafka (`kafka-tls`) are issued by an `Issuer` referencing the `intermediate-ca-secret`. These certificates include `server auth` and `client auth` usages for mTLS.

 **Key Takeaway:** `cert-manager` handles the generation and renewal of raw `.crt` and `.key` files, storing them in Kubernetes Secrets. The `initContainers` then transform these into Java keystores.

 ### 4.2 Keystore & Truststore Generation (initContainers)

 The `initContainers` in both Zookeeper and Kafka StatefulSets are responsible for:
 1.  **Reading Raw Certs:** Mounting the `cert-manager` generated secrets (`zookeeper-server-tls-secret`, `kafka-tls`, `root-ca-secret`, `intermediate-ca-secret`) to access `tls.crt` and `tls.key` files.
 2.  **Creating CA Chain:** Concatenating the intermediate CA and root CA certificates into a single `ca-chain.crt` file.
 3.  **Generating PKCS12:** Using `openssl pkcs12 -export` to create a temporary PKCS12 keystore. This command is crucial for correctly bundling the server certificate with its full chain (`-certfile ca-chain.crt`).
 4.  **Converting to JKS:** Using `keytool -importkeystore` to convert the temporary PKCS12 into a JKS keystore. This is necessary because older Java applications (or specific versions of Zookeeper/Kafka) might have better compatibility with JKS.
 5.  **Creating Truststores:** Using `keytool -importcert` to import the root and intermediate CA certificates into separate JKS truststores.
 6.  **Writing Password Files:** Creating small files containing only the password values (e.g., `kafka.server.keystore.password`) in the shared `/etc/kafka/secrets/` directory. This is a workaround for the Confluent `dub` script's specific password handling.
 7.  **Setting Permissions:** Ensuring correct file permissions (`chmod 600`) for sensitive files.

 **Key Takeaway:** The `initContainer` acts as a secure, ephemeral build environment for Java keystores, ensuring all necessary certificate materials are correctly formatted and placed in shared volumes.

 ### 4.3 Kubernetes Secrets for Passwords

 Passwords for keystores and truststores are stored in Kubernetes `Secret` resources (`zookeeper-credentials`, `kafka-credentials`).
 *   These secrets are mounted as environment variables into the `initContainers` to be used during keystore generation.
 *   For the main Kafka/Zookeeper containers, these passwords are *not* directly passed as environment variables (except for specific `dub` script requirements). Instead, the `initContainer` writes them to files, and the main container references these files.

 **Key Takeaway:** Avoid hardcoding passwords. Use Kubernetes Secrets and manage their access carefully.

 ### 4.4 Kafka & Zookeeper Configuration (`server.properties`, `zookeeper.properties`)

 *   **Zookeeper (`zookeeper.properties`):**
     *   The `initContainer` dynamically generates `zookeeper.properties` including `secureClientPort`, `serverCnxnFactory=org.apache.zookeeper.server.NettyServerCnxnFactory`, and SSL-related paths and passwords.
     *   The `server.1`, `server.2`, `server.3` entries define the Zookeeper ensemble.
 *   **Kafka (`server.properties`):**
     *   **Crucial Change:** The `initContainer` *no longer* generates `server.properties`. Instead, the Confluent `dub` entrypoint script generates this file internally based on environment variables.
     *   The `ConfigMap` (`kafka-config`) now only defines the `server.properties` template for reference, but it's not directly used by the main container.

 **Key Takeaway:** Understand the configuration hierarchy. For Confluent images, environment variables often take precedence or are the primary input for the `dub` entrypoint, which then generates the final properties files.

 ### 4.5 Confluent `dub` Entrypoint & Environment Variables

 The `confluentinc/cp-kafka` and `confluentinc/cp-zookeeper` images use a custom entrypoint script (`/etc/confluent/docker/run` or `/usr/local/bin/dub`) that processes `KAFKA_*` or `ZOOKEEPER_*` environment variables to generate the final configuration files and start the Java process.

 **Common `dub` Requirements:**
 *   **`KAFKA_ADVERTISED_LISTENERS`:** Must be set dynamically per pod.
 *   **`KAFKA_SSL_KEYSTORE_LOCATION`, `KAFKA_SSL_TRUSTSTORE_LOCATION`:** Absolute paths to JKS files.
 *   **`KAFKA_SSL_KEYSTORE_FILENAME`, `KAFKA_SSL_TRUSTSTORE_FILENAME`:** Filenames of the JKS files (required by `dub`'s validation).
 *   **`KAFKA_SSL_KEYSTORE_PASSWORD`, `KAFKA_SSL_KEY_PASSWORD`, `KAFKA_SSL_TRUSTSTORE_PASSWORD`:** These should point to the *password files* created by the `initContainer` (e.g., `kafka.server.keystore.password`).
 *   **`KAFKA_SSL_KEYSTORE_CREDENTIALS`, `KAFKA_SSL_TRUSTSTORE_CREDENTIALS`:** These are additional `dub`-specific aliases for passwords that must be set (pointing to the same password files).
 *   **`KAFKA_ZOOKEEPER_CONNECT`:** Zookeeper connection string.
 *   **`KAFKA_ZOOKEEPER_SSL_CLIENT_ENABLE`:** Set to `true`.
 *   **`KAFKA_ZOOKEEPER_SSL_PROTOCOL`, `KAFKA_ZOOKEEPER_SSL_CIPHER_SUITES`:** Explicitly set for Kafka's Zookeeper client.

 **Key Takeaway:** The `dub` script's behavior is often undocumented and can be very particular. When in doubt, provide all relevant SSL parameters as environment variables, and ensure password values are provided as file paths if `_FILENAME` variables are also required.

 ### 4.6 Readiness & Liveness Probes for mTLS

 Probes must perform a successful mTLS handshake with the application.
 *   They need access to a client certificate and key (`-cert`, `-key`).
 *   They need access to the CA certificate (`-CAfile`).
 *   They should specify a compatible TLS version (`-tls1_2` or `-tls1_3`).

 **Key Takeaway:** Probes are clients too! They must adhere to the server's mTLS requirements. Failing probes lead to pod restarts.

### 4.7 SSL/TLS Mutual Handshake Flow

Understanding the mTLS handshake is key to debugging. Here's a simplified overview of the process between a Kafka client (e.g., another broker, or a producer/consumer) and a Kafka broker (or Kafka's client to Zookeeper):

1.  **ClientHello:** The client initiates the handshake, proposing TLS versions, cipher suites it supports, and optionally, a list of CAs it trusts for server authentication.
    *   **Affected Parameters:** `ssl.enabled.protocols`, `ssl.cipher.suites` (client side).
2.  **ServerHello:** The server responds, selecting the highest mutually supported TLS version and a common cipher suite. It also sends its digital certificate.
    *   **Affected Parameters:** `ssl.enabled.protocols`, `ssl.cipher.suites` (server side), `ssl.keystore.location`, `ssl.keystore.password` (server's identity).
3.  **Server Certificate:** The server sends its certificate chain (leaf, intermediate, root).
    *   **Affected Parameters:** `ssl.keystore.location` (ensuring the full chain is embedded).
4.  **Server Key Exchange (Optional):** If using ephemeral Diffie-Hellman, the server sends parameters for key exchange.
5.  **Server Hello Done:** The server indicates it's done with its part of the handshake.
6.  **Client Certificate (if `ssl.client.auth=required`):** The client verifies the server's certificate chain against its truststore. If `ssl.client.auth` is `required` on the server, the client then sends its own digital certificate chain.
    *   **Affected Parameters:** `ssl.truststore.location`, `ssl.truststore.password` (client's trust of server), `ssl.client.auth` (server's requirement), `ssl.keystore.location`, `ssl.keystore.password` (client's identity).
7.  **Client Key Exchange:** The client sends its key exchange parameters.
8.  **Client Certificate Verify (if client certificate sent):** The client proves ownership of its private key by signing a hash of the handshake messages.
    *   **Affected Parameters:** `ssl.keystore.location`, `ssl.keystore.password` (client's private key).
9.  **Change Cipher Spec:** Both client and server send messages indicating they will switch to the newly negotiated cipher suite.
10. **Finished:** Both client and server send encrypted "Finished" messages, proving they successfully completed the handshake.
11. **Application Data:** Secure communication begins.

Any failure at steps 2, 3, 6, or 8 (e.g., certificate not trusted, chain incomplete, cipher mismatch, client certificate missing) will result in an `SSLHandshakeException`.

 ## 5. Troubleshooting Common Errors & Solutions

 This section details the specific errors encountered during the setup process and their resolutions.

 ### 5.1 `javax.net.ssl.SSLHandshakeException: Empty server certificate chain`
 *   **Problem:** The server presented a certificate, but it did not include the full chain of trust (intermediate CA, root CA).
 *   **Root Cause:** The keystore was not correctly built with the full certificate chain, or the Java application failed to parse it correctly.
 *   **Solution:**
     *   Ensure `openssl pkcs12 -export` uses `-certfile` to include the full CA chain (`cat intermediate-ca.crt root-ca.crt > ca-chain.crt`).
     *   Convert the PKCS12 to JKS using `keytool -importkeystore` if the Java application has better JKS compatibility.
     *   **Robust `openssl` command:** `openssl pkcs12 -export -in server.crt -inkey server.key -certfile fullchain.crt -name alias -out temp.p12`
     *   **Robust `keytool` conversion:** `keytool -importkeystore -srckeystore temp.p12 -srcstoretype PKCS12 -srckeystorepass <pass> -destkeystore final.jks -deststoretype JKS -deststorepass <pass> -destkeypass <pass> -noprompt`
 *   **How to Avoid:** Always verify the generated keystore's chain length (`keytool -list -v`) in the `initContainer` and fail early if it's incorrect.

 ### 5.2 `java.lang.IllegalArgumentException: No enum constant org.apache.zookeeper.common.KeyStoreFileType.PKCS12/JKS`
 *   **Problem:** Zookeeper's `X509Util` class does not recognize the specified `KeyStoreFileType` (PKCS12 or JKS).
 *   **Root Cause:** Specific Zookeeper versions (e.g., `confluentinc/cp-zookeeper:7.5.0`) might have bugs or limitations in their SSL implementation, leading to unexpected rejections of standard keystore types.
 *   **Solution:** If PKCS12 is rejected, revert to JKS. If JKS is rejected, try a different image version. In our case, `confluentinc/cp-zookeeper:7.6.1` was eventually used, and the issue was related to `CLASSPATH` and `dub` script.
 *   **How to Avoid:** Consult the official documentation for the specific image version's SSL configuration. Be prepared to experiment with keystore types if standard ones fail.

 ### 5.3 `Error: Could not find or load main class ... QuorumPeerMain` (`ClassNotFoundException`)
 *   **Problem:** The Java Virtual Machine (JVM) cannot find the main application class.
 *   **Root Cause:** The `CLASSPATH` provided to the `java` command is incorrect or incomplete. Confluent images have specific JAR locations that differ from vanilla Apache distributions.
 *   **Solution:**
     *   Initially, we tried manually setting `CLASSPATH` to include `/usr/share/java/zookeeper/*`, `/usr/share/java/zookeeper/lib/*`, `/usr/bin/confluent/share/java/cp-base/*`, `/usr/bin/confluent/share/java/cp-zookeeper/*`, etc.
     *   **Ultimate Solution:** Remove the custom `command` from the main container and let the image's default entrypoint (`/etc/confluent/docker/run`) handle the `CLASSPATH` and Java invocation. This entrypoint is designed to correctly set up the environment.
 *   **How to Avoid:** For Confluent images, prefer using the default entrypoint (`exec /etc/confluent/docker/run`) and configure via environment variables (`KAFKA_*`, `ZOOKEEPER_*`) rather than overriding the `command` and manually setting `CLASSPATH`.

 ### 5.4 `java.lang.UnsupportedOperationException: SSL isn't supported in NIOServerCnxn`
 *   **Problem:** Zookeeper is configured for SSL but is using a non-SSL capable connection factory.
 *   **Root Cause:** The `serverCnxnFactory` property in `zookeeper.properties` was set to `org.apache.zookeeper.server.NIOServerCnxnFactory` (non-SSL) instead of `org.apache.zookeeper.server.NettyServerCnxnFactory` (SSL-capable).
 *   **Solution:** Set `serverCnxnFactory=org.apache.zookeeper.server.NettyServerCnxnFactory` in `zookeeper.properties`. Additionally, for Confluent images, ensure `ZOOKEEPER_SERVER_CNXN_FACTORY` environment variable is set to `org.apache.zookeeper.server.NettyServerCnxnFactory` as `dub` might prioritize it.
 *   **How to Avoid:** Always use `NettyServerCnxnFactory` for secure Zookeeper connections.

 ### 5.5 `javax.net.ssl.SSLHandshakeException: no cipher suites in common`
 *   **Problem:** The client and server cannot agree on a common set of cryptographic algorithms.
 *   **Root Cause:**
     *   The server (Zookeeper/Kafka) was not explicitly configured with a broad set of modern cipher suites.
     *   The client (e.g., `openssl s_client` in probes) was not explicitly told to use a modern TLS version or compatible ciphers.
 *   **Solution:**
     *   Explicitly define `ssl.cipherSuites` (Zookeeper) and `ssl.cipher.suites` (Kafka) in their respective configurations (or via `ZOOKEEPER_SSL_CIPHER_SUITES`, `KAFKA_SSL_CIPHER_SUITES` env vars).
     *   For `openssl s_client` probes, use `-tls1_2` (or `-tls1_3`) and potentially `-cipher` to specify a compatible list.
 *   **How to Avoid:** Always configure explicit, modern cipher suites. Ensure all clients (including probes) are configured to use compatible TLS versions and ciphers.

 ### 5.6 `Liveness probe failed: Can't open /mnt/ssl-secrets/zookeeper-server-tls/tls.key for reading, No such file or directory`
 *   **Problem:** The `openssl s_client` command in the probe cannot find the client certificate/key.
 *   **Root Cause:** The Kubernetes Secret containing the raw `tls.crt` and `tls.key` files was mounted to the `initContainer` but *not* to the main `zookeeper` (or `kafka`) container, where the probes run.
 *   **Solution:** Mount the relevant `*-tls-secret` volumes (e.g., `zookeeper-server-tls-secret`, `kafka-server-tls-secret`) into the main container's `volumeMounts`.
 *   **How to Avoid:** Always ensure all necessary files for probes (certs, keys, CA files) are mounted into the container where the probe command executes.

 ### 5.7 `KAFKA_ADVERTISED_LISTENERS is required.`
 *   **Problem:** The Confluent `dub` entrypoint script requires this environment variable.
 *   **Root Cause:** The `server.properties` file might define `advertised.listeners`, but `dub` validates environment variables *before* processing the properties file.
 *   **Solution:** Dynamically set `KAFKA_ADVERTISED_LISTENERS` as an environment variable in the main container's `command` section using `POD_NAME` and `POD_NAMESPACE` from the Downward API, then `exec /etc/confluent/docker/run`.
 *   **How to Avoid:** For Confluent images, always provide `KAFKA_ADVERTISED_LISTENERS` as an environment variable.

 ### 5.8 `KAFKA_SSL_KEYSTORE_FILENAME is required.` (and `TRUSTSTORE_FILENAME`)
 *   **Problem:** The `dub` script explicitly requires the filename part of the keystore/truststore path.
 *   **Root Cause:** `dub` has specific validation logic that expects these `_FILENAME` environment variables, even if the full path is provided via `_LOCATION`.
 *   **Solution:** Add `KAFKA_SSL_KEYSTORE_FILENAME` and `KAFKA_SSL_TRUSTSTORE_FILENAME` (and their Zookeeper client equivalents) to the environment variables, providing just the filename (e.g., `kafka.server.keystore.jks`).
 *   **How to Avoid:** Always provide both `_LOCATION` (full path) and `_FILENAME` (just filename) environment variables for keystores/truststores when using Confluent `dub` entrypoints.

 ### 5.9 `Command [/usr/local/bin/dub path /etc/kafka/secrets/changeitdev exists] FAILED !` (and `kafka.server.key.password exists`)
 *   **Problem:** `dub` is trying to interpret a password value as a file path.
 *   **Root Cause:** `dub` gets confused when both `_LOCATION` (or base path) and password values are provided directly, especially if `_FILENAME` variables are also present. It attempts to construct a file path using the literal password value.
 *   **Solution:** The most robust solution is to provide all passwords as *files* to `dub`. The `initContainer` writes password values into separate files (e.g., `kafka.server.keystore.password`) in the shared `/etc/kafka/secrets/` directory. Then, the environment variables for passwords (e.g., `KAFKA_SSL_KEYSTORE_PASSWORD`) are set to the *relative path* of these password files (e.g., `kafka.server.keystore.password`).
 *   **How to Avoid:** Always provide passwords to `dub` via files, especially when using `_FILENAME` variables for keystores/truststores.

 ### 5.10 `KAFKA_SSL_KEY_CREDENTIALS is required.` (and `TRUSTSTORE_CREDENTIALS`, `KEYSTORE_CREDENTIALS`)
 *   **Problem:** `dub` requires specific aliases for password environment variables.
 *   **Root Cause:** `dub` has internal validation checks for these specific `_CREDENTIALS` environment variables.
 *   **Solution:** Add `KAFKA_SSL_KEY_CREDENTIALS`, `KAFKA_SSL_KEYSTORE_CREDENTIALS`, and `KAFKA_SSL_TRUSTSTORE_CREDENTIALS` (and their Zookeeper client equivalents) to the environment variables, pointing them to the respective password files.
 *   **How to Avoid:** Always include these `_CREDENTIALS` environment variables when configuring SSL with Confluent `dub` entrypoints.

 ### 5.11 `io.netty.handler.ssl.NotSslRecordException: not an SSL/TLS record`
 *   **Problem:** Zookeeper's secure port receives non-SSL/TLS data.
 *   **Root Cause:** Kafka's Zookeeper client is failing to initialize its SSL context or is sending plain text. This can be due to:
     *   Missing `zookeeper.clientCnxnSocket=org.apache.zookeeper.ClientCnxnSocketNetty` in `server.properties`.
     *   Inconsistent or missing `zookeeper.ssl.protocol` or `zookeeper.ssl.cipher.suites` configuration for the Zookeeper client.
     *   Kafka failing to load its Zookeeper client keystore/truststore due to incorrect paths.
 *   **Solution:**
     *   Ensure `zookeeper.clientCnxnSocket=org.apache.zookeeper.ClientCnxnSocketNetty` is in `server.properties`.
     *   Ensure `zookeeper.ssl.protocol` (e.g., `TLSv1.2`) and `zookeeper.ssl.cipher.suites` are correctly set for the Zookeeper client in `server.properties`.
     *   Verify all `zookeeper.ssl.keystore.location` and `zookeeper.ssl.truststore.location` paths in `server.properties` are correct (e.g., `/etc/kafka/secrets/`).
 *   **How to Avoid:** Be meticulous with Kafka's Zookeeper client SSL configuration. Ensure all paths are correct and all necessary SSL properties are explicitly set.

 ### 5.12 `Failed to create TrustManager` / `FileNotFoundException: changeitdev` (from `keytool -list` in initContainer)
 *   **Problem:** The `initContainer`'s `keytool -list` command fails to verify the generated JKS.
 *   **Root Cause:** The `keytool -list` command was executed *after* the password environment variables were `unset`, and it was hardcoded to use an empty password, leading to authentication failure.
 *   **Solution:** Ensure all `keytool -list` verification commands use the actual password environment variables (e.g., `keytool -list -v -keystore "${KEYSTORE_PATH}" -storepass "${KAFKA_SERVER_KEYSTORE_PASSWORD}"`) and are executed *before* any `unset` commands or password file writes.
 *   **How to Avoid:** Always verify JKS files using the correct passwords *before* unsetting variables or changing how passwords are stored.

 ### 5.13 `Pod "kafka-0" is invalid: spec.containers[0].env[32].name: Required value`
 *   **Problem:** Kubernetes API server rejects the StatefulSet definition.
 *   **Root Cause:** An empty list item (`-`) was present in the `env` section of the container spec, which Kubernetes interpreted as an incomplete environment variable definition.
 *   **Solution:** Remove the empty list item from the YAML.
 *   **How to Avoid:** Be careful with YAML formatting, especially when commenting out or removing lines. Validate YAML before applying (`kubectl apply --dry-run=client -f your-file.yml`).

 ### 5.14 `kafka.zookeeper.ZooKeeperClientTimeoutException`
 *   **Problem:** Kafka times out trying to connect to Zookeeper.
 *   **Root Cause:**
     *   Network connectivity issues (DNS, firewall).
     *   Zookeeper not fully ready when Kafka attempts connection.
     *   Underlying SSL configuration issues preventing successful handshake (which then manifests as a timeout).
 *   **Solution:**
     *   Verify Zookeeper service and endpoints (`kubectl get svc`).
     *   Test connectivity from inside the Kafka pod using `openssl s_client` with full mTLS parameters.
     *   Ensure `zookeeper.clientCnxnSocket=org.apache.zookeeper.ClientCnxnSocketNetty` is set in Kafka's `server.properties`.
     *   Ensure all Zookeeper client SSL parameters are correctly set in Kafka's configuration (as detailed in previous sections).
 *   **How to Avoid:** Ensure Zookeeper is fully stable before starting Kafka. Use robust connectivity checks.

## 6. Visual Explanations (Diagrams)

 ### 6.1 Overall Architecture Diagram

 This diagram illustrates the high-level components and their communication within the Minikube environment.
 ```mermaid
graph LR
   subgraph Minikube Cluster
       subgraph Control Plane
           kube-apiserver
           kube-scheduler
           kube-controller-manager
       end

       subgraph "Worker Node - minikube"
           kubelet
           kube-proxy
           ContainerRuntime

           subgraph kafka-cluster Namespace
               subgraph Zookeeper Ensemble
                   ZkPod1[Zookeeper Pod 0]
                   ZkPod2[Zookeeper Pod 1]
                   ZkPod3[Zookeeper Pod 2]
                   ZkSvc[Zookeeper Service]
               end

               subgraph Kafka Cluster
                   KafkaPod1[Kafka Pod 0]
                   KafkaPod2[Kafka Pod 1]
                   KafkaPod3[Kafka Pod 2]
                   KafkaHeadlessSvc[Kafka Headless Service]
                   KafkaSvc[Kafka Service]
               end

               subgraph Cert-Manager
                   CertManagerPod[cert-manager Pod]
                   CAIssuer[CA Issuer]
                   Certificates[Certificates]
               end
           end
       end
   end

   User -- kubectl --> kube-apiserver
   CertManagerPod -- Issues Certs --> Certificates
   Certificates -- Stores in --> K8sSecrets[Kubernetes Secrets]
   ZkPod1 <--> ZkPod2
   ZkPod1 <--> ZkPod3
   ZkPod1 -- mTLS --> ZkSvc
   KafkaPod1 <--> KafkaPod2
   KafkaPod1 <--> KafkaPod3
   KafkaPod1 -- mTLS --> KafkaHeadlessSvc
   KafkaPod1 -- mTLS --> KafkaSvc
   KafkaPod1 -- mTLS --> ZkSvc
   KafkaPod2 -- mTLS --> ZkSvc
   KafkaPod3 -- mTLS --> ZkSvc
   K8sSecrets -- Mounted by --> ZkPod1
   K8sSecrets -- Mounted by --> KafkaPod1
```

 ### 6.2 Certificate Hierarchy Diagram

 This diagram illustrates the chain of trust from the self-signed Root CA down to the leaf certificates used by Zookeeper and Kafka.

 ```mermaid
 graph TD
   RootCA[Root CA Self-Signed]
   IntermediateCA[Intermediate CA]
   ZkCert[Zookeeper Server Certificate]
   KafkaCert[Kafka Server Certificate]

   RootCA -- Signs --> IntermediateCA
   IntermediateCA -- Signs --> ZkCert
   IntermediateCA -- Signs --> KafkaCert
 ```

 ### 6.3 mTLS Handshake Flow Diagram

 This sequence diagram visualizes the steps involved in a Mutual TLS (mTLS) handshake, highlighting the roles of certificates, keys, and truststores.

 ```mermaid
 sequenceDiagram
    participant Client
    participant Server

    Client->>Server: ClientHello (TLS versions, Ciphers, Client CAs)
    Server->>Client: ServerHello (Selected TLS, Cipher, Server Cert Chain)
    Client->>Client: Verify Server Cert Chain (using Client Truststore)
    alt Server requires Client Auth
        Client->>Server: Client Certificate (Client Cert Chain)
        Client->>Server: ClientKeyExchange (Encrypted with Client Private Key)
        Server->>Server: Verify Client Cert Chain (using Server Truststore)
        Server->>Server: Decrypt ClientKeyExchange (using Server Private Key)
    end
    Client->>Server: ChangeCipherSpec
    Client->>Server: Finished (Encrypted)
    Server->>Client: ChangeCipherSpec
    Server->>Client: Finished (Encrypted)
    Client->>Server: Application Data (Encrypted)
    Server->>Client: Application Data (Encrypted)
 ```

 ### 6.4 InitContainer Process Diagram

 This flowchart details the steps performed by the `initContainer` to prepare the Java keystores and truststores from raw certificate secrets.
 ```mermaid
 flowchart TD
    A[Start InitContainer] --> B[Mount K8s Secrets<br>(Certs, Keys, CAs)]
    B --> C[Read Raw Cert/Key Files]
    C --> D[Create Full CA Chain File]
    D --> E[Generate PKCS12 Keystore<br>with Server Cert + Full CA Chain]
    E --> F[Convert PKCS12 to JKS Keystore]
    F --> G[Create JKS Truststore<br>with Root + Intermediate CAs]
    G --> G_verify(Verify Keystore & Truststore<br>e.g., keytool -list)
    G_verify --> H[Write Passwords to Files<br>for Confluent 'dub' script]
    H --> I[Set File Permissions<br>(chmod 600, chown 1000:1000)]
    I --> J[Unset Password Env Vars<br>for security]
    J --> K[End InitContainer]
 ```

 ### 6.5 Confluent `dub` Configuration Flow Diagram

 This diagram illustrates how the Confluent `dub` entrypoint script processes environment variables to generate the final `server.properties` and start the Kafka/Zookeeper process.

 ```mermaid
 graph TD
     A[Start Main Container] --> B{Execute /etc/confluent/docker/run<br>(dub entrypoint)}
     B --> C[Read KAFKA_* / ZOOKEEPER_* Env Vars]
     C --> D{Process Env Vars<br>(e.g., _LOCATION, _FILENAME, _PASSWORD, _CREDENTIALS)}
     D --> E{Validate Paths & Credentials<br>(e.g., `dub path ... exists`)}
     E -- Validation Success --> F[Generate Internal server.properties]
     E -- Validation Failed --> G[Exit with Error]
     F --> H[Start Kafka/Zookeeper Java Process<br>(using generated properties)]
     H --> I[Application Running]
 ```

 ## 7. Verification

 Once all pods are `Running` and show `RESTARTS: 0`:
 1.  **Check Pod Status:** `kubectl get pods -n kafka-cluster -o wide`
 2.  **Check Zookeeper Logs:** `kubectl logs zookeeper-0 -n kafka-cluster -f` (Look for `Authenticated Id` messages and no errors).
 3.  **Check Kafka Logs:** `kubectl logs kafka-0 -n kafka-cluster -f` (Look for `Registered broker ...` and `[KafkaServer id=...] started` messages, and no SSL errors).
 4.  **Test Connectivity (from inside a Kafka pod):**
     ```bash
     kubectl exec -it kafka-0 -n kafka-cluster -- bash
     # Inside the Kafka pod:
     # Test Zookeeper connection
     openssl s_client -connect zookeeper-svc.kafka-cluster.svc.cluster.local:2281 -tls1_2 -cert /mnt/ssl-secrets/kafka-server-tls/tls.crt -key /mnt/ssl-secrets/kafka-server-tls/tls.key -CAfile /mnt/ssl-secrets/intermediate-ca/tls.crt
     # Test Kafka broker listener (self-connect)
     openssl s_client -connect localhost:9093 -tls1_2 -cert /mnt/ssl-secrets/kafka-server-tls/tls.crt -key /mnt/ssl-secrets/kafka-server-tls/tls.key -CAfile /mnt/ssl-secrets/intermediate-ca/tls.crt
     ```
     Both `openssl s_client` commands should show a successful handshake and certificate chain.

 ## 8. Further Steps

 Once your Kafka cluster is stable and secure, you can proceed with:
 *   Deploying Kafka clients to produce and consume messages.
 *   Integrating with other Confluent Platform components (Schema Registry, ksqlDB, Control Center).
 *   Setting up external access if required (e.g., NodePort, LoadBalancer, Ingress).