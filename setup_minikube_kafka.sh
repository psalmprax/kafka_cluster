#!/bin/bash

# Script to set up Minikube and deploy the Kafka cluster prerequisites.

set -euo pipefail # Exit on error, unset variable, or pipe failure


# --- Configuration ---
MINIKUBE_CPUS=4
MINIKUBE_MEMORY="8192m" # Or "8g"
MINIKUBE_DISK_SIZE="50g"
MINIKUBE_DRIVER="docker" # Or hyperkit, virtualbox, kvm2 - choose what's best for your system
KAFKA_NAMESPACE="kafka-cluster"

# Define base path for your manifests
MANIFEST_BASE_PATH="."
# Path for Root and Intermediate CA cert-manager manifests
CERT_MANAGER_CA_MANIFEST_PATH="${MANIFEST_BASE_PATH}/ca_manifests" # Ensure 01-root-ca.yaml & 02-intermediate-ca.yaml are here

# --- Storage Configuration ---
USE_LOCAL_PATH_PROVISIONER=true # Set to false if you want to use manual 'local-storage' PVs

# --- Helper Functions ---
check_command() {
  if ! command -v "$1" > /dev/null 2>&1; then
    echo "Error: $1 command not found. Please install it and ensure it's in your PATH."
    exit 1
  fi
}

echo "--- Checking prerequisites ---"
check_command "minikube"
check_command "kubectl"
check_command "docker"

# --- Ensure user is in the 'docker' group for the Minikube docker driver ---
if ! getent group docker > /dev/null; then
    echo "Error: The 'docker' group does not exist. Please install Docker correctly."
    echo "Follow the instructions at https://docs.docker.com/engine/install/ubuntu/"
    exit 1
fi

if ! id -nG "$USER" | grep -qw "docker"; then
    echo "User '$USER' is not in the 'docker' group. This is required to use the docker driver."
    echo "Adding user to the 'docker' group. You will need to enter your password."
    sudo usermod -aG docker "$USER" && newgrp docker
    echo "IMPORTANT: Group change will not take effect until you start a new session."
    echo "Please log out and log back in, or run 'newgrp docker' in your terminal and then re-run this script."
    exit 1
fi

echo "--- Starting Minikube ---"
if ! minikube status --format "{{.Host}}" | grep -q "Running"; then
  minikube start --cpus "${MINIKUBE_CPUS}" --memory "${MINIKUBE_MEMORY}" --disk-size "${MINIKUBE_DISK_SIZE}" --driver "${MINIKUBE_DRIVER}"
else
  echo "Minikube is already running."
fi

echo ""
echo "--- Ensuring kubectl context is Minikube ---"
kubectl config use-context minikube

echo ""
echo "--- Enabling Minikube Addons ---"
# Cert-manager is no longer a direct Minikube addon in recent versions.
# We will install it manually.
echo "Installing cert-manager manually..."
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.5/cert-manager.yaml

if [ "$USE_LOCAL_PATH_PROVISIONER" = true ]; then
  echo "Applying local-path-provisioner (creates 'local-path' StorageClass)..."
  kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/v0.0.26/deploy/local-path-storage.yaml
  echo "Important: StatefulSet volumeClaimTemplates should use 'storageClassName: local-path'"
else
  echo "--- Applying 'local-storage' StorageClass (for manual PVs) ---"
  kubectl apply -f "${MANIFEST_BASE_PATH}/storage/01-storageclass-local.yml" -n "${KAFKA_NAMESPACE}"
  echo "Important: If using 'local-storage' StorageClass, you must manually create PersistentVolumes."
  echo "   - Ensure PV paths (e.g., /mnt/disks/ssd1) exist in the Minikube VM."
  echo "   - Customize and apply '${MANIFEST_BASE_PATH}/storage/02-persistentvolume-local-examples.yml'"
fi

echo ""
echo "--- Waiting for cert-manager pods to be ready ---"
kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=cert-manager -n cert-manager --timeout=300s

echo ""
echo "--- Creating Kafka Namespace: ${KAFKA_NAMESPACE} ---"
if kubectl get namespace "${KAFKA_NAMESPACE}" > /dev/null 2>&1; then
  echo "Namespace ${KAFKA_NAMESPACE} already exists."
else
  kubectl create namespace "${KAFKA_NAMESPACE}"
fi

echo ""
echo "--- Applying RBAC (ServiceAccount, Role, RoleBinding) ---"
kubectl apply -f "${MANIFEST_BASE_PATH}/rbac/" -n "${KAFKA_NAMESPACE}"

echo ""
# The actual application of StorageClass is handled by the USE_LOCAL_PATH_PROVISIONER logic above.
echo "--- Applying Cert-Manager Issuers and CA Certificates (3-stage) ---"
# Ensure 01-root-ca.yaml and 02-intermediate-ca.yaml are in CERT_MANAGER_CA_MANIFEST_PATH
kubectl apply -f "${CERT_MANAGER_CA_MANIFEST_PATH}/01-root-ca.yaml" -n "${KAFKA_NAMESPACE}"
echo "Waiting for root-ca-secret to be created (via kafka-root-ca Certificate)..."
kubectl wait --for=condition=Ready certificate/kafka-root-ca -n "${KAFKA_NAMESPACE}" --timeout=120s
  # Verify the Root CA secret has been created
  if ! kubectl get secret root-ca-secret -n "${KAFKA_NAMESPACE}" -o yaml > /dev/null; then
    echo "Error: root-ca-secret was not created successfully."
    exit 1
  else
    echo "root-ca-secret successfully created."
  fi
kubectl apply -f "${CERT_MANAGER_CA_MANIFEST_PATH}/02-intermediate-ca.yaml" -n "${KAFKA_NAMESPACE}"
echo "Waiting for intermediate-ca-secret to be created (via kafka-intermediate-ca Certificate)..."
kubectl wait --for=condition=Ready certificate/kafka-intermediate-ca -n "${KAFKA_NAMESPACE}" --timeout=120s

echo ""
echo "--- Applying Leaf Certificates (Zookeeper and Kafka) ---"
# The Zookeeper cert manifest also contains the intermediate-ca-issuer definition
kubectl apply -f "${MANIFEST_BASE_PATH}/tls_ssl/04-zk-server-cert.yml" -n "${KAFKA_NAMESPACE}"
kubectl apply -f "${MANIFEST_BASE_PATH}/tls_ssl/03-kafka-server-cert.yml" -n "${KAFKA_NAMESPACE}"

echo ""
# Check the intermediate certificate
if ! kubectl get secret intermediate-ca-secret -n "${KAFKA_NAMESPACE}" -o yaml > /dev/null; then
    echo "Error: intermediate-ca-secret was not created successfully."
    exit 1
  else
    echo "intermediate-ca-secret successfully created."
  fi
echo "--- Waiting for leaf certificates to be issued ---"
echo "Checking Zookeeper certificate..."
kubectl wait --for=condition=Ready certificate/zookeeper-server-cert -n "${KAFKA_NAMESPACE}" --timeout=120s
echo "Checking Kafka certificate..."
kubectl wait --for=condition=Ready certificate/kafka-server-certs -n "${KAFKA_NAMESPACE}" --timeout=120s

echo ""
echo "--- Applying ConfigMaps (Zookeeper and Kafka) ---"
kubectl apply -f "${MANIFEST_BASE_PATH}/configmaps/" -n "${KAFKA_NAMESPACE}"

echo ""
echo "--- Applying Password Secrets ---"
# To generate base64 encoded passwords: echo -n 'changeitdev' | base64
# IMPORTANT: Ensure you have created these secret files with actual base64 encoded passwords
# in the ${MANIFEST_BASE_PATH}/secrets/ directory.
kubectl apply -f "${MANIFEST_BASE_PATH}/secrets/" -n "${KAFKA_NAMESPACE}"

# REMOVE or COMMENT OUT these lines for kafka_zkclient_cert.yml
# echo ""
# echo "--- Applying Kafka ZKClient Certificate ---"
# kubectl apply -f "${MANIFEST_BASE_PATH}/tls_ssl/kafka_zkclient_cert.yml" -n "${KAFKA_NAMESPACE}"
# echo "Waiting for Kafka ZKClient certificate to be issued..."
# kubectl wait --for=condition=Ready certificate/kafka-zkclient-cert -n "${KAFKA_NAMESPACE}" --timeout=120s

echo ""
echo "--- Applying Zookeeper and Kafka Services ---"
kubectl apply -f "${MANIFEST_BASE_PATH}/services/" -n "${KAFKA_NAMESPACE}"

echo ""
echo "--- Applying Zookeeper and Kafka StatefulSets ---"
kubectl apply -f "${MANIFEST_BASE_PATH}/statefulsets/" -n "${KAFKA_NAMESPACE}"


echo ""
echo "--- Deployment of ZK and Kafka StatefulSets initiated ---"
echo "Monitor pod status: kubectl get pods -n ${KAFKA_NAMESPACE} -w"
echo "Check logs if pods are not starting correctly: kubectl logs <pod-name> -n ${KAFKA_NAMESPACE} [-c <container-name>] [-f]"
echo ""
echo "================================================"
echo "            NEXT STEPS & VERIFICATION           "
echo "================================================"
echo "1. Verify all resources: kubectl get all,secrets,certificates,pvc -n ${KAFKA_NAMESPACE}"
echo "2. Check certificate status: kubectl get certificates,certificaterequests -n ${KAFKA_NAMESPACE}"
echo ""
echo "If using manual 'local-storage' PVs (USE_LOCAL_PATH_PROVISIONER=false) and PVCs are not bound:"
echo "   - SSH into Minikube: minikube ssh"
echo "   - Create the directories for your PVs (e.g., sudo mkdir -p /mnt/disks/ssd1 && sudo chmod 777 /mnt/disks/ssd1)"
echo "   - Customize and apply '${MANIFEST_BASE_PATH}/storage/02-persistentvolume-local-examples.yml'"
echo ""
echo "Once Zookeeper and Kafka pods are running and ready, proceed to deploy:"
echo "   - Schema Registry, ksqlDB, Control Center, etc."


```

# **How to use this script:**

# 1.  **Save the script:** Save the content above to a file named `setup_minikube_kafka.sh` in your `/home/psalmprax/DEVELOPMENT_ENV/kafka_cluster/` directory (or any preferred location).
# 2.  **Make it executable:** `chmod +x /home/psalmprax/DEVELOPMENT_ENV/kafka_cluster/setup_minikube_kafka.sh`
# 3.  **Adjust Paths (CRITICAL):**
#    *   The `CERT_MANAGER_MANIFEST_PATH` variable assumes your `/manifests/01-root-ca.yaml` and `/manifests/02-intermediate-ca.yaml` are in a directory named `manifests` at the same level you run the script from, or you need to change it to an absolute path (e.g., `/home/psalmprax/DEVELOPMENT_ENV/kafka_cluster/manifests_from_previous_step/`). **Please ensure this path is correct.**
# 4.  **Review Storage Options:**
#    *   The script defaults to applying the `local-path-provisioner`. If you use this, your StatefulSet's `volumeClaimTemplates` should use `storageClassName: local-path`.
#    *   If you intend to use your manually defined `local-storage` `StorageClass` and `PersistentVolume`s, you'll need to:
#        *   Comment out the `local-path-provisioner` `kubectl apply` line.
#        *   Ensure the `kubectl apply -f "${MANIFEST_BASE_PATH}/storage/01-storageclass-local.yml"` line is active.
#        *   Follow the instructions in the script's output to SSH into Minikube, create the necessary directories on the Minikube VM, and then customize and apply your `02-persistentvolume-local-examples.yml`.
# 5.  **Run the script:** `./setup_minikube_kafka.sh`

# This script automates the initial Minikube setup and deployment of your foundational Kubernetes resources. After it completes, you'll proceed to deploy your Zookeeper and Kafka StatefulSets, followed by other components.
