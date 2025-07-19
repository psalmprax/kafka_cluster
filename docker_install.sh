#!/bin/bash

# Script to set up Docker.

set -euo pipefail # Exit on error, unset variable, or pipe failure
# 1. Set up Docker's apt repository.
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# 2. Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

# 3. Install the Docker packages.
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 4. (Optional but Recommended) Configure Docker to use a reliable DNS.
# This can help resolve "Client.Timeout" or "connection reset" errors when pulling images.
echo "Configuring Docker daemon with Google's DNS..."
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}
EOF

echo "Restarting Docker to apply the new configuration..."
sudo systemctl restart docker
