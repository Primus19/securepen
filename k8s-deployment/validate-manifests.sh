#!/bin/bash

# Script to validate Kubernetes manifests for SecurePen EKS deployment

echo "Validating Kubernetes manifests..."

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo "kubectl is not installed. Please install it to validate manifests."
    exit 1
fi

# Validate each manifest file
for file in /home/ubuntu/securepen/k8s/*.yaml; do
    echo "Validating $file..."
    # Use kubectl to validate the YAML syntax
    kubectl apply --dry-run=client -f $file
    if [ $? -ne 0 ]; then
        echo "Error in $file. Please fix before deploying."
        exit 1
    fi
done

echo "All Kubernetes manifests are valid!"
echo "Ready for deployment to EKS cluster PrimusAllCluster."
