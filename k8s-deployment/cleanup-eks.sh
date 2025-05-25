#!/bin/bash

# Script to clean up SecurePen resources from EKS cluster

# Set variables
AWS_REGION="us-east-1"
EKS_CLUSTER_NAME="PrimusAllCluster"

echo "Starting cleanup of SecurePen resources from EKS cluster $EKS_CLUSTER_NAME..."

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo "kubectl is not installed. Please install it to clean up EKS resources."
    exit 1
fi

# Update kubeconfig to point to the EKS cluster
echo "Updating kubeconfig for EKS cluster..."
aws eks update-kubeconfig --name $EKS_CLUSTER_NAME --region $AWS_REGION

# Delete all SecurePen resources
echo "Deleting SecurePen resources..."
kubectl delete -f ../k8s/ingress.yaml
kubectl delete -f ../k8s/frontend-service.yaml
kubectl delete -f ../k8s/backend-service.yaml
kubectl delete -f ../k8s/frontend-deployment.yaml
kubectl delete -f ../k8s/backend-deployment.yaml
kubectl delete -f ../k8s/configmap.yaml

echo "Cleanup completed successfully!"
