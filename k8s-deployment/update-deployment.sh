#!/bin/bash

# Script to update SecurePen deployment on EKS

# Set variables
AWS_REGION="us-east-1"
EKS_CLUSTER_NAME="PrimusAllCluster"
NAMESPACE="default"

echo "Starting deployment update to EKS cluster $EKS_CLUSTER_NAME..."

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo "kubectl is not installed. Please install it to deploy to EKS."
    exit 1
fi

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "AWS CLI is not installed. Please install it to deploy to EKS."
    exit 1
fi

# Update kubeconfig to point to the EKS cluster
echo "Updating kubeconfig for EKS cluster..."
aws eks update-kubeconfig --name $EKS_CLUSTER_NAME --region $AWS_REGION

# Apply the updated Kubernetes manifests
echo "Applying updated Kubernetes manifests..."

# Apply the backend service first
echo "Updating backend service..."
kubectl apply -f backend-service.yaml

# Apply the ingress with fixed health check path
echo "Updating ingress with fixed health check path..."
kubectl apply -f ingress.yaml

# Wait for the ingress to be updated
echo "Waiting for ingress update to propagate..."
sleep 30

# Check the status of the ingress
echo "Checking ingress status..."
kubectl get ingress securepen-ingress

# Check the status of the backend service
echo "Checking backend service status..."
kubectl get svc securepen-backend-service

# Check the status of the backend pods
echo "Checking backend pods status..."
kubectl get pods -l app=securepen,tier=backend

# Get the load balancer URL
LB_URL=$(kubectl get ingress securepen-ingress -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "Load Balancer URL: $LB_URL"

# Test the backend health endpoint
echo "Testing backend health endpoint..."
curl -v "http://$LB_URL/api/health"

echo "Deployment update completed. Please allow a few minutes for the changes to fully propagate."
echo "You can access the application at: http://$LB_URL"
