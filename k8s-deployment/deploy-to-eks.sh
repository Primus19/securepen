#!/bin/bash

# Script to deploy SecurePen to EKS cluster

# Set variables
AWS_REGION="us-east-1"
EKS_CLUSTER_NAME="PrimusAllCluster"
ECR_REPOSITORY_NAME="securepen"
IMAGE_TAG="latest"

echo "Starting deployment to EKS cluster $EKS_CLUSTER_NAME..."

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
    echo "AWS CLI is not installed. Please install it to deploy to EKS."
    exit 1
fi

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo "kubectl is not installed. Please install it to deploy to EKS."
    exit 1
fi

# Check if envsubst is installed
if ! command -v envsubst &> /dev/null; then
    echo "envsubst is not installed. Installing gettext package..."
    sudo apt-get update && sudo apt-get install -y gettext-base
fi

# Update kubeconfig to point to the EKS cluster
echo "Updating kubeconfig for EKS cluster..."
aws eks update-kubeconfig --name $EKS_CLUSTER_NAME --region $AWS_REGION

# Get ECR repository URI
ECR_REPOSITORY_URI=$(aws ecr describe-repositories --repository-names $ECR_REPOSITORY_NAME --query "repositories[0].repositoryUri" --output text 2>/dev/null)

if [ -z "$ECR_REPOSITORY_URI" ]; then
    echo "Creating ECR repository $ECR_REPOSITORY_NAME..."
    ECR_REPOSITORY_URI=$(aws ecr create-repository --repository-name $ECR_REPOSITORY_NAME --query "repository.repositoryUri" --output text)
fi

echo "ECR Repository URI: $ECR_REPOSITORY_URI"

# Export variables for envsubst
export ECR_REPOSITORY_URI
export IMAGE_TAG

# Create processed directory
mkdir -p processed-k8s

# Process and apply each manifest
echo "Applying Kubernetes manifests..."
for file in ../k8s/*.yaml; do
    echo "Processing $file..."
    envsubst < $file > processed-k8s/$(basename $file)
    kubectl apply -f processed-k8s/$(basename $file)
done

# Wait for deployments to be ready with increased timeout
echo "Waiting for backend deployment (this may take a few minutes)..."
kubectl rollout status deployment/securepen-backend --timeout=600s

echo "Waiting for frontend deployment..."
kubectl rollout status deployment/securepen-frontend --timeout=300s

# Get the load balancer URL
LB_URL=$(kubectl get svc securepen-frontend-service -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
echo "Deployment completed successfully!"
echo "Load Balancer URL: $LB_URL"
echo "Please allow a few minutes for the DNS to propagate and the application to be fully available."

# Verify deployment
echo "Verifying deployment..."
echo "Backend pods:"
kubectl get pods -l app=securepen,tier=backend
echo "Frontend pods:"
kubectl get pods -l app=securepen,tier=frontend
echo "Services:"
kubectl get svc -l app=securepen

# Save URL to a file for reference
echo "Load Balancer URL: $LB_URL" > deployment-url.txt
echo "URL saved to deployment-url.txt"
