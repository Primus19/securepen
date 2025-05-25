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

# Process and apply each manifest
echo "Applying Kubernetes manifests..."
for file in ../k8s/*.yaml; do
    echo "Processing $file..."
    envsubst < $file > processed-$(basename $file)
    kubectl apply -f processed-$(basename $file)
done

# Wait for deployments to be ready
echo "Waiting for deployments to be ready..."
kubectl rollout status deployment/securepen-backend
kubectl rollout status deployment/securepen-frontend

# Get the load balancer URL
echo "Deployment completed successfully!"
echo "Load Balancer URL: $(kubectl get svc securepen-frontend-service -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')"
echo "Please allow a few minutes for the DNS to propagate and the application to be fully available."
