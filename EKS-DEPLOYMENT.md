# SecurePen - EKS Deployment Guide

This guide provides instructions for deploying the SecurePen application to Amazon EKS using GitHub Actions.

## Prerequisites

- AWS Account with appropriate permissions
- GitHub repository with the SecurePen codebase
- EKS cluster named `PrimusAllCluster` already created
- AWS CLI configured locally (for manual deployment testing)

## Repository Structure

```
securepen/
├── backend/                # Backend Node.js application
├── frontend/               # Frontend static files
├── k8s/                    # Kubernetes manifests
│   ├── backend-deployment.yaml
│   ├── backend-service.yaml
│   ├── configmap.yaml
│   ├── frontend-deployment.yaml
│   ├── frontend-service.yaml
│   └── ingress.yaml
├── .github/
│   └── workflows/
│       └── deploy-to-eks.yml  # GitHub Actions workflow
├── Dockerfile.backend      # Backend Docker image definition
├── Dockerfile.frontend     # Frontend Docker image definition
└── docker-compose.yml      # Local development setup
```

## GitHub Actions Setup

1. In your GitHub repository, go to **Settings** > **Secrets and variables** > **Actions**
2. Add the following repository secrets:
   - `AWS_ACCESS_KEY_ID`: Your AWS access key
   - `AWS_SECRET_ACCESS_KEY`: Your AWS secret key

## Deployment Process

### Automated Deployment with GitHub Actions

1. Push your code to the `main` branch or manually trigger the workflow from the Actions tab
2. The GitHub Actions workflow will:
   - Build Docker images for frontend and backend
   - Push images to Amazon ECR
   - Deploy to your EKS cluster using the Kubernetes manifests
   - Output the Load Balancer URL for accessing the application

### Manual Deployment (if needed)

1. Configure AWS CLI and authenticate with ECR:
   ```bash
   aws configure
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <your-aws-account-id>.dkr.ecr.us-east-1.amazonaws.com
   ```

2. Build and push Docker images:
   ```bash
   docker build -t <your-aws-account-id>.dkr.ecr.us-east-1.amazonaws.com/securepen:backend-latest -f Dockerfile.backend .
   docker build -t <your-aws-account-id>.dkr.ecr.us-east-1.amazonaws.com/securepen:frontend-latest -f Dockerfile.frontend .
   
   docker push <your-aws-account-id>.dkr.ecr.us-east-1.amazonaws.com/securepen:backend-latest
   docker push <your-aws-account-id>.dkr.ecr.us-east-1.amazonaws.com/securepen:frontend-latest
   ```

3. Update kubeconfig to point to your EKS cluster:
   ```bash
   aws eks update-kubeconfig --name PrimusAllCluster --region us-east-1
   ```

4. Apply Kubernetes manifests:
   ```bash
   export ECR_REPOSITORY_URI=<your-aws-account-id>.dkr.ecr.us-east-1.amazonaws.com/securepen
   export IMAGE_TAG=latest
   
   # Process and apply each manifest
   for file in k8s/*.yaml; do
     envsubst < $file > processed-$file
     kubectl apply -f processed-$file
   done
   ```

5. Verify deployments:
   ```bash
   kubectl get pods
   kubectl get svc
   ```

6. Get the application URL:
   ```bash
   kubectl get svc securepen-frontend-service -o jsonpath='{.status.loadBalancer.ingress[0].hostname}'
   ```

## Monitoring and Troubleshooting

- Check pod status:
  ```bash
  kubectl get pods
  kubectl describe pod <pod-name>
  kubectl logs <pod-name>
  ```

- Check service status:
  ```bash
  kubectl get svc
  kubectl describe svc securepen-frontend-service
  ```

- Check ingress status:
  ```bash
  kubectl get ingress
  kubectl describe ingress securepen-ingress
  ```

## Cleanup

To remove all resources:
```bash
kubectl delete -f k8s/
```

## Security Considerations

- The JWT secret is stored in a ConfigMap for simplicity. For production, consider using AWS Secrets Manager or Kubernetes Secrets
- Ensure your EKS cluster has appropriate security groups and network policies
- Review IAM permissions to follow the principle of least privilege

## Additional Resources

- [EKS Documentation](https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/)
