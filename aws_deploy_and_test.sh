#!/bin/bash

# AWS CLI must be configured with appropriate credentials and region

# Build Docker image
docker build -t threat-detection-agent .

# Tag Docker image for AWS ECR
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=$(aws configure get region)
ECR_REPO_NAME=threat-detection-agent
ECR_URI=$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO_NAME

# Create ECR repository if not exists
aws ecr describe-repositories --repository-names $ECR_REPO_NAME || aws ecr create-repository --repository-name $ECR_REPO_NAME

# Authenticate Docker to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_URI

# Tag and push image
docker tag threat-detection-agent:latest $ECR_URI:latest
docker push $ECR_URI:latest

# Deploy to AWS ECS (assuming ECS cluster and task definition are pre-configured)
# Update ECS service to use new image
aws ecs update-service --cluster your-ecs-cluster-name --service your-ecs-service-name --force-new-deployment

# Run tests (example: curl health check endpoint)
echo "Waiting for service to stabilize..."
sleep 60
SERVICE_URL="http://your-ecs-service-url/health"
curl -f $SERVICE_URL && echo "Service is healthy" || echo "Service health check failed"

# Additional test scripts can be added here
