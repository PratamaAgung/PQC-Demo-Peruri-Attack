#!/bin/bash
# ============================================================
# AWS Infrastructure Setup for PQC Attack Demo
# Stack: ECR + App Runner
# ============================================================

set -e

AWS_REGION="ap-southeast-1"
ECR_REPO="pqc-attack-demo"
APP_RUNNER_SERVICE="pqc-attack-demo"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "╔══════════════════════════════════════════════════════╗"
echo "║  AWS Infrastructure Setup - PQC Attack Demo         ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Region: $AWS_REGION"
echo "Account: $ACCOUNT_ID"
echo ""

# 1. Create ECR Repository
echo "📦 Creating ECR repository..."
aws ecr create-repository \
  --repository-name $ECR_REPO \
  --region $AWS_REGION \
  --image-scanning-configuration scanOnPush=false \
  2>/dev/null || echo "  (already exists)"

ECR_URI="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO"
echo "  ECR URI: $ECR_URI"

# 2. Create IAM Role for App Runner to pull from ECR
echo ""
echo "🔑 Creating App Runner ECR access role..."
TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "build.apprunner.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

aws iam create-role \
  --role-name AppRunnerECRAccess-pqc-demo \
  --assume-role-policy-document "$TRUST_POLICY" \
  2>/dev/null || echo "  (already exists)"

aws iam attach-role-policy \
  --role-name AppRunnerECRAccess-pqc-demo \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSAppRunnerServicePolicyForECRAccess \
  2>/dev/null || echo "  (already attached)"

ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/AppRunnerECRAccess-pqc-demo"
echo "  Role ARN: $ROLE_ARN"

# 3. Build and push initial image
echo ""
echo "🐳 Building and pushing Docker image..."
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ECR_URI

docker build -t $ECR_URI:latest ..
docker push $ECR_URI:latest

# 4. Create App Runner Service
echo ""
echo "🚀 Creating App Runner service..."
SERVICE_ARN=$(aws apprunner create-service \
  --service-name $APP_RUNNER_SERVICE \
  --source-configuration "{
    \"ImageRepository\": {
      \"ImageIdentifier\": \"$ECR_URI:latest\",
      \"ImageRepositoryType\": \"ECR\",
      \"ImageConfiguration\": {
        \"Port\": \"3000\"
      }
    },
    \"AutoDeploymentsEnabled\": false,
    \"AuthenticationConfiguration\": {
      \"AccessRoleArn\": \"$ROLE_ARN\"
    }
  }" \
  --instance-configuration "{
    \"Cpu\": \"0.25 vCPU\",
    \"Memory\": \"0.5 GB\"
  }" \
  --health-check-configuration "{
    \"Protocol\": \"HTTP\",
    \"Path\": \"/\",
    \"Interval\": 10,
    \"Timeout\": 5,
    \"HealthyThreshold\": 1,
    \"UnhealthyThreshold\": 3
  }" \
  --region $AWS_REGION \
  --query 'Service.ServiceArn' --output text)

echo "  Service ARN: $SERVICE_ARN"

# 5. Wait for service to be running
echo ""
echo "⏳ Waiting for service to be ready..."
aws apprunner wait service-running --service-arn $SERVICE_ARN --region $AWS_REGION 2>/dev/null || true

SERVICE_URL=$(aws apprunner describe-service \
  --service-arn $SERVICE_ARN \
  --region $AWS_REGION \
  --query 'Service.ServiceUrl' --output text)

echo ""
echo "════════════════════════════════════════════════════════"
echo "✅ Deployment complete!"
echo ""
echo "🌐 App URL: https://$SERVICE_URL"
echo ""
echo "📝 GitHub Secrets needed:"
echo "  AWS_ACCESS_KEY_ID       = <your-key>"
echo "  AWS_SECRET_ACCESS_KEY   = <your-secret>"
echo "  APP_RUNNER_SERVICE_ARN  = $SERVICE_ARN"
echo "  APP_RUNNER_ECR_ROLE_ARN = $ROLE_ARN"
echo "════════════════════════════════════════════════════════"
