#!/bin/bash
# ============================================================
# Deploy PQC Attack Demo to ECS (Fargate)
# Prerequisites: ECR repo exists, ECS cluster "default" exists
# ============================================================

set -e

AWS_REGION="ap-southeast-1"
ECR_REPO="pqc-attack-demo"
ECS_CLUSTER="default"
ECS_SERVICE="pqc-attack-demo"
TASK_FAMILY="pqc-attack-demo"
INFRA_ROLE="pqc-demo-ecs-infrastructure-role"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_URI="$ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPO"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  Deploy PQC Attack Demo → ECS Fargate               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Region:  $AWS_REGION"
echo "Account: $ACCOUNT_ID"
echo "Cluster: $ECS_CLUSTER"
echo ""

# 1. Ensure ECR repo exists
echo "📦 Ensuring ECR repository..."
aws ecr create-repository \
  --repository-name $ECR_REPO \
  --region $AWS_REGION 2>/dev/null || echo "  (already exists)"

# 2. Build and push
echo ""
echo "🐳 Building and pushing Docker image..."
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin $ECR_URI

docker build --platform linux/amd64 -t $ECR_URI:latest ..
docker push $ECR_URI:latest

# 3. Create/update task definition
echo ""
echo "📋 Registering task definition..."

TASK_DEF=$(cat <<EOF
{
  "family": "$TASK_FAMILY",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::$ACCOUNT_ID:role/$INFRA_ROLE",
  "containerDefinitions": [
    {
      "name": "app",
      "image": "$ECR_URI:latest",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/$TASK_FAMILY",
          "awslogs-region": "$AWS_REGION",
          "awslogs-stream-prefix": "app",
          "awslogs-create-group": "true"
        }
      }
    }
  ]
}
EOF
)

TASK_ARN=$(aws ecs register-task-definition \
  --cli-input-json "$TASK_DEF" \
  --region $AWS_REGION \
  --query 'taskDefinition.taskDefinitionArn' --output text)

echo "  Task: $TASK_ARN"

# 4. Get default VPC subnets and security group
echo ""
echo "🔍 Getting VPC info..."

VPC_ID=$(aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" \
  --query 'Vpcs[0].VpcId' --output text --region $AWS_REGION)

SUBNETS=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'Subnets[*].SubnetId' --output text --region $AWS_REGION | tr '\t' ',')

# Create security group allowing port 3000
SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=pqc-demo-ecs-sg" "Name=vpc-id,Values=$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text --region $AWS_REGION 2>/dev/null)

if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
  echo "  Creating security group..."
  SG_ID=$(aws ec2 create-security-group \
    --group-name pqc-demo-ecs-sg \
    --description "PQC Demo ECS - allow port 3000" \
    --vpc-id $VPC_ID \
    --region $AWS_REGION \
    --query 'GroupId' --output text)
  
  aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp --port 3000 --cidr 0.0.0.0/0 \
    --region $AWS_REGION
fi

echo "  VPC: $VPC_ID"
echo "  Subnets: $SUBNETS"
echo "  SG: $SG_ID"

# 5. Create or update ECS service
echo ""
echo "🚀 Creating/updating ECS service..."

SERVICE_EXISTS=$(aws ecs describe-services --cluster $ECS_CLUSTER --services $ECS_SERVICE \
  --query 'services[?status==`ACTIVE`].serviceName' --output text --region $AWS_REGION 2>/dev/null)

if [ -z "$SERVICE_EXISTS" ]; then
  echo "  Creating new service..."
  aws ecs create-service \
    --cluster $ECS_CLUSTER \
    --service-name $ECS_SERVICE \
    --task-definition $TASK_ARN \
    --desired-count 1 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$SG_ID],assignPublicIp=ENABLED}" \
    --region $AWS_REGION > /dev/null
else
  echo "  Updating existing service..."
  aws ecs update-service \
    --cluster $ECS_CLUSTER \
    --service $ECS_SERVICE \
    --task-definition $TASK_ARN \
    --force-new-deployment \
    --region $AWS_REGION > /dev/null
fi

# 6. Wait and get public IP
echo ""
echo "⏳ Waiting for task to start..."
sleep 15

TASK_ARN_RUNNING=$(aws ecs list-tasks --cluster $ECS_CLUSTER --service-name $ECS_SERVICE \
  --query 'taskArns[0]' --output text --region $AWS_REGION)

if [ "$TASK_ARN_RUNNING" != "None" ] && [ -n "$TASK_ARN_RUNNING" ]; then
  ENI_ID=$(aws ecs describe-tasks --cluster $ECS_CLUSTER --tasks $TASK_ARN_RUNNING \
    --query 'tasks[0].attachments[0].details[?name==`networkInterfaceId`].value' \
    --output text --region $AWS_REGION)
  
  PUBLIC_IP=$(aws ec2 describe-network-interfaces --network-interface-ids $ENI_ID \
    --query 'NetworkInterfaces[0].Association.PublicIp' --output text --region $AWS_REGION 2>/dev/null)
  
  echo ""
  echo "════════════════════════════════════════════════════════"
  echo "✅ Deployed!"
  echo ""
  echo "🌐 Access: http://$PUBLIC_IP:3000"
  echo ""
  echo "════════════════════════════════════════════════════════"
else
  echo ""
  echo "⏳ Task still starting. Check with:"
  echo "  aws ecs list-tasks --cluster $ECS_CLUSTER --service-name $ECS_SERVICE"
fi

echo ""
echo "📝 Useful commands:"
echo "  # Check task status"
echo "  aws ecs describe-services --cluster $ECS_CLUSTER --services $ECS_SERVICE --query 'services[0].deployments'"
echo ""
echo "  # View logs"
echo "  aws logs tail /ecs/$TASK_FAMILY --follow"
echo ""
echo "  # Get public IP of running task"
echo "  TASK=\$(aws ecs list-tasks --cluster $ECS_CLUSTER --service-name $ECS_SERVICE --query 'taskArns[0]' --output text)"
echo "  ENI=\$(aws ecs describe-tasks --cluster $ECS_CLUSTER --tasks \$TASK --query 'tasks[0].attachments[0].details[?name==\`networkInterfaceId\`].value' --output text)"
echo "  aws ec2 describe-network-interfaces --network-interface-ids \$ENI --query 'NetworkInterfaces[0].Association.PublicIp' --output text"
