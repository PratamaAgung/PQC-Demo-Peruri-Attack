# Deployment Guide — AWS App Runner

## Architecture

```
Internet → App Runner (HTTPS, auto-TLS) → Container (Node.js :3000)
```

**App Runner** handles:
- Container orchestration (like ECS but simpler)
- Auto-scaling (0 to N instances)
- HTTPS/TLS termination (auto-provisioned certificate)
- Load balancing
- Health checks

> Note: App Runner provides HTTPS with auto-provisioned AWS certificate. No self-signed cert needed — AWS manages TLS automatically.

## Minimal Resource Requirements

| Resource | Spec | Estimated Cost |
|----------|------|----------------|
| App Runner | 0.25 vCPU, 0.5 GB RAM | ~$5/month (idle) |
| ECR | 1 image (~50MB) | ~$0.50/month |
| **Total** | | **~$5.50/month** |

App Runner bills per-second when active. At idle (no traffic), cost is minimal.

## Prerequisites

1. AWS CLI configured (`aws configure`)
2. Docker installed
3. GitHub repo created

## Initial Setup (One-time)

```bash
cd infra
./setup.sh
```

This creates:
- ECR repository
- IAM role for App Runner
- App Runner service
- Pushes initial Docker image

## GitHub Secrets

After `setup.sh` completes, add these to your GitHub repo (Settings → Secrets):

| Secret | Value |
|--------|-------|
| `AWS_ACCESS_KEY_ID` | Your AWS access key |
| `AWS_SECRET_ACCESS_KEY` | Your AWS secret key |
| `APP_RUNNER_SERVICE_ARN` | Output from setup script |
| `APP_RUNNER_ECR_ROLE_ARN` | Output from setup script |

## CI/CD Flow

1. Push to `main` branch
2. GitHub Action builds Docker image
3. Pushes to ECR
4. Updates App Runner service
5. App Runner deploys new container (zero-downtime)

## Manual Deploy

```bash
# Build and push
aws ecr get-login-password --region ap-southeast-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.ap-southeast-1.amazonaws.com
docker build -t <ecr-uri>:latest .
docker push <ecr-uri>:latest

# Trigger deploy
aws apprunner start-deployment --service-arn <service-arn>
```

## Why App Runner over ECS + ALB?

| | ECS + ALB | App Runner |
|--|-----------|------------|
| Setup complexity | High (VPC, subnets, ALB, target groups, task def, service) | Low (single command) |
| TLS/HTTPS | Manual cert via ACM + ALB config | Automatic |
| Cost (demo/low-traffic) | ~$20-30/month (ALB alone is $16/month) | ~$5/month |
| Auto-scaling | Manual config | Built-in |
| Best for | Production workloads | Demos, prototypes, simple apps |

For this demo, App Runner is the most cost-effective and simplest option.
