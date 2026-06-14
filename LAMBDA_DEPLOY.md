# Pingoo Backend - AWS Lambda Deployment Guide

## Architecture
```
[React Native App] → [API Gateway] → [Lambda] → [MongoDB Atlas]
                                                → [Cloudinary]
                                                → [Redis (optional)]
```

## Prerequisites

1. **AWS Account** (Free Tier works!)
2. **AWS CLI** installed & configured
3. **Node.js 18+**

## Setup Steps

### 1. Install AWS CLI
```bash
brew install awscli
aws configure
# Enter your Access Key, Secret Key, Region (ap-south-1)
```

### 2. Deploy to Lambda
```bash
cd pingoo-backend

# Set your env variables in a .env file first, then:
npx serverless deploy --stage dev
```

This will output your API URL like:
```
https://xxxxxxx.execute-api.ap-south-1.amazonaws.com
```

### 3. Update Frontend API URL
In your frontend `config/` folder, update the BASE_URL to the Lambda URL.

## Cost Breakdown (Free Tier)

| Service | Free Tier | Your Usage (estimate) | Cost |
|---------|-----------|----------------------|------|
| Lambda | 1M requests/month | ~50K requests | **$0** |
| API Gateway | 1M calls/month | ~50K calls | **$0** |
| Data Transfer | 1GB/month | ~500MB | **$0** |

**Total monthly cost with free tier: $0**

After free tier (12 months):
- Lambda: ~$0.20/month for 50K requests
- API Gateway: ~$0.50/month
- **Total: ~$1-2/month** for small user base

## Real-time Chat (Socket.IO)

Lambda doesn't support WebSockets natively. Options:

1. **Keep Render for WebSocket** (free tier) - simplest
2. **AWS API Gateway WebSocket** - serverless WebSockets (add later)
3. **Small EC2/ECS** for Socket.IO only

**Recommended**: Keep your current Render deployment for Socket.IO chat, use Lambda for all REST APIs.

## Commands

```bash
# Deploy to dev
npm run deploy

# Deploy to production
npm run deploy:prod

# Test locally with serverless offline
npm run offline

# Remove deployment
npx serverless remove
```

## Environment Variables

Set these in `serverless.yml` or AWS Console > Lambda > Configuration > Environment Variables:

- MONGODB_URI
- JWT_SECRET
- CLOUDINARY_CLOUD_NAME
- CLOUDINARY_API_KEY
- CLOUDINARY_API_SECRET
- REDIS_URL (optional)
