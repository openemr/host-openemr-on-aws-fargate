# OpenEMR on AWS Fargate - Quick Start Guide
### Enterprise-Grade EHR System Starting at $214/month
## Table of Contents
- [Value Proposition](#value-proposition)
- [Architecture](#architecture)
  - [Component Relationships](#component-relationships)
  - [Architectural Elements](#architectural-elements)
- [What You Get](#what-you-get)
- [Costs](#costs)
- [Prerequisites](#prerequisites)
- [Quick Setup (~50 minutes)](#quick-setup-50-minutes)
- [Access OpenEMR](#access-openemr)
- [Clean Up](#clean-up)
- [Need Help?](#need-help)
- [Additional Resources](#additional-resources)

## Value Proposition
Transform your healthcare facility with enterprise-grade EHR system at a fraction of traditional costs:

- **Traditional EHR setup**: $40-50M upfront
- **OpenEMR on AWS**: Starting at $214/month
- **Includes**: HIPAA-eligible architecture, automated scaling, multi-zone availability, and 7-year backup retention
- **Zero infrastructure management required**

## Architecture 
![OpenEMR AWS Fargate Architecture](../docs/Architecture.png)

### Component Relationships
| Component | Purpose | Connects To | Scaling |
|-----------|---------|-------------|----------|
| Application Load Balancer | Traffic distribution & SSL termination | WAF, Fargate Tasks | Auto |
| AWS WAF | Web application firewall | Internet, ALB | Fixed |
| ECS Fargate | OpenEMR application hosting | ALB, EFS, RDS, ElastiCache | Auto |
| Amazon EFS | Shared file storage | Fargate Tasks | Auto |
| Aurora Serverless v2 | MySQL database | Fargate Tasks | Auto |
| ElastiCache Serverless | Redis caching | Fargate Tasks | Auto |
| Secrets Manager | Credential storage | Fargate Tasks | Managed |
| KMS | Encryption key management | All encrypted services | Managed |

### Architectural Elements

**Compute Layer**
- **ECS Fargate**: Serverless container platform running OpenEMR with automatic scaling based on CPU/memory utilization

**Storage Layer**
- **Amazon EFS**: Serverless NFS for shared OpenEMR files, documents, and configurations
- **Aurora Serverless v2**: Auto-scaling MySQL database with multi-AZ deployment for high availability

**Caching Layer**
- **ElastiCache Serverless**: Redis cache for session management and application performance optimization

**Security Layer**
- **AWS WAF**: Protection against common web exploits and bot attacks
- **KMS**: Encryption at rest for all data stores
- **Secrets Manager**: Secure credential rotation and access

**Network Layer**
- **Application Load Balancer**: SSL termination and traffic distribution across availability zones
- **Private Subnets**: Isolated network segments for database and cache resources
- **NAT Gateways**: Secure outbound internet access for private resources 

## What You Get
- A fully managed, HIPAA-eligible OpenEMR installation
- Automatic scaling to handle any workload
- Enterprise security with AWS WAF and encrypted storage
- Automated daily, weekly, and monthly backups with 7-year retention
- High availability across multiple AWS availability zones

## Costs
You'll pay for the AWS resources you use with this architecture but since that will depend on your level of usage we'll compute an estimate of the base cost of this architecture (this will vary from region to region).

Key Assumptions:
- Work week: 40 hours (8 hours/day, 5 days/week)
- Peak hours: 8AM-4PM EST, Monday-Friday (160 hours/month)
- Off-peak hours: All other times (570 hours/month)
- Region: N. Virginia (us-east-1)
- Load Balancer: 25 requests per second

### Calculation
- AWS Fargate: **Note: A minimum of two tasks with 1 vCPU and 2GB of memory running during peak and off-peak hours for this architecture**
  - Peak Hours (160 hours):
    - vCPU: 2 tasks × 1 vCPU × 160 hours × $0.04048 = $12.95
    - Memory: 2 tasks × 2 GB × 160 hours × $0.004445 = $2.84
  - Off-Peak Hours (570 hours):
    - vCPU: 2 tasks × 1 vCPU × 570 hours × $0.04048 = $46.15
    - Memory: 2 tasks × 2 GB × 570 hours × $0.004445 = $10.13
  - Total: $59.10 + $12.98 = **$72.07/month**
- Load Balancer: 25 requests per second
  - $0.0225/hour = 730h * $0.0225 = $16.43/month
  - LCU cost: 1 LCU × $0.008 × 730 hours = $5.84/month
  - Total: $16.43 (Fixed) + $5.84 (LCU) = **$22.27/month**
- 2 NAT Gateways: $0.09/hour = 2 * (730h * $0.045) = **$65.70/month**
- Elasticache Serverless: $0.0084/hour = 730h * $0.0088 = **$6.45/month**
- EFS Costs: Minimum billing is 1GB per mount (2 mounts)
  - Total: 2GB × $0.08 per GB-month = **$0.16/month**
- RDS Aurora Serverless V2: 
  - 160 hours per month × 2 ACUs × $0.12 = $38.40/month - Compute
  - 10GB × $0.10 per GB = $1.00/month - Storage
  - Baseline IO operations: (730 hours × 3,600) × $0.0000002 = $0.53
  - Total: $38.40 + $1.00 + $0.53 = **$39.93/month**
- AWS Backup Costs:
  - Backup Storage Calculation: Daily backups (30 days): 0.005 GB × 30 = 0.15 GB Weekly backups (52 weeks): 0.005 GB × 52 = 0.26 GB Monthly backups (84 months/7 years): 0.005 GB × 84 = 0.42 GB Total backup storage: 0.83 GB
  - Warm storage (first 50TB): $0.05 per GB-month
    - Cost per month: 0.83 GB × $0.05 = $0.0415/month
  - Additional costs:
    - Backup API requests: $0.05 per 1,000 requests
    - 30 daily + 4 weekly + 1 monthly = ~35 backups per month
    - Cost: (35/1000) × $0.05 = $0.00175/month
  - Total AWS Backup Monthly Cost: **$0.05/month**
- 2 Secrets Manager Secrets: **$0.80/month**
- 1 WAF ACL: **$5/month**
- 1 KMS Key: **$1/month**
- **Total base cost: ~$214/month**

This works out to a base cost of $214/month. The true value of this architecture is its ability to rapidly autoscale and support even very large organizations. For smaller organizations you may want to consider looking at some of [OpenEMR's offerings in the AWS Marketplace](https://aws.amazon.com/marketplace/seller-profile?id=bec33905-edcb-4c30-b3ae-e2960a9a5ef4) which are more affordable.

## Prerequisites
1. An AWS Account
2. [AWS CLI](https://docs.aws.amazon.com/cli/) installed and configured
3. Python 3.x installed
4. Node.js and npm installed (required for CDK)
5. [AWS CDK](https://docs.aws.amazon.com/cdk/) installed (`npm install -g aws-cdk`)

*For detailed setup instructions, see [DETAILS.md Instructions section](./DETAILS.md#instructions)*

## Quick Setup (~50 minutes)

1. **Install Dependencies**
   ```bash
   # Create and activate Python virtual environment
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows use: .venv\Scripts\activate.bat
   
   # Install required packages
   pip install -r requirements.txt
   
   # Create required AWS service accounts
   aws iam create-service-linked-role --aws-service-name ecs.amazonaws.com
   aws iam create-service-linked-role --aws-service-name ecs.application-autoscaling.amazonaws.com
   ```

2. **Configure Access**
   - Open `cdk.json`
   - Set `security_group_ip_range_ipv4` to your IP address (e.g., "[IP_ADDRESS]")
   - "203.0.113.131/32" will open it to that ip address (Recommended: use your public IP address)
   - For public access, use "0.0.0.0/0" (not recommended)
   
   *For advanced configuration options, see [DETAILS.md Customizing Architecture Attributes](./DETAILS.md#customizing-architecture-attributes)*

3. **Deploy (~40 minutes)** 
   ```bash
   cdk deploy
   ```

## Access OpenEMR
1. Use the URL provided in the deployment output
2. Login credentials:
   - Username: `admin`
   - Password: Find in AWS Secrets Manager under "Password..."


## Clean Up
When you have completed your testing you can clean up the deployed environment by running:
```bash
   cdk destroy
```
Manual cleanup items:
- AWS Backup Vault

*For information about backup retention and recovery, see [DETAILS.md AWS Backup section](DETAILS.md#how-aws-backup-is-used-in-this-architecture)*

## Need Help?
- [Full documentation in DETAILS.md](DETAILS.md)
- Submit issues on GitHub: https://github.com/openemr/host-openemr-on-aws-fargate
- Join the OpenEMR community: https://community.open-emr.org/

## Additional Resources
- [Detailed Architecture Documentation](DETAILS.md#architecture)
- [Load Testing Results](DETAILS.md#load-testing)
- [Customizing Architecture Attributes](DETAILS.md#customizing-architecture-attributes)
- [Serverless Analytics Environment](DETAILS.md#serverless-analytics-environment)
- [HTTPS Setup Guide](DETAILS.md#enabling-https-for-client-to-load-balancer-communication)
- [DNS Automation](DETAILS.md#automating-dns-setup)
- [Security Best Practices](DETAILS.md#regarding-security)
- [HIPAA Compliance Notes](DETAILS.md#notes-on-hipaa-compliance-in-general)
- [REST and FHIR APIs](DETAILS.md#rest-and-fhir-apis)
- [AWS Backup Configuration](DETAILS.md#how-aws-backup-is-used-in-this-architecture)
- [Database Access via ECS Exec](DETAILS.md#using-ecs-exec)
- [Aurora ML for AWS Bedrock](DETAILS.md#aurora-ml-for-aws-bedrock)
- [AWS Global Accelerator](DETAILS.md#using-aws-global-accelerator)
- [AWS CDK Documentation](https://docs.aws.amazon.com/cdk/)
- [AWS CLI Documentation](https://docs.aws.amazon.com/cli/)