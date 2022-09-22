# PyAWSResourceLister

Python Library For AWS Resource Listing

# Supported resources
- EC2 (Instances)
- RDS (Instances/Clusters + DocumentDB)
- ELB (ALB/NLN)
- EFS (File Systems)
- EKS (Clusters)
- ACM (Certificates)
- OpenSearch (Domains)
- S3 (Buckets)
- Lambda (Functions)
- AutoScaling (Groups)
- Storage Gateway
- API Gateway
- WAF (ACLs)
- CloudFront (Distributions)
- ECR (Registries)
- AppStream (Fleets)
- ECS (Clusters)
- Route53 (Hosted Zones)
- SNS (Topic)
- SES (Identities)
- SQS (Queues)

# Key/Value Tags normalization
```
tags = {'Tag1': 'Value1', 'Tag2': 'Value2'}
Tags = [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]
```
For resources:
- EKS
- Lambda
- API Gateway
- AppStream
- SQS
```
Tags = [{'key': 'Tag1', 'value': 'Value1'},{'key': 'Tag2', 'value': 'Value2'}]
Tags = [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]
```
For resource:
- ECS