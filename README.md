# PyAWSResourceLister

Python Library For AWS Resource Listing

# Usage
- Put in requirements.txt: ``git+ssh://git@github.com/ElmecOSS/PyAWSResourceLister.git@main``
- Run ``pip install -r requirements.txt`` to install required packages
- Import library in your program
```
from ElmecAWSResourceLister.resource_lister import ResourceLister

AWSLister = ResourceLister(filter_tag_key, filter_tag_value)
```


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
- Directory Service
- VPC (Subnets)
- codepipeline (Pipelines)
- codebuild (Projects)
- directconnect (Connections)
- dynamodb (NO SQL db)
- fsxs (File System)
- globalaccelerator (Accelerator)
- KMS (Keys)
- mq (Queue)
- elasticache (Cache)
- cognito_user_pool (Cognito User Pool)
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