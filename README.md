# PyAWSResourceLister

Python Library For AWS Resource Listing

# Supported resources
- EC2
- RDS (Instances/Clusters + DocumentDB)
- ELB (ALB/NLN)
- EFS
- EKS
- ACM
- OpenSearch
- S3
- Lambda
- AutoScaling
- Storage Gateway
- API Gateway
- WAF
- CloudFront
- ECR
- AppStream
- ECS

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

```
Tags = [{'key': 'Tag1', 'value': 'Value1'},{'key': 'Tag2', 'value': 'Value2'}]
Tags = [{'Key': 'Tag1', 'Value': 'Value1'},{'Key': 'Tag2', 'Value': 'Value2'}]
```
For resource:
- ECS