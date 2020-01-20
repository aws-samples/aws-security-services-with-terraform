## AWS Security Hub - Bootstrap and Operationalization: Prowler Integration
This module is a Terraform re-write of the AWS Security Blog post on [integrating Prowler with Security Hub](https://aws.amazon.com/blogs/security/use-aws-fargate-prowler-send-security-configuration-findings-about-aws-services-security-hub/). The current solution is hosted on this aws-samples [Github](https://github.com/aws-samples/aws-security-hub-prowler-integrations) repo.

![Architecture](https://github.com/aws-samples/aws-security-hub-prowler-integrations/blob/master/Architecture.jpg)
The integration works as follows:
1.	A time-based CloudWatch Event will start the Fargate task on a schedule
2.	Fargate will pull a Docker image from Amazon Elastic Container Registry (ECR) that contains Prowler and Python scripts used to load an Amazon DynamoDB table.
3.	Prowler scans your AWS infrastructure and writes the scan results to a CSV file
4.	Python scripts convert the CSV to JSON and load DynamoDB with formatted Prowler findings
5.	A DynamoDB stream invokes an AWS Lambda function
6.	Lambda maps Prowler findings into the Amazon Security Finding Format (ASFF) before importing them to Security Hub

## Required IAM Permissions
You will need to modify the CodeBuild role created for the WAF Blog to allow it to create all of these resources, which include the below. You need to give Terraform full create/update/read/delete permissions to be able to apply, update, describe and delete your State.
- CloudWatch Logs
- DynamoDB (and Streams)
- ECS
- ECR
- IAM
- Lambda