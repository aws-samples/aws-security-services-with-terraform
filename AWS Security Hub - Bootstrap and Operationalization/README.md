## AWS Security Hub - Bootstrap and Operationalization

The Terraform configuration files within this folder are designed to help customers bootstrap and operationalize Security Hub. These templates create CIS AWS Foundations Benchmark-compliant resources such as CloudTrail, VPCs, and S3 Buckets as well as enables core security services along with Security Hub. It will also enable Config for you and create a Kinesis-based delivery pipeline to extract Security Hub findings and send them to Elasticsearch to use as a Security Information & Event Management (SIEM) tool. The configuration files are kept separate to allow users to delete ones that are not needed (i.e. remove config.tf if you already have Config enabled, or removed security_services.tf if they already have GuardDuty, Security Hub and Inspector templates). You can reuse your same `provider.tf` file from the WAF Blog for this solution as well.

### Note on IAM Permissions
You will need to modify the CodeBuild role created for the WAF Blog to allow it to create all of these resources, which include:
- Config
- Security Hub
- GuardDuty
- Inspector
- CloudTrail
- IAM
- KMS
- S3
- Kinesis Data Streams
- Kinesis Data Firehose Delivery Streams
- Elasticsearch Service
- CloudWatch Events
- CloudWatch Logs
- SNS
- VPC
- EC2
If you decide to use an administrator policy you do so at your own risk. If you create this policy you will need a full CRUD of permissions for the above services.

### Terraform Configuration File Inventory
#### config.tf
This config file will create all resources needed to create and enable an AWS Config recorder, if you already have one don't clone / delete this file.

**NOTE** You may still need to go through the Config console and hit save depending on your region.

#### security_services.tf
This config fill will enable a GuardDuty recorder, Security Hub and create an Inspector template and target group that will target all EC2 instances with all assessment templates. These assessment templates are provided via a variable, ensure you specify the correct one. Only us-east-1, us-west-1 and ap-southeast-2 templates are created, you'll need to create your own for other regions, refer to [Amazon Inspector ARNS for Rules Packages](https://docs.aws.amazon.com/inspector/latest/userguide/inspector_rules-arns.html) for more information

#### cis_baseline_infrastructure.tf
This config file will create a multi-region CloudTrail trail along with a S3 bucket, CloudWatch Logs group, IAM Password Policy and Server Access Logging S3 Bucket that are all in compliance with CIS 1.x and 2.x controls. Additionally a VPC with private and public subnets, VPC flow logging and an empty default SG (compliant with CIS 4.3) and all IAM roles and policies needed will be created. This will help you be in compliance with CIS and can serve as a baseline for a new environment being created. The amount of AZs that will be created is dependnet on a variable named `Network_Resource_Count`, ensure you do not specify a value higher than the amount of AZs in your Region (i.e. 6 in us-east-1, 3 in us-east-2, etc.)

#### cis_3-x.tf
This config file will create a SNS topic and all needed metric filters and alarms needed to be in compliance with CIS 3.x controls. This depends on the CloudWatch group that was created in `cis_baseline_infrastructure.tf`, if you decide to not use that file you will need to specify your own CloudWatch Log Group that CloudTrail publishes to.

**NOTE** Due to the way Terraform provisions resources, Email SNS subscriptions are not allowed to be created. You will need to manually subscribe and accept an email subscription to the SNS topic for the Security Hub 3.x controls to be compliant

#### security_hub_siem.tf
This config file will create an ElasticSearch Service domain, Cognito resources (for use for signing into Kibana) and a delivery pipeline that includes a CloudWatch Event Rule, Kinesis Data Stream and Kinesis Data Firehose Delivery Stream to send all findings from Security Hub to Elastic for exploration and analysis in Kibana. All necessary IAM roles and event patterns are created in this configuration file, you will need to modify the Firehose resource if you would rather send logs to S3 or to Splunk.

**NOTE** Do *not* re-apply the state from this config file as it will break Cognito auth into Kibana. Upon creation, the Elasticsearch Service app client will override certain settings that will break your authentication if they are modified.

### Solutions Architecture
This is what will be created if all config files are applied
![Architecture](https://github.com/aws-samples/aws-security-services-with-terraform/blob/master/Architecture.jpg)

## License

This library is licensed under the MIT-0 License. See the LICENSE file.