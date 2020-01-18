## AWS Security Hub - Bootstrap and Operationalization
![Architecture](https://github.com/aws-samples/aws-security-services-with-terraform/blob/master/AWS%20Security%20Hub%20-%20Bootstrap%20and%20Operationalization/Terraform%20Security%20Hub%20Operationalization.jpg)

The Terraform configuration files within this folder are designed to help customers bootstrap and operationalize Security Hub by enabling downstream services (Config, GuardDuty, Inspector), creating resources that are compliant with AWS CIS Foundations Benchmark controls and extending Security Hub via CloudWatch and Kinesis by consuming all findings into Elasticsearch Service and using Kibana as a Security Information & Event Management (SIEM) tool. All Terraform config files are created seperately to offer modularity (though all variables are within `variables.tf`) if you already have certain resources deployed, or you wanted to craft your own Terraform config files. You can reuse your same `provider.tf` file from the WAF Blog for this solution as well to retain your state in your remote backend.

## Required IAM Permissions
You will need to modify the CodeBuild role created for the WAF Blog to allow it to create all of these resources, which include:
- CloudWatch Events
- CloudWatch Logs
- CloudTrail
- Config
- Cognito
- EC2
- Elasticsearch Service
- GuardDuty
- IAM
- Inspector
- Kinesis Data Streams
- Kinesis Data Firehose
- KMS
- S3
- SNS
- VPC

## Terraform Configuration File Inventory
### config.tf
This config file will create all resources needed to create and enable an AWS Config recorder, if you already have one don't clone / delete this file.

**NOTE** You may still need to go through the Config console and hit save depending on your region.

### security_services.tf
This config fill will enable a GuardDuty recorder, Security Hub and create an Inspector template and target group that will target all EC2 instances with all assessment templates. These assessment templates are provided via a variable, ensure you specify the correct one. Only us-east-1, us-west-1 and ap-southeast-2 templates are created, you'll need to create your own for other regions, refer to [Amazon Inspector ARNS for Rules Packages](https://docs.aws.amazon.com/inspector/latest/userguide/inspector_rules-arns.html) for more information

**NOTE** Depending on the timing of your resources being created by Terraform, Config and Security Hub (if using both `config.tf` and `security_services.tf`), the Security Hub Service-Linked Rules (SLRs) for Config used for the CIS AWS Foundations Benchmark controls may not created. To remediate this, disable the compliance standard and re-enable it within Security Hub. Don't forget to turn off controls that are not relevant to you.

### cis_baseline_infrastructure.tf
This config file will create a multi-region CloudTrail trail along with a S3 bucket, CloudWatch Logs group, IAM Password Policy and Server Access Logging S3 Bucket that are all in compliance with CIS 1.x and 2.x controls. Additionally a VPC with private and public subnets, VPC flow logging and an empty default SG (compliant with CIS 4.3) and all IAM roles and policies needed will be created. This will help you be in compliance with CIS and can serve as a baseline for a new environment being created. The amount of AZs that will be created is dependnet on a variable named `Network_Resource_Count`, ensure you do not specify a value higher than the amount of AZs in your Region (i.e. 6 in us-east-1, 3 in us-east-2, etc.)

### cis_3-x.tf
This config file will create a SNS topic and all needed metric filters and alarms needed to be in compliance with CIS 3.x controls. This depends on the CloudWatch group that was created in `cis_baseline_infrastructure.tf`, if you decide to not use that file you will need to specify your own CloudWatch Log Group that CloudTrail publishes to.

**NOTE** Due to the way Terraform provisions resources, Email SNS subscriptions are not allowed to be created. You will need to manually subscribe and accept an email subscription to the SNS topic for the Security Hub 3.x controls to be compliant

### security_hub_siem.tf
This config file will create an ElasticSearch Service domain, Cognito resources (for use for signing into Kibana) and a delivery pipeline that includes a CloudWatch Event Rule, Kinesis Data Stream and Kinesis Data Firehose Delivery Stream to send all findings from Security Hub to Elastic for exploration and analysis in Kibana. All necessary IAM roles and event patterns are created in this configuration file, you will need to modify the Firehose resource if you would rather send logs to S3 or to Splunk.

**NOTE** Do *not* re-apply the state from this config file as it will break Cognito auth into Kibana. Upon creation, the Elasticsearch Service app client will override certain settings that will break your authentication if they are modified.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.s