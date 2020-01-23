 # Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 # SPDX-License-Identifier: MIT-0
 #
 # Permission is hereby granted, free of charge, to any person obtaining a copy of this
 # software and associated documentation files (the "Software"), to deal in the Software
 # without restriction, including without limitation the rights to use, copy, modify,
 # merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 # permit persons to whom the Software is furnished to do so.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 # INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 # PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 # HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 # OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 # SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# create KMS key with default cloudtrail policy
resource "aws_kms_key" "Cloudtrail_KMS_CMK" {
  description             = "For CloudTrail - Managed by Terraform"
  deletion_window_in_days = 7
  is_enabled              = true
  enable_key_rotation     = true
  policy                  = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "Key policy created by CloudTrail",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {"AWS": [
                "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
            ]},
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow CloudTrail to encrypt logs",
            "Effect": "Allow",
            "Principal": {"Service": ["cloudtrail.amazonaws.com"]},
            "Action": "kms:GenerateDataKey*",
            "Resource": "*",
            "Condition": {"StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"}}
        },
        {
            "Sid": "Allow CloudTrail to describe key",
            "Effect": "Allow",
            "Principal": {"Service": ["cloudtrail.amazonaws.com"]},
            "Action": "kms:DescribeKey",
            "Resource": "*"
        },
        {
            "Sid": "Allow principals in the account to decrypt log files",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "kms:Decrypt",
                "kms:ReEncryptFrom"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"kms:CallerAccount": "${data.aws_caller_identity.current.account_id}"},
                "StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"}
            }
        },
        {
            "Sid": "Allow alias creation during setup",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "kms:CreateAlias",
            "Resource": "*",
            "Condition": {"StringEquals": {
                "kms:ViaService": "ec2.${var.AWS_REGION}.amazonaws.com",
                "kms:CallerAccount": "${data.aws_caller_identity.current.account_id}"
            }}
        },
        {
            "Sid": "Enable cross account log decryption",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": [
                "kms:Decrypt",
                "kms:ReEncryptFrom"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {"kms:CallerAccount": "${data.aws_caller_identity.current.account_id}"},
                "StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"}
            }
        }
    ]
}
POLICY
}
# Create IAM Password Policy in accordance with CIS 1.5 - 1.11 controls
resource "aws_iam_account_password_policy" "CIS_Password_Policy" {
  minimum_password_length        = 15
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 24
}
# Create S3 Bucket for Access logging
resource "aws_s3_bucket" "Server_Access_Log_S3_Bucket" {
  bucket_prefix = "${var.AccessLog_Bucket_Prefix}"
  acl    = "log-delivery-write"
  versioning {
      enabled = true
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }
}
# create cloudwatch log group for cloudtrail to write to, will be used by 3.x cloudwatch metrics & filters
resource "aws_cloudwatch_log_group" "CIS_CloudWatch_LogsGroup" {
  name = "${var.CIS_CloudTrail_Trail_Name}-log-group"
}
# create IAM role and policy to allow cloudtrail to write logs to cloudwatch
resource "aws_iam_role" "CloudWatch_LogsGroup_IAM_Role" {
  name = "${var.CIS_CloudTrail_Trail_Name}-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "CIS_CloudWatch_LogsGroup_Policy" {
  name   = "${var.CIS_CloudTrail_Trail_Name}-policy"
  role   = "${aws_iam_role.CloudWatch_LogsGroup_IAM_Role.id}"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.arn}*"
    }
  ]
}
EOF
}
# create a CloudTrail trail that is compliant with CIS controls (2.1, 2.2, 2.4)
resource "aws_cloudtrail" "CIS_CloudTrail_Trail" { 
  name                          = "${var.CIS_CloudTrail_Trail_Name}" 
  s3_bucket_name                = "${aws_s3_bucket.CIS_CloudTrail_Logs_S3_Bucket.id}"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = "${aws_kms_key.Cloudtrail_KMS_CMK.arn}"
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.arn}"
  cloud_watch_logs_role_arn     = "${aws_iam_role.CloudWatch_LogsGroup_IAM_Role.arn}"
  depends_on                    = ["aws_s3_bucket_policy.CloudTrail_Bucket_Policy"]
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}
# create bucket and bucket policy for CloudTrail logs, compliant with CIS controls (2.3, 2.6)
resource "aws_s3_bucket" "CIS_CloudTrail_Logs_S3_Bucket" {  
  bucket_prefix = "${var.CloudTrail_Bucket_Prefix}" 
  acl           = "private"
  versioning {
      enabled = true
  }
  logging {
    target_bucket = "${aws_s3_bucket.Server_Access_Log_S3_Bucket.id}"
    target_prefix = "cloudtrailaccess/"
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }
}
resource "aws_s3_bucket_policy" "CloudTrail_Bucket_Policy" {
  bucket = "${aws_s3_bucket.CIS_CloudTrail_Logs_S3_Bucket.id}"
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck20150319",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": "${aws_s3_bucket.CIS_CloudTrail_Logs_S3_Bucket.arn}"
        },
        {
            "Sid": "AWSCloudTrailWrite20150319",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "${aws_s3_bucket.CIS_CloudTrail_Logs_S3_Bucket.arn}/*",
            "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
        }
    ]
}
POLICY
}
# Creates a reference VPC with private and public subnets
resource "aws_vpc" "CIS_VPC" {
  cidr_block           = "${var.CIS_VPC_CIDR}"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags {
      Name = "${var.CIS_VPC_Name_Tag}"
  }
}
# create subnets
resource "aws_subnet" "CIS_Public_Subnets" {
  count                   = "${var.Network_Resource_Count}"
  vpc_id                  = "${aws_vpc.CIS_VPC.id}"
  cidr_block              = "${cidrsubnet(aws_vpc.CIS_VPC.cidr_block, 8, var.Network_Resource_Count + count.index)}"
  availability_zone       = "${data.aws_availability_zones.Available_AZ.names[count.index]}"
  map_public_ip_on_launch = true
  tags {
    Name = "${var.CIS_VPC_Name_Tag}-PUB-Subnet-${element(data.aws_availability_zones.Available_AZ.names, count.index)}"
  }
}
resource "aws_subnet" "CIS_Private_Subnets" {
  count             = "${var.Network_Resource_Count}"
  vpc_id            = "${aws_vpc.CIS_VPC.id}"
  cidr_block        = "${cidrsubnet(aws_vpc.CIS_VPC.cidr_block, 8, count.index)}"
  availability_zone = "${data.aws_availability_zones.Available_AZ.names[count.index]}"
  tags {
    Name = "${var.CIS_VPC_Name_Tag}-PRIV-Subnet-${element(data.aws_availability_zones.Available_AZ.names, count.index)}"
  }
}
# attach IGW
resource "aws_internet_gateway" "CIS_IGW" {
  vpc_id = "${aws_vpc.CIS_VPC.id}"
  tags {
      Name = "${var.CIS_VPC_Name_Tag}-IGW"
  }
}
# create route tables, route table associations and nat gateway
resource "aws_route_table" "CIS_Public_RTB" {
  count  = "${var.Network_Resource_Count}"
  vpc_id = "${aws_vpc.CIS_VPC.id}"
  route {
      cidr_block = "0.0.0.0/0"
      gateway_id = "${aws_internet_gateway.CIS_IGW.id}"
  }
  tags {
    Name = "PUB-RTB-${element(aws_subnet.CIS_Public_Subnets.*.id, count.index)}"
  }
}
resource "aws_eip" "NATGW_Elastic_IPs" {
  count      = "${var.Network_Resource_Count}"
  vpc        = true
  depends_on = ["aws_internet_gateway.CIS_IGW"]
  tags {
    Name = "NAT-Gateway-EIP-${element(aws_subnet.CIS_Public_Subnets.*.id, count.index)}"
  }
}
resource "aws_nat_gateway" "CIS_NAT_Gateway" {
  count         = "${var.Network_Resource_Count}"
  subnet_id     = "${element(aws_subnet.CIS_Public_Subnets.*.id, count.index)}"
  allocation_id = "${element(aws_eip.NATGW_Elastic_IPs.*.id, count.index)}"
  tags {
    Name = "NAT-Gateway-${element(aws_subnet.CIS_Public_Subnets.*.id, count.index)}"
  }
}
resource "aws_route_table" "CIS_Private_RTB" {
  count  = "${var.Network_Resource_Count}"
  vpc_id = "${aws_vpc.CIS_VPC.id}"
  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = "${element(aws_nat_gateway.CIS_NAT_Gateway.*.id, count.index)}"
  }
  tags {
    Name = "PRIV-RTB-${element(aws_subnet.CIS_Private_Subnets.*.id, count.index)}"
  }
}
resource "aws_route_table_association" "Public_Subnet_Association" {
  count          = "${var.Network_Resource_Count}"
  subnet_id      = "${element(aws_subnet.CIS_Public_Subnets.*.id, count.index)}"
  route_table_id = "${element(aws_route_table.CIS_Public_RTB.*.id, count.index)}"
}
resource "aws_route_table_association" "Private_Subnet_Association" {
  count          = "${var.Network_Resource_Count}"
  subnet_id      = "${element(aws_subnet.CIS_Private_Subnets.*.id, count.index)}"
  route_table_id = "${element(aws_route_table.CIS_Private_RTB.*.id, count.index)}"
}
# enable flow logging for the vpc
resource "aws_flow_log" "CIS_VPC_Flow_Log" {
  iam_role_arn    = "${aws_iam_role.CIS_FlowLogs_to_CWL_Role.arn}"
  log_destination = "${aws_cloudwatch_log_group.CIS_FlowLogs_CWL_Group.arn}"
  traffic_type    = "ALL"
  vpc_id          = "${aws_vpc.CIS_VPC.id}"
}
resource "aws_cloudwatch_log_group" "CIS_FlowLogs_CWL_Group" {
  name = "${var.CIS_VPC_Name_Tag}-flowlog-group"
}
# create role & policy to allow VPC to send flow logs to cloudwatch
resource "aws_iam_role" "CIS_FlowLogs_to_CWL_Role" {
  name = "${var.CIS_VPC_Name_Tag}-flowlog-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "CIS_FlowLogs_to_CWL_Role_Policy" {
  name = "${var.CIS_VPC_Name_Tag}-flowlog-policy"
  role = "${aws_iam_role.CIS_FlowLogs_to_CWL_Role.id}"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "${aws_cloudwatch_log_group.CIS_FlowLogs_CWL_Group.arn}*"
    }
  ]
}
EOF
}
# remove rules from default SG
resource "aws_default_security_group" "Default_Security_Group" {
  vpc_id = "${aws_vpc.CIS_VPC.id}"
  tags {
    Name = "DEFAULT_DO_NOT_USE"
  }
}
resource "aws_security_group" "CIS_Linux_SG" {
  name        = "cis-linux-sg"
  description = "Allows 443 in and 22 from trusted IP ranges - Managed by Terraform"
  vpc_id      = "${aws_vpc.CIS_VPC.id}"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${var.TRUSTED_IP}"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
  tags {
      Name = "${var.CIS_VPC_Name_Tag}-Linux-SG"
  }
}