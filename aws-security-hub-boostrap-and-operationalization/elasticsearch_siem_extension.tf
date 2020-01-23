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

###################
# CLOUDTRAIL LOGS #
###################
# create an IAM role and policy that allows kinesis data firehose to interact with
# elasticsearch and kinesis data streams
resource "aws_iam_role" "Cloudtrail_Firehose_Delivery_Role" {
  name = "cloudtrail-firehose-siem-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "firehose.amazonaws.com"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId":"${data.aws_caller_identity.current.account_id}"
        }
      }
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "Cloudtrail_Firehose_Delivery_Policy" {
  name   = "cloudtrail-firehose-siem-policy"
  role   = "${aws_iam_role.Cloudtrail_Firehose_Delivery_Role.id}"
  policy = <<EOF
{
    "Version": "2012-10-17",  
    "Statement": [    
        {      
            "Effect": "Allow",      
            "Action": [        
                "s3:AbortMultipartUpload",        
                "s3:GetBucketLocation",        
                "s3:GetObject",        
                "s3:ListBucket",        
                "s3:ListBucketMultipartUploads",
                "s3:HeadBucket",       
                "s3:PutObject"
            ],      
            "Resource": [        
                "${aws_s3_bucket.Kinesis_Failed_Logs_Bucket.arn}",
                "${aws_s3_bucket.Kinesis_Failed_Logs_Bucket.arn}/*"		    
            ]    
        },
        {
           "Effect": "Allow",
           "Action": [
               "kms:Decrypt",
               "kms:GenerateDataKey"
           ],
           "Resource": [
               "*"           
           ]
        },
        {
           "Effect": "Allow",
           "Action": [
               "es:DescribeElasticsearchDomain",
               "es:DescribeElasticsearchDomains",
               "es:DescribeElasticsearchDomainConfig",
               "es:ESHttpPost",
               "es:ESHttpPut"
           ],
          "Resource": [
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/*"
          ]
       },
       {
          "Effect": "Allow",
          "Action": [
              "es:ESHttpGet"
          ],
          "Resource": [
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_all/_settings",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_cluster/stats",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/index-name*/_mapping/type-name",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_nodes",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_nodes/stats",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_nodes/*/stats",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_stats",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/index-name*/_stats"
          ]
       },        
       {
          "Effect": "Allow",
          "Action": [
              "logs:PutLogEvents",
              "logs:CreateLogStream"
          ],
          "Resource": [
              "${aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup.arn}"
          ]
       }
    ]
}
EOF
}
# create kiensis data firehose delivery stream that will read from data stream and send findings to elasticsearch
resource "aws_kinesis_firehose_delivery_stream" "Cloudtrail_Logs_Firehose" {
  name        = "${var.CloudTrail_To_Elastic_Name_Schema}-deliverystream"
  destination = "elasticsearch"
  s3_configuration {
    role_arn           = "${aws_iam_role.Cloudtrail_Firehose_Delivery_Role.arn}"
    bucket_arn         = "${aws_s3_bucket.Kinesis_Failed_Logs_Bucket.arn}"
    prefix             = "cloudtrail-fails"
    buffer_size        = 5
    buffer_interval    = 60
    compression_format = "GZIP"
  }
  elasticsearch_configuration {
    domain_arn = "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}"
    role_arn   = "${aws_iam_role.Cloudtrail_Firehose_Delivery_Role.arn}"
    index_rotation_period = "${var.ElasticSearch_Rotation_Period}"
    index_name = "cloudtrail"
    type_name  = "cloudtrail" ## if you use 7.x elasticsearch version, do not specify this variable
    cloudwatch_logging_options {
        enabled         = true
        log_group_name  = "${aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup.name}"
        log_stream_name = "cloudtrail-fails"
    }
  }
}
# create a cloudwatch log stream for KDF to log errors to
resource "aws_cloudwatch_log_stream" "Cloudtrail_Firehose_Errors_LogStream" {
  name           = "cloudtrail-fails"
  log_group_name = "${aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup.name}"
  depends_on     = ["aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup"]
}
# create a cloudwatch subscription to send cloudtrail logs to lambda
resource "aws_cloudwatch_log_subscription_filter" "Cloudtrail_Logs_Lambda_Subscription" {
  name            = "${var.CloudTrail_To_Elastic_Name_Schema}-subscription"
  log_group_name  = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"
  filter_pattern  = "" # leave blank for CT
  destination_arn = "${aws_lambda_function.Cloudtrail_Lambda_To_Firehose_Function.arn}"
}
# create lambda function & execution role to send cloudtrail logs to kinesis data firehose
resource "aws_iam_role" "Cloudtrail_Lambda_To_Firehose_Role" {
  name = "${var.CloudTrail_To_Elastic_Name_Schema}-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
resource "aws_iam_policy" "Cloudtrail_Lambda_To_Firehose_Policy" {
  name = "${var.CloudTrail_To_Elastic_Name_Schema}-policy"
  path = "/"
  description = "For ${var.CloudTrail_To_Elastic_Name_Schema} gives permission to cloudwatch and kinesis firehose - Managed by Terraform"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    },
    {
      "Action": [
        "firehose:PutRecord"
      ],
      "Resource": "${aws_kinesis_firehose_delivery_stream.Cloudtrail_Logs_Firehose.arn}",
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "Cloudtrail_Lambda_To_Firehose_Policy_Attachment" {
  role = "${aws_iam_role.Cloudtrail_Lambda_To_Firehose_Role.name}"
  policy_arn = "${aws_iam_policy.Cloudtrail_Lambda_To_Firehose_Policy.arn}"
}
resource "aws_lambda_function" "Cloudtrail_Lambda_To_Firehose_Function" {
  filename      = "./cloudwatch-to-firehose.zip"
  description   = "Parses CloudTrail logs from CloudWatch Log Streams and send them to Kinesis Firehose en route to Elasticsearch Service - Managed by Terraform"
  function_name = "${var.CloudTrail_To_Elastic_Name_Schema}-lambda-function"
  role          = "${aws_iam_role.Cloudtrail_Lambda_To_Firehose_Role.arn}"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.8"
  timeout       = 30
  memory_size   = 384
  environment {
    variables = {
      FIREHOSE_TARGET = "${aws_kinesis_firehose_delivery_stream.Cloudtrail_Logs_Firehose.name}"
    }
  }
  depends_on   = ["aws_iam_role_policy_attachment.Cloudtrail_Lambda_To_Firehose_Policy_Attachment","aws_kinesis_firehose_delivery_stream.Cloudtrail_Logs_Firehose"]
}
# give permissions for cloudwatch logs to invoke lambda
resource "aws_lambda_permission" "Cloudtrail_Logs_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.Cloudtrail_Lambda_To_Firehose_Function.function_name}"
  principal     = "logs.amazonaws.com"
}
#################
# VPC FLOW LOGS #
#################
resource "aws_iam_role" "VPCFlowLogs_Firehose_Delivery_Role" {
  name = "${var.VPCFlowLogs_To_Elastic_Name_Schema}-firehose-siem-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "firehose.amazonaws.com"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId":"${data.aws_caller_identity.current.account_id}"
        }
      }
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "VPCFlowLogs_Firehose_Delivery_Policy" {
  name   = "${var.VPCFlowLogs_To_Elastic_Name_Schema}-firehose-siem-policy"
  role   = "${aws_iam_role.VPCFlowLogs_Firehose_Delivery_Role.id}"
  policy = <<EOF
{
    "Version": "2012-10-17",  
    "Statement": [    
        {      
            "Effect": "Allow",      
            "Action": [        
                "s3:AbortMultipartUpload",        
                "s3:GetBucketLocation",        
                "s3:GetObject",        
                "s3:ListBucket",        
                "s3:ListBucketMultipartUploads",
                "s3:HeadBucket",       
                "s3:PutObject"
            ],      
            "Resource": [        
                "${aws_s3_bucket.Kinesis_Failed_Logs_Bucket.arn}",
                "${aws_s3_bucket.Kinesis_Failed_Logs_Bucket.arn}/*"		    
            ]    
        },
        {
           "Effect": "Allow",
           "Action": [
               "kms:Decrypt",
               "kms:GenerateDataKey"
           ],
           "Resource": [
               "*"           
           ]
        },
        {
           "Effect": "Allow",
           "Action": [
               "es:DescribeElasticsearchDomain",
               "es:DescribeElasticsearchDomains",
               "es:DescribeElasticsearchDomainConfig",
               "es:ESHttpPost",
               "es:ESHttpPut"
           ],
          "Resource": [
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/*"
          ]
       },
       {
          "Effect": "Allow",
          "Action": [
              "es:ESHttpGet"
          ],
          "Resource": [
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_all/_settings",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_cluster/stats",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/index-name*/_mapping/type-name",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_nodes",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_nodes/stats",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_nodes/*/stats",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/_stats",
              "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/index-name*/_stats"
          ]
       },        
       {
          "Effect": "Allow",
          "Action": [
              "logs:PutLogEvents",
              "logs:CreateLogStream"
          ],
          "Resource": [
              "${aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup.arn}"
          ]
       }
    ]
}
EOF
}
# create kiensis data firehose delivery stream that will read from data stream and send findings to elasticsearch
resource "aws_kinesis_firehose_delivery_stream" "VPCFlowLogs_Logs_Firehose" {
  name        = "${var.VPCFlowLogs_To_Elastic_Name_Schema}-deliverystream"
  destination = "elasticsearch"
  s3_configuration {
    role_arn           = "${aws_iam_role.VPCFlowLogs_Firehose_Delivery_Role.arn}"
    bucket_arn         = "${aws_s3_bucket.Kinesis_Failed_Logs_Bucket.arn}"
    prefix             = "vpcflowlogs-fails"
    buffer_size        = 5
    buffer_interval    = 60
    compression_format = "GZIP"
  }
  elasticsearch_configuration {
    domain_arn = "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}"
    role_arn   = "${aws_iam_role.VPCFlowLogs_Firehose_Delivery_Role.arn}"
    index_rotation_period = "${var.ElasticSearch_Rotation_Period}"
    index_name = "vpcflowlogs"
    type_name  = "vpcflowlogs" ## if you use 7.x elasticsearch version, do not specify this variable
    cloudwatch_logging_options {
        enabled         = true
        log_group_name  = "${aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup.name}"
        log_stream_name = "vpcflowlogs-fails"
    }
  }
}
# create a cloudwatch log stream for KDF to log errors to
resource "aws_cloudwatch_log_stream" "VPCFlowLogs_Firehose_Errors_LogStream" {
  name           = "vpcflowlogs-fails"
  log_group_name = "${aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup.name}"
  depends_on     = ["aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup"]
}
# create a cloudwatch subscription to send cloudtrail logs to lambda
resource "aws_cloudwatch_log_subscription_filter" "VPCFlowLogs_Logs_Lambda_Subscription" {
  name            = "${var.VPCFlowLogs_To_Elastic_Name_Schema}-subscription"
  log_group_name  = "${aws_cloudwatch_log_group.CIS_FlowLogs_CWL_Group.name}"
  filter_pattern  = "[version, account_id, interface_id, srcaddr != \"-\", dstaddr != \"-\", srcport != \"-\", dstport != \"-\", protocol, packets, bytes, start, end, action, log_status]" # leave blank for CT
  destination_arn = "${aws_lambda_function.VPCFlowLogs_Lambda_To_Firehose_Function.arn}"
}
# create lambda function & execution role to send cloudtrail logs to kinesis data firehose
resource "aws_iam_role" "VPCFlowLogs_Lambda_To_Firehose_Role" {
  name = "${var.VPCFlowLogs_To_Elastic_Name_Schema}-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}
resource "aws_iam_policy" "VPCFlowLogs_Lambda_To_Firehose_Policy" {
  name = "${var.VPCFlowLogs_To_Elastic_Name_Schema}-policy"
  path = "/"
  description = "For ${var.VPCFlowLogs_To_Elastic_Name_Schema} gives permission to cloudwatch and kinesis firehose - Managed by Terraform"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    },
    {
      "Action": [
        "firehose:PutRecord"
      ],
      "Resource": "${aws_kinesis_firehose_delivery_stream.VPCFlowLogs_Logs_Firehose.arn}",
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "VPCFlowLogs_Lambda_To_Firehose_Policy_Attachment" {
  role = "${aws_iam_role.VPCFlowLogs_Lambda_To_Firehose_Role.name}"
  policy_arn = "${aws_iam_policy.VPCFlowLogs_Lambda_To_Firehose_Policy.arn}"
}
resource "aws_lambda_function" "VPCFlowLogs_Lambda_To_Firehose_Function" {
  filename      = "./cloudwatch-to-firehose.zip"
  description   = "Parses VPC Flow logs from CloudWatch Log Streams and send them to Kinesis Firehose en route to Elasticsearch Service - Managed by Terraform"
  function_name = "${var.VPCFlowLogs_To_Elastic_Name_Schema}-lambda-function"
  role          = "${aws_iam_role.VPCFlowLogs_Lambda_To_Firehose_Role.arn}"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.8"
  timeout       = 30
  memory_size   = 384
  environment {
    variables = {
      FIREHOSE_TARGET = "${aws_kinesis_firehose_delivery_stream.VPCFlowLogs_Logs_Firehose.name}"
    }
  }
  depends_on   = ["aws_iam_role_policy_attachment.VPCFlowLogs_Lambda_To_Firehose_Policy_Attachment","aws_kinesis_firehose_delivery_stream.VPCFlowLogs_Logs_Firehose"]
}
# give permissions for cloudwatch logs to invoke lambda
resource "aws_lambda_permission" "VPCFlowLogs_Logs_Lambda_Permission" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.VPCFlowLogs_Lambda_To_Firehose_Function.function_name}"
  principal     = "logs.amazonaws.com"
}
