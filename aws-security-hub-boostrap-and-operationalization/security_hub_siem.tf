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

# Create ES Domain with Cognito user pool
# Not all instances support encryption at rest & node-to-node encryption
resource "aws_elasticsearch_domain" "Security_Hub_Elasticsearch_Service" {
  domain_name           = "${var.ElasticSearch_Domain_Name}"
  elasticsearch_version = "${var.ElasticSearch_Domain_ES_Version}"
  cluster_config {
    instance_type       = "${var.ElasticSearch_Domain_Instance_Type}"
    instance_count      = "${var.ElasticSearch_Domain_Instance_Count}"    
  }
  ebs_options {
      ebs_enabled  = true
      volume_type  = "gp2"
      volume_size  = "15"
  }
  encrypt_at_rest {
      enabled = true
  }
  node_to_node_encryption {
      enabled = true
  }
  snapshot_options {
    automated_snapshot_start_hour = 23
  }
  cognito_options {
      enabled          = true
      user_pool_id     = "${aws_cognito_user_pool.ES_Cognito_User_Pool.id}"
      identity_pool_id = "${aws_cognito_identity_pool.ES_Cognito_Identity_Pool.id}"
      role_arn         = "${aws_iam_role.ES_Cognito_Role.arn}"
  }
  depends_on           = ["aws_securityhub_account.Security_Hub_Enabled"]
}
# this elasticsearch access policy will only allow your account and the IP your specify to access it
resource "aws_elasticsearch_domain_policy" "Security_Hub_Elasticsearch_Service_Policy" {
  domain_name = "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.domain_name}"
  access_policies = <<POLICIES
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "es:*",
      "Resource": "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "${var.TRUSTED_IP}"
        }
      }
    }
  ]
}
POLICIES
}
# Create cognito user pool with schema and password policy
resource "aws_cognito_user_pool" "ES_Cognito_User_Pool" {
  name                       = "${var.ES_Cognito_User_Pool_Name}"
  email_verification_subject = "${var.ElasticSearch_Domain_Name} Kibana Device Verification Code"
  email_verification_message = "Please use the following code {####}"
  alias_attributes           = ["email", "preferred_username"]
  auto_verified_attributes   = ["email"]
  admin_create_user_config {
    allow_admin_create_user_only = false
  }
  password_policy {
      minimum_length    = 14
      require_lowercase = true
      require_numbers   = true
      require_symbols   = true
      require_uppercase = true
  }
  schema {
    attribute_data_type      = "String"
    developer_only_attribute = false
    mutable                  = false
    name                     = "email"
    required                 = true
    string_attribute_constraints {
      min_length = 7
      max_length = 64
    }
  }
}
# create user pool domain
resource "aws_cognito_user_pool_domain" "ES_Cognito_User_Pool_Domain" {
  domain       = "${var.ES_Cognito_User_Pool_Domain_Name}"
  user_pool_id = "${aws_cognito_user_pool.ES_Cognito_User_Pool.id}"
}
# create identity pool for Cognito
resource "aws_cognito_identity_pool" "ES_Cognito_Identity_Pool" {
  identity_pool_name               = "${var.ES_Cognito_Identity_Pool_Name}"
  allow_unauthenticated_identities = true # MUST BE TRUE FOR KIBANA TO USE THIS
  lifecycle {
    ignore_changes                 = ["*"]
  }
}
# create unauth & auth IAM roles for Cognito
resource "aws_iam_role" "ES_Identity_Pool_Authenticated_Role" {
  name = "${var.ES_Cognito_Identity_Pool_Name}-authenticated-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.ES_Cognito_Identity_Pool.id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      }
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "ES_Identity_Pool_Authenticated_Policy" {
  name = "${var.ES_Cognito_Identity_Pool_Name}-authenticated-policy"
  role = "${aws_iam_role.ES_Identity_Pool_Authenticated_Role.id}"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "es:ESHttp*",
        "mobileanalytics:PutEvents",
        "cognito-sync:*",
        "cognito-identity:*"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}
EOF
}
resource "aws_iam_role" "ES_Identity_Pool_Unauthenticated_Role" {
  name               = "${var.ES_Cognito_Identity_Pool_Name}-unauthenticated-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.ES_Cognito_Identity_Pool.id}"
        },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "unauthenticated"
        }
      }
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "ES_Identity_Pool_Unauthenticated_Policy" {
  name   = "${var.ES_Cognito_Identity_Pool_Name}-unauthenticated-policy"
  role   = "${aws_iam_role.ES_Identity_Pool_Unauthenticated_Role.id}"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "mobileanalytics:PutEvents",
                "cognito-sync:*"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
EOF
}
resource "aws_cognito_identity_pool_roles_attachment" "ES_ID_Pool_Role_Attachment" {
  identity_pool_id    = "${aws_cognito_identity_pool.ES_Cognito_Identity_Pool.id}"
  roles = {
    "authenticated"   = "${aws_iam_role.ES_Identity_Pool_Authenticated_Role.arn}"
    "unauthenticated" = "${aws_iam_role.ES_Identity_Pool_Unauthenticated_Role.arn}"
  }
}
resource "aws_iam_role" "ES_Cognito_Role" {
  name               = "${var.ElasticSearch_Domain_Name}-cognito-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "ES_Cognito_Policy" {
  name   = "${var.ElasticSearch_Domain_Name}-cognito-policy"
  role   = "${aws_iam_role.ES_Cognito_Role.id}"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cognito-idp:DescribeUserPool",
                "cognito-idp:CreateUserPoolClient",
                "cognito-idp:DeleteUserPoolClient",
                "cognito-idp:DescribeUserPoolClient",
                "cognito-idp:AdminInitiateAuth",
                "cognito-idp:AdminUserGlobalSignOut",
                "cognito-idp:ListUserPoolClients",
                "cognito-identity:DescribeIdentityPool",
                "cognito-identity:UpdateIdentityPool",
                "cognito-identity:SetIdentityPoolRoles",
                "cognito-identity:GetIdentityPoolRoles"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*",
            "Condition": {
                "StringEqualsIfExists": {
                    "iam:PassedToService": "cognito-identity.amazonaws.com"
                }
            }
        }
    ]
}
EOF
}
# create cloudwatch event iam role to invoke kinesis data streams
resource "aws_iam_role" "CWE_Kinesis_Role" {
  name               = "security-hub-to-elasticsearch-event-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}
resource "aws_iam_role_policy" "CWE_Kinesis_Policy" {
  name   = "security-hub-to-elasticsearch-event-policy"
  role   = "${aws_iam_role.CWE_Kinesis_Role.id}"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kinesis:PutRecord",
                "kinesis:PutRecords"
            ],
            "Resource": [
                "${aws_kinesis_stream.Security_Hub_Kinesis_Stream.arn}"
            ]
        }
    ]
}
EOF
}
# create cloudwatch event that will export all findings from security hub
resource "aws_cloudwatch_event_rule" "Security_Hub_To_Elastic" {
  name          = "security-hub-to-elasticsearch"
  description   = "Sends all Security Hub findings to Elasticsearch Service"
  role_arn      = "${aws_iam_role.CWE_Kinesis_Role.arn}"
  event_pattern = <<PATTERN
{
  "source": [
    "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ]
}
PATTERN
}
# create a cloudwatch event target that will send all security hub findings to a kinesis data stream
resource "aws_cloudwatch_event_target" "CWE_KinesisDataStream_Target" {
  rule      = "${aws_cloudwatch_event_rule.Security_Hub_To_Elastic.name}"
  target_id = "SendToKDS"
  arn       = "${aws_kinesis_stream.Security_Hub_Kinesis_Stream.arn}"
}
# create kinesis data stream to write security hub findings to firehose delivery stream
resource "aws_kinesis_stream" "Security_Hub_Kinesis_Stream" {
  name                      = "securityhub-kinesis-stream"
  shard_count               = 5
  retention_period          = 24
  enforce_consumer_deletion = true
  encryption_type           = "KMS"
  kms_key_id                = "alias/aws/kinesis"
}
# create an s3 bucket to receive failed records from kinesis data firehose
resource "aws_s3_bucket" "Kinesis_Failed_Logs_Bucket" {
  bucket_prefix = "${var.KDF_Bucket_Prefix}"
  acl           = "private"
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
  lifecycle_rule {
    enabled = true
    expiration {
      days = 365
    }
    noncurrent_version_expiration {
      days = 365
    }
  }
}
# create an IAM role and policy that allows kinesis data firehose to interact with
# elasticsearch and kinesis data streams
resource "aws_iam_role" "Firehose_Delivery_Role" {
  name = "securityhub-firehose-siem-role"
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
resource "aws_iam_role_policy" "Firehose_Delivery_Policy" {
  name   = "securityhub-firehose-siem-policy"
  role   = "${aws_iam_role.Firehose_Delivery_Role.id}"
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
                "s3:HeadBucket",        
                "s3:ListBucket",        
                "s3:ListBucketMultipartUploads",        
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
              "kinesis:DescribeStream",
              "kinesis:GetShardIterator",
              "kinesis:GetRecords"
          ],
          "Resource": "${aws_kinesis_stream.Security_Hub_Kinesis_Stream.arn}"
       },
       {
          "Effect": "Allow",
          "Action": [
              "logs:PutLogEvents",
              "logs:CreateLogGroup",
              "logs:CreateLogStream"
          ],
          "Resource": [
              "${aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup.arn}*"
          ]
       }
    ]
}
EOF
}
# create kiensis data firehose delivery stream that will read from data stream and send findings to elasticsearch
# will also create an additional cloudwatch log group and log stream for firehose to write error logs to
resource "aws_kinesis_firehose_delivery_stream" "Security_Hub_SIEM_KDF" {
  name        = "securityhub-siem-deliverystream"
  destination = "elasticsearch"
  kinesis_source_configuration {
      kinesis_stream_arn = "${aws_kinesis_stream.Security_Hub_Kinesis_Stream.arn}"
      role_arn           = "${aws_iam_role.Firehose_Delivery_Role.arn}"
    }
  s3_configuration {
    role_arn           = "${aws_iam_role.Firehose_Delivery_Role.arn}"
    bucket_arn         = "${aws_s3_bucket.Kinesis_Failed_Logs_Bucket.arn}"
    buffer_size        = 5
    buffer_interval    = 60
    compression_format = "GZIP"
  }
  elasticsearch_configuration {
    domain_arn            = "${aws_elasticsearch_domain.Security_Hub_Elasticsearch_Service.arn}"
    role_arn              = "${aws_iam_role.Firehose_Delivery_Role.arn}"
    index_rotation_period = "${var.ElasticSearch_Rotation_Period}"
    index_name            = "securityhub-findings"
    type_name             = "ASFF" ## if you use 7.x elasticsearch version, do not specify this variable
    cloudwatch_logging_options {
        enabled         = true
        log_group_name  = "${aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup.name}"
        log_stream_name = "sechub-log-fails"
    }
  }
  depends_on = ["aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup"]
}
resource "aws_cloudwatch_log_group" "Kinesis_Firehose_Errors_LogsGroup" {
  name = "Firehose/errors"
}
resource "aws_cloudwatch_log_stream" "Kinesis_Firehose_Errors_LogStream" {
  name           = "sechub-log-fails"
  log_group_name = "${aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup.name}"
  depends_on     = ["aws_cloudwatch_log_group.Kinesis_Firehose_Errors_LogsGroup"]
}