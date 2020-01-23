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

# Create Config Role
resource "aws_iam_role" "Config_IAM_Role" {
  name = "Terraform-ConfigRole"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}
resource "aws_iam_role_policy_attachment" "Config_Role_Attach_Policy" {
  role       = "${aws_iam_role.Config_IAM_Role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}
# Create Config Recorder Bucket
resource "aws_s3_bucket" "Config_Recorder_Bucket" {
  bucket_prefix = "${var.Config_Bucket_Prefix}"
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
# Default Config bucket access policy
resource "aws_s3_bucket_policy" "Config_Recorder_Bucket_Policy" {
  bucket = "${aws_s3_bucket.Config_Recorder_Bucket.id}"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Allow bucket ACL check",
      "Effect": "Allow",
      "Principal": {
        "Service": [
         "config.amazonaws.com"
        ]
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "${aws_s3_bucket.Config_Recorder_Bucket.arn}",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "true"
        }
      }
    },
    {
      "Sid": "Allow bucket write",
      "Effect": "Allow",
      "Principal": {
        "Service": [
         "config.amazonaws.com"
        ]
      },
      "Action": "s3:PutObject",
      "Resource": "${aws_s3_bucket.Config_Recorder_Bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        },
        "Bool": {
          "aws:SecureTransport": "true"
        }
      }
    },
    {
      "Sid": "Require SSL",
      "Effect": "Deny",
      "Principal": {
        "AWS": "*"
      },
      "Action": "s3:*",
      "Resource": "${aws_s3_bucket.Config_Recorder_Bucket.arn}/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
POLICY
}
# Create & Enable Config Recorder
resource "aws_config_configuration_recorder" "Config_Recorder" {
  role_arn = "${aws_iam_role.Config_IAM_Role.arn}"
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}
resource "aws_config_delivery_channel" "Config_Delivery_Channel" {
  name           = "config-example"
  s3_bucket_name = "${aws_s3_bucket.Config_Recorder_Bucket.bucket}"
  snapshot_delivery_properties {
    delivery_frequency = "${var.Config_Delivery_Frequency}"
  }
  depends_on = ["aws_config_configuration_recorder.Config_Recorder"]
}
resource "aws_config_configuration_recorder_status" "Config_Recorder_Enabled" {
  name       = "${aws_config_configuration_recorder.Config_Recorder.name}"
  is_enabled = true
  depends_on = ["aws_config_delivery_channel.Config_Delivery_Channel"]
}