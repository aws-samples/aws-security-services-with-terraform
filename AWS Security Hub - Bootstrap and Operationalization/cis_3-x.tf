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

# SNS topic to receive CIS 3.x alerts
# You will need to subscribe via email manually as this is unsupported by terraform
resource "aws_sns_topic" "CIS_Alerts_SNS_Topic" {
  name_prefix = "${var.CIS_SNS_Prefix}"
}
## These next resources are the CloudWatch Log Metric Filter & associated Alarms to be in compliance with CIS Benchmarks
resource "aws_cloudwatch_log_metric_filter" "CIS_Unauthorized_API_Calls_Metric_Filter" {
  name           = "CIS-UnauthorizedAPICalls"
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-UnauthorizedAPICalls"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Unauthorized_API_Calls_CW_Alarm" {
  alarm_name                = "CIS-3.1-UnauthorizedAPICalls"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Unauthorized_API_Calls_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_No_MFA_Console_Signin_Metric_Filter" {
  name           = "CIS-ConsoleSigninWithoutMFA"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-ConsoleSigninWithoutMFA"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "CIS_No_MFA_Console_Signin_CW_Alarm" {
  alarm_name                = "CIS-3.2-ConsoleSigninWithoutMFA"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_No_MFA_Console_Signin_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_log_metric_filter" "CIS_Root_Account_Use_Metric_Filter" {
  name           = "CIS-RootAccountUsage"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-RootAccountUsage"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "CIS_Root_Account_Use_CW_Alarm" {
  alarm_name                = "CIS-3.3-RootAccountUsage"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Root_Account_Use_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_IAM_Policy_Change_Metric_Filter" {
  name           = "CIS-IAMPolicyChanges"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-IAMPolicyChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_IAM_Policy_Change_CW_Alarm" {
  alarm_name                = "CIS-3.4-IAMPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_IAM_Policy_Change_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_CloudTrail_Config_Change_Metric_Filter" {
  name           = "CIS-CloudTrailChanges"
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-CloudTrailChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_CloudTrail_Config_Change_CW_Alarm" {
  alarm_name                = "CIS-3.5-CloudTrailChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_CloudTrail_Config_Change_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Console_AuthN_Failure_Metric_Filter" {
  name           = "CIS-ConsoleAuthenticationFailure"
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-ConsoleAuthenticationFailure"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Console_AuthN_Failure_CW_Alarm" {
  alarm_name                = "CIS-3.6-ConsoleAuthenticationFailure"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Console_AuthN_Failure_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Disable_Or_Delete_CMK_Metric_Filter" {
  name           = "CIS-DisableOrDeleteCMK"
  pattern        = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-DisableOrDeleteCMK"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Disable_Or_Delete_CMK_CW_Alarm" {
  alarm_name                = "CIS-3.7-DisableOrDeleteCMK"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Disable_Or_Delete_CMK_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_S3_Bucket_Policy_Change_Metric_Filter" {
  name           = "CIS-S3BucketPolicyChanges"
  pattern        = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-S3BucketPolicyChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_S3_Bucket_Policy_Change_CW_Alarm" {
  alarm_name                = "CIS-3.8-S3BucketPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_S3_Bucket_Policy_Change_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_AWS_Config_Change_Metric_Filter" {
  name           = "CIS-AWSConfigChanges"
  pattern        = "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-AWSConfigChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_AWS_Config_Change_CW_Alarm" {
  alarm_name                = "CIS-3.9-AWSConfigChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_AWS_Config_Change_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Security_Group_Changes_Metric_Filter" {
  name           = "CIS-SecurityGroupChanges"
  pattern        = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-SecurityGroupChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Security_Group_Changes_CW_Alarm" {
  alarm_name                = "CIS-3.10-SecurityGroupChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Security_Group_Changes_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Network_ACL_Changes_Metric_Filter" {
  name           = "CIS-NetworkACLChanges"
  pattern        = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-NetworkACLChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Network_ACL_Changes_CW_Alarm" {
  alarm_name                = "CIS-3.11-NetworkACLChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Network_ACL_Changes_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Network_Gateway_Changes_Metric_Filter" {
  name           = "CIS-NetworkGatewayChanges"
  pattern        = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-NetworkGatewayChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Network_Gateway_Changes_CW_Alarm" {
  alarm_name                = "CIS-3.12-NetworkGatewayChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Network_Gateway_Changes_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_Route_Table_Changes_Metric_Filter" {
  name           = "CIS-RouteTableChanges"
  pattern        = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-RouteTableChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_Route_Table_Changes_CW_Alarm" {
  alarm_name                = "CIS-3.13-RouteTableChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_Route_Table_Changes_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
resource "aws_cloudwatch_log_metric_filter" "CIS_VPC_Changes_Metric_Filter" {
  name           = "CIS-VPCChanges"
  pattern        = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
  log_group_name = "${aws_cloudwatch_log_group.CIS_CloudWatch_LogsGroup.name}"

  metric_transformation {
    name      = "CIS-VPCChanges"
    namespace = "${var.CIS_Metric_Alarm_Namespace}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "CIS_VPC_Changes_CW_Alarm" {
  alarm_name                = "CIS-3.14-VPCChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "${aws_cloudwatch_log_metric_filter.CIS_VPC_Changes_Metric_Filter.id}"
  namespace                 = "${var.CIS_Metric_Alarm_Namespace}"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to VPC will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = ["${aws_sns_topic.CIS_Alerts_SNS_Topic.arn}"]
  insufficient_data_actions = []
}
