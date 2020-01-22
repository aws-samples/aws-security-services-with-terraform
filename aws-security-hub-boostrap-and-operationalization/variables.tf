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

######################
# GLOBAL variables
######################
variable "AWS_REGION" {
  default = "us-east-1"
}
######################
# config.tf variables
######################
variable "Config_Bucket_Prefix" {
  default = "config-bucket"
}
variable "Config_Delivery_Frequency" {
  default = "One_Hour"
}
#################################
# security_services.tf variables
#################################
variable "GuardDuty_Finding_Publishing_Frequency" {
  default = "FIFTEEN_MINUTES"
}
variable "Inspector_Assessment_Rules_Packages_USEast1" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-rExsr2X8", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q", // AWS Security Best Practices
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd", // Network Reachability
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gBONHN9h", // RBA (Runtime Behavior Analytics)
   ]
}
variable "Inspector_Assessment_Rules_Packages_USWest1" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TKgzoVOa", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-xUY8iRqX", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TxmXimXF", // AWS Security Best Practices
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-byoQRFYm", // Network Reachability
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-yeYxlt0x", // RBA (Runtime Behavior Analytics)
  ]
}
variable "Inspector_Assessment_Rules_Packages_EUWest2" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:eu-west-2:146838936955:rulespackage/0-kZGCqcE1", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:eu-west-2:146838936955:rulespackage/0-IeCjwf1W", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:eu-west-2:146838936955:rulespackage/0-XApUiSaP", // AWS Security Best Practices
   "arn:aws:inspector:eu-west-2:146838936955:rulespackage/0-AizSYyNq", // Network Reachability
  ]
}
variable "Inspector_Assessment_Rules_Packages_APSoutheast2" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-D5TGAxiR", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-Vkd2Vxjq", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-asL6HRgN", // AWS Security Best Practices
   "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-FLcuV4Gz", // Network Reachability
  ]
}
#################################
# security_hub_siem.tf variables
#################################
variable "ES_Cognito_User_Pool_Name" {
  default = "elastic-kibanausers"
}
variable "ES_Cognito_User_Pool_Domain_Name" {
  default = ""
}
variable "ES_Cognito_Identity_Pool_Name" {
  default = "elastickibanaidp"
}
variable "ElasticSearch_Domain_Name" {
  default = "securityhub-siem"
}
variable "ElasticSearch_Domain_ES_Version" {
  default = "6.8"
}
variable "ElasticSearch_Domain_Instance_Type" {
  default = "c4.large.elasticsearch"
}
variable "ElasticSearch_Master_Instance_Type" {
  default = "c4.large.elasticsearch"
}
variable "ElasticSearch_Domain_Instance_Count" {
  default = "2"
}
variable "ElasticSearch_Master_Instance_Count" {
  default = "3"
}
variable "Elasticsearch_Trusted_IP" {
  default = ""
}
variable "KDF_Bucket_Prefix" {
  default = "elastic-kdf-logs-bucket"
}
variable "ElasticSearch_Rotation_Period" {
  default = "OneMonth"
}
###########################################
# cis_baseline_infrastructure.tf variables
###########################################
variable "AccessLog_Bucket_Prefix" {
  default = "cis-accesslogs-bucket"
}
variable "CIS_CloudTrail_Trail_Name" {
  default = "cis-cloudtrail"
}
variable "CloudTrail_Bucket_Prefix" {
  default = "cis-cloudtrail-logs-bucket"
}
variable "Network_Resource_Count" {
  default     = 3
  description = "Amount of Network Resources Provisioned e.g. Subnets and Route Tables - Adjust for Regional AZ Count"
}
variable "CIS_VPC_CIDR" {
  default = "10.100.0.0/16"
}
variable "CIS_VPC_Name_Tag" {
  default = "CIS_VPC"
}
#######################
# cis_3-x.tf variables
#######################
variable "CIS_SNS_Prefix" {
  default = "cis-3x-alarms"
}
variable "CIS_Metric_Alarm_Namespace" {
  default = "LogMetrics"
}
############################################
# elasticsearch_siem_extension.tf variables 
############################################
variable "CloudTrail_To_Elastic_Name_Schema" {
  default = "cloudtrail-to-elastic"
}
variable "VPCFlowLogs_To_Elastic_Name_Schema" {
  default = "vpc-flowlogs-to-elastic"
}