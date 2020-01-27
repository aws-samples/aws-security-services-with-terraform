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
variable "TRUSTED_IP" {
  description = "Used to populate Elasticsearch SourceIP condition and VPC SSH security group"
  default     = "/32"
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
# US East (N. Virginia)
variable "Inspector_Assessment_Rules_Packages_USEast1" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-rExsr2X8", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q", // AWS Security Best Practices
   "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd", // Network Reachability
   ]
}
# US East (Ohio)
variable "Inspector_Assessment_Rules_Packages_USEast2" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-JnA8Zp85", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-m8r61nnh", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-AxKmMHPX", // AWS Security Best Practices
   "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-cE4kTR30", // Network Reachability
   ]
}
# US West (N. California)
variable "Inspector_Assessment_Rules_Packages_USWest1" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TKgzoVOa", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-xUY8iRqX", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TxmXimXF", // AWS Security Best Practices
   "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-byoQRFYm", // Network Reachability
  ]
}
# US West (Oregon)
variable "Inspector_Assessment_Rules_Packages_USWest2" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-9hgA516p", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-H5hpSawc", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-JJOtZiqQ", // AWS Security Best Practices
   "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-rD1z6dpl", // Network Reachability
   ]
}
# Asia Pacific (Mumbai)
variable "Inspector_Assessment_Rules_Packages_APSouth1" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-LqnJE9dO", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-PSUlX14m", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-fs0IZZBj", // AWS Security Best Practices
   "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-YxKfjFu1", // Network Reachability
  ]
}
# Asia Pacific (Seoul)
variable "Inspector_Assessment_Rules_Packages_APNortheast2" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-PoGHMznc", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-T9srhg1z", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-2WRpmi4n", // AWS Security Best Practices
   "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-s3OmLzhL", // Network Reachability
  ]
}
# Asia Pacific (Sydney)

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
# Asia Pacific (Tokyo)
variable "Inspector_Assessment_Rules_Packages_APNortheast1" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-gHP9oWNT", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-7WNjqgGu", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-bBUQnxMq", // AWS Security Best Practices
   "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-YI95DVd7", // Network Reachability
  ]
}
# Europe (Frankfurt)
variable "Inspector_Assessment_Rules_Packages_EUCentral1" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-wNqHa8M9", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-nZrAVuv8", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-ZujVHEPB", // AWS Security Best Practices
   "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-6yunpJ91", // Network Reachability
  ]
}
# Europe (Ireland)
variable "Inspector_Assessment_Rules_Packages_EUWest1" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-ubA5XvBh", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-sJBhCr0F", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SnojL3Z6", // AWS Security Best Practices
   "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SPzU33xe", // Network Reachability
  ]
}
# Europe (London)
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
# Europe (Stockholm)
variable "Inspector_Assessment_Rules_Packages_EUNorth1" {
  type        = "list"
  description = "All Inspector Assessment Rules for Target All Group"
  default = [
   "arn:aws:inspector:eu-north-1:453420244670:rulespackage/0-IgdgIewd", // NIST Common Vulnerability & Exposures (CVEs)
   "arn:aws:inspector:eu-north-1:453420244670:rulespackage/0-Yn8jlX7f", // CIS OS Security Configuration Benchmark
   "arn:aws:inspector:eu-north-1:453420244670:rulespackage/0-HfBQSbSf", // AWS Security Best Practices
   "arn:aws:inspector:eu-north-1:453420244670:rulespackage/0-52Sn74uu", // Network Reachability
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
variable "ElasticSearch_Domain_Instance_Count" {
  default = "1"
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
  default     = 1
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