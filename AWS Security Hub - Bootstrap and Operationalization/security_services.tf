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

# Enable GuardDuty
resource "aws_guardduty_detector" "GuardDuty_Detector" {
  enable = true
  finding_publishing_frequency = "${var.GuardDuty_Finding_Publishing_Frequency}"
}
# Enable Security Hub
resource "aws_securityhub_account" "Security_Hub_Enabled" {}
# Create Inspector assessment that targets all Instances 
resource "aws_inspector_assessment_target" "Inspector_Assessment_Target_All" {
  name = "target-all-instances"
}
# Change rule package Variables dependent on location
resource "aws_inspector_assessment_template" "Inspector_Assessment_Template" {
  name               = "all-assessments-template"
  duration           = 3600
  target_arn         = "${aws_inspector_assessment_target.Inspector_Assessment_Target_All.arn}"
  rules_package_arns = "${var.Inspector_Assessment_Rules_Packages_APSoutheast2}"
}