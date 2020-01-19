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