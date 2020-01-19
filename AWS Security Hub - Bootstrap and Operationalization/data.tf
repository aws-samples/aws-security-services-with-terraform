# Account ID var
data "aws_caller_identity" "current" {}
# Availability Zones var
data "aws_availability_zones" "Available_AZ" {
  state = "available"
}