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


## Creates an AWS WAF Rule to Blacklist the IP Address specified in the IPSet Condition
resource "aws_waf_rule" "AWS_Security_Blog_IP_Blacklist_Rule" {
  name        = "${var.AWS_Security_Blog_IP_Blacklist_Rule_Name}"
  metric_name = "${var.AWS_Security_Blog_IP_Blacklist_Rule_Name}"
  predicates {
    data_id = "${aws_waf_ipset.AWS_Security_Blog_Blacklist_IPSet.id}"
    negated = false
    type    = "IPMatch"
  }
}
## Creates an AWS WAF Rule matched against Conditions listed in the SQL Injection Condition Match Set
resource "aws_waf_rule" "AWS_Security_Blog_SQL_Injection_Rule" {
  name        = "${var.AWS_Security_Blog_SQL_Injection_Rule_Name}"
  metric_name = "${var.AWS_Security_Blog_SQL_Injection_Rule_Name}"
  predicates{
    data_id = "${aws_waf_sql_injection_match_set.AWS_Security_Blog_SQLI_Match_Set.id}"
    negated = false
    type = "SqlInjectionMatch"
  }
}
## Creates an AWS WAF Web ACL that will Block traffic originiating from the Blacklist, as well as block traffic
## that matches any SQL Injection methods. Logs are sent to a Kinesis Data Firehose for further processing and investigation
resource "aws_waf_web_acl" "AWS_Security_Blog_Blacklist_WACL" {
  name        = "${var.AWS_Security_Blog_Blacklist_WACL_Name}"
  metric_name = "${var.AWS_Security_Blog_Blacklist_WACL_Name}"
  default_action {
    type = "ALLOW"
  }
  rules {
    action {
      type = "BLOCK"
    }
    priority = 1
    rule_id  = "${aws_waf_rule.AWS_Security_Blog_SQL_Injection_Rule.id}"
    type     = "REGULAR"
  }
  rules {
    action {
      type = "BLOCK"
    }
    priority = 2
    rule_id  = "${aws_waf_rule.AWS_Security_Blog_IP_Blacklist_Rule.id}"
    type     = "REGULAR"
  }
}