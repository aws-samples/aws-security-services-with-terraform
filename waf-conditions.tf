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


## Creates a WAF IP Set to be used as a Blacklist for a WAF Rule to add to the Web ACL
## Value can be replaced with a Variable or a Static Value of an EIP within the customer VPC
## to test functionality of the WAF blocking access via IP
resource "aws_waf_ipset" "AWS_Security_Blog_Blacklist_IPSet" {
  name = "${var.AWS_Security_Blog_Blacklist_IPSet_Name}"
  ip_set_descriptors {
    type  = "IPV4"
    value = "10.0.0.99/32"
  }
}
## Creates SQL Injection match condition with multiple filters based on AWS best practices
## reccomendations from the Mitigated OWASP Top 10 with AWS WAF White Paper
resource "aws_waf_sql_injection_match_set" "AWS_Security_Blog_SQLI_Match_Set" {
  name = "${var.AWS_Security_Blog_SQLI_Match_Set_Name}"
  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "QUERY_STRING"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "QUERY_STRING"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "URI"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "URI"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "BODY"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "BODY"
    }
  }  
  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "HEADER"
      data = "Cookie"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "HEADER"
      data = "Cookie"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "HTML_ENTITY_DECODE"
    field_to_match {
      type = "HEADER"
      data = "Authorization"
    }
  }
  sql_injection_match_tuples {
    text_transformation = "URL_DECODE"
    field_to_match {
      type = "HEADER"
      data = "Authorization"
    }
  }
}