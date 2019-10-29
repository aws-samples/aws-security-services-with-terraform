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


#################################
## waf-conditions.tf Variables ##
#################################
variable "AWS_Security_Blog_Blacklist_IPSet_Name" {
  default = "devsecopsblacklistipset"
}
variable "AWS_Security_Blog_SQLI_Match_Set_Name" {
  default = "devsecopssqlimatchset"
}

############################
## waf-rules.tf Variables ##
############################
variable "AWS_Security_Blog_IP_Blacklist_Rule_Name" {
  default = "devsecopsblacklistrule"
}
variable "AWS_Security_Blog_SQL_Injection_Rule_Name" {
  default = "devsecopssqlirule"
}
variable "AWS_Security_Blog_Blacklist_WACL_Name" {
  default = "devsecopswebacl"
}