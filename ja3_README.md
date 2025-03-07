# JA3 Fingerprint Detection and WAF Automation

## Overview
This Lambda function automates the detection and blocking of potentially malicious TLS fingerprints using JA3 signatures. It processes CloudWatch Logs containing JA3 fingerprints, updates AWS WAF pattern sets, and sends notifications through SNS when new fingerprints are detected.

## Architecture
CloudWatch Logs -> Subscription Filter -> Lambda (ja3.py) -> WAF Pattern Set
-> SNS Topics
-> CloudWatch Metrics

## Pattern


### Prerequisites
- AWS Account with appropriate permissions
- Python 3.9 or higher
- AWS WAF configured with a regex pattern set
- CloudWatch Log Group with WAF logs
- SNS Topic for alerts

## AWS Lambda Env Variables required 

- SNS_TOPIC_ARN=arn:aws:sns:region:account:topic-name
- ENVIRONMENT=production
- WAF_PATTERN_SET_NAME=XXXXXXX
- WAF_PATTERN_SET_ID=pattern-set-id
- WAF_SCOPE=REGIONAL or CLOUDFRONT

### Components
- **CloudWatch Log Group**: Contains WAF logs with JA3 fingerprint information
- **Subscription Filter**: Forwards matching log entries to Lambda 
- **Lambda Function**: Processes JA3 fingerprints and updates WAF
- **WAF Regex Pattern Set**: Stores JA3 fingerprints for blocking
- **SNS Topic**: Receives alerts about new detections and pattern updates
- **CloudWatch Metrics**: Tracks JA3 detection metrics

### Features
- Decodes and processes CloudWatch Logs containing JA3 fingerprints
- Updates WAF regex pattern sets with new JA3 signatures
- Sends detailed alerts via SNS for:
  - New JA3 fingerprint detections
  - WAF pattern set updates
- Publishes metrics to CloudWatch for monitoring
- Handles pagination for WAF pattern set updates
- Includes detailed error handling and logging

### IAM Permission

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "wafv2:GetRegexPatternSet",
                "wafv2:UpdateRegexPatternSet"
            ],
            "Resource": "arn:aws:wafv2:*:*:regional/regexpatternset/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": "arn:aws:sns:*:*:*"  - ARN to your SNS Topic
        },
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData"
            ],
            "Resource": "*"
        }
    ]
}


# Setup Instructions
## Create WAF Pattern Set

- Create a regex pattern set in AWS WAF and Note the pattern set ID and name
## SNS Topic
- Create SNS Topic for alerts and add necessary subscriptions (email, Lambda, etc.)
- Alert is triggered when JA3 fingerprint is detected - you can modify the threshold
- Alert includes request details, client information and WAF action
  
## Configure CloudWatch Logs
- Ensure your  WAF logging is enabled
- Create a Lambda subscription filter and use - Filter Pattern: "{ $.timestamp = * && $.ja3Fingerprint = * }"Target: Lambda function ARN. 
  Remember to remove the double quotes

## Deploy Lambda (ja3.py)
- Fine grained permission

## WAF Update Alert
- Triggered when pattern set is updated based on the threshold set

## Error Handling
### Comprehensive error handling for:
  - CloudWatch Logs decoding
  - WAF pattern set updates
  - SNS publishing
  - Metric publishing

### Detailed error logging to CloudWatch Logs
