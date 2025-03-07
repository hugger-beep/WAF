# JA3 Fingerprint Detection and WAF Automation

## Overview
This Lambda function automates the detection and blocking of potentially malicious TLS fingerprints using JA3 signatures. It processes CloudWatch Logs containing JA3 fingerprints, updates AWS WAF pattern sets, and sends notifications through SNS when new fingerprints are detected.

## Architecture
CloudWatch Logs -> Subscription Filter -> Lambda (ja3.py) -> WAF Pattern Set
-> SNS Topics
-> CloudWatch Metrics

## Pattern
e.g  { $.timestamp = * && $.ja3Fingerprint = * }
{ }

### Prerequisites
- AWS Account with appropriate permissions
- Python 3.9 or higher
- AWS WAF configured with a regex pattern set
- CloudWatch Log Group with WAF logs
- SNS Topic for alerts
  
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
