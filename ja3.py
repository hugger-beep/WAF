import json
import base64
import gzip
import boto3
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from io import BytesIO

class JA3AlertDecoder:
    def __init__(self):
        self.cloudwatch = boto3.client('cloudwatch')
        self.sns = boto3.client('sns')
        self.wafv2 = boto3.client('wafv2')
        
        # Environment variables
        self.sns_topic_arn = os.environ['SNS_TOPIC_ARN']
        self.environment = os.environ.get('ENVIRONMENT', 'production')
        self.pattern_set_name = os.environ['WAF_PATTERN_SET_NAME']
        self.pattern_set_id = os.environ['WAF_PATTERN_SET_ID']
        self.waf_scope = os.environ.get('WAF_SCOPE', 'REGIONAL')  # or CLOUDFRONT

    def decode_event(self, event) -> Optional[List[dict]]:
        """Decode and decompress CloudWatch Logs data"""
        try:
            if 'awslogs' not in event:
                raise ValueError("Missing CloudWatch Logs data")

            decoded_data = base64.b64decode(event['awslogs']['data'])
            with BytesIO(decoded_data) as compressed_data:
                with gzip.GzipFile(fileobj=compressed_data) as decompressor:
                    log_data = json.loads(decompressor.read())
                    
            return log_data.get('logEvents', [])
            
        except Exception as e:
            print(f"Error decoding event: {str(e)}")
            raise

    def process_and_update(self, log_events: List[dict]) -> List[dict]:
        """Process events and update WAF patterns"""
        ja3_fingerprints = set()
        alerts_sent = []
        
        for event in log_events:
            try:
                message = json.loads(event['message'])
                ja3_hash = message.get('ja3Fingerprint')
                
                if not ja3_hash:
                    continue
                
                http_request = message.get('httpRequest', {})
                alert_context = self.build_alert_context(message, http_request, ja3_hash)
                
                # Add to set of fingerprints
                ja3_fingerprints.add(ja3_hash)
                
                # Send alert
                self.send_alert(alert_context)
                
                # Publish metrics
                self.publish_metrics(alert_context)
                
                alerts_sent.append(alert_context)
                
            except json.JSONDecodeError as e:
                print(f"Error parsing message: {str(e)}")
                continue
            except Exception as e:
                print(f"Error processing event: {str(e)}")
                continue

        # Update WAF pattern set with new fingerprints
        if ja3_fingerprints:
            self.update_waf_pattern_set(ja3_fingerprints)
        
        return alerts_sent

    def update_waf_pattern_set(self, new_patterns: Set[str]) -> None:
        """Update WAF regex pattern set with new JA3 fingerprints"""
        try:
            # Get current pattern set
            response = self.wafv2.get_regex_pattern_set(
                Name=self.pattern_set_name,
                Scope=self.waf_scope,
                Id=self.pattern_set_id
            )
            
            current_patterns = {
                pattern['RegexString'] 
                for pattern in response['RegexPatternSet']['RegularExpressionList']
            }
            
            # Combine with new patterns
            updated_patterns = current_patterns.union(new_patterns)
            
            # Update only if there are changes
            if updated_patterns != current_patterns:
                self.wafv2.update_regex_pattern_set(
                    Name=self.pattern_set_name,
                    Scope=self.waf_scope,
                    Id=self.pattern_set_id,
                    RegularExpressionList=[
                        {'RegexString': pattern} 
                        for pattern in updated_patterns
                    ],
                    LockToken=response['LockToken']
                )
                
                print(f"Updated pattern set with {len(new_patterns)} new patterns")
                
                # Send notification about pattern update
                self.send_pattern_update_alert(current_patterns, updated_patterns)
                
        except Exception as e:
            print(f"Error updating WAF pattern set: {str(e)}")
            raise

    def send_pattern_update_alert(self, old_patterns: Set[str], new_patterns: Set[str]) -> None:
        """Send alert about pattern set updates"""
        try:
            added_patterns = new_patterns - old_patterns
            
            message = {
                'alert_type': 'WAF_PATTERN_UPDATE',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'details': {
                    'pattern_set_name': self.pattern_set_name,
                    'pattern_set_id': self.pattern_set_id,
                    'patterns_added': list(added_patterns),
                    'total_patterns': len(new_patterns)
                }
            }

            self.sns.publish(
                TopicArn=self.sns_topic_arn,
                Message=json.dumps(message, indent=2),
                Subject=f"WAF Pattern Set Updated - {len(added_patterns)} new patterns",
                MessageAttributes={
                    'Environment': {
                        'DataType': 'String',
                        'StringValue': self.environment
                    },
                    'AlertType': {
                        'DataType': 'String',
                        'StringValue': 'WAF_UPDATE'
                    }
                }
            )
            
        except Exception as e:
            print(f"Error sending pattern update alert: {str(e)}")

    def build_alert_context(self, message: dict, http_request: dict, ja3_hash: str) -> dict:
        """Build alert context"""
        headers = http_request.get('headers', [])
        headers_dict = {
            h.get('name', '').lower(): h.get('value')
            for h in headers
        }
        
        event_time = datetime.fromtimestamp(
            message.get('timestamp', 0) / 1000,
            timezone.utc
        )
        
        return {
            'detection_time': event_time.isoformat(),
            'ja3_fingerprint': ja3_hash,
            'request_details': {
                'client_ip': http_request.get('clientIp', 'unknown'),
                'country': http_request.get('country', 'unknown'),
                'uri': http_request.get('uri', ''),
                'method': http_request.get('method', ''),
                'protocol': http_request.get('protocol', ''),
                'user_agent': headers_dict.get('user-agent', 'unknown'),
                'host': headers_dict.get('host', 'unknown')
            },
            'waf_details': {
                'action': message.get('action', 'unknown'),
                'terminating_rule': message.get('terminatingRuleId', 'unknown')
            }
        }

    def send_alert(self, alert_context: dict) -> None:
        """Send SNS alert for JA3 detection"""
        try:
            message = {
                'alert_type': 'JA3_FINGERPRINT_DETECTION',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'alert_details': alert_context
            }

            self.sns.publish(
                TopicArn=self.sns_topic_arn,
                Message=json.dumps(message, indent=2),
                Subject=f"JA3 Detection - {alert_context['ja3_fingerprint'][:8]}",
                MessageAttributes={
                    'Environment': {
                        'DataType': 'String',
                        'StringValue': self.environment
                    },
                    'AlertType': {
                        'DataType': 'String',
                        'StringValue': 'JA3_DETECTION'
                    }
                }
            )
            
        except Exception as e:
            print(f"Error sending alert: {str(e)}")
            raise

    def publish_metrics(self, alert_context: dict) -> None:
        """Publish CloudWatch metrics"""
        try:
            timestamp = datetime.now(timezone.utc)
            
            self.cloudwatch.put_metric_data(
                Namespace='WAF/JA3Detections',
                MetricData=[
                    {
                        'MetricName': 'JA3Detection',
                        'Value': 1,
                        'Unit': 'Count',
                        'Timestamp': timestamp,
                        'Dimensions': [
                            {
                                'Name': 'JA3Hash',
                                'Value': alert_context['ja3_fingerprint']
                            },
                            {
                                'Name': 'Environment',
                                'Value': self.environment
                            }
                        ]
                    }
                ]
            )
        except Exception as e:
            print(f"Error publishing metrics: {str(e)}")

def lambda_handler(event, context):
    """Lambda handler function"""
    try:
        decoder = JA3AlertDecoder()
        
        # Decode events
        log_events = decoder.decode_event(event)
        if not log_events:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'error': 'No valid log events found'
                })
            }
        
        # Process events and update WAF
        alerts_sent = decoder.process_and_update(log_events)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Successfully processed JA3 detections and updated WAF',
                'alerts_sent': len(alerts_sent)
            }, default=str)
        }
        
    except Exception as e:
        print(f"Error in lambda handler: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }
