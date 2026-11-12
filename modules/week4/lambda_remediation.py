import boto3
import os
import json

ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    print("Received event:", json.dumps(event))
    isolation_sg_id = os.environ['ISOLATION_SG_ID']
    
    # Extract instance ID from Security Hub Custom Action or GuardDuty Finding
    instance_id = None
    if 'detail' in event and 'findings' in event['detail']:
        for finding in event['detail']['findings']:
            for resource in finding.get('Resources', []):
                if resource.get('Type') == 'AwsEc2Instance':
                    # Format: arn:aws:ec2:region:account:instance/i-xxxxxxxx
                    instance_id = resource['Id'].split('/')[-1]
                    break
                    
    if instance_id:
        print(f"Isolating compromised EC2 instance: {instance_id}")
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg_id]
        )
        return {
            'statusCode': 200,
            'body': f'Successfully isolated instance {instance_id} into SG {isolation_sg_id}'
        }
    
    return {
        'statusCode': 400,
        'body': 'No EC2 instance found in the finding event.'
    }