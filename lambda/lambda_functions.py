import boto3
import os
import hmac
import base64
import hashlib
import json
import email
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

def generate_ssl_materials(event, context):

    #Create ECS client
    ecs_client = boto3.client('ecs')

    #Get environment variables
    cluster = os.environ['ECS_CLUSTER']
    task_definition = os.environ['TASK_DEFINITION']
    security_groups = os.environ['SECURITY_GROUPS'].split(',')
    subnets = os.environ['SUBNETS'].split(',')

    #Run ECS task
    response = ecs_client.run_task(
        cluster=cluster,
        launchType='FARGATE',
        taskDefinition=task_definition,
        count=1,
        networkConfiguration={
            'awsvpcConfiguration': {
                'securityGroups': security_groups,
                'subnets': subnets
            }
        }
    )

    #Get TaskARN
    task_arn = response["tasks"][0]['taskArn']

    #Wait for task to stop
    tasks_stopped_waiter = ecs_client.get_waiter('tasks_stopped')
    tasks_stopped_waiter.wait(
        cluster=cluster,
        tasks=[task_arn]
    )

    #Return success code
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/plain'
        }
    }

def generate_smtp_credential(event, context):

    # Define Helper functions
    # See here for documentation: https://docs.aws.amazon.com/ses/latest/dg/smtp-credentials.html
    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
    def calculate_key(secret_access_key, region):
        #static values
        DATE = "11111111"
        SERVICE = "ses"
        MESSAGE = "SendRawEmail"
        TERMINAL = "aws4_request"
        VERSION = 0x04
        #calculate and return signature.
        signature = sign(("AWS4" + secret_access_key).encode("utf-8"), DATE)
        signature = sign(signature, region)
        signature = sign(signature, SERVICE)
        signature = sign(signature, TERMINAL)
        signature = sign(signature, MESSAGE)
        signature_and_version = bytes([VERSION]) + signature
        smtp_password = base64.b64encode(signature_and_version)
        return smtp_password.decode("utf-8")
    def get_secret(secret_name, region_name):
        # Create a Secrets Manager client
        client = boto3.client("secretsmanager", region_name=region_name)
        response = client.get_secret_value(SecretId=secret_name)
        secret = response["SecretString"]
        return json.loads(secret)  # If the secret is JSON, parse it
    def update_secret(secret_name, new_value, region_name):
        # Create a Secrets Manager client
        client = boto3.client("secretsmanager", region_name=region_name)
        # Update the secret
        response = client.update_secret(
            SecretId=secret_name,
            SecretString=json.dumps(new_value)  # Ensure it's a JSON string
        )
        print(f"Secret {secret_name} updated successfully.")
        return response

    # Read, Calculate and Update Value
    secret = get_secret(os.environ['SECRET_ACCESS_KEY'], os.environ['AWS_REGION'])
    secret['password'] = calculate_key(secret['password'], os.environ['AWS_REGION'])
    response = update_secret(os.environ['SMTP_PASSWORD'], secret, os.environ['AWS_REGION'])

    #Return success code
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/plain'
        }
    }

def send_email(event, context):

    # Pull message id from S3 and create file dictionary
    message_id = event['Records'][0]['ses']['mail']['messageId']
    s3_client = boto3.client('s3', os.environ['AWS_REGION'])
    file = s3_client.get_object(Bucket=os.environ["BUCKET_NAME"], Key=message_id)['Body'].read()

    # Get string message
    string_message = file.decode('utf-8')

    # Create a MIME container.
    msg = MIMEMultipart('alternative')
    sender = os.environ['SOURCE_NAME']
    recipient = os.environ['FORWARD_TO']

    # Parse the email body.
    mail_object = email.message_from_string(string_message)

    # Get original sender for reply-to
    original_sender = mail_object['Return-Path'].replace('<', '').replace('>', '')

    # Get subject from original message
    subject = mail_object['Subject']

    # Construct message object based on whether the original mail object is multipart.
    if mail_object.is_multipart():
        index = string_message.find('Content-Type: multipart/')
        string_body = string_message[index:]
        string_data = 'Subject: ' + subject + '\nTo: ' + sender + '\nreply-to: ' + original_sender + '\n' + string_body
        message = {
            "Source": sender,
            "Destinations": recipient,
            "Data": string_data
        }
    else:
        body = MIMEText(mail_object.get_payload(decode=True), 'UTF-8')
        msg.attach(body)

        # Remove all alphanumeric characters as append an ".eml" extension
        filename = re.sub('[^0-9a-zA-Z]+', '_', subject) + ".eml"

        # Add subject, from and to lines.
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipient
        msg['reply-to'] = mail_object['Return-Path']

        # Create a new MIME object.
        att = MIMEApplication(file, filename)
        att.add_header("Content-Disposition", 'attachment', filename=filename)

        # Attach the file object to the message.
        msg.attach(att)
        message = {
            "Source": sender,
            "Destinations": recipient,
            "Data": msg.as_string()
        }

    ses_client = boto3.client('ses', os.environ['AWS_REGION'])
    response = ses_client.send_raw_email(
        Source=os.environ['SOURCE_NAME'],
        SourceArn=os.environ['SOURCE_ARN'],
        RawMessage={'Data': message['Data']}
    )

    #Return success code
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/plain'
        }
    }

def make_ruleset_active(event, context):
    # Initialize client
    ses_client = boto3.client("ses")

    # Make target rule set active
    response = ses_client.set_active_receipt_rule_set(
        RuleSetName=os.environ["RULE_SET_NAME"]
    )

    #Return success code
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/plain'
        }
    }

def export_from_rds_to_s3(event, context):
    # Initialize client
    client = boto3.client('rds')

    # Start export from RDS to S3
    response = client.start_export_task(
        ExportTaskIdentifier='aurora-to-s3-openemr-export',
        KmsKeyId=os.environ['KMS_KEY_ID'],
        SourceArn=os.environ['DB_CLUSTER_ARN'],
        S3BucketName=os.environ['S3_BUCKET_NAME'],
        IamRoleArn=os.environ['EXPORT_ROLE_ARN']
    )
    return response

def sync_efs_to_s3(event, context):
    #Create ECS client
    ecs_client = boto3.client('ecs')

    #Get environment variables
    cluster = os.environ['ECS_CLUSTER']
    task_definition = os.environ['TASK_DEFINITION']
    security_groups = os.environ['SECURITY_GROUPS'].split(',')
    subnets = os.environ['SUBNETS'].split(',')

    #Run ECS task
    response = ecs_client.run_task(
        cluster=cluster,
        launchType='FARGATE',
        taskDefinition=task_definition,
        count=1,
        networkConfiguration={
            'awsvpcConfiguration': {
                'securityGroups': security_groups,
                'subnets': subnets
            }
        }
    )

    #Get TaskARN
    task_arn = response["tasks"][0]['taskArn']

    #Return TaskARN
    return task_arn