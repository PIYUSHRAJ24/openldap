import json
import os

import boto3
import dotenv
from botocore.exceptions import ClientError

dotenv.load_dotenv()
class SecretManager:
    def __init__(self):
        pass
    
    def get_secret():
        try:
            secret_name = os.getenv('secret_name')
            region_name = "ap-south-1"

            # Create a Secrets Manager client
            session = boto3.session.Session()
            client = session.client(
                service_name='secretsmanager',
                region_name=region_name
            )

            try:
                get_secret_value_response = client.get_secret_value(
                    SecretId=secret_name
                )
            except ClientError as e:
                # For a list of exceptions thrown, see
                # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
                # raise e
                return json.dumps({'status':'error', 'error_description':str(e)})

            # Decrypts secret using the associated KMS key.
            secret = get_secret_value_response['SecretString']
            return secret
        except Exception as d:
            return json.dumps({'status':'error', 'error_description':str(d)})
    
    @staticmethod
    def get_mob_app_signing_secret(sec_name, reg_name):
        try:
            secret_name = sec_name
            region_name = reg_name
            # Create a Secrets Manager client
            session = boto3.session.Session()
            client = session.client(service_name='secretsmanager', region_name=region_name)
            try:
                get_secret_value_response = client.get_secret_value(SecretId=secret_name)
            except ClientError as e:
                # For a list of exceptions thrown, see
                # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
                return json.dumps({'status':'error', 'error_description':str(e)})
            # Decrypts secret using the associated KMS key.
            secret = get_secret_value_response['SecretString']
            print(secret)
            return secret
        except Exception as d:
            return json.dumps({'status':'error', 'error_description':str(d)})