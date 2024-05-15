import boto3, base64
import math
from botocore.client import Config
from lib.constants import *
import botocore.exceptions
import os, dotenv

dotenv.load_dotenv()

class Connectors3:
    def __init__(self):
        self.BUCKET = CONFIG['s3_org']['S3_BUCKET_DASHBOARD']
        self.KEY = CONFIG['s3_org']['S3_KEY_DASHBOARD']
        self.SECRET = CONFIG['s3_org']['S3_SECRET_DASHBOARD']
        self.REGION = CONFIG['s3_org']['S3_REGION_DASHBOARD']
        self.ENVIRONMENT = os.getenv('environment')
        

    @staticmethod
    def convert_size(size_bytes):
        try:
            if size_bytes is None:
                return "0B"
            size_bytes = int(size_bytes)
            size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
            i = int(math.floor(math.log(size_bytes, 1024)))
            p = math.pow(1024, i)
            s = round(size_bytes / p, 2)
            return "%s %s" % (s, size_name[i])
        except Exception as e:
            print("convert_size exception " + str(e))
            return "0B"
    
    def file_upload_obj(self, path, file_name, file, content_type='application/pdf'):
        try:
            key = path
            if file_name:
                key = path + file_name
            config = Config(connect_timeout=300, retries={'max_attempts': 10})
            if self.ENVIRONMENT=='BETA' or self.ENVIRONMENT=='PROD':
                s3 = boto3.resource('s3', region_name=self.REGION,config=config)
                
            else:
                s3 = boto3.resource('s3',region_name=self.REGION, aws_access_key_id=self.KEY, aws_secret_access_key=self.SECRET, config=config)
            
            s3.Bucket(self.BUCKET).put_object(Key=key, Body=file,ContentType=content_type)   
            # s3.put_object(Bucket=self.BUCKET, Key=key, Body=file, ContentType=content_type)
            return {STATUS: SUCCESS, MESSAGE: "Files successfully locked"}, 201
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Connectors3:upload_obj:: ' + str(e)}, 400

    def read_obj(self, path, file_name, ops=None):
        try:
            key = path
            if file_name:
                key = path + file_name
            if self.ENVIRONMENT=='BETA' or self.ENVIRONMENT=='PROD':
                s3 = boto3.resource('s3', region_name=self.REGION)
            else:
                s3 = boto3.resource('s3',region_name=self.REGION, aws_access_key_id=self.KEY, aws_secret_access_key=self.SECRET)
               
            obj = s3.Object(self.BUCKET, key)
            body = obj.get()["Body"].read()
            content_type = obj.get()["ContentType"]
            if ops == 'enc':
                return base64.b64encode(body).decode('utf-8'), content_type
            return body, content_type
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'Exception:Connectors3:read_obj:: '+str(e)}, 400

    def set_metadata(self,path, file_name,metadata):
        try:
            key = path
            if file_name:
                key = path + file_name
            if self.ENVIRONMENT=='BETA' or self.ENVIRONMENT=='PROD':
                s3 = boto3.resource('s3', region_name=self.REGION)
            else:
                s3 = boto3.resource('s3',region_name=self.REGION, aws_access_key_id=self.KEY, aws_secret_access_key=self.SECRET)
               
            obj = s3.Object(self.BUCKET, key)
            obj.put(Metadata={'doc_type': metadata})
            return {"status": "success"}, 201
        except botocore.exceptions.ClientError as e:
            code = e.response.get('ResponseMetadata').get('HTTPStatusCode')
            return {"status": "error", "error_description": 'Exception:Connectors3:upload_to_s3:: ' + str(e)}, code

    def get_metadata(self,path, file_name):
        try:
            key = path
            if file_name:
                key = path + file_name
            if self.ENVIRONMENT=='BETA' or self.ENVIRONMENT=='PROD':
                s3 = boto3.resource('s3', region_name=self.REGION)
            else:
                s3 = boto3.resource('s3',region_name=self.REGION, aws_access_key_id=self.KEY, aws_secret_access_key=self.SECRET)
               
            obj = s3.Object(self.BUCKET, key)
            return {"status": "success", "doc_type":obj.metadata }, 200
        except botocore.exceptions.ClientError as e:
            code = e.response.get('ResponseMetadata').get('HTTPStatusCode')
            return {"status": "error", "error_description": 'Exception:Connectors3:upload_to_s3:: ' + str(e)}, code