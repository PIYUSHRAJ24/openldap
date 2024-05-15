import hashlib
import json
import os
import time
from datetime import datetime

import jwt
import pika
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv
from lib.constants import CONFIG, ERROR, ERROR_DES, RESPONSE, STATUS, Errors
from lib.mongolib import MongoLib
from lib.secretsmanager import SecretManager

load_dotenv()
class SignData:    
    def __init__(self, priv_key, user_data, ack_id= None):
        self.priv_key= priv_key
        self.user_data= user_data
        self.ack_id= ack_id
                
    def sign_data(self):
        try:            
            consent_aapid= os.getenv("CONSENT_APPID")
            kid=  hashlib.md5(self.priv_key.encode('utf-8')).hexdigest()            
            iat= int(time.time())
            exp= iat+300
            headers= {"typ": "JWT", "alg": "RS256", "kid": kid}
            payload= {"ack_id": self.ack_id, "app_id": consent_aapid, "sub": self.user_data.get("locker_id"), "iat": iat, "nbf": iat, "exp": exp}
            jwt_token= jwt.encode(payload, self.priv_key, algorithm="RS256", headers=headers)            
            return 200, {"status": True, "jwt_token": jwt_token}
        except Exception as e:
            return 400, {"status": False, "message": "Exception:In creating Signed Data::" + str(e)}
        
class PostData:
    def __init__(self, url, header= None, payload= None, connect_timeout= 10, read_timeout= 60):
        self.url= url        
        self.header= header 
        self.payload= payload
        self.connect_timeout= connect_timeout
        self.read_timeout= read_timeout
        
    def send_get_request(self):
        if(self.url is None or self.url== ""):
            return 400, {"status": False, "message": "Please declare the request url."}        
        if(self.header is None ):
            return 400, {"status": False, "message": "Please declare the headers."}
        server_res= requests.get(self.url, timeout=(self.connect_timeout, self.read_timeout), data=self.payload, headers= self.header)        
        return server_res
    
    def send_patch_request(self):
        if(self.url is None or self.url== ""):
            return 400, {"status": False, "message": "Please declare the request url."}        
        if(self.header is None ):
            return 400, {"status": False, "message": "Please declare the headers."}        
        server_res= requests.patch(self.url, timeout=(self.connect_timeout, self.read_timeout), data=self.payload, headers= self.header)
        return server_res
    
    def send_post_request(self):
        if(self.url is None or self.url== ""):
            return 400, {"status": False, "message": "Please declare the request url."}        
        if(self.header is None ):
            return 400, {"status": False, "message": "Please declare the headers."}        
        server_res= requests.post(self.url, timeout=(self.connect_timeout, self.read_timeout), data=self.payload, headers= self.header)
        return server_res

def load_private_key_pem_as_bare_base64():
    file_path= os.getenv("CONSENT_PEM_FILE_PATH")
    return load_private_key_pem(file_path)

def load_private_key_pem(path):
    try :
        with open(path, 'r') as f:
            data= f.read().strip()
            return 200, {"status": True, "key":data}
    except Exception as e:
        return 400, {"status": False, "message": "Exception:RSA Private key::" + str(e)}

def rsa_generate_private_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
    return private_key

class DeviceUtils:
    def __init__(self):        
        self.rabbitmq_accounts = CONFIG["rabbitmq_accounts"]
        self.notifications = CONFIG["devices_data"]
        self.db_collection= self.notifications["collection"]
        
        self.entity_notifications = CONFIG["entity_devices_data"]
        self.entity_db_collection= self.entity_notifications["collection"]        
        
    def pop_if_data_exist(self, db_res, device_id):
        ''' pop old data '''
        res= db_res["response"]
        for index, item in enumerate(res):
            if item["device_id"]== device_id:
                db_res["response"].pop(index)
                return db_res, True
        return db_res, False
    
    def is_data_exist(self, db_res, device_id):
        ''' check weather devices already exist in database '''
        res= db_res["response"]
        for item in res:
            if item["device_id"]== device_id:
                return True
        return False
    
    def sort_data_by_date(self, data):        
        ''' sort details by date'''
        try:
            sorted_data= sorted(data, key= lambda x: (x["modify_date"]== "null", x["modify_date"]=="", datetime.strptime(x["modify_date"][0:10], '%Y-%m-%d')) )
            return sorted_data, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: "Error in sorting data:::" +str(e)}, 400
        
    def find_devices_by_locker_id(self, locker_id, device_id= None):
        ''' find all devices by locker id '''
        try:
            mongo_lib= MongoLib()
            if device_id is None:
                where = {"digilockerid": locker_id}
            else :
                where = {"digilockerid": locker_id, "device_id": device_id}            
            res, status_code= mongo_lib.devices_eve(locker_id, self.db_collection, where)
            if status_code == 200 and res :
                return res, 200
            return {STATUS: ERROR, ERROR_DES: res[ERROR_DES]}, status_code
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: "Error in fetchin data:::" +str(e)}, 400        
        
    def find_devices_by_locker_id_and_entity_id(self, locker_id, entity_id, device_id= None):
        ''' find all devices by locker id '''
        try:
            mongo_lib= MongoLib()
            if device_id is None:
                where = {"digilockerid": locker_id, "entity_id":entity_id}
            else :
                where = {"digilockerid": locker_id, "entity_id":entity_id, "device_id": device_id}
            res, status_code= mongo_lib.devices_entity_lockerid_eve(locker_id, entity_id, self.entity_db_collection, where)
            if status_code == 200 and res :
                return res, 200
            return {STATUS: ERROR, ERROR_DES: res[ERROR_DES]}, status_code
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: "Error in fetchin data:::" +str(e)}, 400
    
    def find_devices_by_entity_id(self, entity_id, device_id= None):
        ''' find all devices by locker id '''
        try:
            mongo_lib= MongoLib()
            if device_id is None:
                where = {"entity_id":entity_id}
            else :
                where = {"entity_id":entity_id, "device_id": device_id}
            res, status_code= mongo_lib.devices_entity_eve_by_entity_id(entity_id, self.entity_db_collection, where)
            if status_code == 200 and res :
                return res, 200
            return {STATUS: ERROR, ERROR_DES: res[ERROR_DES]}, status_code
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: "Error in fetchin data:::" +str(e)}, 400
    
    def send_devices_data_to_queue(self, operation, data):
        ''' send details to RMQ'''
        try:
            credentials= pika.PlainCredentials(self.rabbitmq_accounts["username"], self.rabbitmq_accounts["password"])
            parameters = pika.ConnectionParameters(self.rabbitmq_accounts["host"], self.rabbitmq_accounts["port"], self.rabbitmq_accounts["vhost"], credentials)
            connection = pika.BlockingConnection(parameters= parameters)
            channel = connection.channel()
            exchange_name= self.notifications["mq_xchange_name"]
            if operation== "C":            
                routing_key = self.notifications["mq_routing_key_create"]
            elif operation== "U":
                routing_key = self.notifications["mq_routing_key_update"]
            elif operation== "DU":
                routing_key = self.notifications["mq_routing_key_delup"]
            else:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_109'), RESPONSE: 'RabbitMQ::device_data_mongo: Operation - ' + operation}, 406
            channel.exchange_declare(exchange=exchange_name, exchange_type='direct', durable=True)
            channel.queue_bind(exchange=exchange_name, queue=self.notifications["mq_queue_name"], routing_key=routing_key)
            channel.basic_publish(exchange=exchange_name, routing_key=routing_key, body=json.dumps(data), properties=pika.BasicProperties(delivery_mode=2, priority=0))
            connection.close()
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: "Failed to send data to MQ"}, 400
    
    def send_entity_devices_data_to_queue(self, operation, data):
        try:
            credentials1= pika.PlainCredentials(self.rabbitmq_accounts["username"], self.rabbitmq_accounts["password"])
            parameters1 = pika.ConnectionParameters(self.rabbitmq_accounts["host"], self.rabbitmq_accounts["port"], self.rabbitmq_accounts["vhost"], credentials1)
            connection1 = pika.BlockingConnection(parameters= parameters1)
            channel1 = connection1.channel()
            exchange_name1= self.entity_notifications["mq_xchange_name"]            
            if operation== "C":            
                routing_key = self.entity_notifications["mq_routing_key_create"]
            elif operation== "U":
                routing_key = self.entity_notifications["mq_routing_key_update"]
            elif operation== "DU":
                routing_key = self.entity_notifications["mq_routing_key_delup"]
            else:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_109'), RESPONSE: 'RabbitMQ::device_data_mongo: Operation - ' + operation}, 406
            channel1.exchange_declare(exchange= exchange_name1, exchange_type= "direct", durable= True)            
            channel1.queue_bind(exchange=exchange_name1, queue=self.entity_notifications["mq_queue_name"], routing_key=routing_key)
            channel1.basic_publish(exchange=exchange_name1, routing_key=routing_key, body=json.dumps(data), properties=pika.BasicProperties(delivery_mode=2, priority=0))
            connection1.close()            
        except Exception as e:            
            return {STATUS: ERROR, ERROR_DES: "Failed to send data to MQ"}, 400
        
def load_credential():
    section= CONFIG.has_section("DEVICE_CRED")
    if not section:
        CONFIG.add_section('DEVICE_CRED')
        try:            
            secrets = json.loads(SecretManager.get_secret())
            CONFIG['DEVICE_CRED']['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
            CONFIG['DEVICE_CRED']['APP_ENCRYPTION_KEY'] = secrets.get('app_encryption_key', os.getenv('app_encryption_key'))
            CONFIG['DEVICE_CRED']['NOTIFICATION_SECRET_KEY'] = secrets.get('notification_sec_key', os.getenv('notification_sec_key'))
        except Exception as e:
            CONFIG['DEVICE_CRED']['JWT_SECRET'] = os.getenv('JWT_SECRET')
            CONFIG['DEVICE_CRED']['APP_ENCRYPTION_KEY'] = os.getenv('app_encryption_key')
            CONFIG['DEVICE_CRED']['NOTIFICATION_SECRET_KEY'] = os.getenv('notification_sec_key')

def load_apk_signature():
    section= CONFIG.has_section("apk_signin_key_hash_new")
    if not section:
        CONFIG.add_section('apk_signin_key_hash_new')
        try:
            secret_name = os.getenv("mob_app_secret_name", "mob_app_signing")
            region_name = os.getenv("region_name", "ap-south-1")            
            secrets = json.loads(SecretManager.get_mob_app_signing_secret(secret_name, region_name))
            CONFIG['apk_signin_key_hash_new']['d_key'] = secrets.get('d_key', os.getenv('d_key'))
            CONFIG['apk_signin_key_hash_new']['r_key'] = secrets.get('r_key', os.getenv('r_key'))
            CONFIG['apk_signin_key_hash_new']['er_key'] = secrets.get('er_key', os.getenv('er_key'))
            CONFIG['apk_signin_key_hash_new']['indus_app_r_key'] = secrets.get('indus_app_r_key', os.getenv('indus_app_r_key'))
            CONFIG['apk_signin_key_hash_new']['indus_app_er_key'] = secrets.get('indus_app_er_key', os.getenv('indus_app_er_key'))
        except Exception as e:
            CONFIG['apk_signin_key_hash_new']['d_key'] = secrets.get('d_key', os.getenv('d_key'))
            CONFIG['apk_signin_key_hash_new']['r_key'] = secrets.get('r_key', os.getenv('r_key'))
            CONFIG['apk_signin_key_hash_new']['er_key'] = secrets.get('er_key', os.getenv('er_key'))
            CONFIG['apk_signin_key_hash_new']['indus_app_r_key'] = secrets.get('indus_app_r_key', os.getenv('indus_app_r_key'))
            CONFIG['apk_signin_key_hash_new']['indus_app_er_key'] = secrets.get('indus_app_er_key', os.getenv('indus_app_er_key'))