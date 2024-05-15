import pika
import json
from lib.constants import *
rabbitmq_accounts = CONFIG['rabbitmq_accounts']
notifications = CONFIG['notifications']
rabbitmq_logstash = CONFIG['rabbitmq_logstash']


class RabbitMQAcsUsers:
    def __init__(self):
        pass

    def dl_notification_mongo(self, collection, operation, data):
        try:
            credentials = pika.PlainCredentials(
                rabbitmq_accounts['username'], rabbitmq_accounts['password'])
            parameters = pika.ConnectionParameters(rabbitmq_accounts['host'], rabbitmq_accounts['port'],  # type: ignore
                                                   rabbitmq_accounts['vhost'], credentials)  # type: ignore
            accounts_connection = pika.BlockingConnection(parameters)
            accounts_channel = accounts_connection.channel()
            exchange_name = notifications['exchange_name']
            if operation == "C":
                routing_key = 'Create_' + collection.split('_')[0].upper() + '_' + '_'.join(
                    list(map(lambda x: x.title(), collection.split('_')[1:]))) + '_' + APP_ENVIRONMENT
            elif operation == "U":
                routing_key = 'Update_' + collection.split('_')[0].upper() + '_' + '_'.join(
                    list(map(lambda x: x.title(), collection.split('_')[1:]))) + '_' + APP_ENVIRONMENT
            else:
                return {
                    STATUS: ERROR,
                    ERROR_DES: Errors.error('ERR_MSG_109'),
                    RESPONSE: 'RabbitMQ::dl_notification_mongo: Operation - ' + operation
                }, 406
            print(routing_key) # beta debug
            accounts_channel.exchange_declare(
                exchange=exchange_name, exchange_type='direct', durable=True)  # type: ignore
            accounts_channel.basic_publish(exchange=exchange_name,
                                           routing_key=routing_key,
                                           body=json.dumps(data),
                                           properties=pika.BasicProperties(
                                               delivery_mode=2,  # makes persistent job
                                               priority=0,  # default priority
                                           ))
            accounts_connection.close()
            return {STATUS: SUCCESS, MESSAGE: 'Request Sent'}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: 'RabbitMQ::dl_notification_mongo: Connection Error! '+str(e)}

    def send_to_queue(self,data,exchange_name,queue_name):
        try:
            
            credentials = pika.PlainCredentials(rabbitmq_accounts['username'], rabbitmq_accounts['password'])
            parameters = pika.ConnectionParameters(rabbitmq_accounts['host'], rabbitmq_accounts['port'],  # type: ignore
                                                rabbitmq_accounts['vhost'], credentials, retry_delay=5,
                                                connection_attempts=10)
            connection = pika.BlockingConnection(parameters)
            channel = connection.channel()
            route_key = queue_name + APP_ENVIRONMENT
            channel.exchange_declare(exchange=exchange_name, exchange_type="direct",
                                    durable=True, arguments={'x-queue-mode': 'lazy'})
            channel.queue_bind(exchange=exchange_name, queue=route_key, routing_key=route_key)
            channel.basic_publish(exchange=exchange_name, routing_key=route_key, body=json.dumps(data, default=str),
                                    properties=pika.BasicProperties(
                                    delivery_mode=2,  # makes persistent job
                                    priority=0,  # default priority
                                ))
            channel.close()
            return {STATUS: SUCCESS, MESSAGE: 'Request Sent'}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_111'), RESPONSE: 'RabbitMQ::send_to_queue: Connection Error! '+str(e)}, 500
            
        
    def createUser(self, data):
        try:
            credentials = pika.PlainCredentials(os.getenv('RABBITMQ_ACCOUNTS_USERS_HOST'), os.getenv('RABBITMQ_ACCOUNTS_USERS_PASSWORD'))
            parameters = pika.ConnectionParameters(os.getenv('RABBITMQ_ACCOUNTS_USERS_HOST'), os.getenv('RABBITMQ_ACCOUNTS_USERS_PORT'),  # type: ignore
                                                os.getenv('RABBITMQ_ACCOUNTS_USERS_VHOST'), credentials, retry_delay=5,
                                                connection_attempts=10)
            accounts_connection = pika.BlockingConnection(parameters)
            accounts_channel = accounts_connection.channel()
            
            exchange_name = 'Create_User_Xchange'
            routing_key = 'Create_NonDemo_User_' + APP_ENVIRONMENT
            
            body = data
            
            accounts_channel.exchange_declare(exchange=exchange_name, exchange_type='direct', durable=True)
            accounts_channel.basic_publish(exchange=exchange_name,
                                       routing_key=routing_key,
                                       body=json.dumps(body),
                                       properties=pika.BasicProperties(
                                           delivery_mode=2,  # makes persistent job
                                           priority=0,  # default priority
                                           ))
            accounts_connection.close()
            
            return {'status': 1, 'msg': 'Request Sent'}
        except Exception as e:
            return {'status': 0, 'msg': str(e)+'create_user_Connection Error!'}
               
    '''To update users coll'''
    def updateUser(self, data):
        try:
            self.credentials = pika.PlainCredentials(os.getenv('RABBITMQ_ACCOUNTS_USERS_HOST'),os.getenv('RABBITMQ_ACCOUNTS_USERS_PASSWORD'))
            self.accounts_connection = pika.BlockingConnection(pika.ConnectionParameters(os.getenv('RABBITMQ_ACCOUNTS_USERS_HOST'),os.getenv('RABBITMQ_ACCOUNTS_USERS_PORT'),os.getenv('RABBITMQ_ACCOUNTS_USERS_VHOST'), self.credentials))
            self.accounts_channel = self.accounts_connection.channel()
                        
            exchange_name = 'Create_User_Xchange'
            routing_key = 'Update_User_' + APP_ENVIRONMENT
            data_to_be_sent = {}
            data_to_be_sent['data'] = data
            body = data_to_be_sent
            self.accounts_channel.basic_publish(exchange=exchange_name,
                                       routing_key=routing_key,
                                       body=json.dumps(body),
                                       properties=pika.BasicProperties(
                                           delivery_mode=2,  # makes persistent job
                                           priority=0,  # default priority
                                           ))
            self.accounts_connection.close()
            return {'status': 1}
        except Exception as e:
            print(str(e))
            return {'status': 0, 'msg': str(e)+'update_user_Connection Error!'}
    
    '''To update users profile coll'''
    
    def updateUserProfile(self, data):
        try:
            self.credentials = pika.PlainCredentials(os.getenv('RABBITMQ_ACCOUNTS_USERS_USERNAME'),os.getenv('RABBITMQ_ACCOUNTS_USERS_PASSWORD'))
            self.accounts_connection = pika.BlockingConnection(pika.ConnectionParameters(os.getenv('RABBITMQ_ACCOUNTS_USERS_HOST'),os.getenv('RABBITMQ_ACCOUNTS_USERS_PORT'),os.getenv('RABBITMQ_ACCOUNTS_USERS_VHOST'), self.credentials))
            self.accounts_channel = self.accounts_connection.channel()
            
            
            exchange_name = 'Create_User_Xchange'
            routing_key = 'Update_User_Profile_' + APP_ENVIRONMENT
            data_to_be_sent = {}
            data_to_be_sent['data'] = data
            body = data_to_be_sent
            self.accounts_channel.basic_publish(exchange=exchange_name,
                                       routing_key=routing_key,
                                       body=json.dumps(body),
                                       properties=pika.BasicProperties(
                                           delivery_mode=2,  # makes persistent job
                                           priority=0,  # default priority
                                           ))
            self.accounts_connection.close()
            return {'status': 1}
        except Exception as e:
            print(str(e))
            return {'status': 0, 'msg': str(e)+'update_user_Profile Connection Error!'}
        
    '''This will be used to send otp'''
    def send_sms(self, to, msg, sms_provider, sms_type='singlemsg', object_id='', key='', template_id=''):
        try:
            self.credentials = pika.PlainCredentials(os.getenv('RABBITMQ_SMS_EMAIL_OTP_USERNAME'),os.getenv('RABBITMQ_SMS_EMAIL_OTP_PASSWORD'))
            self.accounts_connection = pika.BlockingConnection(pika.ConnectionParameters(os.getenv('RABBITMQ_SMS_EMAIL_OTP_HOST'),os.getenv('RABBITMQ_SMS_EMAIL_OTP_PORT'),os.getenv('RABBITMQ_SMS_EMAIL_OTP_VHOST'), self.credentials))
            self.accounts_channel = self.accounts_connection.channel()
            
            sms_queue_type = 'OTP' if sms_type == 'otpmsg' else 'REG'
            exchange_name = 'SMS_Xchange'
            routing_key = sms_provider + '_SMS_' + sms_queue_type + '_' + APP_ENVIRONMENT
            body = {'phone_number': to,
                    'content': msg,
                    'sms_type': sms_type,
                    'id': str(object_id),
                    'key': key,
                    'template_id': template_id
                }
                    
            
            self.accounts_channel.basic_publish(exchange=exchange_name,
                                       routing_key=routing_key,
                                       body=json.dumps(body),
                                       properties=pika.BasicProperties(
                                           delivery_mode=2,  # makes persistent job
                                           priority=0,  # default priority
                                           ))
            self.accounts_connection.close()
            return {'status': 1, 'msg': 'SMS SENT'}
        except Exception as e:
            return {'status': 0, 'msg': 'Connection Error!'}
    
    def send_to_logstash(self,data,exchange_name,queue_name):
        try:
            credentials = pika.PlainCredentials(rabbitmq_logstash['username'], rabbitmq_logstash['password'])
            parameters = pika.ConnectionParameters(rabbitmq_logstash['host'], rabbitmq_logstash['port'],  # type: ignore
                                                rabbitmq_logstash['vhost'], credentials, retry_delay=5,
                                                connection_attempts=10)
            connection = pika.BlockingConnection(parameters)
            channel = connection.channel()
            route_key = queue_name + 'PROD'
            channel.exchange_declare(exchange=exchange_name, exchange_type="direct",
                                    durable=True, arguments={'x-queue-mode': 'lazy'})
            channel.queue_bind(exchange=exchange_name, queue=queue_name+ APP_ENVIRONMENT, routing_key=route_key)
            channel.basic_publish(exchange=exchange_name, routing_key=route_key, body=json.dumps(data),
                                    properties=pika.BasicProperties(
                                    delivery_mode=2,  # makes persistent job
                                    priority=0,  # default priority
                                ))
            channel.close()
            return {STATUS: SUCCESS, MESSAGE: 'Request Sent'}, 200
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: Errors.error('ERROR_DES'), RESPONSE: 'RabbitMQ::send_to_queue: Connection Error! '+str(e)}, 500
        
    