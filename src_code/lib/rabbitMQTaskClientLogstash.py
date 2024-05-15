
import pika, json, os
from flask import request
from dotenv import load_dotenv

load_dotenv()

DELIVERY_MODE = 'delivery_mode'
fanout = 'fanout'
error_description = 'error_description'
STATUS = 'status'
SUCCESS = 'success'
ERROR = 'error'


class RabbitMQTaskClientLogstash:

	@staticmethod
	def log_stash_logeer(fields, queue, function = None):		
		if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
			ip = request.environ['REMOTE_ADDR']
		else:
			ip = request.environ['HTTP_X_FORWARDED_FOR']
		
		fields['ip_address'] = ip
		if function is not None:
			fields['function'] = function
		try:
			''' insert data to rmq queue '''
			if (fields == None):
				response = {STATUS: ERROR, error_description: "input error"}
				return response

			message = {"data": fields, DELIVERY_MODE: 2}
			exchange_name = os.getenv('EXCHANGE_NAME')
			exchange_type = os.getenv('EXCHANGE_TYPE')
			routing_key = queue
			# RabbitMQ connection credentials
			try:
				credentials = pika.PlainCredentials(os.getenv('RABBITMQ_LOGS_USERNAME'),
													os.getenv('RABBITMQ_LOGS_PASSWORD'))
				parameters = pika.ConnectionParameters(os.getenv('RABBITMQ_LOGS_HOST'), os.getenv('RABBITMQ_LOGS_PORT'), os.getenv('RABBITMQ_LOGS_VHOST'), credentials, socket_timeout=int(os.getenv('RABBITMQ_LOGS_SOCKET_TIME')))
				connection = pika.BlockingConnection(parameters)
				accounts_channel = connection.channel()
				accounts_channel.exchange_declare(exchange=exchange_name, exchange_type=exchange_type, durable=True)
				accounts_channel.basic_publish(exchange=exchange_name, routing_key=routing_key, body=json.dumps(message))
				accounts_channel.close()
				response = {STATUS: SUCCESS, 'message': 'request send to queue'}
				return response
			except Exception as logException:
				response = {STATUS: ERROR, error_description: logException}
				return response
		except Exception as e:
			return {STATUS: ERROR, error_description: str(e)}
	
	
	@staticmethod
	def log_adh_requests(fields, queue, exchange_name = 'adh_Xchange', function = None):		
		if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
			ip = request.environ['REMOTE_ADDR']
		else:
			ip = request.environ['HTTP_X_FORWARDED_FOR']
		
		fields['ip_address'] = ip
		if function is not None:
			fields['function'] = function
		try:
			''' insert data to rmq queue '''
			if (fields == None):
				response = {STATUS: ERROR, error_description: "input error"}
				return response

			message = {**fields, DELIVERY_MODE: 2}
			exchange_type = 'direct'
			routing_key = queue
			# RabbitMQ connection credentials
			try:
				credentials = pika.PlainCredentials(os.getenv('RABBITMQ_LOGS_USERNAME'),
													os.getenv('RABBITMQ_LOGS_PASSWORD'))
				parameters = pika.ConnectionParameters(os.getenv('RABBITMQ_LOGS_HOST'), os.getenv('RABBITMQ_LOGS_PORT'), os.getenv('RABBITMQ_LOGS_VHOST'), credentials, socket_timeout=int(os.getenv('RABBITMQ_LOGS_SOCKET_TIME')))
				connection = pika.BlockingConnection(parameters)
				accounts_channel = connection.channel()
				accounts_channel.exchange_declare(exchange=exchange_name, exchange_type=exchange_type, durable=True)
				accounts_channel.basic_publish(exchange=exchange_name, routing_key=routing_key, body=json.dumps(message))
				accounts_channel.close()
				response = {STATUS: SUCCESS, 'message': 'logs sent to queue'}
				return response
			except Exception as logException:
				response = {STATUS: ERROR, error_description: logException}
				return response
		except Exception as e:
			return {STATUS: ERROR, error_description: str(e)}
