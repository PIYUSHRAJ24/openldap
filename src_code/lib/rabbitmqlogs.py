import pika
import json
from lib.constants import *
rabbitmq_accounts = CONFIG['rabbitmq_logstash']


class RabbitMQLogs:
    def __init__(self):
        pass

    def send_to_queue(self,data,exchange_name,queue_name):
        try:
            credentials = pika.PlainCredentials(rabbitmq_accounts['username'], rabbitmq_accounts['password'])
            parameters = pika.ConnectionParameters(
                rabbitmq_accounts['host'], int(rabbitmq_accounts['port']),  # type: ignore
                rabbitmq_accounts['vhost'], credentials, retry_delay=1,
                connection_attempts=2, socket_timeout=int(rabbitmq_accounts['socket_timeout'])
            )
            connection = pika.BlockingConnection(parameters)
            channel = connection.channel()
            route_key = queue_name + 'PROD'

            channel.exchange_declare(exchange=exchange_name, exchange_type="direct",
                                    durable=True, arguments={'x-queue-mode': 'lazy'})
            channel.queue_bind(exchange=exchange_name, queue=route_key, routing_key=route_key)
            channel.basic_publish(
                exchange=exchange_name, routing_key=route_key, body=json.dumps(data),
                properties=pika.BasicProperties(
                delivery_mode=2,  # makes persistent job
                priority=0,  # default priority
            ))
            channel.close()
            return {STATUS: SUCCESS, MESSAGE: 'Request Sent'}, 200
        except Exception as e:
            return {STATUS: ERROR, MESSAGE: Errors.error('ERR_MSG_145'),
                    ERROR_DES: 'RabbitMQ::send_to_queue: Connection Error! '+str(e)},500