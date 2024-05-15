import time, hashlib, os, requests, json
from lib.rabbitmq import RabbitMQ
from lib.constants import *
from lib.rabbitMQAcsUsers import RabbitMQAcsUsers
acs_rmq = RabbitMQ()
users_acs_rmq = RabbitMQAcsUsers()

class SmsLib:

    def send_message(self, to=None, msg=None, sms_type='', template_id=None):
        if template_id is None:
            template_id = os.getenv('NIC_SMS_OTP_TEMPLATE_ID')
        
        object_id = ''
        sms_provider = os.getenv('SMS_SERVICES_OPTION_1')
        rmq_status = users_acs_rmq.send_sms(to, msg, sms_provider, sms_type, object_id, '', template_id)
        if rmq_status['status'] == 1:
            return {'status':'success'}
        else:
            nic = self.nic_sms(to, msg, template_id)
            if nic:
                return {'status':'success'}
            else:
                 {STATUS:ERROR,  ERROR_DES:Errors.error("ERR_MSG_111")}
                
    def nic_sms(self, mobile_no, msg, template_id=''):
        try:
            url = os.getenv('NIC_SMS_URL') + "?username=" + os.getenv('NIC_SMS_USERNAME') + "&pin=" + os.getenv(
                'NIC_SMS_PASSWORD') \
                  + "&message=" + msg + "&mnumber=91" + mobile_no + "&signature=" + os.getenv('NIC_SMS_SDID') \
                  + "&dlt_entity_id=" + os.getenv('NIC_SMS_ENTITY_ID') + "&dlt_template_id=" + template_id
            r = requests.get(url, verify=bool(int(os.getenv('SSL_VERIFY'))))
            
            res = r.text
            res_code = int(r.status_code)
            r.close()
            if res_code == 200:
                return '000' in res
            else:
                return False
        except Exception as e:
            return False



