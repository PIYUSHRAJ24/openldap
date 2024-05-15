import os
import hashlib
from dotenv import load_dotenv
import random
from datetime import datetime
from lib.redislib import RedisLib
from lib.smslib import SmsLib
from lib.constants import *
import uuid
import random
import time
from lib import smslib
SmsLib = smslib.SmsLib()


load_dotenv()


'''Constants'''
CURRENT_D_FORMAT_YMDHIS = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
CURRENT_D_YMDHIS = datetime.now().strftime('YmdHMS')
redis_ttl = os.getenv('OTP_TTL')


class OTP_services:
    def __init__(self):
        self.rs = RedisLib()

    def send_mobile_otp(self, mobile):
        try:
            otpdetail = self.generateotp(mobile)
            if otpdetail and otpdetail['status'] == True:
                app_message = str(otpdetail['data_sms']['otp']) + ' is your OTP to access DigiLocker. OTP is confidential and valid for 10 minutes. For security reasons, DO NOT share this OTP with anyone.'
                self.rs.set(key = str(mobile) + '_otp', value =  otpdetail['data_sms']['otp'], ex=redis_ttl)
                response = SmsLib.send_message(otpdetail['data_sms']['mobileno'], app_message, 'otpmsg', os.getenv('NIC_SMS_OTP_TEMPLATE_ID'))
                if response.get('status') == 'success':
                    return {'status': response['status'],'message':otpdetail['data_sms']['otpmsg'],'txn': self.get_txn(mobile)}, 200
                else:
                    return response, 400     
            elif otpdetail and not otpdetail['status']:
                return {'status': 'success','message':otpdetail['data_sms']['otpmsg']}, 200
            else:
                return {STATUS:ERROR,  ERROR_DES:Errors.error("ERR_MSG_111")}, 400
        except Exception as e:
            return {STATUS:ERROR,  ERROR_DES: str(e)}, 400
    
    def entity_send_mobile_otp(self, mobile):
        try:
            otpdetail = self.generateotp(mobile)
            if otpdetail and otpdetail['status'] == True:
                app_message = str(otpdetail['data_sms']['otp']) + ' is your OTP to access DigiLocker. OTP is confidential and valid for 10 minutes. For security reasons, DO NOT share this OTP with anyone.'
                self.rs.set(key = str(mobile) + '_otp', value =  otpdetail['data_sms']['otp'], ex=redis_ttl)
                response = SmsLib.send_message(otpdetail['data_sms']['mobileno'], app_message, 'otpmsg', os.getenv('NIC_SMS_OTP_TEMPLATE_ID'))
                if response.get('status') == 'success':
                    return {'status': response['status'],'msg':otpdetail['data_sms']['otpmsg'],'txn': self.get_txn(mobile)}, 200
                else:
                    return response, 400 
                    
            elif otpdetail and not otpdetail['status']:
                return {'status': 'error','msg':otpdetail['data_sms']['otpmsg']},400
            else:
                return {STATUS:ERROR,  ERROR_DES:Errors.error("ERR_MSG_111")}, 400
        except Exception as e:
            return {STATUS:ERROR,  ERROR_DES: str(e)}, 400    

    def generateotp(self, mobile):
        try:
            six_digit_random_number = random.randrange(100000, 999999)
            time = CURRENT_D_FORMAT_YMDHIS
            data_sms = {}
            #get otp from redis if alreday exists
            redis_data = self.rs.get(key = str(mobile)+'_otp')
            resend_after = self.rs.get(key = str(mobile) + '_otp_generated')
            if resend_after and redis_data and redis_data != None:
                data_sms['mobileno'] = mobile
                data_sms['otp'] = redis_data
                data_sms['otpmsg'] = 'An OTP has already been sent to your mobile number, please use the same.  To resend OTP,  please wait for 60 seconds.'
                data_sms['otp_generated_from'] = 'redis'
                return {'status': False, 'data_sms': data_sms}
            else:    
                data_sms['mobileno'] = mobile
                data_sms['otp'] = six_digit_random_number
                data_sms['otpmsg'] = 'DigiLocker has sent you an OTP to your registered mobile (xxxxxx'+ str(mobile[-4: ])+')'
                data_sms['otp_generated_time'] = time
                data_sms['otp_generated_from'] = 'new'
                self.rs.set(key = str(mobile) + '_otp_generated', value =  data_sms['otp'], ex=60)
                return {'status': True, 'data_sms': data_sms}
        except Exception as e:
            return {STATUS:ERROR,  ERROR_DES : str(e)}

    def verify_mobile_otp(self, mobile, otp):
        try:
            redis_data = self.rs.get(str(mobile)+'_otp')
            if redis_data is not None and redis_data ==otp:
                # once otp verified, remove data from redis 
                self.rs.remove(key= str(mobile)+'_otp')
                return {'status':'success'}, 200
            elif redis_data is None:
                '''if otp is expired'''
                return {STATUS:ERROR,  ERROR_DES:Errors.error("ERR_MSG_128")}, 400
            else:
                return {STATUS:ERROR,  ERROR_DES:Errors.error("ERR_MSG_131")}, 400
        except Exception as e:
            return {STATUS:ERROR,  ERROR_DES: str(e)}, 400
   
        
    def get_txn(self,random_key):
        random_number = random.randint(111111, 999999)
        timestamp = int(time.time())

        uuid_v4 = uuid.uuid4()
        namespace = uuid.UUID(int=uuid_v4.int)
        txn_id = uuid.uuid5(namespace, str(random_number) + random_key + str(timestamp))
        return txn_id

            