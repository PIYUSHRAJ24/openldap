import os, hashlib, json
from lib.redislib import RedisLib
from lib.rabbitmq import RabbitMQ
from lib.constants import *
from lib.mongolib import MongoLib
import urllib.parse
from lib.rabbitMQAcsUsers import RabbitMQAcsUsers

MONGOLIB = MongoLib()
rmq_connector = RabbitMQ()
users_acs_rmq = RabbitMQAcsUsers()

accounts_eve = CONFIG['accounts_eve']
from lib import otp_service
otp_connector = otp_service.OTP_services
logarray = {}
class Signup_model:
    def __init__(self, conf):
        self.rs = RedisLib()
        self.config = conf

    def aadhaar_signup(self, res, data):
        try:
            UIDTOKEN = res.get('UID_Token')
            residentName = res.get('residentName')
            users_info = {
                'name': residentName,
                'gender' : res.get('gender'),
                'dob' : res.get('dateOfBirth'),
                'careOf' : res.get('careOf'),
                'state' : res.get('state'),
                'district' : res.get('district'),
                'city' : res.get('city'),
                'uid_token' : UIDTOKEN,
                'mobile':None,
                'email':None,
            }
            finaldata = {}
            
            if UIDTOKEN is None or residentName is None:
                finaldata['status'] = ERROR
                finaldata[ERROR_DES] = Errors.error('err_111')
                finaldata['code'] = 205
                return finaldata
            
            user_data = self.check_for_uid_token_exists(UIDTOKEN)
            if user_data.get('status') is False and user_data.get('max_org_reached') is True:
                return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_165')}, 400
            elif user_data.get('status') is False:
                # uid_token does not exists and ac need to be created
                createuser = self.add_aadhaar_user_mq(data, res)
                if createuser['status'] == 'success':
                    self.rs.set(key = data['txn'] + '_otp_verified', value='yes', ex=3600 * 24)
                    # aadhaar saveuri
                    MONGOLIB.saveuri_aadhaar(data['txn'], UIDTOKEN, data['txn'])
                    finaldata[STATUS]= SUCCESS
                    finaldata['username']= data['txn']
                    finaldata['digilockerid']= data['txn']
                    finaldata['email_id']= data.get('email_id')
                    finaldata['mobile_no']= data.get('mobile_no')
                    finaldata['type']= 'new'
                    finaldata['name'] = residentName
                    finaldata['pin_enabled'] = 'no'
                    
                    finaldata['code']= 200
                    finaldata['careOf'] = res.get('careOf') if res.get('careOf') else ''
                    finaldata['user_info'] = users_info
                    return finaldata
                else:
                    return {STATUS: ERROR, ERROR_DES: Errors.error('ERR_MSG_166'), 'actual_err':createuser.get('error_description')}
            elif user_data.get('status') and user_data.get('data') and len(user_data.get('data'))>0:
                em = user_data.get('data').get('email_id')
                emv = user_data.get('data').get('email_id_verified')
                users_info['email'] = em if em and emv == 1 else None
                users_info['mobile'] = user_data.get('data').get('mobile_no')
                
                finaldata[STATUS]= SUCCESS
                finaldata['username']= user_data.get('data').get('user_id')
                finaldata['digilockerid']= user_data.get('data').get('digilockerid')
                finaldata['type']= 'old'
                # Optimized
                pin = user_data.get('data', {}).get('pin')
                finaldata['pin_enabled'] = 'yes' if pin and len(pin) >= 32 else 'no'

                finaldata['name'] = self.get_profile_data(finaldata['digilockerid']).get('name')
                finaldata['code']= 200
                finaldata['careOf'] = res.get('careOf') if res.get('careOf') else ''
                finaldata['user_info'] = users_info

                # aadhaar saveuri
                MONGOLIB.saveuri_aadhaar(finaldata['digilockerid'], user_data.get('data').get('uid_token'), finaldata['username'])
                self.rs.set(finaldata['digilockerid']+'_org_add_user_verify_otp', json.dumps(finaldata))
                return finaldata 
            else:
                finaldata['status'] = ERROR
                finaldata[ERROR_DES] = Errors.error('err_111')
                finaldata['code'] = 205
                return finaldata
                  
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: str(e)}
        
    def check_for_uid_token_exists(self, uid_token):
        try:
            if uid_token  is None:
               return {'status':False, 'data': {}}

            where = {"uid_token": urllib.parse.quote(uid_token)} 
            res, code = MONGOLIB.accounts_eve_v2('users', where, projection={'_id':0})
            if code == 200 and res['status'] == 'success' and res.get('response') is not None:
                data = res['response'][0]
                org_id_from_db = data.get('org_id') if data.get('org_id') else []
                if len(org_id_from_db) >= int(CONFIG['roles']['max_organizations']): # type: ignore
                    return {'status': False, 'max_org_reached':True, 'data': {}}
                return {'status':True, 'data': data}
            else:
                return {'status':False, 'data': {}}
            
        except Exception as e:
                return {'status':False, 'data': {}}
    
    def get_profile_data(self, lockerid):
        try:
            if lockerid  is None:
                return {}

            where = {"digilockerid": lockerid} 
            res, code = MONGOLIB.accounts_eve_v2('users_profile', where, projection={'_id':0})
            
            if code == 200 and res['status'] == 'success' and res.get('response') is not None:
                data = res['response'][0]
                return data
            else:
                return {}
            
        except Exception as e:
            return {}
    
    def getHash(self, key):
        return hashlib.md5(((str(key)).strip()).encode()).hexdigest()
    
    def add_aadhaar_user_mq(self, data, res):
        ''' verify otp response'''
        try:
           
            userCreationData = {
                'user_id' : data['txn'],
                'digilockerid' : data['txn'],
                'user_from' : data['client_id'],
                'data_directory_type' : os.getenv('DEFAULT_DATADIRECTORY','v6'),
                'user_type' : 'aadhaar',
                'flow' : 'aadhaar_signup_oauth'
            }
            if len(data['uid']) == 12:
                userCreationData['uid'] = self.getHash(data['uid'])
            if res['dateOfBirth'] is not None:
                dob = res['dateOfBirth'].split('-')
                userCreationData['date_of_birth'] = '-'.join((dob[2],dob[1],dob[0]))
            
            userCreationData['name'] = res['residentName']
            userCreationData['gender'] = res['gender']
            userCreationData['uid_token'] = res['UID_Token']
            userCreationData['state'] = res['state']
            userCreationData['district'] = res['district']
            userCreationData['city'] = res['city']
            userCreationData['option1'] = 'CM'
            mqdata = {}
            mqdata['data'] = userCreationData
            rmq_status = rmq_connector.createUser(mqdata)
            # rmq_status = users_acs_rmq.createUser(mqdata)
            if rmq_status['status'] == 1:
                self.rs.set(key = userCreationData['user_id'] + '_user_data', value=json.dumps(userCreationData))
                self.rs.set(key = userCreationData['user_id'] + '_users', value=json.dumps(userCreationData))
                self.rs.set(key = userCreationData['digilockerid'] + '_user_data', value=json.dumps(userCreationData))
                self.rs.set(key = userCreationData['digilockerid'] + '_users', value=json.dumps(userCreationData))
                self.rs.set(key = userCreationData['user_id'] + '_exist', value=userCreationData['user_id'])
                return {STATUS: SUCCESS, 'SUCC_DES': 'User Created'}
            else:
                return {STATUS: ERROR, ERROR_DES : rmq_status['msg']}
            
        except Exception as e:
            return {STATUS: ERROR, ERROR_DES: str(e)}
    