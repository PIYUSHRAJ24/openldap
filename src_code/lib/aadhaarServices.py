import os, hashlib, requests, time, json
import xmltodict
from dotenv import load_dotenv
from datetime import datetime
from lib.redislib import RedisLib
from lib.constants import *
from php import Php
from lib.rabbitmq import RabbitMQ
import os, configparser
from lib.mongolib import MongoLib
import urllib.parse


MONGOLIB = MongoLib()
RABITMQ = RabbitMQ()

# CONFIG = configparser.ConfigParser()
# root_folder = os.path.dirname(os.path.abspath(__file__))
# root_folder = os.getcwd()
# config_ini_file = os.path.join(root_folder, 'config/appconfig/config.ini')
# CONFIG.read(config_ini_file)

logarray = {}

'''Constants'''
CURRENT_D_FORMAT_YMDHIS = datetime.now().strftime('%Y%m%d%H%M%S')
CURRENT_D_YMDHIS = datetime.now().strftime('YmdTHMS')
redis_ttl = CONFIG['redis']['redis_key_ttl']

AADHAAR_TOKEN = 'aadhaar_token'
TRANSACTION_ID = 'transaction_id'


class AADHAAR_services:
    def __init__(self, conf):
        self.config = conf
        self.rs = RedisLib()
        
    def code(self, key):
        c = {
            '''config const'''
            'AADHAAROTPURL': self.config.get('uidailib', 'uidai_otp_api_url'),
            'DLCLIENTID' : self.config.get('credentials', 'client_id'),
            'DLSECRET' : self.config.get('credentials', 'client_secret'),

            'AADHAAROTPAC' : self.config.get('uidailib', 'uidai_otp_ac'),
            'AADHAAROTPSA' : self.config.get('uidailib', 'uidai_otp_sa'),
            'AADHAAROTVER' : self.config.get('uidailib', 'uidai_otp_ver'),
            'AADHAAROTPLK' : self.config.get('uidailib', 'uidai_otp_lk'),
            
            
            'AADHAAROTPPEFCH' : self.config.get('uidailib', 'uidai_otp_preferred_channel'),
            
            'AADHAAROTPKYCURL' : self.config.get('uidailib', 'uidai_otp_kyc_api_url'),
            'AADHAAROTPAUTHURL' : self.config.get('uidailib', 'uidai_otp_auth_api_url'),
            
        }
        return c.get(key)
        
    def send_aadhaar_otp(self, aadhaar, txnId = None, org_client_id = None, org_txn = None, function = None, restrict_otp = 'no', template_id = None, partner_name = None, app_name = None, orgid = None):
        try:
            uid_type = self.get_uid_type(aadhaar)
            if self.rs.checkAttemptValidateOtp(hashlib.md5(str(aadhaar).encode('utf-8')).hexdigest()) == False:
                retMsg = {
                    STATUS:ERROR,
                    ERROR_DES:Errors.error('err_953')
                }
                logarray.update({"request": "aadhaar_otp_verify", "response": retMsg})
                RABITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return retMsg,400
            
            logData = self.prepareLogData(aadhaar, 'sendOTP', txnId, uid_type, org_client_id, org_txn, function, partner_name, app_name, orgid)
            ret = self.sendOTPaadhaar(aadhaar, self.code('AADHAAROTPPEFCH'), uid_type, txnId, org_client_id, org_txn, function)
            # Rmq.logStashLogeer(logData.update(ret), 'sendValidateOTP')
            return ret
            
        except Exception as e:
            logarray.update({"request": "send_aadhaar_otp", "response": str(e)})
            RABITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return {STATUS: ERROR, ERROR_DES: str(e)}
        
    def get_uid_type(self, aadhaar): 
        aadhaarLen = len(aadhaar)
        uid_type = 'A'
        if (aadhaarLen == 72): # condition for uid_token
            uid_type = 'T'
        
        if (aadhaarLen == 12): # condition for Aadhaar
            uid_type = 'A'
        
        if (aadhaarLen == 16): # condition for VID
            uid_type = 'V'
        
        return uid_type
    
    def prepareLogData(self, aadhaar, request_function, txnId, type, org_client_id, org_txn, function, partner_name = None, app_name = None, orgid = None):
        logData = {}
        aadhaarLen = len(aadhaar)
        logData['request_aadhaar_details'] = 'req-' + aadhaar
        logData['request_adh_mob'] = 'Aadhaar' if aadhaarLen in {'12', '16', '72'} else 'UNKNOWN-' + aadhaar
        logData['request_function'] = request_function
        logData["request_type_data"] = type
        logData["request_org_client_id"] = org_client_id
        logData["request_org_txn"] = org_txn
        logData["request_function"] = function
        logData["request_txnId"] = txnId

        param = {}
        param["request_partner_name"] = partner_name
        param["request_app_name"] = app_name
        param["request_orgid"] = orgid
        param["request_function"] = function

        return logData
    
    def getHash(self, key):
        return hashlib.md5(((str(key)).strip()).encode()).hexdigest()
    
    def sendOTPaadhaar(self, aadhaar, otp_ch, uid_type, txnId, org_client_id, org_txn, function):
        try:
            txn = self.getHash(aadhaar) + CURRENT_D_FORMAT_YMDHIS
            self.rs.set(key = txn +'_logID', value =  txnId, ex=int(redis_ttl))
            self.rs.set(key = txnId +'_logID', value =  txnId, ex=int(redis_ttl))
            
            timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
            
            uidai_AC = self.code('AADHAAROTPAC')
            uidai_SA = self.code('AADHAAROTPSA')
            uidai_VER = self.code('AADHAAROTVER')
            uidai_LK = self.code('AADHAAROTPLK')
            #A for Aadhaar, V for Virtual ID & T for UID Token
            
            xml_data = '<Otp uid="' + aadhaar + '" ac="' + uidai_AC + '" sa="' + uidai_SA + '" ver="' + uidai_VER + '" txn="' + txn + '" ts="' + timestamp + '" lk="' + uidai_LK + '" type="' + uid_type + '"><Opts ch="' + otp_ch + '"/></Otp>'
            headers = {'Content-Type': 'text/xml'}
            curl_result = requests.request("POST", 'http://id.dl6.in/NicASAServer/ASAMain', headers=headers, data=xml_data, timeout=60)

            response = curl_result.text
            tree = xmltodict.parse(response, attr_prefix='')
            output = self.getOutputFromCurlResultSendOTP(tree)
            return self.getResponseFromOutputSendOTP(output, otp_ch, aadhaar, txn, txnId)
            
        except Exception as e:
            logarray.update({"request": "sendOTPaadhaar", "response": str(e)})
            RABITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return {STATUS: ERROR, ERROR_DES: str(e)}
        
    def getOutputFromCurlResultSendOTP(self, curl_result):
        err = '503'
        dic = curl_result.get("OtpRes")
        if dic is not None:
            return dic
        else:
            return {'err':str(err), ERROR_DES:err, 'server_error':err}
        
    def getResponseFromOutputSendOTP(self, output , otp_ch, aadhaar, txn, txnId):
        if 'ret' in output and str(output.get('ret')) == 'y':
            return self.sendOtpSuccessRes(output, otp_ch, aadhaar, txn, txnId)
        
        elif str(output.get('ret')) in {'110', '111', '112', '952', '995', '996', '997', '330', '515', '998', '931'}:
            return self.createErrorRes(output['err'], Errors.error('err_'+output['err']) + '[#' + output['err'] + ']', txn=txn)
        
        elif str(output.get('ret')) in {'1201', '1202', '1203', '1204', '1205', '0', '7', '28', '55', '56'}:
            return self.createErrorRes(output['err'], Errors.error('err_'+output['err']) + '[#' + output['err'] + ']', txn=txn)
        elif str(output.get('ret')):
            return self.createErrorRes(output['err'], 'DigiLocker has received Unknown error (Error Code : ' + output['err'] + ') from UIDAI. Please visit your nearest Aadhaar enrollment center for further information.', txn=txn)
        else:
            return {STATUS:ERROR, 'err_transaction_id':txn, ERROR_DES:Errors.error('err_109'), 'server_error':output['server_error']}        
    
    def sendOtpSuccessRes(self, output, otp_ch, aadhaar, txn, txnId):
        masked_msg = self.getmaskedMsg(output, otp_ch)
        info = output['info'].split(',')
        
        self.rs.set(key = 'aadhaar_OTP_txn_'+self.getHash(aadhaar), value =  txn, ex=int(redis_ttl))
        self.rs.incr(key = 'sendOTP_'+ aadhaar)
        # Remove old count
        self.rs.clearRetry('validateOTP_' + aadhaar)
        self.rs.clearAttempt('validateOTP_' + aadhaar)
        
        return {
            STATUS:SUCCESS,
            'msg':masked_msg,
            'txn' : txnId,
            'masked_mobile' : info[6] if info[6] else None,
            'uidai_txn_id': txn
        }
    
    
    def getmaskedMsg(self, output, otp_ch):
        masked_msg = ''
        info = output['info'].split(',') #returns lists
        masked_msg = 'UIDAI has sent a temporary  OTP to your mobile ending in ' + info[6] + '(valid for 10 mins).'

        if (otp_ch == '02'):
            masked_msg = 'Please enter One Time Password (OTP) sent to your email (' + info[7][0:-1] + ')'
        return masked_msg
            
        
    def createErrorRes(self, err_code, error_description, txn={}):
        if txn:
            txn = {'uidai_txn_id': txn} 
        return {
            STATUS:ERROR,
            'err':int(err_code),
            ERROR_DES:error_description,
            **txn
        }
        
         
    '''VERIFY AADHAAR OTP---->START'''    
    
    def aadhaar_otp_verify(self, data):
        try:
            param = self.prepareParamValidateOtp(data)
            logData = param
           
            if self.rs.checkAttemptValidateOtp('validateOTP_'+data['otp']) == False:
                retMsg = {
                    STATUS:ERROR,
                    ERROR_DES:Errors.error('err_954')
                }
                logarray.update({"request": "aadhaar_otp_verify", "response": retMsg})
                RABITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return retMsg,400
            
            activity = 'KYC' if param['isKYC'] == 'Y' else 'AUTH'
            # aadhaarConsentLog function depreciated
            uid_type = self.get_uid_type(param['aadhaar'])
           
            if 'app_name' not in param:
                param['app_name'] = None
            
            if 'partner_name' not in param:
                param['partner_name'] = None
            
            if 'orgid' not in param:
                param['orgid'] = None
            
            ret = self.verifyAadhaarOTP(activity, param['aadhaar'], param['otp'], uid_type, param['requst_pdf'], param['requst_xml'], param['update'], param['partner_name'], param['app_name'], param['orgid'])
            logarray.update({"request": "aadhaar_otp_verify", "response": ret})
            RABITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return ret
        except Exception as e:
            logarray.update({"request": "aadhaar_otp_verify", "response": str(e)})
            RABITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
            return {STATUS: ERROR, ERROR_DES: str(e)}
    
    def prepareParamValidateOtp(self, param):
        param['aadhaar'] = param['uid']
        param['update'] = param['update'] if 'update' in param else 'N'
        param['request_aadhaar_details'] = param['uid'] if 'uid' in param else param['txn']
        param['username'] = param['txn']
        param['client_id'] = param['client_id'] if param['client_id'] else None
        param['isKYC'] = param['isKYC'] if param['isKYC'] else "N"
        param['requst_pdf'] = param['requst_pdf'] if 'requst_pdf' in param else "Y"
        param['requst_xml'] = param['requst_xml'] if 'requst_xml' in param else "Y"
        param["requst_org_client_id"] = param['org_client_id'] if 'org_client_id' in param else None
        param["requst_org_txn"] = param['org_txn'] if 'org_txn' in param else None
        param["requst_partner_name"] = param['partner_name'] if 'partner_name' in param else None
        param["requst_app_name"] = param['app_name'] if 'app_name' in param else None
        param["requst_orgid"] = param['orgid'] if 'orgid' in param else None
        param["requst_function"] = param['function_name'] if 'function_name' in param else 'validateOTP'
        param["request_txnId"] = param['txn']
        
        return param
        
    
    def get_expired_token(self, aadhaar):
        expired_txn = self.rs.get(key = 'aadhaar_OTP_txn_'+ self.getHash(aadhaar))
        if expired_txn is None:
            expired_txn = self.rs.get(key = 'aadhaar_OTP_txn_' + self.getHash(aadhaar))
        
        return expired_txn if expired_txn is not None else False
                
    def verifyAadhaarOTP(self, activity, aadhaar, otp, type, requestPDF = "Y", requestXML = "Y", update = 'N', partner_name = None, app_name = None, orgid = None):
        expired_txn = self.get_expired_token(aadhaar)
        
        if expired_txn is None:
            return {STATUS:ERROR, ERROR_DES:Errors.error('err_488')} 
        
        url = self.code('AADHAAROTPKYCURL') if activity == 'KYC' else self.code('AADHAAROTPAUTHURL')
        is_kyc = 'Y' if activity == 'KYC' else 'N'
        access_token = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        
        curl_result = self.curlForUIDAI(url, is_kyc, aadhaar, otp, access_token, expired_txn, update, 'Y', type, requestPDF, requestXML, partner_name, app_name, orgid)
        # return {'curl_result':curl_result, 'url':url, 'is_kyc':is_kyc} curl_result IS DICTIONARY
        
        res = self.prepareVerifyAadhaarOTPResponse(aadhaar, curl_result, access_token, requestPDF)
        res['requestPDF'] = requestPDF
        res['uidai_txn_id'] = expired_txn
        return res
    
    
    def curlForUIDAI(self, curlurl, isKYC, aadhaar, otp, access_token, expired_txn, update, consent, type, requestPDF = 'N', requestXML = 'N', partner_name = None, app_name = None, orgid = None):
        timestamp = int(time.time())
        plain_text = self.code('DLSECRET') + self.code('DLCLIENTID') + str(timestamp) + aadhaar + otp
        hmac = hashlib.sha256(plain_text.encode()).hexdigest()
        fields = {
            'aadhaarNumber' : aadhaar,
            'OTP' : otp,
            AADHAAR_TOKEN : access_token,
            TRANSACTION_ID : expired_txn,
            'update' : update,
            'consent' : consent,
            'type' : type,
            'pdf' : requestPDF,
            'xml' : requestXML,
            'requst_pdf' : requestPDF,
            'requst_xml' : requestXML,
            'partner_name' : partner_name,
            'app_name' : app_name,
            'orgid' : orgid,
            'hmac' : hmac,
            'ts' : timestamp,
            'clientid' : self.code('DLCLIENTID')
        }
        if isKYC != "Y":
            fields.pop('aadhaarNumber')
            fields['AadhaarNumber'] = aadhaar
        
        fields_string = Php.http_build_query(fields)
        headers = {'Content-Type': 'application/x-www-form-urlencoded charset=UTF-8'}
        curl_result = requests.request("POST", curlurl, headers=headers, data=fields_string, timeout=120)
        response = json.loads(curl_result.text)
        return response
    
    def prepareVerifyAadhaarOTPResponse(self, aadhaar, curl_result, access_token, requestPDF):
        if curl_result is None:
            return {STATUS:ERROR, ERROR_DES:Errors.error('err_118')}
    
        if curl_result['msg'] == 'Invalid Response Recieved.':
            curl_result['code'] = 'D-104'
        
        if curl_result['code'] in self.clearAttemptUIDAIErrorCode():
            self.clearAttempt(aadhaar)
        
        if curl_result['code'] in self.getKnownErrorCodesUIDAI():
            if curl_result['code'] == 'D-104':
                requestLabel = {'Y' : 'P', 'N' : 'X'}
                return {
                    STATUS:ERROR,
                    ERROR_DES: Errors.error('UIDAI-'+ curl_result['code']) + '[#' + str(curl_result['code']) + '-' + requestLabel[requestPDF] + ']',
                }
            return {
                STATUS:ERROR,
                ERROR_DES:Errors.error('UIDAI-'+ curl_result['code']) + '[#' + str(curl_result['code']) + ']',    
            }
        if 'status' not in curl_result:
            return {
                STATUS:ERROR,
                ERROR_DES: Errors.error('err_499') + '[#499]',
                }
        if curl_result is None or not curl_result['status'] or curl_result['access_token'] != access_token:
            return {
                STATUS:ERROR,
                ERROR_DES:Errors.error('err_101') + '[#' + str(curl_result['code']) + ']',
            }
        else:
            self.clearAttempt(aadhaar)
            return {
                STATUS:SUCCESS,
                'response':curl_result
            }
        
    def clearAttemptUIDAIErrorCode(self):
        errorCodes = ['504', '102', '1201', '1202', '1203', '1204', '1205', 'K-200','K-545', 'K-955', 'K-956', 'D-102', 'D-103', 'D-104']
        return errorCodes
    
    def getKnownErrorCodesUIDAI(self):
        errorCodes = ['400', '101', '102', '1201', '1202', '1203', '1204', '1205', 'K-100', 'K-200',
            'K-540', 'K-541', 'K-542', 'K-544', 'K-545', 'K-546', 'K-547', 'K-550',
            'K-551', 'K-552', 'K-569', 'K-570', 'K-600', 'K-601', 'K-602', 'K-603',
            'K-604', 'K-605', 'K-955', 'K-956', 'K-999', 'D-102', 'D-103', 'D-104']
        return errorCodes
    
    def clearAttempt(self, aadhaar):
        self.rs.clearRetry('sendOTP_' + aadhaar)
        self.rs.clearAttempt('sendOTP_' + aadhaar)
        self.rs.clearRetry('validateOTP_' + aadhaar)
        self.rs.clearAttempt('validateOTP_' + aadhaar)
        self.rs.remove('aadhaar_OTP_txn_' + self.getHash(aadhaar))
    
    
        '''VERIFY AADHAAR OTP----END'''


    def check_for_uid_token_exists(self, uid_token):
        try:
            if uid_token is None:
               logarray.update({"request": "check_for_uid_token_exists", "response": uid_token})
               RABITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
               return {'status':False, 'data': {}}

            where = {"uid_token": urllib.parse.quote(uid_token)} 
            res, code = MONGOLIB.accounts_eve_v2('users', where, projection={'_id':0})
            if code == 200 and res['status'] == 'success' and res.get('response') is not None:
                data = res['response'][0]
                return {'status':True, 'data': data}
            else:
                return {'status':False, 'data': {}}
            
        except Exception as e:
                logarray.update({"request": "check_for_uid_token_exists", "response": str(e)})
                RABITMQ.send_to_queue(logarray, 'Logstash_Xchange', 'org_logs_')
                return {'status':False, 'data': {}}
