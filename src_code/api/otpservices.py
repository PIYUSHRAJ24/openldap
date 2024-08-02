import hashlib
from flask import Blueprint, request, g
from datetime import datetime
from lib.constants import *
from lib.validations import Validations
from lib.aadhaarServices import AADHAAR_services
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.rabbitMQTaskClientLogstash import RabbitMQTaskClientLogstash
from lib.drivejwt import DriveJwt
from lib.commonlib import CommonLib
from lib.redislib import RedisLib
from lib.signup_model import Signup_model
from lib.secretsmanager import SecretManager

import logging
from pythonjsonlogger import jsonlogger

# Setup logging
current_date = datetime.datetime.now().strftime("%Y-%m-%d")
log_file_path = f"ORG-logs-{current_date}.log"
logHandler = logging.FileHandler(log_file_path)
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)


VALIDATIONS = Validations()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
REDISLIB = RedisLib()
AADHAAR_CONNECTOR = AADHAAR_services(CONFIG)
RABBITMQ_LOGSTASH = RabbitMQTaskClientLogstash()
SIGNUP_CONNECTOR = Signup_model(CONFIG)

CONFIG = dict(CONFIG)
secrets = json.loads(SecretManager.get_secret())
try:
    CONFIG['JWT_SECRET'] = secrets.get('aes_secret', os.getenv('JWT_SECRET'))
except Exception as s:
    CONFIG['JWT_SECRET'] = os.getenv('JWT_SECRET') #for local

bp = Blueprint('aadhaar', __name__)
logarray = {}


@bp.before_request
def validate():
    """
        JWT Authentication
    """
    try:
        
        request_data = {
            'time_start': datetime.datetime.utcnow().isoformat(),
            'method': request.method,
            'url': request.url,
            'headers': dict(request.headers),
            'body': request.get_data(as_text=True)
        }
        request.logger_data = request_data
        
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck')
        if request.path.split('/')[1] in bypass_urls or request.path.split('/')[-1] in bypass_urls:
            return
        g.endpoint = request.endpoint.split('.')[-1]
        g.logs = {
            ENDPOINT: g.endpoint,
            'source': request.headers.get("Host"),
            'ip': request.remote_addr,
            'clientid': "",
            'browser': request.headers.get("User-Agent"),
            'timestamp': datetime.now().isoformat(),
            HEADERS: dict(request.headers),
            REQUEST: {**dict(request.values), **dict(request.args)}
        }
    
        if request.values.get('hmac'):
            res, status_code = CommonLib().validation_rules(request, True)
            if status_code != 200:
                return res, status_code
            org_id = request.values.get('org_id')
            if not org_id or VALIDATIONS.is_valid_did(org_id) == None:
                return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_123")}, 400
            g.logs['clientid'] = res[1]
            g.org_id = org_id
            return

        jwtlib = DriveJwt(request, CONFIG)

        jwtres, status_code = jwtlib.jwt_login()
        if status_code == 200:
            g.path = jwtres
            g.jwt_token = jwtlib.jwt_token
            g.did = jwtlib.device_security_id
            g.digilockerid = jwtlib.digilockerid
            g.org_id = jwtlib.org_id
        else:
            return jwtres, status_code
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(JWT): " + str(e)}, 401

@bp.route('/send_otp',methods =['POST'])
def send_otp():
    g.logs['queue'] = 'adh_send_otp_PROD'
    try:
        res, status_code = VALIDATIONS.send_otp(request, g.org_id)
        if status_code == 200:
            uid, function_name = res
        else:
            return res, status_code  

        '''Once validaion and hmac done..genereate txn '''
        txnId = VALIDATIONS.get_txn(uid)
        org_client_id = request.values.get('org_client_id')
        org_txn = request.values.get('org_txn')
        partner_name = request.values.get('partner_name')
        app_name = request.values.get('app_name')
        orgid = g.org_id
        res = AADHAAR_CONNECTOR.send_aadhaar_otp(uid, txnId, org_client_id, org_txn, function_name, 'yes', partner_name, app_name, orgid)
        return res
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_111"), RESPONSE: str(e)}

        
@bp.route('/verify_otp', methods=['POST'])
def verify_otp():
    g.logs['queue'] = 'adh_kyc_PROD'
    try:
        res, status_code = VALIDATIONS.verify_otp(request,g.org_id)
        if status_code == 200:
            uid, txn, otp, consent = res
        else:
            return res, status_code
        
        '''Once validaion and hmac done.. '''
        data = {
            'uid':uid,
            'otp':otp,
            'txn':txn,
            'client_id': CONFIG['credentials']['client_id'],
            'isKYC':'Y',
            'requst_pdf': 'N',
            'requst_xml': request.values.get('request_xml') if request.values.get('request_xml') is not None else 'Y',
            'org_client_id': request.values.get('org_client_id'),
            'org_txn':request.values.get('org_txn'),
            'partner_name':request.values.get('partner_name'),
            'app_name':request.values.get('app_name'),
            'orgid': g.org_id,
            'function_name':request.values.get('function'),
            'update':'N'
        }
        res_data = AADHAAR_CONNECTOR.aadhaar_otp_verify(data)
        if res_data['status']== 'success':
            resp = res_data['response']

            user_data = AADHAAR_CONNECTOR.check_for_uid_token_exists(resp['UID_Token'])
            if user_data.get('status') and user_data.get('data') and  len(user_data.get('data')) > 0:
                finaldata = {}
                finaldata[STATUS]= SUCCESS
                finaldata['digilockerid']= user_data.get('data').get('digilockerid')
                finaldata['user_name']= resp['residentName']
                finaldata['photo']= resp['photo']
                finaldata['code']= 200
                finaldata['type']= 'old'
                finaldata['careOf'] = resp.get('careOf') if resp.get('careOf') else ''
                REDISLIB.set(finaldata['digilockerid']+'_org_add_user_verify_otp', json.dumps(finaldata))
                return finaldata
            else:
                REDISLIB.remove(txn + '_logID')
                resp = res_data['response']
                return SIGNUP_CONNECTOR.aadhaar_signup(resp, data)
        else:
            g.logs.update({RESPONSE: res_data})
            return {
                STATUS: ERROR,
                ERROR_DES: res_data['error_description'] #OTP not valid. Please enter Correct OTP as sent by UIDAI.[#K-100]
            }
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: Errors.error("ERR_MSG_111"), RESPONSE: str(e)}
    
@bp.route('/send_otp/1.0',methods =['POST'])
def send_aadhaar_otp1():
    try:
        res, status_code = VALIDATIONS.send_aadhaar_otp_valid(request)
        
        if status_code == 200:
            uid, din = res
        else:
            return res, status_code  
        
        '''Once validaion and hmac done..genereate txn '''
        txnId = VALIDATIONS.get_txn(uid)
        logarray.update({"response": txnId})
        RABBITMQ.send_to_logstash(logarray, 'Logstash_Xchange', 'org_logs_')
        return AADHAAR_CONNECTOR.send_aadhaar_otp(uid, txnId)
    except Exception as e:
        logarray.update({"response": str(e)})
        RABBITMQ.send_to_logstash(logarray, 'Logstash_Xchange', 'org_logs_')
        return {STATUS: ERROR, ERROR_DES: str(e)}
        
@bp.route('/verify_otp/1.0', methods=['POST'])
def verify_aadhaar_otp1():
    try:
        res, status_code = VALIDATIONS.verify_aadhaar_otp_valid(request)
        if status_code == 200:
            uid, txn, otp = res
        else:
            return res, status_code
        
        '''Once validaion and hmac done.. '''
        data = {
            'uid':uid,
            'otp':otp,
            'txn':txn,
            'client_id': CONFIG['credentials']['client_id'],
            'isKYC':'Y',
        }
        res_data = AADHAAR_CONNECTOR.aadhaar_otp_verify(data)
        if res_data['status']== 'success':
            REDISLIB.remove(txn + '_logID')
            resp = res_data['response']
            logarray.update({"response": resp})
            RABBITMQ.send_to_logstash(logarray, 'Logstash_Xchange', 'org_logs_') 
            return SIGNUP_CONNECTOR.aadhaar_signup(resp, data)
        else:
            logarray.update({"response": res_data})
            RABBITMQ.send_to_logstash(logarray, 'Logstash_Xchange', 'org_logs_')
            return {
                STATUS: ERROR,
                ERROR_DES:res_data['error_description'] #OTP not valid. Please enter Correct OTP as sent by UIDAI.[#K-100]
            }
    except Exception as e:
        logarray.update({"response": str(e)})
        RABBITMQ.send_to_logstash(logarray, 'Logstash_Xchange', 'org_logs_')
        return {STATUS: ERROR, ERROR_DES: str(e)}

@bp.after_request
def after_request(response):
    code = response.status_code
    res = response.get_data(as_text=True)
    res_json = response.get_json()
    g.logs.update({RESPONSE_CODE: code})
    if not g.logs.get(RESPONSE):
        g.logs.update({
            RESPONSE: {STATUS: SUCCESS, 'content-length': len(res), 'uidai_txn_id': res_json.pop('uidai_txn_id', None), 'txn': res_json.get('txn')} 
                if code == 200 and
                    (res_json.get('status') not in ('error', 'failed') if response.content_type == 'application/json' else True)
                else response.get_json() if response.content_type == 'application/json' else {STATUS: ERROR, 'content': res}
        })
    g.logs[REQUEST].pop('uid', None)
    # if g.logs[REQUEST].get('uid'):
    #     uid_decrypted = CommonLib.aes_decryption_v2(g.logs[REQUEST]['uid'], g.org_id[:16])
    #     if uid_decrypted and len(uid_decrypted) == 12:
    #         g.logs[REQUEST]['uid'] = hashlib.md5(uid_decrypted.encode()).hexdigest()
    RABBITMQ_LOGSTASH.log_adh_requests(g.logs, g.logs.pop('queue'))
    return response


@bp.after_request
def after_request(response):
    try:
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Access-Control-Allow-Headers'] = 'Accept,Authorization,Cache-Control,Content-Type,DNT,If-Modified-Since,Keep-Alive,Origin,User-Agent,X-Requested-With'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, POST'
        
        
        response_data = {
            'status': response.status,
            'headers': dict(response.headers),
            'body': response.get_data(as_text=True),
            'time_end': datetime.datetime.utcnow().isoformat()
        }
        log_data = {
            'request': request.logger_data,
            'response': response_data
        }
        logger.info(log_data)
        return response
    except Exception as e:
        print(f"Logging error: {str(e)}")
    return response

@bp.errorhandler(Exception)
def handle_exception(e):
    log_data = {
        'error': str(e),
        'time': datetime.datetime.utcnow().isoformat()
    }
    logger.error(log_data)
    response = jsonify({STATUS: ERROR, ERROR_DES: "Internal Server Error"})
    response.status_code = 500
    return response