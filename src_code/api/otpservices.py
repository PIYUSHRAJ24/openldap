from flask import Blueprint, request
from lib.constants import *
from lib.validations import Validations
from lib.aadhaarServices import AADHAAR_services
from lib.mongolib import MongoLib
from lib.rabbitmq import RabbitMQ
from lib.redislib import RedisLib
from lib.rabbitmq import RabbitMQ
from lib.signup_model import Signup_model

VALIDATIONS = Validations()
REDISLIB = RedisLib()
MONGOLIB = MongoLib()
RABBITMQ = RabbitMQ()
AADHAAR_CONNECTOR = AADHAAR_services(CONFIG)
SIGNUP_CONNECTOR = Signup_model(CONFIG)


bp = Blueprint('aadhaar', __name__)
logarray = {}

@bp.before_request
def validate_user():
    """
        HMAC Authentication
    """
    logarray.update({
        ENDPOINT: request.path,
        HEADER: {
            'user-agent': request.headers.get('User-Agent'),
            "client_id": request.headers.get("client_id"),
            "ts": request.headers.get("ts"),
            "hmac": request.headers.get("hmac")
        },
        REQUEST: {}
    })
    if dict(request.args):
        logarray[REQUEST].update(dict(request.args))
    if dict(request.values):
        logarray[REQUEST].update(dict(request.values))
    if request.headers.get('Content-Type') == "application/json":
        logarray[REQUEST].update(dict(request.json)) # type: ignore

    try:
        if request.method == 'OPTIONS':
            return {"status": "error", "error_description": "OPTIONS OK"}
        bypass_urls = ('healthcheck')
        if request.path.split('/')[1] in bypass_urls:
            return

        res, status_code = VALIDATIONS.hmac_authentication(request)

        if status_code != 200:
            return res, status_code
        
    except Exception as e:
        return {STATUS: ERROR, ERROR_DES: "Exception(HMAC): " + str(e)}, 401

@bp.route('/send_otp/1.0',methods =['POST'])
def send_aadhaar_otp():
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
def verify_aadhaar_otp():
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





        
        
